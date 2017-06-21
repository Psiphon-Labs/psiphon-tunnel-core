/*
 * Copyright (c) 2017, Psiphon Inc.
 * All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

package psiphon

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Psiphon-Inc/goarista/monotime"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
)

const (
	PACKET_TUNNEL_PROBE_SLOW_READ  = 3 * time.Second
	PACKET_TUNNEL_PROBE_SLOW_WRITE = 3 * time.Second
)

// PacketTunnelTransport is an integration layer that presents an io.ReadWriteCloser interface
// to a tun.Client as the transport for relaying packets. The Psiphon client may periodically
// disconnect from and reconnect to the same or different Psiphon servers. PacketTunnelTransport
// allows the Psiphon client to substitute new transport channels on-the-fly.
// PacketTunnelTransport implements transport monitoring, using heuristics to determine when
// the channel tunnel should be probed as a failure check.
type PacketTunnelTransport struct {
	// Note: 64-bit ints used with atomic operations are placed
	// at the start of struct to ensure 64-bit alignment.
	// (https://golang.org/pkg/sync/atomic/#pkg-note-BUG)
	lastReadComplete  int64
	lastWriteStart    int64
	lastWriteComplete int64

	runContext    context.Context
	stopRunning   context.CancelFunc
	workers       *sync.WaitGroup
	readMutex     sync.Mutex
	writeMutex    sync.Mutex
	channelReady  *sync.Cond
	channelMutex  sync.Mutex
	channelConn   net.Conn
	channelTunnel *Tunnel
}

// NewPacketTunnelTransport initializes a PacketTunnelTransport.
func NewPacketTunnelTransport() *PacketTunnelTransport {

	runContext, stopRunning := context.WithCancel(context.Background())

	p := &PacketTunnelTransport{
		runContext:   runContext,
		stopRunning:  stopRunning,
		workers:      new(sync.WaitGroup),
		channelReady: sync.NewCond(new(sync.Mutex)),
	}

	// The monitor worker will signal the tunnel channel when it
	// suspects that the packet tunnel channel has failed.

	p.workers.Add(1)
	go p.monitor()

	return p
}

// Read implements the io.Reader interface. It uses the current transport channel
// to read packet data, or waits for a new transport channel to be established
// after a failure.
func (p *PacketTunnelTransport) Read(data []byte) (int, error) {

	p.readMutex.Lock()
	defer p.readMutex.Unlock()

	// getChannel will block if there's no channel.

	channelConn, channelTunnel, err := p.getChannel()
	if err != nil {
		return 0, common.ContextError(err)
	}

	n, err := channelConn.Read(data)

	atomic.StoreInt64(&p.lastReadComplete, int64(monotime.Now()))

	if err != nil {

		// This assumes that any error means the channel has failed, which
		// is the case for ssh.Channel reads. io.EOF is not ignored, since
		// a single ssh.Channel may EOF and still get substituted with a new
		// channel.

		p.failedChannel(channelConn, channelTunnel)
	}

	return n, err
}

// Write implements the io.Writer interface. It uses the current transport channel
// to write packet data, or waits for a new transport channel to be established
// after a failure.
func (p *PacketTunnelTransport) Write(data []byte) (int, error) {

	p.writeMutex.Lock()
	defer p.writeMutex.Unlock()

	channelConn, channelTunnel, err := p.getChannel()
	if err != nil {
		return 0, common.ContextError(err)
	}

	// ssh.Channels are pseudo net.Conns and don't support timeouts/deadlines.
	// Instead of spawning a goroutine per write, record time values that the
	// monitor worker will use to detect possible failures, such as writes taking
	// too long.

	atomic.StoreInt64(&p.lastWriteStart, int64(monotime.Now()))

	n, err := channelConn.Write(data)

	atomic.StoreInt64(&p.lastWriteComplete, int64(monotime.Now()))

	if err != nil {

		// This assumes that any error means the channel has failed, which
		// is the case for ssh.Channel writes.

		p.failedChannel(channelConn, channelTunnel)
	}

	return n, err
}

// Close implements the io.Closer interface. Any underlying transport channel is
// called, the monitor worker is stopped, and any blocking Read/Write calls will
// be interrupted.
func (p *PacketTunnelTransport) Close() error {

	p.stopRunning()

	p.workers.Wait()

	// This broadcast is to wake up reads or writes blocking in getChannel; those
	// getChannel calls should then abort on the p.runContext.Done() check.
	p.channelReady.Broadcast()

	p.channelMutex.Lock()
	if p.channelConn != nil {
		p.channelConn.Close()
		p.channelConn = nil
	}
	p.channelMutex.Unlock()

	return nil
}

// UseNewTunnel sets the PacketTunnelTransport to use a new transport channel within
// the specified tunnel. UseNewTunnel does not block on the open channel call; it spawns
// a worker that calls tunnel.DialPacketTunnelChannel and uses the resulting channel.
func (p *PacketTunnelTransport) UseNewTunnel(tunnel *Tunnel) {

	p.workers.Add(1)
	go func(tunnel *Tunnel) {
		defer p.workers.Done()

		// channelConn is a net.Conn, since some layering has been applied
		// (e.g., transferstats.Conn). PacketTunnelTransport assumes the
		// channelConn is ultimately an ssh.Channel, which is not a fully
		// functional net.Conn.

		channelConn, err := tunnel.DialPacketTunnelChannel()
		if err != nil {
			// Note: DialPacketTunnelChannel will signal a probe on failure,
			// so it's not necessary to do so here.

			NoticeAlert("dial packet tunnel channel failed : %s", err)
			// TODO: retry?
			return
		}

		p.setChannel(channelConn, tunnel)

	}(tunnel)
}

func (p *PacketTunnelTransport) setChannel(
	channelConn net.Conn, channelTunnel *Tunnel) {

	p.channelMutex.Lock()
	defer p.channelMutex.Unlock()

	// Concurrency note: this check is within the mutex to ensure that a
	// UseNewTunnel call concurrent with a Close call doesn't leave a channel
	// set.
	select {
	case <-p.runContext.Done():
		return
	default:
	}

	p.channelConn = channelConn
	p.channelTunnel = channelTunnel

	p.channelMutex.Unlock()

	p.channelReady.Broadcast()
}

func (p *PacketTunnelTransport) getChannel() (net.Conn, *Tunnel, error) {

	var channelConn net.Conn
	var channelTunnel *Tunnel

	p.channelReady.L.Lock()
	defer p.channelReady.L.Unlock()
	for {

		select {
		case <-p.runContext.Done():
			return nil, nil, common.ContextError(errors.New("already closed"))
		default:
		}

		p.channelMutex.Lock()
		channelConn = p.channelConn
		channelTunnel = p.channelTunnel
		p.channelMutex.Unlock()
		if channelConn != nil {
			break
		}

		p.channelReady.Wait()
	}

	return channelConn, channelTunnel, nil
}

func (p *PacketTunnelTransport) failedChannel(
	channelConn net.Conn, channelTunnel *Tunnel) {

	// In case the channel read/write failed and the tunnel isn't
	// yet in the failed state, trigger a probe.

	select {
	case channelTunnel.signalPortForwardFailure <- *new(struct{}):
	default:
	}

	// Clear the current channel. This will cause subsequent Read/Write
	// calls to block in getChannel until a new channel is provided.
	// Concurrency note: must check, within the mutex, that the channelConn
	// is still the one that failed before clearing, since both Read and
	// Write could call failedChannel concurrently.

	p.channelMutex.Lock()
	if p.channelConn == channelConn {
		p.channelConn.Close()
		p.channelConn = nil
		p.channelTunnel = nil
	}
	p.channelMutex.Unlock()
}

func (p *PacketTunnelTransport) monitor() {

	defer p.workers.Done()

	monitorTicker := time.NewTicker(1 * time.Second)
	defer monitorTicker.Stop()

	for {
		select {
		case <-p.runContext.Done():
			return
		case <-monitorTicker.C:
			lastReadComplete := monotime.Time(atomic.LoadInt64(&p.lastReadComplete))
			lastWriteStart := monotime.Time(atomic.LoadInt64(&p.lastWriteStart))
			lastWriteComplete := monotime.Time(atomic.LoadInt64(&p.lastWriteComplete))

			// Heuristics to determine if the tunnel channel may have failed:
			// - a Write has blocked for too long
			// - no Reads after recent Writes
			//
			// When a heuristic is hit, a signal is sent to the channel tunnel
			// which will invoke and SSH keep alive probe of the tunnel. Nothing
			// is torn down here. If the tunnel determines it has failed, it will
			// close itself, which closes its channels, which will cause blocking
			// PacketTunnelTransport Reads/Writes to fail and call failedChannel.

			if (lastWriteStart != 0 &&
				lastWriteStart.Sub(lastWriteComplete) > PACKET_TUNNEL_PROBE_SLOW_WRITE) ||
				(lastWriteComplete.Sub(lastReadComplete) > PACKET_TUNNEL_PROBE_SLOW_READ) {

				p.channelMutex.Lock()
				channelTunnel := p.channelTunnel
				p.channelMutex.Unlock()

				// TODO: store/check last probe signal time to prevent continuous probe signals?

				if channelTunnel != nil {
					select {
					case channelTunnel.signalPortForwardFailure <- *new(struct{}):
					default:
					}
				}
			}
		}
	}
}
