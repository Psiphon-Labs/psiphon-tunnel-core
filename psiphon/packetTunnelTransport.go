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
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/monotime"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/parameters"
)

// PacketTunnelTransport is an integration layer that presents an io.ReadWriteCloser interface
// to a tun.Client as the transport for relaying packets. The Psiphon client may periodically
// disconnect from and reconnect to the same or different Psiphon servers. PacketTunnelTransport
// allows the Psiphon client to substitute new transport channels on-the-fly.
type PacketTunnelTransport struct {
	readTimeout   atomic.Int64
	readDeadline  atomic.Int64
	closed        int32
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
	return &PacketTunnelTransport{
		workers:      new(sync.WaitGroup),
		channelReady: sync.NewCond(new(sync.Mutex)),
	}
}

// Read implements the io.Reader interface. It uses the current transport channel
// to read packet data, or waits for a new transport channel to be established
// after a failure.
func (p *PacketTunnelTransport) Read(data []byte) (int, error) {

	p.readMutex.Lock()
	defer p.readMutex.Unlock()

	// getChannel will block if there's no channel, or return an error when
	// closed.
	channelConn, channelTunnel, err := p.getChannel()
	if err != nil {
		return 0, errors.Trace(err)
	}

	n, err := channelConn.Read(data)

	if err != nil {

		// This assumes that any error means the channel has failed, which
		// is the case for ssh.Channel reads. io.EOF is not ignored, since
		// a single ssh.Channel may EOF and still get substituted with a new
		// channel.

		p.failedChannel(channelConn, channelTunnel)

	} else {

		// Clear the read deadline now that a read has succeeded.
		// See read deadline comment in Write.
		p.readDeadline.Store(0)
	}

	return n, errors.Trace(err)
}

// Write implements the io.Writer interface. It uses the current transport channel
// to write packet data, or waits for a new transport channel to be established
// after a failure.
func (p *PacketTunnelTransport) Write(data []byte) (int, error) {

	p.writeMutex.Lock()
	defer p.writeMutex.Unlock()

	// getChannel will block if there's no channel, or return an error when
	// closed.
	channelConn, channelTunnel, err := p.getChannel()
	if err != nil {
		return 0, errors.Trace(err)
	}

	n, err := channelConn.Write(data)

	if err != nil {

		// This assumes that any error means the channel has failed, which
		// is the case for ssh.Channel writes.

		p.failedChannel(channelConn, channelTunnel)

	} else {

		// Set a read deadline: a successful read should occur within the deadline;
		// otherwise an SSH keep alive probe is triggered to check the tunnel
		// status.
		//
		// This scheme mirrors the tunnel dial port forward timeout mechanism
		// present in port forward mode: for any port forwarded connection attempt,
		// if there's a timeout before receiving a response from the server, an SSH
		// keep alive probe is triggered to check the tunnel state. Unlike port
		// forward mode, packet tunnel doesn't track tunneled connections (flows).
		//
		// Here, we deploy a heuristic based on the observation that, for most
		// traffic, a packet sent from the client -- a PacketTunnelTransport.Write
		// -- is followed by a packet received from the server -- a
		// PacketTunnelTransport.Read. For example, a UDP DNS request followed by a
		// response; or a TCP handshake sequence. The heuristic is to trigger an SSH
		// keep alive probe when there is no Read within the timeout period after a
		// Write. Any Read is sufficient to satisfy the deadline.
		//
		// To limit performance impact, we do not use, and continuously reset, a
		// time.Timer; instead we record the deadline upon successful Write and
		// check any set deadline during subsequent Writes. For the same reason, we
		// do we use a time.Ticker to check the deadline. This means that this
		// scheme depends on the host continuing to attempt to send packets in order
		// to trigger the SSH keep alive.
		//
		// Access to readDeadline/readTimeout is not intended to be completely
		// atomic.

		readDeadline := monotime.Time(p.readDeadline.Load())

		if readDeadline > 0 {

			if monotime.Now().After(readDeadline) {

				select {
				case channelTunnel.signalPortForwardFailure <- struct{}{}:
				default:
				}

				// Clear the deadline now that a probe is triggered.
				p.readDeadline.Store(0)
			}

			// Keep an existing deadline as set: subsequent writes attempts shouldn't
			// extend the deadline.

		} else {

			readTimeout := time.Duration(p.readTimeout.Load())
			readDeadline := monotime.Now().Add(readTimeout)
			p.readDeadline.Store(int64(readDeadline))
		}
	}

	return n, errors.Trace(err)
}

// Close implements the io.Closer interface. Any underlying transport channel is
// closed and any blocking Read/Write calls will be interrupted.
func (p *PacketTunnelTransport) Close() error {

	if !atomic.CompareAndSwapInt32(&p.closed, 0, 1) {
		return nil
	}

	p.workers.Wait()

	// This broadcast is to wake up reads or writes blocking in getChannel; those
	// getChannel calls should then abort on the p.closed check.
	p.channelReady.Broadcast()

	p.channelMutex.Lock()
	if p.channelConn != nil {
		p.channelConn.Close()
		p.channelConn = nil
	}
	p.channelMutex.Unlock()

	return nil
}

// UseTunnel sets the PacketTunnelTransport to use a new transport channel within
// the specified tunnel. UseTunnel does not block on the open channel call; it spawns
// a worker that calls tunnel.DialPacketTunnelChannel and uses the resulting channel.
// UseTunnel has no effect once Close is called.
//
// Note that a blocked tunnel.DialPacketTunnelChannel with block Close;
// callers should arrange for DialPacketTunnelChannel to be interrupted when
// calling Close.
func (p *PacketTunnelTransport) UseTunnel(tunnel *Tunnel) {

	// Don't start a worker when closed, after which workers.Wait may be called.
	if atomic.LoadInt32(&p.closed) == 1 {
		return
	}

	// Spawning a new worker ensures that the latest tunnel is used to dial a
	// new channel without delaying, as might happen if using a single worker
	// that consumes a channel of tunnels.

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

			NoticeWarning("dial packet tunnel channel failed: %s", err)
			// TODO: retry?
			return
		}

		p.setChannel(channelConn, tunnel)

	}(tunnel)
}

func (p *PacketTunnelTransport) setChannel(
	channelConn net.Conn, channelTunnel *Tunnel) {

	p.channelMutex.Lock()

	// Concurrency note: this check is within the mutex to ensure that a
	// UseTunnel call concurrent with a Close call doesn't leave a channel
	// set.
	if atomic.LoadInt32(&p.closed) == 1 {
		p.channelMutex.Unlock()
		return
	}

	// Interrupt Read/Write calls blocking on any previous channel.
	if p.channelConn != nil {
		p.channelConn.Close()
	}

	p.channelConn = channelConn
	p.channelTunnel = channelTunnel

	p.channelMutex.Unlock()

	// Initialize the read deadline mechanism using parameters associated with the
	// new tunnel.
	timeout := channelTunnel.config.
		GetParameters().
		GetCustom(channelTunnel.dialParams.NetworkLatencyMultiplier).
		Duration(parameters.PacketTunnelReadTimeout)
	p.readTimeout.Store(int64(timeout))
	p.readDeadline.Store(0)

	p.channelReady.Broadcast()
}

func (p *PacketTunnelTransport) getChannel() (net.Conn, *Tunnel, error) {

	var channelConn net.Conn
	var channelTunnel *Tunnel

	p.channelReady.L.Lock()
	defer p.channelReady.L.Unlock()
	for {

		if atomic.LoadInt32(&p.closed) == 1 {
			return nil, nil, errors.TraceNew("already closed")
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
	case channelTunnel.signalPortForwardFailure <- struct{}{}:
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

	// Try to establish a new channel within the current tunnel. If this
	// fails, a port forward failure probe will be triggered which will
	// ultimately trigger a SSH keep alive probe.
	//
	// One case where this is necessary is when the server closes an idle
	// packet tunnel port forward for a live SSH tunnel.

	p.UseTunnel(channelTunnel)
}
