/*
 * Copyright (c) 2016, Psiphon Inc.
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

package server

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/crypto/ssh"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/monotime"
)

// handleUdpgwChannel implements UDP port forwarding. A single UDP
// SSH channel follows the udpgw protocol, which multiplexes many
// UDP port forwards.
//
// The udpgw protocol and original server implementation:
// Copyright (c) 2009, Ambroz Bizjak <ambrop7@gmail.com>
// https://github.com/ambrop72/badvpn
func (sshClient *sshClient) handleUdpgwChannel(newChannel ssh.NewChannel) {

	// Accept this channel immediately. This channel will replace any
	// previously existing udpgw channel for this client.

	sshChannel, requests, err := newChannel.Accept()
	if err != nil {
		if !isExpectedTunnelIOError(err) {
			log.WithTraceFields(LogFields{"error": err}).Warning("accept new channel failed")
		}
		return
	}
	go ssh.DiscardRequests(requests)
	defer sshChannel.Close()

	multiplexer := &udpgwPortForwardMultiplexer{
		sshClient:      sshClient,
		sshChannel:     sshChannel,
		portForwards:   make(map[uint16]*udpgwPortForward),
		portForwardLRU: common.NewLRUConns(),
		relayWaitGroup: new(sync.WaitGroup),
		runWaitGroup:   new(sync.WaitGroup),
	}

	multiplexer.runWaitGroup.Add(1)

	// setUdpgwChannelHandler will close any existing
	// udpgwPortForwardMultiplexer, waiting for all run/relayDownstream
	// goroutines to first terminate and all UDP socket resources to be
	// cleaned up.
	//
	// This synchronous shutdown also ensures that the
	// concurrentPortForwardCount is reduced to 0 before installing the new
	// udpgwPortForwardMultiplexer and its LRU object. If the older handler
	// were to dangle with open port forwards, and concurrentPortForwardCount
	// were to hit the max, the wrong LRU, the new one, would be used to
	// close the LRU port forward.
	//
	// Call setUdpgwHandler only after runWaitGroup is initialized, to ensure
	// runWaitGroup.Wait() cannot be invoked (by some subsequent new udpgw
	// channel) before initialized.

	if !sshClient.setUdpgwChannelHandler(multiplexer) {
		// setUdpgwChannelHandler returns false if some other SSH channel
		// calls setUdpgwChannelHandler in the middle of this call. In that
		// case, discard this channel: the client's latest udpgw channel is
		// retained.
		return
	}

	multiplexer.run()
	multiplexer.runWaitGroup.Done()
}

type udpgwPortForwardMultiplexer struct {
	sshClient            *sshClient
	sshChannelWriteMutex sync.Mutex
	sshChannel           ssh.Channel
	portForwardsMutex    sync.Mutex
	portForwards         map[uint16]*udpgwPortForward
	portForwardLRU       *common.LRUConns
	relayWaitGroup       *sync.WaitGroup
	runWaitGroup         *sync.WaitGroup
}

func (mux *udpgwPortForwardMultiplexer) stop() {

	// udpgwPortForwardMultiplexer must be initialized by handleUdpgwChannel.
	//
	// stop closes the udpgw SSH channel, which will cause the run goroutine
	// to exit its message read loop and await closure of all relayDownstream
	// goroutines. Closing all port forward UDP conns will cause all
	// relayDownstream to exit.

	_ = mux.sshChannel.Close()

	mux.portForwardsMutex.Lock()
	for _, portForward := range mux.portForwards {
		_ = portForward.conn.Close()
	}
	mux.portForwardsMutex.Unlock()

	mux.runWaitGroup.Wait()
}

func (mux *udpgwPortForwardMultiplexer) run() {

	// In a loop, read udpgw messages from the client to this channel. Each
	// message contains a UDP packet to send upstream either via a new port
	// forward, or on an existing port forward.
	//
	// A goroutine is run to read downstream packets for each UDP port forward. All read
	// packets are encapsulated in udpgw protocol and sent down the channel to the client.
	//
	// When the client disconnects or the server shuts down, the channel will close and
	// readUdpgwMessage will exit with EOF.

	buffer := make([]byte, udpgwProtocolMaxMessageSize)
	for {
		// Note: message.packet points to the reusable memory in "buffer".
		// Each readUdpgwMessage call will overwrite the last message.packet.
		message, err := readUdpgwMessage(mux.sshChannel, buffer)
		if err != nil {
			if err != io.EOF {
				// Debug since I/O errors occur during normal operation
				log.WithTraceFields(LogFields{"error": err}).Debug("readUdpgwMessage failed")
			}
			break
		}

		mux.portForwardsMutex.Lock()
		portForward := mux.portForwards[message.connID]
		mux.portForwardsMutex.Unlock()

		// In the udpgw protocol, an existing port forward is closed when
		// either the discard flag is set or the remote address has changed.

		if portForward != nil &&
			(message.discardExistingConn ||
				!bytes.Equal(portForward.remoteIP, message.remoteIP) ||
				portForward.remotePort != message.remotePort) {

			// The port forward's goroutine will complete cleanup, including
			// tallying stats and calling sshClient.closedPortForward.
			// portForward.conn.Close() will signal this shutdown.
			portForward.conn.Close()

			// Synchronously await the termination of the relayDownstream
			// goroutine. This ensures that the previous goroutine won't
			// invoke removePortForward, with the connID that will be reused
			// for the new port forward, after this point.
			//
			// Limitation: this synchronous shutdown cannot prevent a "wrong
			// remote address" error on the badvpn udpgw client, which occurs
			// when the client recycles a port forward (setting discard) but
			// receives, from the server, a udpgw message containing the old
			// remote address for the previous port forward with the same
			// conn ID. That downstream message from the server may be in
			// flight in the SSH channel when the client discard message arrives.
			portForward.relayWaitGroup.Wait()

			portForward = nil
		}

		if portForward == nil {

			// Create a new port forward

			dialIP := net.IP(message.remoteIP)
			dialPort := int(message.remotePort)

			// Validate DNS packets and check the domain blocklist both when the client
			// indicates DNS or when DNS is _not_ indicated and the destination port is
			// 53.
			if message.forwardDNS || message.remotePort == 53 {

				domain, err := common.ParseDNSQuestion(message.packet)
				if err != nil {
					log.WithTraceFields(LogFields{"error": err}).Debug("ParseDNSQuestion failed")
					// Drop packet
					continue
				}

				if domain != "" {
					ok, _ := mux.sshClient.isDomainPermitted(domain)
					if !ok {
						// Drop packet
						continue
					}
				}
			}

			if message.forwardDNS {
				// Transparent DNS forwarding. In this case, isPortForwardPermitted
				// traffic rules checks are bypassed, since DNS is essential.
				dialIP = mux.sshClient.sshServer.support.DNSResolver.Get()
				dialPort = DNS_RESOLVER_PORT

			} else if !mux.sshClient.isPortForwardPermitted(
				portForwardTypeUDP, dialIP, int(message.remotePort)) {
				// The udpgw protocol has no error response, so
				// we just discard the message and read another.
				continue
			}

			// Note: UDP port forward counting has no dialing phase

			// establishedPortForward increments the concurrent UDP port
			// forward counter and closes the LRU existing UDP port forward
			// when already at the limit.

			mux.sshClient.establishedPortForward(portForwardTypeUDP, mux.portForwardLRU)
			// Can't defer sshClient.closedPortForward() here;
			// relayDownstream will call sshClient.closedPortForward()

			// Pre-check log level to avoid overhead of rendering log for
			// every DNS query and other UDP port forward.
			if IsLogLevelDebug() {
				log.WithTraceFields(
					LogFields{
						"remoteAddr": net.JoinHostPort(dialIP.String(), strconv.Itoa(dialPort)),
						"connID":     message.connID}).Debug("dialing")
			}

			udpConn, err := net.DialUDP(
				"udp", nil, &net.UDPAddr{IP: dialIP, Port: dialPort})
			if err != nil {
				mux.sshClient.closedPortForward(portForwardTypeUDP, 0, 0)

				// Monitor for low resource error conditions
				mux.sshClient.sshServer.monitorPortForwardDialError(err)

				// Note: Debug level, as logMessage may contain user traffic destination address information
				log.WithTraceFields(LogFields{"error": err}).Debug("DialUDP failed")
				continue
			}

			lruEntry := mux.portForwardLRU.Add(udpConn)
			// Can't defer lruEntry.Remove() here;
			// relayDownstream will call lruEntry.Remove()

			// ActivityMonitoredConn monitors the UDP port forward I/O and updates
			// its LRU status. ActivityMonitoredConn also times out I/O on the port
			// forward if both reads and writes have been idle for the specified
			// duration.

			var activityUpdaters []common.ActivityUpdater
			// Don't incur activity monitor overhead for DNS requests
			if !message.forwardDNS {
				activityUpdaters = mux.sshClient.getPortForwardActivityUpdaters(
					portForwardTypeUDP, dialIP)
			}

			conn, err := common.NewActivityMonitoredConn(
				udpConn,
				mux.sshClient.idleUDPPortForwardTimeout(),
				true,
				lruEntry,
				activityUpdaters...)
			if err != nil {
				lruEntry.Remove()
				mux.sshClient.closedPortForward(portForwardTypeUDP, 0, 0)
				log.WithTraceFields(LogFields{"error": err}).Error("NewActivityMonitoredConn failed")
				continue
			}

			portForward = &udpgwPortForward{
				connID:         message.connID,
				preambleSize:   message.preambleSize,
				remoteIP:       message.remoteIP,
				remotePort:     message.remotePort,
				dialIP:         dialIP,
				conn:           conn,
				lruEntry:       lruEntry,
				relayWaitGroup: new(sync.WaitGroup),
				mux:            mux,
			}

			if message.forwardDNS {
				portForward.dnsFirstWriteTime.Store(int64(monotime.Now()))
			}

			mux.portForwardsMutex.Lock()
			mux.portForwards[portForward.connID] = portForward
			mux.portForwardsMutex.Unlock()

			portForward.relayWaitGroup.Add(1)
			mux.relayWaitGroup.Add(1)
			go portForward.relayDownstream()
		}

		// Note: assumes UDP writes won't block (https://golang.org/pkg/net/#UDPConn.WriteToUDP)
		_, err = portForward.conn.Write(message.packet)
		if err != nil {
			// Debug since errors such as "write: operation not permitted" occur during normal operation
			log.WithTraceFields(LogFields{"error": err}).Debug("upstream UDP relay failed")
			// The port forward's goroutine will complete cleanup
			portForward.conn.Close()
		}

		portForward.lruEntry.Touch()

		portForward.bytesUp.Add(int64(len(message.packet)))
	}

	// Cleanup all udpgw port forward workers when exiting

	mux.portForwardsMutex.Lock()
	for _, portForward := range mux.portForwards {
		// The port forward's goroutine will complete cleanup
		portForward.conn.Close()
	}
	mux.portForwardsMutex.Unlock()

	mux.relayWaitGroup.Wait()
}

func (mux *udpgwPortForwardMultiplexer) removePortForward(connID uint16) {
	mux.portForwardsMutex.Lock()
	delete(mux.portForwards, connID)
	mux.portForwardsMutex.Unlock()
}

type udpgwPortForward struct {
	dnsFirstWriteTime atomic.Int64
	dnsFirstReadTime  atomic.Int64
	bytesUp           atomic.Int64
	bytesDown         atomic.Int64
	connID            uint16
	preambleSize      int
	remoteIP          []byte
	remotePort        uint16
	dialIP            net.IP
	conn              net.Conn
	lruEntry          *common.LRUConnsEntry
	relayWaitGroup    *sync.WaitGroup
	mux               *udpgwPortForwardMultiplexer
}

var udpgwBufferPool = &sync.Pool{
	New: func() any {
		b := make([]byte, udpgwProtocolMaxMessageSize)
		return &b
	},
}

func (portForward *udpgwPortForward) relayDownstream() {
	defer portForward.relayWaitGroup.Done()
	defer portForward.mux.relayWaitGroup.Done()

	// Downstream UDP packets are read into the reusable memory
	// in "buffer" starting at the offset past the udpgw message
	// header and address, leaving enough space to write the udpgw
	// values into the same buffer and use for writing to the ssh
	// channel.
	//
	// Note: there is one downstream buffer per UDP port forward,
	// while for upstream there is one buffer per client.
	// TODO: is the buffer size larger than necessary?

	// Use a buffer pool to minimize GC churn resulting from frequent,
	// short-lived UDP flows, including DNS requests. A pointer to a slice is
	// used with sync.Pool to avoid an allocation on Put, as would happen if
	// passing in a slice instead of a pointer; see
	// https://github.com/dominikh/go-tools/issues/1042#issuecomment-869064445
	// and
	// https://github.com/dominikh/go-tools/issues/1336#issuecomment-1331206290
	// (which should not apply here).
	b := udpgwBufferPool.Get().(*[]byte)
	buffer := *b
	clear(buffer)
	defer udpgwBufferPool.Put(b)

	packetBuffer := buffer[portForward.preambleSize:udpgwProtocolMaxMessageSize]
	for {
		// TODO: if read buffer is too small, excess bytes are discarded?
		packetSize, err := portForward.conn.Read(packetBuffer)
		if packetSize > udpgwProtocolMaxPayloadSize {
			err = fmt.Errorf("unexpected packet size: %d", packetSize)
		}
		if err != nil {
			if err != io.EOF {
				// Debug since errors such as "use of closed network connection" occur during normal operation
				if IsLogLevelDebug() {
					log.WithTraceFields(LogFields{"error": err}).Debug("downstream UDP relay failed")
				}
			}
			break
		}

		if portForward.dnsFirstWriteTime.Load() > 0 &&
			portForward.dnsFirstReadTime.Load() == 0 { // Check if already set before invoking Now.
			portForward.dnsFirstReadTime.CompareAndSwap(0, int64(monotime.Now()))
		}

		err = writeUdpgwPreamble(
			portForward.preambleSize,
			0,
			portForward.connID,
			portForward.remoteIP,
			portForward.remotePort,
			uint16(packetSize),
			buffer)
		if err == nil {
			// ssh.Channel.Write cannot be called concurrently.
			// See: https://github.com/Psiphon-Inc/crypto/blob/82d98b4c7c05e81f92545f6fddb45d4541e6da00/ssh/channel.go#L272,
			// https://codereview.appspot.com/136420043/diff/80002/ssh/channel.go
			portForward.mux.sshChannelWriteMutex.Lock()
			_, err = portForward.mux.sshChannel.Write(buffer[0 : portForward.preambleSize+packetSize])
			portForward.mux.sshChannelWriteMutex.Unlock()
		}

		if err != nil {
			// Close the channel, which will interrupt the main loop.
			portForward.mux.sshChannel.Close()
			log.WithTraceFields(LogFields{"error": err}).Debug("downstream UDP relay failed")
			break
		}

		portForward.lruEntry.Touch()

		portForward.bytesDown.Add(int64(packetSize))
	}

	portForward.mux.removePortForward(portForward.connID)

	portForward.lruEntry.Remove()

	portForward.conn.Close()

	bytesUp := portForward.bytesUp.Load()
	bytesDown := portForward.bytesDown.Load()
	portForward.mux.sshClient.closedPortForward(portForwardTypeUDP, bytesUp, bytesDown)

	dnsStartTime := monotime.Time(portForward.dnsFirstWriteTime.Load())
	if dnsStartTime > 0 {

		// Record DNS metrics using a heuristic: if a UDP packet was written and
		// then a packet was read, assume the DNS request successfully received a
		// valid response; failure occurs when the resolver fails to provide a
		// response; a "no such host" response is still a success. Limitations: we
		// assume a resolver will not respond when, e.g., rate limiting; we ignore
		// subsequent requests made via the same UDP port forward.

		dnsEndTime := monotime.Time(portForward.dnsFirstReadTime.Load())

		dnsSuccess := true
		if dnsEndTime == 0 {
			dnsSuccess = false
			dnsEndTime = monotime.Now()
		}

		resolveElapsedTime := dnsEndTime.Sub(dnsStartTime)

		portForward.mux.sshClient.updateQualityMetricsWithDNSResult(
			dnsSuccess,
			resolveElapsedTime,
			net.IP(portForward.dialIP))
	}

	log.WithTraceFields(
		LogFields{
			"remoteAddr": net.JoinHostPort(
				net.IP(portForward.remoteIP).String(), strconv.Itoa(int(portForward.remotePort))),
			"bytesUp":   bytesUp,
			"bytesDown": bytesDown,
			"connID":    portForward.connID}).Debug("exiting")
}

// TODO: express and/or calculate udpgwProtocolMaxPayloadSize as function of MTU?
const (
	udpgwProtocolFlagKeepalive = 1 << 0
	udpgwProtocolFlagRebind    = 1 << 1
	udpgwProtocolFlagDNS       = 1 << 2
	udpgwProtocolFlagIPv6      = 1 << 3

	udpgwProtocolMaxPreambleSize = 23
	udpgwProtocolMaxPayloadSize  = 32768
	udpgwProtocolMaxMessageSize  = udpgwProtocolMaxPreambleSize + udpgwProtocolMaxPayloadSize
)

type udpgwProtocolMessage struct {
	connID              uint16
	preambleSize        int
	remoteIP            []byte
	remotePort          uint16
	discardExistingConn bool
	forwardDNS          bool
	packet              []byte
}

func readUdpgwMessage(
	reader io.Reader, buffer []byte) (*udpgwProtocolMessage, error) {

	// udpgw message layout:
	//
	// | 2 byte size | 3 byte header | 6 or 18 byte address | variable length packet |

	for {
		// Read message

		_, err := io.ReadFull(reader, buffer[0:2])
		if err != nil {
			if err != io.EOF {
				err = errors.Trace(err)
			}
			return nil, err
		}

		size := binary.LittleEndian.Uint16(buffer[0:2])

		if size < 3 || int(size) > len(buffer)-2 {
			return nil, errors.TraceNew("invalid udpgw message size")
		}

		_, err = io.ReadFull(reader, buffer[2:2+size])
		if err != nil {
			if err != io.EOF {
				err = errors.Trace(err)
			}
			return nil, err
		}

		flags := buffer[2]

		connID := binary.LittleEndian.Uint16(buffer[3:5])

		// Ignore udpgw keep-alive messages -- read another message

		if flags&udpgwProtocolFlagKeepalive == udpgwProtocolFlagKeepalive {
			continue
		}

		// Read address

		var remoteIP []byte
		var remotePort uint16
		var packetStart, packetEnd int

		if flags&udpgwProtocolFlagIPv6 == udpgwProtocolFlagIPv6 {

			if size < 21 {
				return nil, errors.TraceNew("invalid udpgw message size")
			}

			remoteIP = make([]byte, 16)
			copy(remoteIP, buffer[5:21])
			remotePort = binary.BigEndian.Uint16(buffer[21:23])
			packetStart = 23
			packetEnd = 23 + int(size) - 21

		} else {

			if size < 9 {
				return nil, errors.TraceNew("invalid udpgw message size")
			}

			remoteIP = make([]byte, 4)
			copy(remoteIP, buffer[5:9])
			remotePort = binary.BigEndian.Uint16(buffer[9:11])
			packetStart = 11
			packetEnd = 11 + int(size) - 9
		}

		// Assemble message
		// Note: udpgwProtocolMessage.packet references memory in the input buffer

		message := &udpgwProtocolMessage{
			connID:              connID,
			preambleSize:        packetStart,
			remoteIP:            remoteIP,
			remotePort:          remotePort,
			discardExistingConn: flags&udpgwProtocolFlagRebind == udpgwProtocolFlagRebind,
			forwardDNS:          flags&udpgwProtocolFlagDNS == udpgwProtocolFlagDNS,
			packet:              buffer[packetStart:packetEnd],
		}

		return message, nil
	}
}

func writeUdpgwPreamble(
	preambleSize int,
	flags uint8,
	connID uint16,
	remoteIP []byte,
	remotePort uint16,
	packetSize uint16,
	buffer []byte) error {

	if preambleSize != 7+len(remoteIP) {
		return errors.TraceNew("invalid udpgw preamble size")
	}

	size := uint16(preambleSize-2) + packetSize

	// size
	binary.LittleEndian.PutUint16(buffer[0:2], size)

	// flags
	buffer[2] = flags

	// connID
	binary.LittleEndian.PutUint16(buffer[3:5], connID)

	// addr
	copy(buffer[5:5+len(remoteIP)], remoteIP)
	binary.BigEndian.PutUint16(buffer[5+len(remoteIP):7+len(remoteIP)], remotePort)

	return nil
}
