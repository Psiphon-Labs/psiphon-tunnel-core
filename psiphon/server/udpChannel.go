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
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon"
	"golang.org/x/crypto/ssh"
)

// setUDPChannel sets the single UDP channel for this sshClient.
// Each sshClient may have only one concurrent UDP channel. Each
// UDP channel multiplexes many UDP port forwards via the udpgw
// protocol. Any existing UDP channel is closed.
func (sshClient *sshClient) setUDPChannel(channel ssh.Channel) {
	sshClient.Lock()
	if sshClient.udpChannel != nil {
		sshClient.udpChannel.Close()
	}
	sshClient.udpChannel = channel
	sshClient.Unlock()
}

// handleUDPChannel implements UDP port forwarding. A single UDP
// SSH channel follows the udpgw protocol, which multiplexes many
// UDP port forwards.
//
// The udpgw protocol and original server implementation:
// Copyright (c) 2009, Ambroz Bizjak <ambrop7@gmail.com>
// https://github.com/ambrop72/badvpn
//
func (sshClient *sshClient) handleUDPChannel(newChannel ssh.NewChannel) {

	// Accept this channel immediately. This channel will replace any
	// previously existing UDP channel for this client.

	fwdChannel, requests, err := newChannel.Accept()
	if err != nil {
		log.WithContextFields(LogFields{"error": err}).Warning("accept new channel failed")
		return
	}
	go ssh.DiscardRequests(requests)
	defer fwdChannel.Close()

	sshClient.setUDPChannel(fwdChannel)

	// In a loop, read udpgw messages from the client to this channel. Each message is
	// a UDP packet to send upstream either via a new port forward, or on an existing
	// port forward.
	//
	// A goroutine is run to read downstream packets for each UDP port forward. All read
	// packets are encapsulated in udpgw protocol and sent down the channel to the client.
	//
	// When the client disconnects or the server shuts down, the channel will close and
	// readUdpgwMessage will exit with EOF.

	type udpPortForward struct {
		connID       uint16
		conn         *net.UDPConn
		lastActivity int64
		bytesUp      int64
		bytesDown    int64
	}

	var portForwardsMutex sync.Mutex
	portForwards := make(map[uint16]*udpPortForward)
	relayWaitGroup := new(sync.WaitGroup)
	buffer := make([]byte, udpgwProtocolMaxMessageSize)

	for {
		// Note: udpProtocolMessage.packet points to the resuable
		// memory in "buffer". Each readUdpgwMessage call will overwrite
		// the last udpProtocolMessage.packet.
		udpProtocolMessage, err := readUdpgwMessage(
			sshClient.sshServer.config, fwdChannel, buffer)
		if err != nil {
			if err != io.EOF {
				log.WithContextFields(LogFields{"error": err}).Warning("readUpdgwMessage failed")
			}
			break
		}

		portForwardsMutex.Lock()
		portForward := portForwards[udpProtocolMessage.connID]
		portForwardsMutex.Unlock()

		if portForward != nil && udpProtocolMessage.discardExistingConn {
			// The port forward's goroutine will complete cleanup, including
			// tallying stats and calling sshClient.closedPortForward.
			// portForward.conn.Close() will signal this shutdown.
			// TODO: wait for goroutine to exit before proceeding?
			portForward.conn.Close()
			portForward = nil
		}

		if portForward == nil {

			if !sshClient.isPortForwardPermitted(
				udpProtocolMessage.portToConnect,
				sshClient.trafficRules.AllowUDPPorts,
				sshClient.trafficRules.DenyUDPPorts) {
				// The udpgw protocol has no error response, so
				// we just discard the message and read another.
				continue
			}

			if sshClient.isPortForwardLimitExceeded(
				sshClient.tcpTrafficState,
				sshClient.trafficRules.MaxUDPPortForwardCount) {

				// When the UDP port forward limit is exceeded, we
				// select the least recently used (red from or written
				// to) port forward and discard it.

				// TODO: use "container/list" and avoid a linear scan?
				portForwardsMutex.Lock()
				oldestActivity := int64(math.MaxInt64)
				var oldestPortForward *udpPortForward
				for _, nextPortForward := range portForwards {
					if nextPortForward.lastActivity < oldestActivity {
						oldestPortForward = nextPortForward
					}
				}
				if oldestPortForward != nil {
					// *** comment: let goro call closePortForward
					oldestPortForward.conn.Close()
				}
				portForwardsMutex.Unlock()
			}

			// TODO: on EADDRNOTAVAIL, temporarily suspend new clients
			// TODO: IPv6 support
			updConn, err := net.Dial(
				"udp4",
				fmt.Sprintf("%s:%d", udpProtocolMessage.hostToConnect, udpProtocolMessage.portToConnect))
			if err != nil {
				log.WithContextFields(LogFields{"error": err}).Warning("DialUDP failed")
				continue
			}

			portForward := &udpPortForward{
				connID:       udpProtocolMessage.connID,
				conn:         updConn.(*net.UDPConn),
				lastActivity: time.Now().UnixNano(),
				bytesUp:      0,
				bytesDown:    0,
			}
			portForwardsMutex.Lock()
			portForwards[portForward.connID] = portForward
			portForwardsMutex.Unlock()

			// TODO: timeout inactive UDP port forwards

			sshClient.establishedPortForward(sshClient.udpTrafficState)

			relayWaitGroup.Add(1)
			go func(portForward *udpPortForward) {
				defer relayWaitGroup.Done()

				// Downstream UDP packets are read into the reusable memory
				// in "buffer" starting at the offset udpgwProtocolHeaderSize,
				// leaving enough space to write the udpgw header into the
				// same buffer and use for writing to the ssh channel.
				//
				// Note: there is one downstream buffer per UDP port forward,
				// while for upstream there is one buffer per client.
				// TODO: is the buffer size larger than necessary?
				buffer := make([]byte, udpgwProtocolMaxMessageSize)
				packetBuffer := buffer[udpgwProtocolHeaderSize:udpgwProtocolMaxMessageSize]
				for {
					// TODO: if read buffer is too small, excess bytes are discarded?
					packetSize, _, err := portForward.conn.ReadFrom(packetBuffer)
					if packetSize > udpgwProtocolMaxPayloadSize {
						err = fmt.Errorf("unexpected packet size: %d", packetSize)
					}
					if err != nil {
						if err != io.EOF {
							log.WithContextFields(LogFields{"error": err}).Warning("downstream UDP relay failed")
						}
						break
					}

					writeUdpgwHeader(buffer, uint16(packetSize), portForward.connID)

					_, err = fwdChannel.Write(buffer[0 : udpgwProtocolHeaderSize+packetSize])
					if err != nil {
						// Close the channel, which will interrupt the main loop.
						fwdChannel.Close()
						log.WithContextFields(LogFields{"error": err}).Warning("downstream UDP relay failed")
						break
					}

					atomic.StoreInt64(&portForward.lastActivity, time.Now().UnixNano())
					atomic.AddInt64(&portForward.bytesDown, int64(packetSize))
				}

				portForwardsMutex.Lock()
				delete(portForwards, portForward.connID)
				portForwardsMutex.Unlock()

				portForward.conn.Close()

				bytesUp := atomic.LoadInt64(&portForward.bytesUp)
				bytesDown := atomic.LoadInt64(&portForward.bytesDown)
				sshClient.closedPortForward(sshClient.udpTrafficState, bytesUp, bytesDown)

			}(portForward)
		}

		// Note: assumes UDP writes won't block (https://golang.org/pkg/net/#UDPConn.WriteToUDP)
		_, err = portForward.conn.WriteTo(udpProtocolMessage.packet, nil)
		if err != nil {
			log.WithContextFields(LogFields{"error": err}).Warning("upstream UDP relay failed")
			// The port forward's goroutine will complete cleanup
			portForward.conn.Close()
		}
		atomic.StoreInt64(&portForward.lastActivity, time.Now().UnixNano())
		atomic.AddInt64(&portForward.bytesUp, int64(len(udpProtocolMessage.packet)))
	}

	// Cleanup all UDP port forward workers when exiting

	portForwardsMutex.Lock()
	for _, portForward := range portForwards {
		// The port forward's goroutine will complete cleanup
		portForward.conn.Close()
	}
	portForwardsMutex.Unlock()

	relayWaitGroup.Wait()
}

// TODO: express and/or calculate udpgwProtocolMaxPayloadSize as function of MTU?
const (
	udpgwProtocolFlagKeepalive = 1 << 0
	udpgwProtocolFlagRebind    = 1 << 1
	udpgwProtocolFlagDNS       = 1 << 2
	udpgwProtocolFlagIPv6      = 1 << 3

	udpgwProtocolHeaderSize     = 3
	udpgwProtocolIPv4AddrSize   = 6
	udpgwProtocolIPv6AddrSize   = 18
	udpgwProtocolMaxPayloadSize = 32768
	udpgwProtocolMaxMessageSize = udpgwProtocolHeaderSize +
		udpgwProtocolIPv6AddrSize +
		udpgwProtocolMaxPayloadSize
)

type udpgwHeader struct {
	Size   uint16
	Flags  uint8
	ConnID uint16
}

type udpgwAddrIPv4 struct {
	IP   uint32
	Port uint16
}

type udpgwAddrIPv6 struct {
	IP   [16]uint8
	Port uint16
}

type udpProtocolMessage struct {
	connID              uint16
	discardExistingConn bool
	hostToConnect       string
	portToConnect       int
	packet              []byte
}

func readUdpgwMessage(
	config *Config, reader io.Reader, buffer []byte) (*udpProtocolMessage, error) {

	for {
		// Read udpgwHeader

		_, err := io.ReadFull(reader, buffer[0:udpgwProtocolHeaderSize])
		if err != nil {
			return nil, psiphon.ContextError(err)
		}

		var header udpgwHeader
		err = binary.Read(
			bytes.NewReader(buffer[0:udpgwProtocolHeaderSize]), binary.BigEndian, &header)
		if err != nil {
			return nil, psiphon.ContextError(err)
		}

		if int(header.Size) < udpgwProtocolHeaderSize || int(header.Size) > len(buffer) {
			return nil, psiphon.ContextError(errors.New("invalid udpgw message size"))
		}

		_, err = io.ReadFull(reader, buffer[udpgwProtocolHeaderSize:header.Size])
		if err != nil {
			return nil, psiphon.ContextError(err)
		}

		// Ignore udpgw keep-alive messages -- read another message

		if header.Flags&udpgwProtocolFlagKeepalive == udpgwProtocolFlagKeepalive {
			continue
		}

		// Read udpgwAddrIPv4 or udpgwAddrIPv6

		var hostToConnect string
		var portToConnect int
		var packetOffset int

		if header.Flags&udpgwProtocolFlagIPv6 == udpgwProtocolFlagIPv6 {

			var addr udpgwAddrIPv6
			err = binary.Read(
				bytes.NewReader(
					buffer[udpgwProtocolHeaderSize:udpgwProtocolHeaderSize+udpgwProtocolIPv6AddrSize]),
				binary.BigEndian, &addr)
			if err != nil {
				return nil, psiphon.ContextError(err)
			}

			ip := make(net.IP, 16)
			copy(ip, addr.IP[:])

			hostToConnect = ip.String()
			portToConnect = int(addr.Port)
			packetOffset = udpgwProtocolHeaderSize + udpgwProtocolIPv6AddrSize

		} else {

			var addr udpgwAddrIPv4
			err = binary.Read(
				bytes.NewReader(
					buffer[udpgwProtocolHeaderSize:udpgwProtocolHeaderSize+udpgwProtocolIPv4AddrSize]),
				binary.BigEndian, &addr)

			ip := make(net.IP, 4)
			binary.BigEndian.PutUint32(ip, addr.IP)

			hostToConnect = net.IP(ip).String()
			portToConnect = int(addr.Port)
			packetOffset = udpgwProtocolHeaderSize + udpgwProtocolIPv4AddrSize
		}

		// Assemble message
		// Note: udpProtocolMessage.packet references memory in the input buffer

		udpProtocolMessage := &udpProtocolMessage{
			connID:              header.ConnID,
			discardExistingConn: header.Flags&udpgwProtocolFlagRebind == udpgwProtocolFlagRebind,
			hostToConnect:       hostToConnect,
			portToConnect:       portToConnect,
			packet:              buffer[packetOffset : int(header.Size)-packetOffset],
		}

		// Transparent DNS forwarding

		if (header.Flags&udpgwProtocolFlagDNS == udpgwProtocolFlagDNS) &&
			config.DNSServerAddress != "" {

			// Note: DNSServerAddress SplitHostPort is checked in LoadConfig
			host, portStr, _ := net.SplitHostPort(config.DNSServerAddress)
			port, _ := strconv.Atoi(portStr)
			udpProtocolMessage.hostToConnect = host
			udpProtocolMessage.portToConnect = port
		}

		return udpProtocolMessage, nil
	}
}

func writeUdpgwHeader(
	buffer []byte, packetSize uint16, connID uint16) {
	// TODO: write directly into buffer
	header := make([]byte, 0, udpgwProtocolHeaderSize)
	binary.Write(
		bytes.NewBuffer(header),
		binary.BigEndian,
		&udpgwHeader{
			Size:   udpgwProtocolHeaderSize + packetSize,
			Flags:  0,
			ConnID: connID})
	copy(buffer[0:udpgwProtocolHeaderSize], header)
}
