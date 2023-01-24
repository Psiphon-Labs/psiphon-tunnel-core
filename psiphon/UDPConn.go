/*
 * Copyright (c) 2018, Psiphon Inc.
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
	"math/rand"
	"net"
	"strconv"
	"syscall"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
)

// NewUDPConn resolves addr and configures a new *net.UDPConn. The UDP socket
// is created using options in DialConfig, including DeviceBinder. The
// returned UDPAddr uses DialConfig options IPv6Synthesizer and
// ResolvedIPCallback.
//
// The UDP conn is not dialed; it is intended for use with WriteTo using the
// returned UDPAddr, not Write.
//
// The returned conn is not a common.Closer; the caller is expected to wrap
// this conn with another higher-level conn that provides that interface.
func NewUDPConn(
	ctx context.Context, addr string, config *DialConfig) (net.PacketConn, *net.UDPAddr, error) {

	host, strPort, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, nil, errors.Trace(err)
	}
	port, err := strconv.Atoi(strPort)
	if err != nil {
		return nil, nil, errors.Trace(err)
	}

	if port <= 0 || port >= 65536 {
		return nil, nil, errors.Tracef("invalid destination port: %d", port)
	}

	if config.ResolveIP == nil {
		// Fail even if we don't need a resolver for this dial: this is a code
		// misconfiguration.
		return nil, nil, errors.TraceNew("missing resolver")
	}
	ipAddrs, err := config.ResolveIP(ctx, host)
	if err != nil {
		return nil, nil, errors.Trace(err)
	}
	if len(ipAddrs) < 1 {
		return nil, nil, errors.TraceNew("no IP address")
	}

	ipAddr := ipAddrs[rand.Intn(len(ipAddrs))]

	if config.IPv6Synthesizer != nil {
		if ipAddr.To4() != nil {
			synthesizedIPAddress := config.IPv6Synthesizer.IPv6Synthesize(ipAddr.String())
			if synthesizedIPAddress != "" {
				synthesizedAddr := net.ParseIP(synthesizedIPAddress)
				if synthesizedAddr != nil {
					ipAddr = synthesizedAddr
				}
			}
		}
	}

	listen := &net.ListenConfig{
		Control: func(_, _ string, c syscall.RawConn) error {
			var controlErr error
			err := c.Control(func(fd uintptr) {

				socketFD := int(fd)

				setAdditionalSocketOptions(socketFD)

				if config.BPFProgramInstructions != nil {
					err := setSocketBPF(config.BPFProgramInstructions, socketFD)
					if err != nil {
						controlErr = errors.Tracef("setSocketBPF failed: %s", err)
						return
					}
				}

				if config.DeviceBinder != nil {
					_, err := config.DeviceBinder.BindToDevice(socketFD)
					if err != nil {
						controlErr = errors.Tracef("BindToDevice failed: %s", err)
						return
					}
				}
			})
			if controlErr != nil {
				return errors.Trace(controlErr)
			}
			return errors.Trace(err)
		},
	}

	network := "udp4"
	if ipAddr.To4() == nil {
		network = "udp6"
	}

	// It's necessary to create an unbound UDP socket, for use with WriteTo,
	// as required by quic-go. As documented in net.ListenUDP: with an
	// unspecified IP address, the resulting conn "listens on all available
	// IP addresses of the local system except multicast IP addresses".
	//
	// Limitation: these UDP sockets are not necessarily closed when a device
	// changes active network (e.g., WiFi to mobile). It's possible that a
	// QUIC connection does not immediately close on a network change, and
	// instead outbound packets are sent from a different active interface.
	// As quic-go does not yet support connection migration, these packets
	// will be dropped by the server. This situation is mitigated by network
	// change event detection, which initiates new tunnel connections, and by
	// timeouts/keep-alives.

	conn, err := listen.ListenPacket(ctx, network, "")
	if err != nil {
		return nil, nil, errors.Trace(err)
	}

	udpConn, ok := conn.(*net.UDPConn)
	if !ok {
		return nil, nil, errors.Tracef("unexpected conn type: %T", conn)
	}

	if config.ResolvedIPCallback != nil {
		config.ResolvedIPCallback(ipAddr.String())
	}

	return udpConn, &net.UDPAddr{IP: ipAddr, Port: port}, nil
}
