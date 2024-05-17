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
	"net"
	"strconv"
	"syscall"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
)

// NewUDPConn resolves raddr and configures a new *net.UDPConn. The UDP socket
// is created using options in DialConfig, including DeviceBinder. The
// returned UDPAddr uses DialConfig options IPv6Synthesizer and
// ResolvedIPCallback.
//
// The network input may be "udp", "udp4", or "udp6". When "udp4" or "udp6" is
// specified, the raddr host IP address or resolved domain addresses must
// include IP address of the corresponding type.
//
// If laddr is specified, the UDP socket is bound to that local address. Any
// laddr host must be an IP address.
//
// If useDial is specified, the UDP socket is "connected" to the raddr remote
// address; otherwise the UDP socket is "unconnected", and each write
// (WriteTo) can specify an arbitrary remote address.
//
// The caller should wrap the returned conn with common.WriteTimeoutUDPConn,
// as appropriate.
//
// The returned conn is not a common.Closer; the caller is expected to wrap
// this conn with another higher-level conn that provides that interface.
func NewUDPConn(
	ctx context.Context,
	network string,
	dial bool,
	laddr string,
	raddr string,
	config *DialConfig) (*net.UDPConn, *net.UDPAddr, error) {

	switch network {
	case "udp", "udp4", "udp6":
	default:
		return nil, nil, errors.TraceNew("invalid network")
	}

	if laddr != "" {
		localHost, _, err := net.SplitHostPort(laddr)
		if err != nil {
			return nil, nil, errors.Trace(err)
		}
		if net.ParseIP(localHost) == nil {
			return nil, nil, errors.TraceNew("invalid local address")
		}
	}

	host, strPort, err := net.SplitHostPort(raddr)
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

	var ipAddr net.IP

	if network == "udp" {

		// Pick any IP address, IPv4 or IPv6.

		ipAddr = ipAddrs[prng.Intn(len(ipAddrs))]

		network = "udp4"
		if ipAddr.To4() == nil {
			network = "udp6"
		}

	} else {

		// "udp4" or "udp6" was specified, so pick from either IPv4 or IPv6
		//  candidates.

		// Don't shuffle or otherwise mutate the slice returned by ResolveIP.
		permutedIndexes := prng.Perm(len(ipAddrs))

		for _, i := range permutedIndexes {
			if (network == "udp6") == (ipAddrs[i].To4() == nil) {
				ipAddr = ipAddrs[i]
				break
			}
		}
		if ipAddr == nil {
			return nil, nil, errors.TraceNew("no IP address for network")
		}
	}

	// When configured, attempt to synthesize IPv6 addresses from
	// an IPv4 addresses for compatibility on DNS64/NAT64 networks.
	// If synthesize fails, try the original addresses.
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

	controlFunc := func(_, _ string, c syscall.RawConn) error {
		var controlErr error
		err := c.Control(func(fd uintptr) {

			socketFD := int(fd)

			setAdditionalSocketOptions(socketFD)

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
	}

	var udpConn *net.UDPConn

	if dial {

		// Create a "connected" UDP socket, which is associated with a fixed
		// remote address. Writes will always send to that address.
		//
		// This mode is required for the Conjure DTLS transport.
		//
		// Unlike non-dial mode, the UDP socket doesn't listen on all local
		// IPs, and LocalAddr will return an address with a specific IP address.

		var addr net.Addr
		if laddr != "" {

			// ResolveUDPAddr won't resolve a domain here -- there's a check
			// above that the host in laddr must be an IP address.
			addr, err = net.ResolveUDPAddr(network, laddr)
			if err != nil {
				return nil, nil, errors.Trace(err)
			}
		}

		dialer := &net.Dialer{
			Control:   controlFunc,
			LocalAddr: addr,
		}

		conn, err := dialer.DialContext(
			ctx, network, net.JoinHostPort(ipAddr.String(), strPort))
		if err != nil {
			return nil, nil, errors.Trace(err)
		}

		var ok bool
		udpConn, ok = conn.(*net.UDPConn)
		if !ok {
			return nil, nil, errors.Tracef("unexpected conn type: %T", conn)
		}

	} else {

		// Create an "unconnected" UDP socket, which can be used with WriteTo,
		// which specifies a remote address per write.
		//
		// This mode is required by quic-go.
		//
		// As documented in net.ListenUDP: with an unspecified IP address, the
		// resulting conn "listens on all available IP addresses of the local
		// system except multicast IP addresses".
		//
		// Limitation: these UDP sockets are not necessarily closed when a device
		// changes active network (e.g., WiFi to mobile). It's possible that a
		// QUIC connection does not immediately close on a network change, and
		// instead outbound packets are sent from a different active interface.
		// As quic-go does not yet support connection migration, these packets
		// will be dropped by the server. This situation is mitigated by use of
		// DeviceBinder; by network change event detection, which initiates new
		// tunnel connections; and by timeouts/keep-alives.

		listen := &net.ListenConfig{
			Control: controlFunc,
		}

		conn, err := listen.ListenPacket(ctx, network, laddr)
		if err != nil {
			return nil, nil, errors.Trace(err)
		}

		var ok bool
		udpConn, ok = conn.(*net.UDPConn)
		if !ok {
			return nil, nil, errors.Tracef("unexpected conn type: %T", conn)
		}
	}

	if config.ResolvedIPCallback != nil {
		config.ResolvedIPCallback(ipAddr.String())
	}

	return udpConn, &net.UDPAddr{IP: ipAddr, Port: port}, nil
}
