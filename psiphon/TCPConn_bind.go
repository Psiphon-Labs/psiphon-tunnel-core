//go:build !windows
// +build !windows

/*
 * Copyright (c) 2015, Psiphon Inc.
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
	"syscall"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
)

// tcpDial is the platform-specific part of DialTCP
func tcpDial(ctx context.Context, addr string, config *DialConfig) (net.Conn, error) {

	// Get the remote IP and port, resolving a domain name if necessary
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, errors.Trace(err)
	}
	ipAddrs, err := LookupIP(ctx, host, config)
	if err != nil {
		return nil, errors.Trace(err)
	}
	if len(ipAddrs) < 1 {
		return nil, errors.TraceNew("no IP address")
	}

	// When configured, attempt to synthesize IPv6 addresses from
	// an IPv4 addresses for compatibility on DNS64/NAT64 networks.
	// If synthesize fails, try the original addresses.
	if config.IPv6Synthesizer != nil {
		for i, ipAddr := range ipAddrs {
			if ipAddr.To4() != nil {
				synthesizedIPAddress := config.IPv6Synthesizer.IPv6Synthesize(ipAddr.String())
				if synthesizedIPAddress != "" {
					synthesizedAddr := net.ParseIP(synthesizedIPAddress)
					if synthesizedAddr != nil {
						ipAddrs[i] = synthesizedAddr
					}
				}
			}
		}
	}

	// Iterate over a pseudorandom permutation of the destination
	// IPs and attempt connections.
	//
	// Only continue retrying as long as the dial context is not
	// done. Unlike net.Dial, we do not fractionalize the context
	// deadline, as the dial is generally intended to apply to a
	// single attempt. So these serial retries are most useful in
	// cases of immediate failure, such as "no route to host"
	// errors when a host resolves to both IPv4 and IPv6 but IPv6
	// addresses are unreachable.
	//
	// Retries at higher levels cover other cases: e.g.,
	// Controller.remoteServerListFetcher will retry its entire
	// operation and tcpDial will try a new permutation; or similarly,
	// Controller.establishCandidateGenerator will retry a candidate
	// tunnel server dials.

	permutedIndexes := rand.Perm(len(ipAddrs))

	lastErr := errors.TraceNew("unknown error")

	for _, index := range permutedIndexes {

		dialer := &net.Dialer{
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

		conn, err := dialer.DialContext(
			ctx, "tcp", net.JoinHostPort(ipAddrs[index].String(), port))
		if err != nil {
			lastErr = errors.Trace(err)
			continue
		}

		return &TCPConn{Conn: conn}, nil
	}

	return nil, lastErr
}
