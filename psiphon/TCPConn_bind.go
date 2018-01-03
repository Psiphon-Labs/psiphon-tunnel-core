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
	"errors"
	"fmt"
	"math/rand"
	"net"
	"os"
	"strconv"
	"syscall"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/creack/goselect"
)

// tcpDial is the platform-specific part of DialTCP
//
// To implement socket device binding, the lower-level syscall APIs are used.
// The sequence of syscalls in this implementation are taken from:
// https://github.com/golang/go/issues/6966
// (originally: https://code.google.com/p/go/issues/detail?id=6966)
func tcpDial(ctx context.Context, addr string, config *DialConfig) (net.Conn, error) {

	// Get the remote IP and port, resolving a domain name if necessary
	host, strPort, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, common.ContextError(err)
	}
	port, err := strconv.Atoi(strPort)
	if err != nil {
		return nil, common.ContextError(err)
	}
	ipAddrs, err := LookupIP(ctx, host, config)
	if err != nil {
		return nil, common.ContextError(err)
	}
	if len(ipAddrs) < 1 {
		return nil, common.ContextError(errors.New("no IP address"))
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

	lastErr := errors.New("unknown error")

	for _, index := range permutedIndexes {

		// Get address type (IPv4 or IPv6)

		var ipv4 [4]byte
		var ipv6 [16]byte
		var domain int
		var sockAddr syscall.Sockaddr

		ipAddr := ipAddrs[index]
		if ipAddr != nil && ipAddr.To4() != nil {
			copy(ipv4[:], ipAddr.To4())
			domain = syscall.AF_INET
		} else if ipAddr != nil && ipAddr.To16() != nil {
			copy(ipv6[:], ipAddr.To16())
			domain = syscall.AF_INET6
		} else {
			lastErr = common.ContextError(fmt.Errorf("invalid IP address: %s", ipAddr.String()))
			continue
		}
		if domain == syscall.AF_INET {
			sockAddr = &syscall.SockaddrInet4{Addr: ipv4, Port: port}
		} else if domain == syscall.AF_INET6 {
			sockAddr = &syscall.SockaddrInet6{Addr: ipv6, Port: port}
		}

		// Create a socket and bind to device, when configured to do so

		socketFD, err := syscall.Socket(domain, syscall.SOCK_STREAM, 0)
		if err != nil {
			lastErr = common.ContextError(err)
			continue
		}

		syscall.CloseOnExec(socketFD)

		tcpDialSetAdditionalSocketOptions(socketFD)

		if config.DeviceBinder != nil {
			err = config.DeviceBinder.BindToDevice(socketFD)
			if err != nil {
				syscall.Close(socketFD)
				lastErr = common.ContextError(fmt.Errorf("BindToDevice failed: %s", err))
				continue
			}
		}

		// Connect socket to the server's IP address

		err = syscall.SetNonblock(socketFD, true)
		if err != nil {
			syscall.Close(socketFD)
			lastErr = common.ContextError(err)
			continue
		}

		err = syscall.Connect(socketFD, sockAddr)
		if err != nil {
			if errno, ok := err.(syscall.Errno); !ok || errno != syscall.EINPROGRESS {
				syscall.Close(socketFD)
				lastErr = common.ContextError(err)
				continue
			}
		}

		// Use a control pipe to interrupt if the dial context is done (timeout or
		// interrupted) before the TCP connection is established.

		var controlFDs [2]int
		err = syscall.Pipe(controlFDs[:])
		if err != nil {
			syscall.Close(socketFD)
			lastErr = common.ContextError(err)
			continue

		}

		for _, controlFD := range controlFDs {
			syscall.CloseOnExec(controlFD)
			err = syscall.SetNonblock(controlFD, true)
			if err != nil {
				break
			}
		}

		if err != nil {
			syscall.Close(socketFD)
			lastErr = common.ContextError(err)
			continue
		}

		resultChannel := make(chan error)

		go func() {

			readSet := goselect.FDSet{}
			readSet.Set(uintptr(controlFDs[0]))
			writeSet := goselect.FDSet{}
			writeSet.Set(uintptr(socketFD))

			max := socketFD
			if controlFDs[0] > max {
				max = controlFDs[0]
			}

			err := goselect.Select(max+1, &readSet, &writeSet, nil, -1)

			if err == nil && !writeSet.IsSet(uintptr(socketFD)) {
				err = errors.New("interrupted")
			}

			resultChannel <- err
		}()

		done := false
		select {
		case err = <-resultChannel:
		case <-ctx.Done():
			err = ctx.Err()
			// Interrupt the goroutine
			// TODO: if this Write fails, abandon the goroutine instead of hanging?
			var b [1]byte
			syscall.Write(controlFDs[1], b[:])
			<-resultChannel
			done = true
		}

		syscall.Close(controlFDs[0])
		syscall.Close(controlFDs[1])

		if err != nil {
			syscall.Close(socketFD)

			if done {
				// Skip retry as dial context has timed out of been canceled.
				return nil, common.ContextError(err)
			}

			lastErr = common.ContextError(err)
			continue
		}

		err = syscall.SetNonblock(socketFD, false)
		if err != nil {
			syscall.Close(socketFD)
			lastErr = common.ContextError(err)
			continue
		}

		// Convert the socket fd to a net.Conn
		// This code block is from:
		// https://github.com/golang/go/issues/6966

		file := os.NewFile(uintptr(socketFD), "")
		conn, err := net.FileConn(file) // net.FileConn() dups socketFD
		file.Close()                    // file.Close() closes socketFD
		if err != nil {
			lastErr = common.ContextError(err)
			continue
		}

		return &TCPConn{Conn: conn}, nil
	}

	return nil, lastErr
}
