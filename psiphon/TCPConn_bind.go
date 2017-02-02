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
	"errors"
	"fmt"
	"math/rand"
	"net"
	"os"
	"strconv"
	"syscall"

	"github.com/Psiphon-Inc/goarista/monotime"
	"github.com/Psiphon-Inc/goselect"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
)

// tcpDial is the platform-specific part of interruptibleTCPDial
//
// To implement socket device binding, the lower-level syscall APIs are used.
// The sequence of syscalls in this implementation are taken from:
// https://github.com/golang/go/issues/6966
// (originally: https://code.google.com/p/go/issues/detail?id=6966)
func tcpDial(addr string, config *DialConfig) (net.Conn, error) {

	// Get the remote IP and port, resolving a domain name if necessary
	host, strPort, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, common.ContextError(err)
	}
	port, err := strconv.Atoi(strPort)
	if err != nil {
		return nil, common.ContextError(err)
	}
	ipAddrs, err := LookupIP(host, config)
	if err != nil {
		return nil, common.ContextError(err)
	}
	if len(ipAddrs) < 1 {
		return nil, common.ContextError(errors.New("no IP address"))
	}

	// Iterate over a pseudorandom permutation of the destination
	// IPs and attempt connections.
	//
	// Only continue retrying as long as the initial ConnectTimeout
	// has not expired. Unlike net.Dial, we do not fractionalize the
	// timeout, as the ConnectTimeout is generally intended to apply
	// to a single attempt. So these serial retries are most useful
	// in cases of immediate failure, such as "no route to host"
	// errors when a host resolves to both IPv4 and IPv6 but IPv6
	// addresses are unreachable.
	// Retries at higher levels cover other cases: e.g.,
	// Controller.remoteServerListFetcher will retry its entire
	// operation and tcpDial will try a new permutation; or similarly,
	// Controller.establishCandidateGenerator will retry a candidate
	// tunnel server dials.

	permutedIndexes := rand.Perm(len(ipAddrs))

	lastErr := errors.New("unknown error")

	var deadline monotime.Time
	if config.ConnectTimeout != 0 {
		deadline = monotime.Now().Add(config.ConnectTimeout)
	}

	for iteration, index := range permutedIndexes {

		if iteration > 0 && deadline != 0 && monotime.Now().After(deadline) {
			// lastErr should be set by the previous iteration
			break
		}

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
			lastErr = common.ContextError(fmt.Errorf("Got invalid IP address: %s", ipAddr.String()))
			continue
		}
		if domain == syscall.AF_INET {
			sockAddr = &syscall.SockaddrInet4{Addr: ipv4, Port: port}
		} else if domain == syscall.AF_INET6 {
			sockAddr = &syscall.SockaddrInet6{Addr: ipv6, Port: port}
		}

		// Create a socket and bind to device, when configured to do so

		socketFd, err := syscall.Socket(domain, syscall.SOCK_STREAM, 0)
		if err != nil {
			lastErr = common.ContextError(err)
			continue
		}

		if config.DeviceBinder != nil {
			// WARNING: this potentially violates the direction to not call into
			// external components after the Controller may have been stopped.
			// TODO: rework DeviceBinder as an internal 'service' which can trap
			// external calls when they should not be made?
			err = config.DeviceBinder.BindToDevice(socketFd)
			if err != nil {
				syscall.Close(socketFd)
				lastErr = common.ContextError(fmt.Errorf("BindToDevice failed: %s", err))
				continue
			}
		}

		// Connect socket to the server's IP address

		err = syscall.SetNonblock(socketFd, true)
		if err != nil {
			syscall.Close(socketFd)
			lastErr = common.ContextError(err)
			continue
		}

		err = syscall.Connect(socketFd, sockAddr)
		if err != nil {
			if errno, ok := err.(syscall.Errno); !ok || errno != syscall.EINPROGRESS {
				syscall.Close(socketFd)
				lastErr = common.ContextError(err)
				continue
			}
		}

		fdset := &goselect.FDSet{}
		fdset.Set(uintptr(socketFd))

		timeout := config.ConnectTimeout
		if config.ConnectTimeout == 0 {
			timeout = -1
		}

		err = goselect.Select(socketFd+1, nil, fdset, nil, timeout)
		if err != nil {
			lastErr = common.ContextError(err)
			continue
		}
		if !fdset.IsSet(uintptr(socketFd)) {
			lastErr = common.ContextError(errors.New("file descriptor not set"))
			continue
		}

		err = syscall.SetNonblock(socketFd, false)
		if err != nil {
			syscall.Close(socketFd)
			lastErr = common.ContextError(err)
			continue
		}

		// Convert the socket fd to a net.Conn

		file := os.NewFile(uintptr(socketFd), "")
		netConn, err := net.FileConn(file) // net.FileConn() dups socketFd
		file.Close()                       // file.Close() closes socketFd
		if err != nil {
			lastErr = common.ContextError(err)
			continue
		}

		return netConn, nil
	}

	return nil, lastErr
}
