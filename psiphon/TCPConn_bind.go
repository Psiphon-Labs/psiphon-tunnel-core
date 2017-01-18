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
	"net"
	"os"
	"strconv"
	"syscall"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
)

// tcpDial is the platform-specific part of interruptibleTCPDial
//
// To implement socket device binding, the lower-level syscall APIs are used.
// The sequence of syscalls in this implementation are taken from:
// https://code.google.com/p/go/issues/detail?id=6966
func tcpDial(addr string, config *DialConfig, dialResult chan error) (net.Conn, error) {

	// Like interruption, this timeout doesn't stop this connection goroutine,
	// it just unblocks the calling interruptibleTCPDial.
	if config.ConnectTimeout != 0 {
		time.AfterFunc(config.ConnectTimeout, func() {
			select {
			case dialResult <- errors.New("connect timeout"):
			default:
			}
		})
	}

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

	// Select an IP at random from the list, so we're not always
	// trying the same IP (when > 1) which may be blocked.
	// TODO: retry all IPs until one connects? For now, this retry
	// will happen on subsequent TCPDial calls, when a different IP
	// is selected.
	index, err := common.MakeSecureRandomInt(len(ipAddrs))
	if err != nil {
		return nil, common.ContextError(err)
	}

	var ip []byte
	var domain int
	ipAddr := ipAddrs[index]

	// Get address type (IPv4 or IPv6)
	if ipAddr != nil && ipAddr.To4() != nil {
		ip = make([]byte, 4)
		copy(ip, ipAddr.To4())
		domain = syscall.AF_INET
	} else if ipAddr != nil && ipAddr.To16() != nil {
		ip = make([]byte, 16)
		copy(ip, ipAddr.To16())
		domain = syscall.AF_INET6
	} else {
		return nil, common.ContextError(fmt.Errorf("Got invalid ip address: %s", ipAddr.String()))
	}

	// Create a socket and bind to device, when configured to do so
	socketFd, err := syscall.Socket(domain, syscall.SOCK_STREAM, 0)
	if err != nil {
		return nil, common.ContextError(err)
	}

	if config.DeviceBinder != nil {
		// WARNING: this potentially violates the direction to not call into
		// external components after the Controller may have been stopped.
		// TODO: rework DeviceBinder as an internal 'service' which can trap
		// external calls when they should not be made?
		err = config.DeviceBinder.BindToDevice(socketFd)
		if err != nil {
			syscall.Close(socketFd)
			return nil, common.ContextError(fmt.Errorf("BindToDevice failed: %s", err))
		}
	}

	// Connect socket fd to the address
	if domain == syscall.AF_INET {
		var inet4Addr [4]byte
		copy(inet4Addr[:], ip)
		servAddr := syscall.SockaddrInet4{Addr: inet4Addr, Port: port}
		err = syscall.Connect(socketFd, &servAddr)
	} else if domain == syscall.AF_INET6 {
		var inet6Addr [16]byte
		copy(inet6Addr[:], ip)
		servAddr := syscall.SockaddrInet6{Addr: inet6Addr, Port: port}
		err = syscall.Connect(socketFd, &servAddr)
	}
	if err != nil {
		syscall.Close(socketFd)
		return nil, common.ContextError(err)
	}

	// Convert the socket fd to a net.Conn
	file := os.NewFile(uintptr(socketFd), "")
	netConn, err := net.FileConn(file) // net.FileConn() dups socketFd
	file.Close()                       // file.Close() closes socketFd
	if err != nil {
		return nil, common.ContextError(err)
	}

	return netConn, nil
}
