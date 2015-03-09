// +build android darwin dragonfly freebsd linux nacl netbsd openbsd solaris

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
)

type interruptibleTCPSocket struct {
	socketFd int
}

const _INVALID_FD = -1

// interruptibleTCPDial establishes a TCP network connection. A conn is added
// to config.PendingConns before blocking on network IO, which enables interruption.
// The caller is responsible for removing an established conn from PendingConns.
//
// To implement socket device binding and interruptible connecting, the lower-level
// syscall APIs are used. The sequence of syscalls in this implementation are
// taken from: https://code.google.com/p/go/issues/detail?id=6966
func interruptibleTCPDial(addr string, config *DialConfig) (conn *TCPConn, err error) {

	// Create a socket and then, before connecting, add a TCPConn with
	// the unconnected socket to pendingConns. This allows pendingConns to
	// abort connections in progress.
	socketFd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		return nil, ContextError(err)
	}
	defer func() {
		// Cleanup on error
		// (socketFd is reset to _INVALID_FD once it should no longer be closed)
		if err != nil && socketFd != _INVALID_FD {
			syscall.Close(socketFd)
		}
	}()

	if config.DeviceBinder != nil {
		err = config.DeviceBinder.BindToDevice(socketFd)
		if err != nil {
			return nil, ContextError(fmt.Errorf("BindToDevice failed: %s", err))
		}
	}

	// When using an upstream HTTP proxy, first connect to the proxy,
	// then use HTTP CONNECT to connect to the original destination.
	dialAddr := addr
	if config.UpstreamHttpProxyAddress != "" {
		dialAddr = config.UpstreamHttpProxyAddress
	}

	// Get the remote IP and port, resolving a domain name if necessary
	// TODO: domain name resolution isn't interruptible
	host, strPort, err := net.SplitHostPort(dialAddr)
	if err != nil {
		return nil, ContextError(err)
	}
	port, err := strconv.Atoi(strPort)
	if err != nil {
		return nil, ContextError(err)
	}
	ipAddrs, err := LookupIP(host, config)
	if err != nil {
		return nil, ContextError(err)
	}
	if len(ipAddrs) < 1 {
		return nil, ContextError(errors.New("no ip address"))
	}
	// TODO: IPv6 support
	var ip [4]byte
	copy(ip[:], ipAddrs[0].To4())

	// Enable interruption
	conn = &TCPConn{
		interruptible: interruptibleTCPSocket{socketFd: socketFd},
		readTimeout:   config.ReadTimeout,
		writeTimeout:  config.WriteTimeout}

	if !config.PendingConns.Add(conn) {
		return nil, ContextError(errors.New("pending connections already closed"))
	}

	// Connect the socket
	// TODO: adjust the timeout to account for time spent resolving hostname
	sockAddr := syscall.SockaddrInet4{Addr: ip, Port: port}
	if config.ConnectTimeout != 0 {
		errChannel := make(chan error, 2)
		time.AfterFunc(config.ConnectTimeout, func() {
			errChannel <- errors.New("connect timeout")
		})
		go func() {
			errChannel <- syscall.Connect(socketFd, &sockAddr)
		}()
		err = <-errChannel
	} else {
		err = syscall.Connect(socketFd, &sockAddr)
	}

	// Mutex required for writing to conn, since conn remains in
	// pendingConns, through which conn.Close() may be called from
	// another goroutine.

	conn.mutex.Lock()

	// From this point, ensure conn.interruptible.socketFd is reset
	// since the fd value may be reused for a different file or socket
	// before Close() -- and interruptibleTCPClose() -- is called for
	// this conn.
	conn.interruptible.socketFd = _INVALID_FD // (requires mutex)

	// This is the syscall.Connect result
	if err != nil {
		conn.mutex.Unlock()
		return nil, ContextError(err)
	}

	// Convert the socket fd to a net.Conn

	file := os.NewFile(uintptr(socketFd), "")
	fileConn, err := net.FileConn(file)
	file.Close()
	// No more deferred fd clean up on err
	socketFd = _INVALID_FD
	if err != nil {
		conn.mutex.Unlock()
		return nil, ContextError(err)
	}
	conn.Conn = fileConn // (requires mutex)

	conn.mutex.Unlock()

	// Going through upstream HTTP proxy
	if config.UpstreamHttpProxyAddress != "" {
		// This call can be interrupted by closing the pending conn
		err := HttpProxyConnect(conn, addr)
		if err != nil {
			return nil, ContextError(err)
		}
	}

	return conn, nil
}

func interruptibleTCPClose(interruptible interruptibleTCPSocket) error {
	if interruptible.socketFd == _INVALID_FD {
		return nil
	}
	return syscall.Close(interruptible.socketFd)
}
