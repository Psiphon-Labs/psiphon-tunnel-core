// +build android darwin dragonfly freebsd linux nacl netbsd openbsd solaris

/*
 * Copyright (c) 2014, Psiphon Inc.
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
	"net"
	"os"
	"strconv"
	"syscall"
	"time"
)

type interruptibleTCPSocket struct {
	socketFd int
}

// interruptibleTCPDial creates a socket connection.
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
		if err != nil {
			syscall.Close(socketFd)
		}
	}()

	// Note: this step is not interruptible
	if config.BindToDeviceServiceAddress != "" {
		err = bindToDevice(socketFd, config)
		if err != nil {
			return nil, ContextError(err)
		}
	}

	// Get the remote IP and port, resolving a domain name if necessary
	host, strPort, err := net.SplitHostPort(addr)
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
	config.PendingConns.Add(conn)

	// Connect the socket
	// TODO: adjust the timeout to account for time spent resolving hostname
	sockAddr := syscall.SockaddrInet4{Addr: ip, Port: port}
	if config.ConnectTimeout != 0 {
		errChannel := make(chan error, 2)
		time.AfterFunc(config.ConnectTimeout, func() {
			errChannel <- errors.New("connect timeout")
		})
		go func() {
			errChannel <- syscall.Connect(conn.interruptible.socketFd, &sockAddr)
		}()
		err = <-errChannel
	} else {
		err = syscall.Connect(conn.interruptible.socketFd, &sockAddr)
	}
	config.PendingConns.Remove(conn)
	if err != nil {
		return nil, ContextError(err)
	}

	// Convert the syscall socket to a net.Conn
	file := os.NewFile(uintptr(conn.interruptible.socketFd), "")
	defer file.Close()
	conn.Conn, err = net.FileConn(file)
	if err != nil {
		return nil, ContextError(err)
	}
	return conn, nil
}

func interruptibleTCPClose(interruptible interruptibleTCPSocket) error {
	return syscall.Close(interruptible.socketFd)
}
