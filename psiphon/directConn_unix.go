// +build darwin dragonfly freebsd linux nacl netbsd openbsd solaris

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

type interruptibleConn struct {
	socketFd int
}

// interruptibleDial creates a socket connection.
// To implement device binding and interruptible connecting, the lower-level
// syscall APIs are used. The sequence of syscalls in this implementation are
// taken from: https://code.google.com/p/go/issues/detail?id=6966
func interruptibleDial(
	addr string,
	connectTimeout, readTimeout, writeTimeout time.Duration,
	pendingConns *Conns) (conn *DirectConn, err error) {
	// Create a socket and then, before connecting, add a DirectConn with
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
	conn = &DirectConn{
		interruptible: interruptibleConn{socketFd: socketFd},
		readTimeout:   readTimeout,
		writeTimeout:  writeTimeout}
	pendingConns.Add(conn)
	// Before connecting, ensure the socket doesn't route through a VPN interface
	// TODO: this method requires root, which we won't have on Android in VpnService mode
	// an alternative may be to use http://golang.org/pkg/syscall/#UnixRights to send the
	// fd to the main Android process which receives the fd with
	// http://developer.android.com/reference/android/net/LocalSocket.html#getAncillaryFileDescriptors%28%29
	// and then calls
	// http://developer.android.com/reference/android/net/VpnService.html#protect%28int%29.
	// See, for example:
	// https://code.google.com/p/ics-openvpn/source/browse/main/src/main/java/de/blinkt/openvpn/core/OpenVpnManagementThread.java#164
	/*
		const SO_BINDTODEVICE = 0x19 // only defined for Linux
		err = syscall.SetsockoptString(socketFd, syscall.SOL_SOCKET, SO_BINDTODEVICE, deviceName)
	*/
	// Resolve domain name
	// TODO: ensure DNS UDP traffic doesn't route through a VPN interface
	// ...use https://golang.org/src/pkg/net/dnsclient.go?
	host, strPort, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, ContextError(err)
	}
	port, err := strconv.Atoi(strPort)
	if err != nil {
		return nil, ContextError(err)
	}
	// TODO: IPv6 support
	var ip [4]byte
	ipAddrs, err := net.LookupIP(host)
	if err != nil {
		return nil, ContextError(err)
	}
	if len(ipAddrs) < 1 {
		return nil, ContextError(errors.New("no ip address"))
	}
	copy(ip[:], ipAddrs[0].To4())
	// Connect the socket
	sockAddr := syscall.SockaddrInet4{Addr: ip, Port: port}
	if connectTimeout != 0 {
		errChannel := make(chan error, 2)
		time.AfterFunc(connectTimeout, func() {
			errChannel <- errors.New("connect timeout")
		})
		go func() {
			errChannel <- syscall.Connect(conn.interruptible.socketFd, &sockAddr)
		}()
		err = <-errChannel
	} else {
		err = syscall.Connect(conn.interruptible.socketFd, &sockAddr)
	}
	pendingConns.Remove(conn)
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

func interruptibleClose(interruptible interruptibleConn) error {
	return syscall.Close(interruptible.socketFd)
}
