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
	"net"
	"os"
	"syscall"
	"time"
)

type interruptibleConn struct {
	socketFd int
}

func interruptibleDial(
	ipAddress string, port int,
	readTimeout, writeTimeout time.Duration,
	pendingConns *PendingConns) (conn *Conn, err error) {

	socketFd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		return nil, err
	}
	err = syscall.SetsockoptInt(socketFd, syscall.IPPROTO_TCP, syscall.TCP_KEEPALIVE, TCP_KEEP_ALIVE_PERIOD_SECONDS)
	if err != nil {
		syscall.Close(socketFd)
		return nil, err
	}
	/*
		// TODO: requires root, which we won't have on Android in VpnService mode
		//       an alternative may be to use http://golang.org/pkg/syscall/#UnixRights to
		//       send the fd to the main Android process which receives the fd with
		//       http://developer.android.com/reference/android/net/LocalSocket.html#getAncillaryFileDescriptors%28%29
		//       and then calls
		//       http://developer.android.com/reference/android/net/VpnService.html#protect%28int%29.
		//       See, for example:
		//       https://code.google.com/p/ics-openvpn/source/browse/main/src/main/java/de/blinkt/openvpn/core/OpenVpnManagementThread.java#164
		const SO_BINDTODEVICE = 0x19 // only defined for Linux
		err = syscall.SetsockoptString(socketFd, syscall.SOL_SOCKET, SO_BINDTODEVICE, deviceName)
	*/
	conn = &Conn{
		interruptible: interruptibleConn{socketFd: socketFd},
		readTimeout:   readTimeout,
		writeTimeout:  writeTimeout}
	// Note: syscall.Close(socketFd) not called on error after pendingConns.Add
	pendingConns.Add(conn)
	// TODO: domain name resolution (for meek)
	var addr [4]byte
	copy(addr[:], net.ParseIP(ipAddress).To4())
	sockAddr := syscall.SockaddrInet4{Addr: addr, Port: port}
	err = syscall.Connect(conn.interruptible.socketFd, &sockAddr)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(conn.interruptible.socketFd), "")
	defer file.Close()
	conn.Conn, err = net.FileConn(file)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func interruptibleClose(interruptible interruptibleConn) error {
	return syscall.Close(interruptible.socketFd)
}
