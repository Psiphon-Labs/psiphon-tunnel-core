// +build android linux

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
	"fmt"
	"net"
	"syscall"
	"time"
)

// bindToDevice sends a file descriptor a service which will bind the socket to
// a device so that it doesn't route through a VPN interface. This is used for
// TCP tunnel connections made while the VPN is active and for UDP DNS requests
// sent as part of establishing those TCP connections.
// On Android, where this facility is used, the underlying implementation uses
// setsockopt(SO_BINDTODEVICE). This socket options requires root, which is
// why this is delegated to a remote service.
func bindToDevice(socketFd int, config *DialConfig) error {
	addr, err := net.ResolveUnixAddr("unix", config.BindToDeviceServiceAddr)
	if err != nil {
		return ContextError(err)
	}
	conn, err := net.DialUnix("unix", nil, addr)
	if err != nil {
		return ContextError(err)
	}
	defer conn.Close()
	// Set request timeouts, using the ConnectTimeout from the overall Dial
	conn.SetReadDeadline(time.Now().Add(config.ConnectTimeout))
	conn.SetWriteDeadline(time.Now().Add(config.ConnectTimeout))
	// The 0 byte payload for the write is a dummy message. The important
	// payload is the file descriptor.
	// The response is also a single byte. 0 is success, and any other
	// byte value is an error code.
	msg := []byte{byte(0)}
	rights := syscall.UnixRights(socketFd)
	bytesWritten, ooBytesWritten, err := conn.WriteMsgUnix(msg, rights, nil)
	if err != nil {
		return ContextError(err)
	}
	if bytesWritten != len(msg) || ooBytesWritten != len(rights) {
		return ContextError(errors.New("bindToDevice write request failed"))
	}
	bytesRead, err := conn.Read(msg)
	if err != nil {
		return ContextError(err)
	}
	if bytesRead != len(msg) || msg[0] != 0 {
		return ContextError(fmt.Errorf("bindToDevice read response failed: %d", int(msg[0])))
	}
	return nil
}
