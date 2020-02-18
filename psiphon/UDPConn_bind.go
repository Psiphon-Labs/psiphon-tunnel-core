// +build !windows

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
	"net"
	"os"
	"syscall"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
)

func newUDPConn(domain int, config *DialConfig) (net.PacketConn, error) {

	// TODO: use https://golang.org/pkg/net/#Dialer.Control, introduced in Go 1.11?

	socketFD, err := syscall.Socket(domain, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return nil, errors.Trace(err)
	}

	syscall.CloseOnExec(socketFD)

	setAdditionalSocketOptions(socketFD)

	if config.DeviceBinder != nil {
		_, err = config.DeviceBinder.BindToDevice(socketFD)
		if err != nil {
			syscall.Close(socketFD)
			return nil, errors.Tracef("BindToDevice failed: %s", err)
		}
	}

	// Convert the socket fd to a net.PacketConn
	// This code block is from:
	// https://github.com/golang/go/issues/6966

	file := os.NewFile(uintptr(socketFD), "")
	conn, err := net.FilePacketConn(file) // net.FilePackateConn() dups socketFD
	file.Close()                          // file.Close() closes socketFD
	if err != nil {
		return nil, errors.Trace(err)
	}

	return conn, nil
}
