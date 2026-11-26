/*
 * Copyright (c) 2026, Psiphon Inc.
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

package portmapper

import (
	"errors"
	"net"
	"syscall"
	"unsafe"
)

// enablePortUnreachable makes conn report an ICMP port unreachable reply as
// a read error. The Go runtime turns this reporting off for every UDP
// socket on Windows.
func enablePortUnreachable(conn *net.UDPConn) {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return
	}
	_ = rawConn.Control(func(fd uintptr) {
		flag := uint32(1)
		returned := uint32(0)
		_ = syscall.WSAIoctl(
			syscall.Handle(fd),
			syscall.SIO_UDP_CONNRESET,
			(*byte)(unsafe.Pointer(&flag)),
			uint32(unsafe.Sizeof(flag)),
			nil, 0, &returned, nil, 0)
	})
}

// isPortUnreachable reports whether err is the read or write error a
// connected UDP socket returns after an ICMP port unreachable reply.
func isPortUnreachable(err error) bool {
	return errors.Is(err, syscall.WSAECONNRESET) ||
		errors.Is(err, syscall.ECONNREFUSED)
}
