//go:build !windows

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
)

// enablePortUnreachable does nothing: a connected UDP socket already
// receives the gateway's ICMP port unreachable reply as a read error.
func enablePortUnreachable(_ *net.UDPConn) {}

// isPortUnreachable reports whether err is the read or write error a
// connected UDP socket returns after an ICMP port unreachable reply.
func isPortUnreachable(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED)
}
