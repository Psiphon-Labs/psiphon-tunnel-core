// +build windows

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
	"fmt"
	"net"
	"time"
)

type interruptibleConn struct {
}

func interruptibleDial(
	ipAddress string, port int,
	readTimeout, writeTimeout time.Duration,
	pendingConns *PendingConns) (conn *Conn, err error) {
	// Note: using net.Dial(); interruptible connections not supported on Windows
	netConn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", ipAddress, port))
	if err != nil {
		return nil, err
	}
	conn = &Conn{
		Conn:         netConn,
		readTimeout:  readTimeout,
		writeTimeout: writeTimeout}
	return conn, nil
}

func interruptibleClose(interruptible interruptibleConn) error {
	panic("interruptibleClose not supported on Windows")
}
