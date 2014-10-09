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
	addr string,
	connectTimeout, readTimeout, writeTimeout time.Duration,
	pendingConns *PendingConns) (conn *DirectConn, err error) {
	// Note: using net.Dial(); interruptible connections not supported on Windows
	netConn, err := net.DialTimeout("tcp", addr, connectTimeout)
	if err != nil {
		return nil, ContextError(err)
	}
	conn = &DirectConn{
		Conn:         netConn,
		readTimeout:  readTimeout,
		writeTimeout: writeTimeout}
	return conn, nil
}

func interruptibleClose(interruptible interruptibleConn) error {
	Fatal("interruptibleClose not supported on Windows")
}
