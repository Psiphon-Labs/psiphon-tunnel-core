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
	"net"
)

type interruptibleTCPSocket struct {
}

func interruptibleTCPDial(addr string, config *DialConfig) (conn *TCPConn, err error) {
	if config.BindToDeviceServiceAddress != "" {
		Fatal("psiphon.interruptibleTCPDial with bind not supported on Windows")
	}
	// Note: using standard net.Dial(); interruptible connections not supported on Windows
	netConn, err := net.DialTimeout("tcp", addr, config.ConnectTimeout)
	if err != nil {
		return nil, ContextError(err)
	}
	conn = &TCPConn{
		Conn:         netConn,
		readTimeout:  config.ReadTimeout,
		writeTimeout: config.WriteTimeout}
	return conn, nil
}

func interruptibleTCPClose(interruptible interruptibleTCPSocket) error {
	Fatal("psiphon.interruptibleTCPClose not supported on Windows")
	return nil
}
