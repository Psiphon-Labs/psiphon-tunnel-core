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
	"sync"
)

// Dialer is a custom dialer compatible with http.Transport.Dial.
type Dialer func(string, string) (net.Conn, error)

// Conn is a net.Conn which supports sending a signal to a channel when
// it is closed. In Psiphon, this interface is implemented by tunnel
// connection types (DirectConn and MeekConn) and the close signal is
// used as one trigger for tearing down the tunnel.
type Conn interface {
	net.Conn

	// SetClosedSignal sets the channel which will be signaled
	// when the connection is closed. This function returns an error
	// if the connection is already closed (and would never send
	// the signal). SetClosedSignal and Close may be called by
	// concurrent goroutines.
	SetClosedSignal(closedSignal chan struct{}) (err error)
}

// PendingConns is a synchronized list of Conns that is used to coordinate
// interrupting a set of goroutines establishing connections.
type PendingConns struct {
	mutex sync.Mutex
	conns []Conn
}

func (pendingConns *PendingConns) Add(conn Conn) {
	pendingConns.mutex.Lock()
	defer pendingConns.mutex.Unlock()
	pendingConns.conns = append(pendingConns.conns, conn)
}

func (pendingConns *PendingConns) Remove(conn Conn) {
	pendingConns.mutex.Lock()
	defer pendingConns.mutex.Unlock()
	for index, pendingConn := range pendingConns.conns {
		if conn == pendingConn {
			pendingConns.conns = append(pendingConns.conns[:index], pendingConns.conns[index+1:]...)
			break
		}
	}
}

func (pendingConns *PendingConns) Interrupt() {
	pendingConns.mutex.Lock()
	defer pendingConns.mutex.Unlock()
	for _, conn := range pendingConns.conns {
		conn.Close()
	}
}
