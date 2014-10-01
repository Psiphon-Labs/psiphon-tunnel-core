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
	"sync"
	"time"
)

// Conn is a customized network connection that:
// - can be interrupted while connecting;
// - turns on TCP keep alive;
// - implements idle read/write timeouts;
// - supports sending a signal to a channel when it disconnects;
// - can be bound to a specific system device (for Android VpnService
//   routing compatibility, for example).
type Conn struct {
	net.Conn
	mutex         sync.Mutex
	interruptible interruptibleConn
	isClosed      bool
	closedSignal  chan bool
	readTimeout   time.Duration
	writeTimeout  time.Duration
}

// Dial creates a new, connected Conn. The connection may be interrupted
// using pendingConns.interrupt(): on platforms that support this, the new
// Conn is added to pendingConns before the socket connect begins.
// The caller is responsible for removing any Conns added to pendingConns,
// even when Dial returns an error.
// To implement device binding and interruptible connecting, the lower-level
// syscall APIs are used. The sequence of syscalls in this implementation are
// taken from: https://code.google.com/p/go/issues/detail?id=6966
// connectTimeout is rounded up to the nearest second on some platforms.
func Dial(
	ipAddress string, port int,
	connectTimeout, readTimeout, writeTimeout time.Duration,
	pendingConns *PendingConns) (conn *Conn, err error) {

	conn, err = interruptibleDial(ipAddress, port, connectTimeout, readTimeout, writeTimeout, pendingConns)
	if err != nil {
		return nil, ContextError(err)
	}
	return conn, nil
}

// SetClosedSignal sets the channel which will be signaled
// when the connection is closed. This function returns an error
// if the connection is already closed (and would never send
// the signal).
func (conn *Conn) SetClosedSignal(closedSignal chan bool) (err error) {
	conn.mutex.Lock()
	defer conn.mutex.Unlock()
	if conn.isClosed {
		return errors.New("connection is already closed")
	}
	conn.closedSignal = closedSignal
	return nil
}

// Close terminates a connected (net.Conn) or connecting (socketFd) Conn.
// A mutex syncs access to conn struct, allowing Close() to be called
// from a goroutine that wants to interrupt the primary goroutine using
// the connection.
func (conn *Conn) Close() (err error) {
	var closedSignal chan bool
	conn.mutex.Lock()
	if !conn.isClosed {
		if conn.Conn == nil {
			err = interruptibleClose(conn.interruptible)
		} else {
			err = conn.Conn.Close()
		}
		closedSignal = conn.closedSignal
		conn.isClosed = true
	}
	conn.mutex.Unlock()
	if closedSignal != nil {
		select {
		case closedSignal <- true:
		default:
		}
	}
	return err
}

// Read wraps standard Read to add an idle timeout. The connection
// is explicitly closed on timeout.
func (conn *Conn) Read(buffer []byte) (n int, err error) {
	// Note: no mutex on the conn.readTimeout access
	if conn.readTimeout != 0 {
		err = conn.Conn.SetReadDeadline(time.Now().Add(conn.readTimeout))
		if err != nil {
			return 0, err
		}
	}
	n, err = conn.Conn.Read(buffer)
	if err != nil {
		conn.Close()
	}
	return
}

// Write wraps standard Write to add an idle timeout The connection
// is explicitly closed on timeout.
func (conn *Conn) Write(buffer []byte) (n int, err error) {
	// Note: no mutex on the conn.writeTimeout access
	if conn.writeTimeout != 0 {
		err = conn.Conn.SetWriteDeadline(time.Now().Add(conn.writeTimeout))
		if err != nil {
			return 0, err
		}
	}
	n, err = conn.Conn.Write(buffer)
	if err != nil {
		conn.Close()
	}
	return
}

// PendingConns is a synchronized list of Conns that's used to coordinate
// interrupting a set of goroutines establishing connections.
type PendingConns struct {
	mutex sync.Mutex
	conns []*Conn
}

func (pendingConns *PendingConns) Add(conn *Conn) {
	pendingConns.mutex.Lock()
	defer pendingConns.mutex.Unlock()
	pendingConns.conns = append(pendingConns.conns, conn)
}

func (pendingConns *PendingConns) Remove(conn *Conn) {
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
