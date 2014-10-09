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

// DirectConn is a customized network connection that:
// - can be interrupted while connecting;
// - implements idle read/write timeouts;
// - can be bound to a specific system device (for Android VpnService
//   routing compatibility, for example).
// - implements the psiphon.Conn interface
type DirectConn struct {
	net.Conn
	mutex         sync.Mutex
	isClosed      bool
	closedSignal  chan struct{}
	interruptible interruptibleConn
	readTimeout   time.Duration
	writeTimeout  time.Duration
}

// NewDirectDialer creates a DirectDialer.
func NewDirectDialer(
	connectTimeout, readTimeout, writeTimeout time.Duration,
	pendingConns *PendingConns) Dialer {

	return func(network, addr string) (net.Conn, error) {
		if network != "tcp" {
			Fatal("unsupported network type in NewDirectDialer")
		}
		return DirectDial(
			addr,
			connectTimeout, readTimeout, writeTimeout,
			pendingConns)
	}
}

// DirectDial creates a new, connected DirectConn. The connection may be
// interrupted using pendingConns.interrupt(): on platforms that support this,
// the new DirectConn is added to pendingConns before the socket connect begins
// and removed from pendingConns once the connect succeeds or fails.
func DirectDial(
	addr string,
	connectTimeout, readTimeout, writeTimeout time.Duration,
	pendingConns *PendingConns) (conn *DirectConn, err error) {

	conn, err = interruptibleDial(addr, connectTimeout, readTimeout, writeTimeout, pendingConns)
	if err != nil {
		return nil, ContextError(err)
	}
	return conn, nil
}

// SetClosedSignal implements psiphon.Conn.SetClosedSignal
func (conn *DirectConn) SetClosedSignal(closedSignal chan struct{}) (err error) {
	conn.mutex.Lock()
	defer conn.mutex.Unlock()
	if conn.isClosed {
		return ContextError(errors.New("connection is already closed"))
	}
	conn.closedSignal = closedSignal
	return nil
}

// Close terminates a connected (net.Conn) or connecting (socketFd) DirectConn.
// A mutex is required to support psiphon.Conn.SetClosedSignal concurrency semantics.
func (conn *DirectConn) Close() (err error) {
	conn.mutex.Lock()
	defer conn.mutex.Unlock()
	if !conn.isClosed {
		if conn.Conn == nil {
			err = interruptibleClose(conn.interruptible)
		} else {
			err = conn.Conn.Close()
		}
		conn.isClosed = true
		select {
		case conn.closedSignal <- *new(struct{}):
		default:
		}
	}
	return err
}

// Read wraps standard Read to add an idle timeout. The connection
// is explicitly closed on timeout.
func (conn *DirectConn) Read(buffer []byte) (n int, err error) {
	// Note: no mutex on the conn.readTimeout access
	if conn.readTimeout != 0 {
		err = conn.Conn.SetReadDeadline(time.Now().Add(conn.readTimeout))
		if err != nil {
			return 0, ContextError(err)
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
func (conn *DirectConn) Write(buffer []byte) (n int, err error) {
	// Note: no mutex on the conn.writeTimeout access
	if conn.writeTimeout != 0 {
		err = conn.Conn.SetWriteDeadline(time.Now().Add(conn.writeTimeout))
		if err != nil {
			return 0, ContextError(err)
		}
	}
	n, err = conn.Conn.Write(buffer)
	if err != nil {
		conn.Close()
	}
	return
}

// Override implementation of net.Conn.SetDeadline
func (conn *DirectConn) SetDeadline(t time.Time) error {
	return ContextError(errors.New("not supported"))
}

// Override implementation of net.Conn.SetReadDeadline
func (conn *DirectConn) SetReadDeadline(t time.Time) error {
	return ContextError(errors.New("not supported"))
}

// Override implementation of net.Conn.SetWriteDeadline
func (conn *DirectConn) SetWriteDeadline(t time.Time) error {
	return ContextError(errors.New("not supported"))
}
