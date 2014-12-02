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

// TCPConn is a customized TCP connection that:
// - can be interrupted while connecting;
// - implements idle read/write timeouts;
// - can be bound to a specific system device (for Android VpnService
//   routing compatibility, for example).
// - implements the psiphon.Conn interface
type TCPConn struct {
	net.Conn
	mutex         sync.Mutex
	isClosed      bool
	closedSignal  chan struct{}
	interruptible interruptibleTCPSocket
	readTimeout   time.Duration
	writeTimeout  time.Duration
}

// NewTCPDialer creates a TCPDialer.
func NewTCPDialer(config *DialConfig) Dialer {
	return func(network, addr string) (net.Conn, error) {
		if network != "tcp" {
			Fatal("unsupported network type in NewTCPDialer")
		}
		return DialTCP(addr, config)
	}
}

// TCPConn creates a new, connected TCPConn.
func DialTCP(addr string, config *DialConfig) (conn *TCPConn, err error) {
	conn, err = interruptibleTCPDial(addr, config)
	if err != nil {
		return nil, ContextError(err)
	}
	return conn, nil
}

// SetClosedSignal implements psiphon.Conn.SetClosedSignal
func (conn *TCPConn) SetClosedSignal(closedSignal chan struct{}) (err error) {
	conn.mutex.Lock()
	defer conn.mutex.Unlock()
	if conn.isClosed {
		return ContextError(errors.New("connection is already closed"))
	}
	conn.closedSignal = closedSignal
	return nil
}

// Close terminates a connected (net.Conn) or connecting (socketFd) TCPConn.
// A mutex is required to support psiphon.Conn.SetClosedSignal concurrency semantics.
func (conn *TCPConn) Close() (err error) {
	conn.mutex.Lock()
	defer conn.mutex.Unlock()
	if !conn.isClosed {
		if conn.Conn == nil {
			err = interruptibleTCPClose(conn.interruptible)
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
func (conn *TCPConn) Read(buffer []byte) (n int, err error) {
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
func (conn *TCPConn) Write(buffer []byte) (n int, err error) {
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
func (conn *TCPConn) SetDeadline(t time.Time) error {
	Fatal("net.Conn SetDeadline not supported")
	return nil
}

// Override implementation of net.Conn.SetReadDeadline
func (conn *TCPConn) SetReadDeadline(t time.Time) error {
	Fatal("net.Conn SetReadDeadline not supported")
	return nil
}

// Override implementation of net.Conn.SetWriteDeadline
func (conn *TCPConn) SetWriteDeadline(t time.Time) error {
	Fatal("net.Conn SetWriteDeadline not supported")
	return nil
}
