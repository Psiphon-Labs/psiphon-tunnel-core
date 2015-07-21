/*
 * Copyright (c) 2015, Psiphon Inc.
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

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/upstreamproxy"
)

// TCPConn is a customized TCP connection that:
// - can be interrupted while connecting;
// - implements a connect timeout;
// - implements idle read/write timeouts;
// - uses an upstream proxy when specified, and includes
//   upstream proxy dialing in the connect timeout;
// - can be bound to a specific system device (for Android VpnService
//   routing compatibility, for example);
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
	return makeTCPDialer(config)
}

// DialTCP creates a new, connected TCPConn.
func DialTCP(addr string, config *DialConfig) (conn net.Conn, err error) {
	return makeTCPDialer(config)("tcp", addr)
}

// makeTCPDialer creates a custom dialer which creates TCPConn. An upstream
// proxy is used when specified.
func makeTCPDialer(config *DialConfig) func(network, addr string) (net.Conn, error) {

	dialer := func(network, addr string) (net.Conn, error) {
		if network != "tcp" {
			return nil, errors.New("unsupported network type in TCPConn dialer")
		}
		conn, err := interruptibleTCPDial(addr, config)
		if err != nil {
			return nil, ContextError(err)
		}
		if config.ClosedSignal != nil {
			if !conn.SetClosedSignal(config.ClosedSignal) {
				// Conn is already closed. This is not unexpected -- for example,
				// when establish is interrupted.
				// TODO: make this not log an error when called from establishTunnelWorker?
				return nil, ContextError(errors.New("conn already closed"))
			}
		}
		return conn, nil
	}

	if config.UpstreamProxyUrl != "" {

		upstreamDialer := upstreamproxy.NewProxyDialFunc(
			&upstreamproxy.UpstreamProxyConfig{
				ForwardDialFunc: dialer,
				ProxyURIString:  config.UpstreamProxyUrl,
			})

		dialer = func(network, addr string) (net.Conn, error) {

			// The entire upstream dial is wrapped in an explicit timeout. This
			// may include network connection read and writes when proxy auth negotation
			// is performed.

			type upstreamDialResult struct {
				conn net.Conn
				err  error
			}
			resultChannel := make(chan *upstreamDialResult, 2)
			time.AfterFunc(config.ConnectTimeout, func() {
				// TODO: we could "interrupt" the underlying TCPConn at this point, as
				// it's being abandoned. But we don't have a reference to it. It's left
				// to the outer DialConfig.PendingConns to track and clean up that TCPConn.
				resultChannel <- &upstreamDialResult{nil, errors.New("upstreamproxy dial timeout")}
			})
			go func() {
				conn, err := upstreamDialer(network, addr)
				resultChannel <- &upstreamDialResult{conn, err}
			}()
			result := <-resultChannel

			if _, ok := result.err.(*upstreamproxy.Error); ok {
				NoticeUpstreamProxyError(result.err)
			}

			return result.conn, result.err
		}
	}

	return dialer
}

// SetClosedSignal implements psiphon.Conn.SetClosedSignal.
func (conn *TCPConn) SetClosedSignal(closedSignal chan struct{}) bool {
	conn.mutex.Lock()
	defer conn.mutex.Unlock()
	if conn.isClosed {
		return false
	}
	conn.closedSignal = closedSignal
	return true
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
	return errors.New("net.Conn SetDeadline not supported")
}

// Override implementation of net.Conn.SetReadDeadline
func (conn *TCPConn) SetReadDeadline(t time.Time) error {
	return errors.New("net.Conn SetReadDeadline not supported")
}

// Override implementation of net.Conn.SetWriteDeadline
func (conn *TCPConn) SetWriteDeadline(t time.Time) error {
	return errors.New("net.Conn SetWriteDeadline not supported")
}
