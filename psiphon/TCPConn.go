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
// - can be interrupted while dialing;
// - implements a connect timeout;
// - uses an upstream proxy when specified, and includes
//   upstream proxy dialing in the connect timeout;
// - can be bound to a specific system device (for Android VpnService
//   routing compatibility, for example);
type TCPConn struct {
	net.Conn
	mutex      sync.Mutex
	isClosed   bool
	dialResult chan error
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
		return conn, nil
	}

	if config.UpstreamProxyUrl != "" {

		upstreamDialer := upstreamproxy.NewProxyDialFunc(
			&upstreamproxy.UpstreamProxyConfig{
				ForwardDialFunc: dialer,
				ProxyURIString:  config.UpstreamProxyUrl,
			})

		dialer = func(network, addr string) (conn net.Conn, err error) {

			// The entire upstream dial is wrapped in an explicit timeout. This
			// may include network connection read and writes when proxy auth negotation
			// is performed.

			type upstreamDialResult struct {
				conn net.Conn
				err  error
			}
			if config.ConnectTimeout != 0 {
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

				conn, err = result.conn, result.err
			} else {
				conn, err = upstreamDialer(network, addr)
			}

			if _, ok := err.(*upstreamproxy.Error); ok {
				NoticeUpstreamProxyError(err)
			}
			return conn, err
		}
	}

	return dialer
}

// interruptibleTCPDial establishes a TCP network connection. A conn is added
// to config.PendingConns before blocking on network I/O, which enables interruption.
// The caller is responsible for removing an established conn from PendingConns.
//
// Note that interruption does not actually cancel a connection in progress; it
// stops waiting for the goroutine blocking on connect()/Dial.
func interruptibleTCPDial(addr string, config *DialConfig) (*TCPConn, error) {

	// Buffers the first result; senders should discard results when
	// sending would block, as that means the first result is already set.
	conn := &TCPConn{dialResult: make(chan error, 1)}

	// Enable interruption
	if !config.PendingConns.Add(conn) {
		return nil, ContextError(errors.New("pending connections already closed"))
	}

	// Call the blocking Connect() in a goroutine
	// Note: since this goroutine may be left running after an interrupt, don't
	// call Notice() or perform other actions unexpected after a Controller stops.
	// The lifetime of the goroutine may depend on the host OS TCP connect timeout
	// when tcpDial, amoung other things, when makes a blocking syscall.Connect()
	// call.
	go func() {
		netConn, err := tcpDial(addr, config, conn.dialResult)

		// Mutex is necessary for referencing conn.isClosed and conn.Conn as
		// TCPConn.Close may be called while this goroutine is running.
		conn.mutex.Lock()

		// If already interrupted, cleanup the net.Conn resource and discard.
		if conn.isClosed && netConn != nil {
			netConn.Close()
			conn.mutex.Unlock()
			return
		}

		conn.Conn = netConn
		conn.mutex.Unlock()

		select {
		case conn.dialResult <- err:
		default:
		}
	}()

	// Wait until Dial completes (or times out) or until interrupt
	err := <-conn.dialResult
	if err != nil {
		return nil, ContextError(err)
	}

	return conn, nil
}

// Close terminates a connected TCPConn or interrupts a dialing TCPConn.
func (conn *TCPConn) Close() (err error) {
	conn.mutex.Lock()
	defer conn.mutex.Unlock()

	if conn.isClosed {
		return
	}
	conn.isClosed = true

	if conn.Conn != nil {
		err = conn.Conn.Close()
	}

	select {
	case conn.dialResult <- errors.New("dial interrupted"):
	default:
	}

	return err
}
