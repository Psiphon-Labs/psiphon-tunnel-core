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

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
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

// makeTCPDialer creates a custom dialer which creates TCPConn.
func makeTCPDialer(config *DialConfig) func(network, addr string) (net.Conn, error) {
	return func(network, addr string) (net.Conn, error) {
		if network != "tcp" {
			return nil, errors.New("unsupported network type in TCPConn dialer")
		}
		conn, err := interruptibleTCPDial(addr, config)
		if err != nil {
			return nil, common.ContextError(err)
		}
		// Note: when an upstream proxy is used, we don't know what IP address
		// was resolved, by the proxy, for that destination.
		if config.ResolvedIPCallback != nil && config.UpstreamProxyUrl == "" {
			ipAddress := common.IPAddressFromAddr(conn.RemoteAddr())
			if ipAddress != "" {
				config.ResolvedIPCallback(ipAddress)
			}
		}
		return conn, nil
	}
}

// interruptibleTCPDial establishes a TCP network connection. A conn is added
// to config.PendingConns before blocking on network I/O, which enables interruption.
// The caller is responsible for removing an established conn from PendingConns.
// An upstream proxy is used when specified.
//
// Note: do not to set a UpstreamProxyUrl in the config when using
// NewTCPDialer as a custom dialer for NewProxyAuthTransport (or http.Transport
// with a ProxyUrl), as that would result in double proxy chaining.
//
// Note: interruption does not actually cancel a connection in progress; it
// stops waiting for the goroutine blocking on connect()/Dial.
func interruptibleTCPDial(addr string, config *DialConfig) (*TCPConn, error) {

	// Buffers the first result; senders should discard results when
	// sending would block, as that means the first result is already set.
	conn := &TCPConn{dialResult: make(chan error, 1)}

	// Enable interruption
	if config.PendingConns != nil && !config.PendingConns.Add(conn) {
		return nil, common.ContextError(errors.New("pending connections already closed"))
	}

	// Call the blocking Connect() in a goroutine. ConnectTimeout is handled
	// in the platform-specific tcpDial helper function.
	// Note: since this goroutine may be left running after an interrupt, don't
	// call Notice() or perform other actions unexpected after a Controller stops.
	// The lifetime of the goroutine may depend on the host OS TCP connect timeout
	// when tcpDial, amoung other things, when makes a blocking syscall.Connect()
	// call.
	go func() {
		var netConn net.Conn
		var err error
		if config.UpstreamProxyUrl != "" {
			netConn, err = proxiedTcpDial(addr, config, conn.dialResult)
		} else {
			netConn, err = tcpDial(addr, config, conn.dialResult)
		}

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
		if config.PendingConns != nil {
			config.PendingConns.Remove(conn)
		}
		return nil, common.ContextError(err)
	}

	// TODO: now allow conn.dialResult to be garbage collected?

	return conn, nil
}

// proxiedTcpDial wraps a tcpDial call in an upstreamproxy dial.
func proxiedTcpDial(
	addr string, config *DialConfig, dialResult chan error) (net.Conn, error) {
	dialer := func(network, addr string) (net.Conn, error) {
		return tcpDial(addr, config, dialResult)
	}
	upstreamDialer := upstreamproxy.NewProxyDialFunc(
		&upstreamproxy.UpstreamProxyConfig{
			ForwardDialFunc: dialer,
			ProxyURIString:  config.UpstreamProxyUrl,
			CustomHeaders:   config.UpstreamProxyCustomHeaders,
		})
	netConn, err := upstreamDialer("tcp", addr)
	if _, ok := err.(*upstreamproxy.Error); ok {
		NoticeUpstreamProxyError(err)
	}
	return netConn, err
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
