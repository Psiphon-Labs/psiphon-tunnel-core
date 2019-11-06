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
	"context"
	std_errors "errors"
	"net"
	"sync/atomic"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/fragmentor"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/upstreamproxy"
)

// TCPConn is a customized TCP connection that supports the Closer interface
// and which may be created using options in DialConfig, including
// UpstreamProxyURL, DeviceBinder, IPv6Synthesizer, and ResolvedIPCallback.
// DeviceBinder is implemented using SO_BINDTODEVICE/IP_BOUND_IF, which
// requires syscall-level socket code.
type TCPConn struct {
	net.Conn
	isClosed int32
}

// NewTCPDialer creates a TCP Dialer.
//
// Note: do not set an UpstreamProxyURL in the config when using NewTCPDialer
// as a custom dialer for NewProxyAuthTransport (or http.Transport with a
// ProxyUrl), as that would result in double proxy chaining.
func NewTCPDialer(config *DialConfig) Dialer {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		if network != "tcp" {
			return nil, errors.Tracef("%s unsupported", network)
		}
		return DialTCP(ctx, addr, config)
	}
}

// DialTCP creates a new, connected TCPConn.
func DialTCP(
	ctx context.Context, addr string, config *DialConfig) (net.Conn, error) {

	var conn net.Conn
	var err error

	if config.UpstreamProxyURL != "" {
		conn, err = proxiedTcpDial(ctx, addr, config)
	} else {
		conn, err = tcpDial(ctx, addr, config)
	}

	if err != nil {
		return nil, errors.Trace(err)
	}

	// Note: when an upstream proxy is used, we don't know what IP address
	// was resolved, by the proxy, for that destination.
	if config.ResolvedIPCallback != nil && config.UpstreamProxyURL == "" {
		ipAddress := common.IPAddressFromAddr(conn.RemoteAddr())
		if ipAddress != "" {
			config.ResolvedIPCallback(ipAddress)
		}
	}

	if config.FragmentorConfig.MayFragment() {
		conn = fragmentor.NewConn(
			config.FragmentorConfig,
			func(message string) {
				NoticeFragmentor(config.DiagnosticID, message)
			},
			conn)
	}

	return conn, nil
}

// proxiedTcpDial wraps a tcpDial call in an upstreamproxy dial.
func proxiedTcpDial(
	ctx context.Context, addr string, config *DialConfig) (net.Conn, error) {

	interruptConns := common.NewConns()

	// Note: using interruptConns to interrupt a proxy dial assumes
	// that the underlying proxy code will immediately exit with an
	// error when all underlying conns unexpectedly close; e.g.,
	// the proxy handshake won't keep retrying to dial new conns.

	dialer := func(network, addr string) (net.Conn, error) {
		conn, err := tcpDial(ctx, addr, config)
		if conn != nil {
			if !interruptConns.Add(conn) {
				err = std_errors.New("already interrupted")
				conn.Close()
				conn = nil
			}
		}
		if err != nil {
			return nil, errors.Trace(err)
		}
		return conn, nil
	}

	upstreamDialer := upstreamproxy.NewProxyDialFunc(
		&upstreamproxy.UpstreamProxyConfig{
			ForwardDialFunc: dialer,
			ProxyURIString:  config.UpstreamProxyURL,
			CustomHeaders:   config.CustomHeaders,
		})

	type upstreamDialResult struct {
		conn net.Conn
		err  error
	}

	resultChannel := make(chan upstreamDialResult)

	go func() {
		conn, err := upstreamDialer("tcp", addr)
		if _, ok := err.(*upstreamproxy.Error); ok {
			NoticeUpstreamProxyError(err)
		}
		resultChannel <- upstreamDialResult{
			conn: conn,
			err:  err,
		}
	}()

	var result upstreamDialResult

	select {
	case result = <-resultChannel:
	case <-ctx.Done():
		result.err = ctx.Err()
		// Interrupt the goroutine
		interruptConns.CloseAll()
		<-resultChannel
	}

	if result.err != nil {
		return nil, errors.Trace(result.err)
	}

	return result.conn, nil
}

// Close terminates a connected TCPConn or interrupts a dialing TCPConn.
func (conn *TCPConn) Close() (err error) {

	if !atomic.CompareAndSwapInt32(&conn.isClosed, 0, 1) {
		return nil
	}

	return conn.Conn.Close()
}

// IsClosed implements the Closer iterface. The return value
// indicates whether the TCPConn has been closed.
func (conn *TCPConn) IsClosed() bool {
	return atomic.LoadInt32(&conn.isClosed) == 1
}

// CloseWrite calls net.TCPConn.CloseWrite when the underlying
// conn is a *net.TCPConn.
func (conn *TCPConn) CloseWrite() (err error) {

	if conn.IsClosed() {
		return errors.TraceNew("already closed")
	}

	tcpConn, ok := conn.Conn.(*net.TCPConn)
	if !ok {
		return errors.TraceNew("conn is not a *net.TCPConn")
	}

	return tcpConn.CloseWrite()
}
