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
	"syscall"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/fragmentor"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
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
func NewTCPDialer(config *DialConfig) common.Dialer {

	// Use config.CustomDialer when set. This ignores all other parameters in
	// DialConfig.
	if config.CustomDialer != nil {
		return config.CustomDialer
	}

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

	interruptConns := common.NewConns[net.Conn]()

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
			if config.UpstreamProxyErrorCallback != nil {
				config.UpstreamProxyErrorCallback(err)
			}
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

func tcpDial(ctx context.Context, addr string, config *DialConfig) (net.Conn, error) {

	// Get the remote IP and port, resolving a domain name if necessary
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, errors.Trace(err)
	}
	if config.ResolveIP == nil {
		// Fail even if we don't need a resolver for this dial: this is a code
		// misconfiguration.
		return nil, errors.TraceNew("missing resolver")
	}
	ipAddrs, err := config.ResolveIP(ctx, host)
	if err != nil {
		return nil, errors.Trace(err)
	}
	if len(ipAddrs) < 1 {
		return nil, errors.TraceNew("no IP address")
	}

	// When configured, attempt to synthesize IPv6 addresses from
	// an IPv4 addresses for compatibility on DNS64/NAT64 networks.
	// If synthesize fails, try the original addresses.
	if config.IPv6Synthesizer != nil {
		for i, ipAddr := range ipAddrs {
			if ipAddr.To4() != nil {
				synthesizedIPAddress := config.IPv6Synthesizer.IPv6Synthesize(ipAddr.String())
				if synthesizedIPAddress != "" {
					synthesizedAddr := net.ParseIP(synthesizedIPAddress)
					if synthesizedAddr != nil {
						ipAddrs[i] = synthesizedAddr
					}
				}
			}
		}
	}

	// Iterate over a pseudorandom permutation of the destination
	// IPs and attempt connections.
	//
	// Only continue retrying as long as the dial context is not
	// done. Unlike net.Dial, we do not fractionalize the context
	// deadline, as the dial is generally intended to apply to a
	// single attempt. So these serial retries are most useful in
	// cases of immediate failure, such as "no route to host"
	// errors when a host resolves to both IPv4 and IPv6 but IPv6
	// addresses are unreachable.
	//
	// Retries at higher levels cover other cases: e.g.,
	// Controller.remoteServerListFetcher will retry its entire
	// operation and tcpDial will try a new permutation; or similarly,
	// Controller.establishCandidateGenerator will retry a candidate
	// tunnel server dials.

	// Don't shuffle or otherwise mutate the slice returned by ResolveIP.
	permutedIndexes := prng.Perm(len(ipAddrs))

	lastErr := errors.TraceNew("unknown error")

	for _, index := range permutedIndexes {

		dialer := &net.Dialer{
			Control: func(_, _ string, c syscall.RawConn) error {
				var controlErr error
				err := c.Control(func(fd uintptr) {

					socketFD := int(fd)

					setAdditionalSocketOptions(socketFD)

					if config.BPFProgramInstructions != nil {
						err := setSocketBPF(config.BPFProgramInstructions, socketFD)
						if err != nil {
							controlErr = errors.Tracef("setSocketBPF failed: %s", err)
							return
						}
					}

					if config.DeviceBinder != nil {
						_, err := config.DeviceBinder.BindToDevice(socketFD)
						if err != nil {
							controlErr = errors.Tracef("BindToDevice failed: %s", err)
							return
						}
					}
				})
				if controlErr != nil {
					return errors.Trace(controlErr)
				}
				return errors.Trace(err)
			},
		}

		conn, err := dialer.DialContext(
			ctx, "tcp", net.JoinHostPort(ipAddrs[index].String(), port))
		if err != nil {
			lastErr = errors.Trace(err)
			continue
		}

		return &TCPConn{Conn: conn}, nil
	}

	return nil, lastErr
}
