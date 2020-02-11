// +build TAPDANCE

/*
 * Copyright (c) 2018, Psiphon Inc.
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

/*

Package tapdance wraps github.com/refraction-networking/gotapdance with net.Listener
and net.Conn types that provide drop-in integration with Psiphon.

*/
package tapdance

import (
	"context"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/armon/go-proxyproto"
	refraction_networking_tapdance "github.com/refraction-networking/gotapdance/tapdance"
)

const (
	READ_PROXY_PROTOCOL_HEADER_TIMEOUT = 5 * time.Second
)

// Enabled indicates if Tapdance functionality is enabled.
func Enabled() bool {
	return true
}

// Listener is a net.Listener.
type Listener struct {
	net.Listener
}

// Listen creates a new Tapdance listener on top of an existing TCP listener.
//
// The Tapdance station will send the original client address via the HAProxy
// proxy protocol v1, https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt.
// The original client address is read and returned by accepted conns'
// RemoteAddr. RemoteAddr _must_ be called non-concurrently before calling Read
// on accepted conns as the HAProxy proxy protocol header reading logic sets
// SetReadDeadline and performs a Read.
func Listen(tcpListener net.Listener) (net.Listener, error) {

	// Setting a timeout ensures that reading the proxy protocol
	// header completes or times out and RemoteAddr will not block. See:
	// https://godoc.org/github.com/armon/go-proxyproto#Conn.RemoteAddr

	proxyListener := &proxyproto.Listener{
		Listener:           tcpListener,
		ProxyHeaderTimeout: READ_PROXY_PROTOCOL_HEADER_TIMEOUT}

	stationListener := &stationListener{
		proxyListener: proxyListener,
	}

	return &Listener{Listener: stationListener}, nil
}

// stationListener uses the proxyproto.Listener SourceCheck callback to
// capture and record the direct remote address, the Tapdance station address,
// and wraps accepted conns to provide station address metrics via GetMetrics.
// These metrics enable identifying which station fronted a connection, which
// is useful for network operations and troubleshooting.
//
// go-proxyproto.Conn.RemoteAddr reports the originating client IP address,
// which is geolocated and recorded for metrics. The underlying conn's remote
// address, the Tapdance station address, is not accessible via the
// go-proxyproto API.
//
// stationListener is not safe for concurrent access.
type stationListener struct {
	proxyListener *proxyproto.Listener
}

func (l *stationListener) Accept() (net.Conn, error) {
	var stationRemoteAddr net.Addr
	l.proxyListener.SourceCheck = func(addr net.Addr) (bool, error) {
		stationRemoteAddr = addr
		return true, nil
	}
	conn, err := l.proxyListener.Accept()
	if err != nil {
		return nil, err
	}
	if stationRemoteAddr == nil {
		return nil, errors.TraceNew("missing station address")
	}
	return &stationConn{
		Conn:             conn,
		stationIPAddress: common.IPAddressFromAddr(stationRemoteAddr),
	}, nil
}

func (l *stationListener) Close() error {
	return l.proxyListener.Close()
}

func (l *stationListener) Addr() net.Addr {
	return l.proxyListener.Addr()
}

type stationConn struct {
	net.Conn
	stationIPAddress string
}

// IrregularTunnelError implements the common.IrregularIndicator interface.
func (c *stationConn) IrregularTunnelError() error {

	// We expect a PROXY protocol header, but go-proxyproto does not produce an
	// error if the "PROXY " prefix is absent; instead the connection will
	// proceed. To detect this case, check if the go-proxyproto RemoteAddr IP
	// address matches the underlying connection IP address. When these values
	// match, there was no PROXY protocol header.
	//
	// Limitation: the values will match if there is a PROXY protocol header
	// containing the same IP address as the underlying connection. This is not
	// an expected case.

	if common.IPAddressFromAddr(c.RemoteAddr()) == c.stationIPAddress {
		return errors.TraceNew("unexpected station IP address")
	}
	return nil
}

// GetMetrics implements the common.MetricsSource interface.
func (c *stationConn) GetMetrics() common.LogFields {

	logFields := make(common.LogFields)

	// Ensure we don't log a potential non-station IP address.
	if c.IrregularTunnelError() == nil {
		logFields["station_ip_address"] = c.stationIPAddress
	}

	return logFields
}

// dialManager tracks all dials performed by and dialed conns used by a
// refraction_networking_tapdance client. dialManager.close interrupts/closes
// all pending dials and established conns immediately. This ensures that
// blocking calls within refraction_networking_tapdance, such as tls.Handhake,
// are interrupted:
// E.g., https://github.com/refraction-networking/gotapdance/blob/4d84655dad2e242b0af0459c31f687b12085dcca/tapdance/conn_raw.go#L307
// (...preceeding SetDeadline is insufficient for immediate cancellation.)
type dialManager struct {
	tcpDialer func(ctx context.Context, network, address string) (net.Conn, error)

	ctxMutex       sync.Mutex
	useRunCtx      bool
	initialDialCtx context.Context
	runCtx         context.Context
	stopRunning    context.CancelFunc

	conns *common.Conns
}

func newDialManager(
	tcpDialer func(ctx context.Context, network, address string) (net.Conn, error)) *dialManager {

	runCtx, stopRunning := context.WithCancel(context.Background())

	return &dialManager{
		tcpDialer:   tcpDialer,
		runCtx:      runCtx,
		stopRunning: stopRunning,
		conns:       common.NewConns(),
	}
}

func (manager *dialManager) dial(ctx context.Context, network, address string) (net.Conn, error) {

	if network != "tcp" {
		return nil, errors.Tracef("unsupported network: %s", network)
	}

	// The context for this dial is either:
	// - ctx, during the initial tapdance.DialContext, when this is Psiphon tunnel
	//   establishment.
	// - manager.runCtx after the initial tapdance.Dial completes, in which case
	//   this is a Tapdance protocol reconnection that occurs periodically for
	//   already established tunnels.

	manager.ctxMutex.Lock()
	if manager.useRunCtx {

		// Preserve the random timeout configured by the tapdance client:
		// https://github.com/refraction-networking/gotapdance/blob/4d84655dad2e242b0af0459c31f687b12085dcca/tapdance/conn_raw.go#L263
		deadline, ok := ctx.Deadline()
		if !ok {
			return nil, errors.Tracef("unexpected nil deadline")
		}
		var cancelFunc context.CancelFunc
		ctx, cancelFunc = context.WithDeadline(manager.runCtx, deadline)
		defer cancelFunc()
	}
	manager.ctxMutex.Unlock()

	conn, err := manager.tcpDialer(ctx, network, address)
	if err != nil {
		return nil, errors.Trace(err)
	}

	// Fail immediately if CloseWrite isn't available in the underlying dialed
	// conn. The equivalent check in managedConn.CloseWrite isn't fatal and
	// tapdance will run in a degraded state.
	// Limitation: if the underlying conn _also_ passes through CloseWrite, this
	// check may be insufficient.
	if _, ok := conn.(common.CloseWriter); !ok {
		return nil, errors.TraceNew("underlying conn is not a CloseWriter")
	}

	conn = &managedConn{
		Conn:    conn,
		manager: manager,
	}

	if !manager.conns.Add(conn) {
		conn.Close()
		return nil, errors.TraceNew("already closed")
	}

	return conn, nil
}

func (manager *dialManager) startUsingRunCtx() {
	manager.ctxMutex.Lock()
	manager.initialDialCtx = nil
	manager.useRunCtx = true
	manager.ctxMutex.Unlock()
}

func (manager *dialManager) close() {
	manager.conns.CloseAll()
	manager.stopRunning()
}

type managedConn struct {
	net.Conn
	manager *dialManager
}

// CloseWrite exposes the net.TCPConn.CloseWrite() functionality
// required by tapdance.
func (conn *managedConn) CloseWrite() error {
	if closeWriter, ok := conn.Conn.(common.CloseWriter); ok {
		return closeWriter.CloseWrite()
	}
	return errors.TraceNew("underlying conn is not a CloseWriter")
}

func (conn *managedConn) Close() error {
	// Remove must be invoked asynchronously, as this Close may be called by
	// conns.CloseAll, leading to a reentrant lock situation.
	go conn.manager.conns.Remove(conn)
	return conn.Conn.Close()
}

type tapdanceConn struct {
	net.Conn
	manager  *dialManager
	isClosed int32
}

func (conn *tapdanceConn) Close() error {
	conn.manager.close()
	err := conn.Conn.Close()
	atomic.StoreInt32(&conn.isClosed, 1)
	return err
}

func (conn *tapdanceConn) IsClosed() bool {
	return atomic.LoadInt32(&conn.isClosed) == 1
}

// Dial establishes a new Tapdance session to a Tapdance station specified in
// the config assets and forwarding through to the Psiphon server specified by
// address.
//
// The Tapdance station config assets are read from dataDirectory/"tapdance".
// When no config is found, default assets are paved. ctx is expected to have
// a timeout for the dial.
//
// Limitation: the parameters emitLogs and dataDirectory are used for one-time
// initialization and are ignored after the first Dial call.
func Dial(
	ctx context.Context,
	emitLogs bool,
	dataDirectory string,
	netDialer common.NetDialer,
	address string) (net.Conn, error) {

	err := initTapdance(emitLogs, dataDirectory)
	if err != nil {
		return nil, errors.Trace(err)
	}

	if _, ok := ctx.Deadline(); !ok {
		return nil, errors.TraceNew("dial context has no timeout")
	}

	manager := newDialManager(netDialer.DialContext)

	tapdanceDialer := &refraction_networking_tapdance.Dialer{
		TcpDialer: manager.dial,
	}

	// If the dial context is cancelled, use dialManager to interrupt
	// tapdanceDialer.DialContext. See dialManager comment explaining why
	// tapdanceDialer.DialContext may block even when the input context is
	// cancelled.
	dialComplete := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
		case <-dialComplete:
		}
		select {
		// Prioritize the dialComplete case.
		case <-dialComplete:
			return
		default:
		}
		manager.close()
	}()

	conn, err := tapdanceDialer.DialContext(ctx, "tcp", address)
	close(dialComplete)
	if err != nil {
		manager.close()
		return nil, errors.Trace(err)
	}

	manager.startUsingRunCtx()

	return &tapdanceConn{
		Conn:    conn,
		manager: manager,
	}, nil
}

var initTapdanceOnce sync.Once

func initTapdance(emitLogs bool, dataDirectory string) error {

	var initErr error
	initTapdanceOnce.Do(func() {

		if !emitLogs {
			refraction_networking_tapdance.Logger().Out = ioutil.Discard
		}

		refraction_networking_tapdance.EnableProxyProtocol()

		assetsDir := filepath.Join(dataDirectory, "tapdance")

		err := os.MkdirAll(assetsDir, 0700)
		if err != nil {
			initErr = errors.Trace(err)
			return
		}

		clientConfFileName := filepath.Join(assetsDir, "ClientConf")
		_, err = os.Stat(clientConfFileName)
		if err != nil && os.IsNotExist(err) {
			err = ioutil.WriteFile(clientConfFileName, getEmbeddedClientConf(), 0644)
		}
		if err != nil {
			initErr = errors.Trace(err)
			return
		}

		refraction_networking_tapdance.AssetsSetDir(assetsDir)
	})

	return initErr
}
