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

Package tapdance wraps github.com/sergeyfrolov/gotapdance with net.Listener
and net.Conn types that provide drop-in integration with Psiphon.

*/
package tapdance

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/armon/go-proxyproto"
	refraction_networking_tapdance "github.com/sergeyfrolov/gotapdance/tapdance"
)

const (
	READ_PROXY_PROTOCOL_HEADER_TIMEOUT = 5 * time.Second
)

func init() {
	refraction_networking_tapdance.Logger().Out = ioutil.Discard
	refraction_networking_tapdance.EnableProxyProtocol()
}

// Enabled indicates if Tapdance functionality is enabled.
func Enabled() bool {
	return true
}

// Listener is a net.Listener.
type Listener struct {
	net.Listener
}

// Listen creates a new Tapdance listener.
//
// The Tapdance station will send the original client address via the HAProxy
// proxy protocol v1, https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt.
// The original client address is read and returned by accepted conns'
// RemoteAddr. RemoteAddr _must_ be called non-concurrently before calling Read
// on accepted conns as the HAProxy proxy protocol header reading logic sets
// SetReadDeadline and performs a Read.
func Listen(address string) (*Listener, error) {

	listener, err := net.Listen("tcp", address)
	if err != nil {
		return nil, common.ContextError(err)
	}

	// Setting a timeout ensures that reading the proxy protocol
	// header completes or times out and RemoteAddr will not block. See:
	// https://godoc.org/github.com/armon/go-proxyproto#Conn.RemoteAddr

	listener = &proxyproto.Listener{
		Listener:           listener,
		ProxyHeaderTimeout: READ_PROXY_PROTOCOL_HEADER_TIMEOUT}

	return &Listener{Listener: listener}, nil
}

// dialManager tracks all dials performed by and dialed conns used by a
// refraction_networking_tapdance client. dialManager.close interrupts/closes
// all pending dials and established conns immediately. This ensures that
// blocking calls within refraction_networking_tapdance, such as tls.Handhake,
// are interrupted:
// E.g., https://github.com/sergeyfrolov/gotapdance/blob/2ce6ef6667d52f7391a92fd8ec9dffb97ec4e2e8/tapdance/conn_raw.go#L260
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
		return nil, common.ContextError(fmt.Errorf("unsupported network: %s", network))
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
		// https://github.com/sergeyfrolov/gotapdance/blob/2ce6ef6667d52f7391a92fd8ec9dffb97ec4e2e8/tapdance/conn_raw.go#L219
		deadline, ok := ctx.Deadline()
		if !ok {
			return nil, common.ContextError(fmt.Errorf("unexpected nil deadline"))
		}
		var cancelFunc context.CancelFunc
		ctx, cancelFunc = context.WithDeadline(manager.runCtx, deadline)
		defer cancelFunc()
	}
	manager.ctxMutex.Unlock()

	conn, err := manager.tcpDialer(ctx, network, address)
	if err != nil {
		return nil, common.ContextError(err)
	}

	conn = &managedConn{
		Conn:    conn,
		manager: manager,
	}

	if !manager.conns.Add(conn) {
		conn.Close()
		return nil, common.ContextError(errors.New("already closed"))
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

type closeWriter interface {
	CloseWrite() error
}

// CloseWrite exposes the net.TCPConn.CloseWrite() functionality
// required by tapdance.
func (conn *managedConn) CloseWrite() error {
	if closeWriter, ok := conn.Conn.(closeWriter); ok {
		return closeWriter.CloseWrite()
	}
	return common.ContextError(errors.New("dialedConn is not a closeWriter"))
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
// a timeout for the  dial.
func Dial(
	ctx context.Context,
	dataDirectory string,
	netDialer common.NetDialer,
	address string) (net.Conn, error) {

	err := initAssets(dataDirectory)
	if err != nil {
		return nil, common.ContextError(err)
	}

	if _, ok := ctx.Deadline(); !ok {
		return nil, common.ContextError(errors.New("dial context has no timeout"))
	}

	manager := newDialManager(netDialer.DialContext)

	tapdanceDialer := &refraction_networking_tapdance.Dialer{
		TcpDialer: manager.dial,
	}

	conn, err := tapdanceDialer.DialContext(ctx, "tcp", address)
	if err != nil {
		manager.close()
		return nil, common.ContextError(err)
	}

	manager.startUsingRunCtx()

	return &tapdanceConn{
		Conn:    conn,
		manager: manager,
	}, nil
}

var setAssetsOnce sync.Once

func initAssets(dataDirectory string) error {

	var initErr error
	setAssetsOnce.Do(func() {

		assetsDir := filepath.Join(dataDirectory, "tapdance")

		err := os.MkdirAll(assetsDir, 0700)
		if err != nil {
			initErr = common.ContextError(err)
			return
		}

		clientConfFileName := filepath.Join(assetsDir, "ClientConf")
		if _, err = os.Stat(clientConfFileName); os.IsNotExist(err) {

			// Default ClientConf from:
			// https://github.com/sergeyfrolov/gotapdance/blob/089794326cf0b8a5d0e1f3cbb703ff3ee289f0ed/assets/ClientConf
			clientConf := []byte{
				10, 33, 10, 31, 10, 24, 116, 97, 112, 100, 97, 110, 99, 101, 49, 46,
				102, 114, 101, 101, 97, 101, 115, 107, 101, 121, 46, 120, 121, 122,
				21, 104, 190, 122, 192, 16, 148, 145, 6, 26, 36, 10, 32, 81, 88, 104,
				190, 127, 69, 171, 111, 49, 10, 254, 212, 178, 41, 183, 164, 121, 252,
				159, 222, 85, 61, 234, 76, 205, 179, 105, 171, 24, 153, 231, 12, 16, 90}

			err = ioutil.WriteFile(clientConfFileName, clientConf, 0644)
			if err != nil {
				initErr = common.ContextError(err)
				return
			}
		}

		refraction_networking_tapdance.AssetsSetDir(assetsDir)
	})

	return initErr
}
