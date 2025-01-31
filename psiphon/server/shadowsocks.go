/*
 * Copyright (c) 2024, Psiphon Inc.
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

package server

import (
	"bytes"
	"fmt"
	"io"
	"net"

	"github.com/Jigsaw-Code/outline-sdk/transport"
	"github.com/Jigsaw-Code/outline-sdk/transport/shadowsocks"
	"github.com/Jigsaw-Code/outline-ss-server/service"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
)

// ShadowsocksServer tunnels TCP traffic (in the case of Psiphon, SSH traffic)
// over Shadowsocks.
type ShadowsocksServer struct {
	support               *SupportServices
	listener              net.Listener
	key                   *shadowsocks.EncryptionKey
	saltGenerator         service.ServerSaltGenerator
	replayCache           service.ReplayCache
	irregularTunnelLogger func(string, error, common.LogFields)
}

// ListenShadowsocks returns the listener of a new ShadowsocksServer.
func ListenShadowsocks(
	support *SupportServices,
	listener net.Listener,
	ssEncryptionKey string,
	irregularTunnelLogger func(string, error, common.LogFields),
) (net.Listener, error) {

	server, err := NewShadowsocksServer(support, listener, ssEncryptionKey, irregularTunnelLogger)
	if err != nil {
		return nil, errors.Trace(err)
	}

	return NewShadowsocksListener(listener, server), nil
}

// NewShadowsocksServer initializes a new ShadowsocksServer.
func NewShadowsocksServer(
	support *SupportServices,
	listener net.Listener,
	ssEncryptionKey string,
	irregularTunnelLogger func(string, error, common.LogFields)) (*ShadowsocksServer, error) {

	// Note: client must use the same cipher.
	key, err := shadowsocks.NewEncryptionKey(shadowsocks.CHACHA20IETFPOLY1305, ssEncryptionKey)
	if err != nil {
		return nil, errors.TraceMsg(err, "shadowsocks.NewEncryptionKey failed")
	}

	// Note: see comment for service.MaxCapacity for a description of
	// the expected false positive rate.
	replayHistory := service.MaxCapacity

	shadowsocksServer := &ShadowsocksServer{
		support:               support,
		listener:              listener,
		key:                   key,
		saltGenerator:         service.NewServerSaltGenerator(ssEncryptionKey),
		replayCache:           service.NewReplayCache(replayHistory),
		irregularTunnelLogger: irregularTunnelLogger,
	}

	return shadowsocksServer, nil
}

// ShadowsocksListener implements the net.Listener interface. Accept returns a
// net.Conn which implements the common.MetricsSource interface.
type ShadowsocksListener struct {
	net.Listener
	server *ShadowsocksServer
}

// NewShadowsocksListener initializes a new ShadowsocksListener.
func NewShadowsocksListener(listener net.Listener, server *ShadowsocksServer) *ShadowsocksListener {
	return &ShadowsocksListener{
		Listener: listener,
		server:   server,
	}
}

func (l *ShadowsocksListener) Accept() (net.Conn, error) {

	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, errors.Trace(err)
	}

	salt, reader, err := l.readSalt(conn)
	if err != nil {
		return nil, errors.TraceMsg(err, "failed to read salt")
	}

	// TODO: code mostly copied from [1]; use NewShadowsocksStreamAuthenticator instead?
	//
	// [1] https://github.com/Jigsaw-Code/outline-ss-server/blob/fa651d3e87cc0a94104babb3ae85253471a22ebc/service/tcp.go#L138

	// Hardcode key ID because all clients use the same cipher per server,
	// which is fine because the underlying SSH connection protects the
	// confidentiality and integrity of client traffic between the client and
	// server.
	keyID := "1"

	isServerSalt := l.server.saltGenerator.IsServerSalt(salt)

	if isServerSalt || !l.server.replayCache.Add(keyID, salt) {

		go drainConn(conn)

		var err error
		if isServerSalt {
			err = errors.TraceNew("server replay detected")
		} else {
			err = errors.TraceNew("client replay detected")
		}

		l.server.irregularTunnelLogger(conn.RemoteAddr().String(), err, nil)

		return nil, err
	}

	ssr := shadowsocks.NewReader(reader, l.server.key)
	ssw := shadowsocks.NewWriter(conn, l.server.key)
	ssw.SetSaltGenerator(l.server.saltGenerator)
	ssClientConn := transport.WrapConn(conn.(*net.TCPConn), ssr, ssw)

	return NewShadowsocksConn(ssClientConn), nil
}

func drainConn(conn net.Conn) {
	_, _ = io.Copy(io.Discard, conn)
	conn.Close()
}

func (l *ShadowsocksListener) readSalt(conn net.Conn) ([]byte, io.Reader, error) {

	type result struct {
		salt []byte
		err  error
	}

	resultChannel := make(chan result)

	go func() {
		saltSize := l.server.key.SaltSize()
		salt := make([]byte, saltSize)
		if n, err := io.ReadFull(conn, salt); err != nil {
			resultChannel <- result{
				err: fmt.Errorf("reading conn failed after %d bytes: %w", n, err),
			}
			return
		}

		resultChannel <- result{
			salt: salt,
		}
	}()

	select {
	case result := <-resultChannel:
		if result.err != nil {
			return nil, nil, result.err
		}
		return result.salt, io.MultiReader(bytes.NewReader(result.salt), conn), nil
	case <-l.server.support.TunnelServer.shutdownBroadcast:
		return nil, nil, errors.TraceNew("shutdown broadcast")
	}
}

// ShadowsocksConn implements the net.Conn and common.MetricsSource interfaces.
type ShadowsocksConn struct {
	net.Conn
}

// NewShadowsocksConn initializes a new NewShadowsocksConn.
func NewShadowsocksConn(conn net.Conn) *ShadowsocksConn {
	return &ShadowsocksConn{
		Conn: conn,
	}
}

func (conn *ShadowsocksConn) Read(b []byte) (int, error) {
	return conn.Conn.Read(b)
}

// GetMetrics implements the common.MetricsSource interface.
func (conn *ShadowsocksConn) GetMetrics() common.LogFields {

	var logFields common.LogFields

	// Relay any metrics from the underlying conn.
	if m, ok := conn.Conn.(common.MetricsSource); ok {
		logFields = m.GetMetrics()
	} else {
		logFields = make(common.LogFields)
	}

	return logFields
}
