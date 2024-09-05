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
	"net"

	"github.com/Jigsaw-Code/outline-sdk/transport"
	"github.com/Jigsaw-Code/outline-sdk/transport/shadowsocks"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/shadowsocks/go-shadowsocks2/socks"
)

type ShadowsocksServer struct {
	support  *SupportServices
	listener net.Listener
	key      *shadowsocks.EncryptionKey
}

func ListenShadowsocks(
	support *SupportServices,
	listener net.Listener,
	ssEncryptionKey string,
) (net.Listener, error) {

	server, err := NewShadowsocksServer(support, listener, ssEncryptionKey)
	if err != nil {
		return nil, errors.Trace(err)
	}

	return NewShadowsocksListener(listener, server), nil
}

// NewShadowsocksServer initializes a new ShadowsocksServer.
func NewShadowsocksServer(
	support *SupportServices,
	listener net.Listener,
	ssEncryptionKey string) (*ShadowsocksServer, error) {

	key, err := shadowsocks.NewEncryptionKey(shadowsocks.CHACHA20IETFPOLY1305, ssEncryptionKey)
	if err != nil {
		return nil, errors.TraceMsg(err, "shadowsocks.NewEncryptionKey failed")
	}

	shadowsocksServer := &ShadowsocksServer{
		support:  support,
		listener: listener,
		key:      key,
	}

	return shadowsocksServer, nil
}

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

	ssr := shadowsocks.NewReader(conn, l.server.key)
	ssw := shadowsocks.NewWriter(conn, l.server.key)
	ssClientConn := transport.WrapConn(conn.(*net.TCPConn), ssr, ssw)

	return NewShadowsocksConn(ssClientConn, l.server), nil
}

// ShadowsocksConn implements the net.Conn and common.MetricsSource interfaces.
type ShadowsocksConn struct {
	net.Conn
	readTargetAddr bool // TODO: atomic?
	server         *ShadowsocksServer
}

// NewShadowsocksConn initializes a new NewShadowsocksConn.
func NewShadowsocksConn(conn net.Conn, server *ShadowsocksServer) *ShadowsocksConn {
	return &ShadowsocksConn{
		Conn:   conn,
		server: server,
	}
}

func (conn *ShadowsocksConn) Read(b []byte) (int, error) {
	// First read and discard target address
	if !conn.readTargetAddr {
		_, err := socks.ReadAddr(conn.Conn)
		if err != nil {
			return 0, errors.Trace(err)
		}
		// TODO: check target address is what we expect
		conn.readTargetAddr = true
	}
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
