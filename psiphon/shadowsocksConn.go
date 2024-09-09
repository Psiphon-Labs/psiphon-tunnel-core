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

package psiphon

import (
	"context"
	"net"

	"github.com/Jigsaw-Code/outline-sdk/transport"
	"github.com/Jigsaw-Code/outline-sdk/transport/shadowsocks"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
)

// ShadowsockConfig specifies the behavior of a shadowsocksConn.
type ShadowsockConfig struct {
	dialAddr string
	key      string
}

// shadowsocksConn is a network connection that tunnels net.Conn flows over Shadowsocks.
type shadowsocksConn struct {
	net.Conn
}

// DialShadowsocksTunnel returns an initialized Shadowsocks connection.
func DialShadowsocksTunnel(
	ctx context.Context,
	shadowsocksConfig *ShadowsockConfig,
	dialConfig *DialConfig) (*shadowsocksConn, error) {

	// TODO: consider using other AEAD ciphers; server cipher needs to match.
	key, err := shadowsocks.NewEncryptionKey(shadowsocks.CHACHA20IETFPOLY1305, shadowsocksConfig.key)
	if err != nil {
		return nil, errors.Trace(err)
	}

	conn, err := DialTCP(ctx, shadowsocksConfig.dialAddr, dialConfig)
	if err != nil {
		return nil, errors.Trace(err)
	}

	// Based on shadowsocks.DialStream
	// TODO: explicitly set SaltGenerator?
	ssw := shadowsocks.NewWriter(conn, key)
	ssr := shadowsocks.NewReader(conn, key)
	// TODO: is this cast correct/safe?
	ssConn := transport.WrapConn(conn.(*TCPConn).Conn.(*net.TCPConn), ssr, ssw)

	return &shadowsocksConn{
		Conn: ssConn,
	}, nil
}
