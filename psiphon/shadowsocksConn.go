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
	"io"
	"net"

	"github.com/Jigsaw-Code/outline-sdk/transport/shadowsocks"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/transforms"
)

// ShadowsockConfig specifies the behavior of a shadowsocksConn.
type ShadowsockConfig struct {
	dialAddr string
	key      string
	prefix   *ShadowsocksPrefixSpec
}

// shadowsocksConn is a network connection that tunnels net.Conn flows over Shadowsocks.
type shadowsocksConn struct {
	net.Conn
	ssw io.Writer
	ssr io.Reader
}

// DialShadowsocksTunnel returns an initialized Shadowsocks connection.
func DialShadowsocksTunnel(
	ctx context.Context,
	shadowsocksConfig *ShadowsockConfig,
	dialConfig *DialConfig) (*shadowsocksConn, error) {

	// Note: server must use the same cipher.
	key, err := shadowsocks.NewEncryptionKey(shadowsocks.CHACHA20IETFPOLY1305, shadowsocksConfig.key)
	if err != nil {
		return nil, errors.Trace(err)
	}

	conn, err := DialTCP(ctx, shadowsocksConfig.dialAddr, dialConfig)
	if err != nil {
		return nil, errors.Trace(err)
	}

	ssw := shadowsocks.NewWriter(conn, key)

	if shadowsocksConfig.prefix != nil {

		prefix, err := makePrefix(shadowsocksConfig.prefix)
		if err != nil {
			return nil, errors.Trace(err)
		}

		// Prefixes must be <= 16 bytes as longer prefixes risk salt collisions,
		// which can compromise the security of the connection [1][2].
		// [1] https://developers.google.com/outline/docs/guides/service-providers/prefixing
		// [2] See comment for shadowsocks.NewPrefixSaltGenerator
		if len(prefix) > 16 {
			return nil, errors.Tracef("invalid prefix length %d", len(prefix))
		}

		ssw.SetSaltGenerator(shadowsocks.NewPrefixSaltGenerator(prefix))
	}

	return &shadowsocksConn{
		Conn: conn,
		ssr:  shadowsocks.NewReader(conn, key),
		ssw:  ssw,
	}, nil
}

func (conn *shadowsocksConn) Read(p []byte) (n int, err error) {
	return conn.ssr.Read(p)
}

func (conn *shadowsocksConn) Write(p []byte) (n int, err error) {
	return conn.ssw.Write(p)
}

// GetMetrics implements the common.MetricsSource interface.
func (conn *shadowsocksConn) GetMetrics() common.LogFields {
	// Relay any metrics from the underlying conn.
	m, ok := conn.Conn.(common.MetricsSource)
	if ok {
		return m.GetMetrics()
	}
	return nil
}

func (conn *shadowsocksConn) IsClosed() bool {
	closer, ok := conn.Conn.(common.Closer)
	if !ok {
		return false
	}
	return closer.IsClosed()
}

type ShadowsocksPrefixSpec struct {
	Name string
	Spec transforms.Spec
	Seed *prng.Seed
}

func makePrefix(spec *ShadowsocksPrefixSpec) ([]byte, error) {

	minLength := 0

	prefix, _, err := spec.Spec.ApplyPrefix(spec.Seed, minLength)
	if err != nil {
		return nil, errors.Trace(err)
	}

	return prefix, nil
}
