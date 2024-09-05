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

type ShadowsockConfig struct {
	endpoint *transport.TCPEndpoint

	key *shadowsocks.EncryptionKey
}

type shadowsocksConn struct {
	net.Conn
}

func DialShadowsocksTunnel(ctx context.Context, shadowsocksConfig *ShadowsockConfig) (*shadowsocksConn, error) {

	// Connects to ss server
	// TODO: ss also supports UDP with NewPacketListener
	d, err := shadowsocks.NewStreamDialer(shadowsocksConfig.endpoint, shadowsocksConfig.key)
	if err != nil {
		return nil, errors.TraceMsg(err, "failed to create StreamDialer")
	}

	// Connects to target endpoint beyond ss server. We can use a phony address
	// here, which will be ignored on the server, and pass data through this
	// Conn.
	phonyTargetAddr := "phony.local:1111"
	conn, err := d.DialStream(context.Background(), phonyTargetAddr)
	if err != nil {
		return nil, errors.TraceMsg(err, "StreamDialer.Dial failed")
	}
	// conn.SetReadDeadline(time.Now().Add(time.Second * 5))

	return &shadowsocksConn{
		Conn: conn,
	}, nil
}
