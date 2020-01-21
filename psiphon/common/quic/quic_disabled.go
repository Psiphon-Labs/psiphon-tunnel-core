// +build DISABLE_QUIC

/*
 * Copyright (c) 2020, Psiphon Inc.
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

package quic

import (
	"context"
	"net"
	"net/http"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
)

// Enabled indicates if QUIC functionality is enabled.
func Enabled() bool {
	return false
}

func Listen(
	logger common.Logger,
	address string,
	obfuscationKey string) (net.Listener, error) {

	return nil, errors.TraceNew("operation is not enabled")
}

func Dial(
	ctx context.Context,
	packetConn net.PacketConn,
	remoteAddr *net.UDPAddr,
	quicSNIAddress string,
	negotiateQUICVersion string,
	obfuscationKey string,
	obfuscationPaddingSeed *prng.Seed) (net.Conn, error) {

	return nil, errors.TraceNew("operation is not enabled")
}

type QUICTransporter struct {
}

func (t *QUICTransporter) SetRequestContext(ctx context.Context) {
}

func (t *QUICTransporter) CloseIdleConnections() {
}

func (t *QUICTransporter) RoundTrip(req *http.Request) (resp *http.Response, err error) {
	return nil, errors.TraceNew("operation is not enabled")
}

func NewQUICTransporter(
	ctx context.Context,
	noticeEmitter func(string),
	udpDialer func(ctx context.Context) (net.PacketConn, *net.UDPAddr, error),
	quicSNIAddress string,
	negotiateQUICVersion string) (*QUICTransporter, error) {

	return nil, errors.TraceNew("operation is not enabled")
}
