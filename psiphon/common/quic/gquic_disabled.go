//go:build !PSIPHON_DISABLE_QUIC && PSIPHON_DISABLE_GQUIC
// +build !PSIPHON_DISABLE_QUIC,PSIPHON_DISABLE_GQUIC

/*
 * Copyright (c) 2021, Psiphon Inc.
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
	"time"

	tls "github.com/Psiphon-Labs/psiphon-tls"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
)

func GQUICEnabled() bool {
	return false
}

func gQUICListen(
	_ net.PacketConn,
	_ tls.Certificate,
	_ time.Duration) (quicListener, error) {

	return nil, errors.TraceNew("operation is not enabled")
}

func gQUICDialContext(
	_ context.Context,
	_ net.PacketConn,
	_ *net.UDPAddr,
	_ string,
	_ uint32) (quicConnection, error) {

	return nil, errors.TraceNew("operation is not enabled")
}

func gQUICRoundTripper(_ *QUICTransporter) (quicRoundTripper, error) {

	return nil, errors.TraceNew("operation is not enabled")
}
