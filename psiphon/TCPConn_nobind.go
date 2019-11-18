// +build windows

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
	"net"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
)

// tcpDial is the platform-specific part of DialTCP
func tcpDial(ctx context.Context, addr string, config *DialConfig) (net.Conn, error) {

	if config.DeviceBinder != nil {
		return nil, errors.TraceNew("psiphon.interruptibleTCPDial with DeviceBinder not supported")
	}

	dialer := net.Dialer{}

	conn, err := dialer.DialContext(ctx, "tcp", addr)

	// Remove domain names from "net" error messages.
	if err != nil && !GetEmitNetworkParameters() {
		err = RedactNetError(err)
	}

	if err != nil {
		return nil, errors.Trace(err)
	}

	return &TCPConn{Conn: conn}, nil
}
