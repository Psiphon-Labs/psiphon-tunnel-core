/*
 * Copyright (c) 2017, Psiphon Inc.
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
	"io"
	"net"
	"sync/atomic"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
)

var registeredPluginProtocolDialer atomic.Value

// PluginProtocolDialer creates a connection to addr over a
// plugin protocol. It uses dialConfig to create its base network
// connection(s) and sends its log messages to loggerOutput.
//
// To ensure timely interruption and shutdown, each
// PluginProtocolDialerimplementation must:
//
// - Places its outer net.Conn in pendingConns and leave it
//   there unless an error occurs
// - Replace the dialConfig.pendingConns with its own
//   PendingConns and use that to ensure base network
//   connections are interrupted when Close() is invoked on
//   the returned net.Conn.
//
// PluginProtocolDialer returns true if it attempts to create
// a connection, or false if it decides not to attempt a connection.
type PluginProtocolDialer func(
	config *Config,
	loggerOutput io.Writer,
	pendingConns *common.Conns,
	addr string,
	dialConfig *DialConfig) (bool, net.Conn, error)

// RegisterPluginProtocol sets the current plugin protocol
// dialer.
func RegisterPluginProtocol(protocolDialer PluginProtocolDialer) {
	registeredPluginProtocolDialer.Store(protocolDialer)
}

// DialPluginProtocol uses the current plugin protocol dialer,
// if set, to connect to addr over the plugin protocol.
func DialPluginProtocol(
	config *Config,
	loggerOutput io.Writer,
	pendingConns *common.Conns,
	addr string,
	dialConfig *DialConfig) (bool, net.Conn, error) {

	dialer := registeredPluginProtocolDialer.Load()
	if dialer != nil {
		return dialer.(PluginProtocolDialer)(
			config, loggerOutput, pendingConns, addr, dialConfig)
	}
	return false, nil, nil
}
