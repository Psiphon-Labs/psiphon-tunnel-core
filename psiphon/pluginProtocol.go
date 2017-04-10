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

// PluginProtocolNetDialer is a base network dialer that's used
// by PluginProtocolDialer to make its IP network connections. This
// is used, for example, to create TCPConns as the base TCP
// connections used by the plugin protocol.
type PluginProtocolNetDialer func(network, addr string) (net.Conn, error)

// PluginProtocolDialer creates a connection to addr over a
// plugin protocol. It uses netDialer to create its base network
// connection(s) and sends its log messages to loggerOutput.
// PluginProtocolDialer returns true if it attempts to create
// a connection, or false if it decides not to attempt a connection.
// PluginProtocolDialer must add its connection to pendingConns
// before the initial dial to allow for interruption.
type PluginProtocolDialer func(
	config *Config,
	loggerOutput io.Writer,
	pendingConns *common.Conns,
	netDialer PluginProtocolNetDialer,
	addr string) (
	bool, net.Conn, error)

// RegisterPluginProtocol sets the current plugin protocol
// dialer.
func RegisterPluginProtocol(protcolDialer PluginProtocolDialer) {
	registeredPluginProtocolDialer.Store(protcolDialer)
}

// DialPluginProtocol uses the current plugin protocol dialer,
// if set, to connect to addr over the plugin protocol.
func DialPluginProtocol(
	config *Config,
	loggerOutput io.Writer,
	pendingConns *common.Conns,
	netDialer PluginProtocolNetDialer,
	addr string) (
	bool, net.Conn, error) {

	dialer := registeredPluginProtocolDialer.Load()
	if dialer != nil {
		return dialer.(PluginProtocolDialer)(
			config, loggerOutput, pendingConns, netDialer, addr)
	}
	return false, nil, nil
}
