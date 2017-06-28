// +build !darwin,!linux

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

package tun

import (
	"errors"
	"net"
	"os"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
)

var unsupportedError = errors.New("operation unsupported on this platform")

func makeDeviceInboundBuffer(_ int) []byte {
	return nil
}

func makeDeviceOutboundBuffer(_ int) []byte {
	return nil
}

func configureServerInterface(_ *ServerConfig, _ string) error {
	return common.ContextError(unsupportedError)
}

func configureClientInterface(_ *ClientConfig, _ string) error {
	return common.ContextError(unsupportedError)
}

func createTunDevice() (*os.File, string, error) {
	return nil, "", common.ContextError(unsupportedError)
}

func (device *Device) readTunPacket() (int, int, error) {
	return 0, 0, common.ContextError(unsupportedError)
}

func (device *Device) writeTunPacket(_ []byte) error {
	return common.ContextError(unsupportedError)
}

func configureNetworkConfigSubprocessCapabilities() error {
	return common.ContextError(unsupportedError)
}

func resetNATTables(_ *ServerConfig, _ net.IP) error {
	return common.ContextError(unsupportedError)
}

func routeServerInterface(_ string, _ int) error {
	return common.ContextError(unsupportedError)
}

func dupCloseOnExec(_ int) (int, error) {
	return -1, common.ContextError(unsupportedError)
}
