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
	"net"
	"os"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
)

const (
	DEFAULT_PUBLIC_INTERFACE_NAME = ""
)

func IsSupported() bool {
	return false
}

func makeDeviceInboundBuffer(_ int) []byte {
	return nil
}

func makeDeviceOutboundBuffer(_ int) []byte {
	return nil
}

func OpenTunDevice(_ string) (*os.File, string, error) {
	return nil, "", errors.Trace(unsupportedError)
}

func (device *Device) readTunPacket() (int, int, error) {
	return 0, 0, errors.Trace(unsupportedError)
}

func (device *Device) writeTunPacket(_ []byte) error {
	return errors.Trace(unsupportedError)
}

func configureNetworkConfigSubprocessCapabilities() error {
	return errors.Trace(unsupportedError)
}

func resetNATTables(_ *ServerConfig, _ net.IP) error {
	return errors.Trace(unsupportedError)
}

func configureServerInterface(_ *ServerConfig, _ string) error {
	return errors.Trace(unsupportedError)
}

func configureClientInterface(_ *ClientConfig, _ string) error {
	return errors.Trace(unsupportedError)
}

func BindToDevice(_ int, _ string) error {
	return errors.Trace(unsupportedError)
}

func fixBindToDevice(_ common.Logger, _ bool, _ string) error {
	// Not required
	return nil
}

type NonblockingIO struct {
}

func NewNonblockingIO(ioFD int) (*NonblockingIO, error) {
	return nil, errors.Trace(unsupportedError)
}

func (nio *NonblockingIO) Read(p []byte) (int, error) {
	return 0, errors.Trace(unsupportedError)
}

func (nio *NonblockingIO) Write(p []byte) (int, error) {
	return 0, errors.Trace(unsupportedError)
}

func (nio *NonblockingIO) IsClosed() bool {
	return false
}

func (nio *NonblockingIO) Close() error {
	return errors.Trace(unsupportedError)
}
