//go:build windows
// +build windows

/*
 * Copyright (c) 2026, Psiphon Inc.
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

// Windows BindToDevice implementation using IP_UNICAST_IF /
// IPV6_UNICAST_IF. This is more like "route via interface X" rather
// than the stronger Linux SO_BINDTODEVICE, but it is the standard Windows
// equivalent.
//
// TODO: The rest of the tun device functionality (OpenTunDevice, readTunPacket,
// etc.) is not implemented on Windows.

package tun

import (
	"math/bits"
	"net"
	"os"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"golang.org/x/sys/cpu"
	"golang.org/x/sys/windows"
)

const (
	DEFAULT_PUBLIC_INTERFACE_NAME = ""

	// IP_UNICAST_IF and IPV6_UNICAST_IF share the same numeric value (31)
	// on Windows.
	// https://docs.microsoft.com/en-us/windows/win32/winsock/ipproto-ip-socket-options
	sockoptBoundInterface = 31
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
	return nil, "", errors.Trace(errUnsupported)
}

func (device *Device) readTunPacket() (int, int, error) {
	return 0, 0, errors.Trace(errUnsupported)
}

func (device *Device) writeTunPacket(_ []byte) error {
	return errors.Trace(errUnsupported)
}

func configureNetworkConfigSubprocessCapabilities() error {
	return errors.Trace(errUnsupported)
}

func resetNATTables(_ *ServerConfig, _ net.IP) error {
	return errors.Trace(errUnsupported)
}

func configureServerInterface(_ *ServerConfig, _ string) error {
	return errors.Trace(errUnsupported)
}

func configureClientInterface(_ *ClientConfig, _ string) error {
	return errors.Trace(errUnsupported)
}

func IsBindToDeviceSupported() bool {
	return true
}

// BindToDevice binds a socket to the specified interface on Windows.
// deviceName must match the interface FriendlyName that Go exposes as
// net.Interface.Name.
//
// Sets both IP_UNICAST_IF and IPV6_UNICAST_IF unconditionally. Go may
// create AF_INET, AF_INET6 dual-stack, or AF_INET6 v6-only sockets
// depending on the dial target and platform. Rather than probing the
// socket family, which is unreliable on some Windows versions, both
// options are attempted unconditionally. The option that doesn't apply
// to the socket's address family fails harmlessly. At least one must
// succeed for the bind to be successful.
//
// Caveat: this is not as strong as Linux SO_BINDTODEVICE. It is
// effectively "route this socket via interface X", which is the normal
// Windows equivalent.
func BindToDevice(fd int, deviceName string) error {
	iface, err := net.InterfaceByName(deviceName)
	if err != nil {
		return errors.Trace(err)
	}

	handle := windows.Handle(fd)
	ifIndexBE := int(nativeToBigEndian(uint32(iface.Index)))

	ipv4Err := windows.SetsockoptInt(handle, windows.IPPROTO_IP, sockoptBoundInterface, ifIndexBE)
	ipv6Err := windows.SetsockoptInt(handle, windows.IPPROTO_IPV6, sockoptBoundInterface, iface.Index)

	if ipv4Err != nil && ipv6Err != nil {
		return errors.Tracef(
			"BindToDevice failed: IPv4=%v, IPv6=%v", ipv4Err, ipv6Err)
	}

	return nil
}

func fixBindToDevice(_ common.Logger, _ bool, _ string) error {
	return nil
}

func fileFromFD(_ int, _ string) (*os.File, error) {
	return nil, errors.Trace(errUnsupported)
}

// nativeToBigEndian converts a uint32 from native byte order to
// big-endian. Required because IP_UNICAST_IF expects the interface index
// in network (big-endian) byte order for IPv4.
func nativeToBigEndian(i uint32) uint32 {
	if cpu.IsBigEndian {
		return i
	}
	return bits.ReverseBytes32(i)
}
