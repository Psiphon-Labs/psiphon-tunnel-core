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

// BindToDevice binds a socket to the specified interface on Windows.
// deviceName must match the interface FriendlyName that Go exposes as
// net.Interface.Name.
//
// Uses IP_UNICAST_IF for IPv4 sockets and IPV6_UNICAST_IF for IPv6
// sockets. The socket's address family is detected by probing the
// IPV6_V6ONLY option, which is documented to work on a socket of any
// type in any state; this avoids a getsockname call that, per
// Microsoft's docs, may return WSAEINVAL on an unbound, unconnected
// socket -- the state of the sockets we get from net.Dialer.Control and
// net.ListenConfig.Control.
//
// Caveat: this is not as strong as Linux SO_BINDTODEVICE. It is
// effectively "route this socket via interface X", which is the normal
// Windows equivalent.
func BindToDevice(fd int, deviceName string) error {
	iface, err := net.InterfaceByName(deviceName)
	if err != nil {
		return errors.Trace(err)
	}

	socket := windows.Handle(fd)
	ifIndexBE := int(nativeToBigEndian(uint32(iface.Index)))

	// Probe IPV6_V6ONLY to detect address family: on an AF_INET socket
	// this returns WSAENOPROTOOPT because IPPROTO_IPV6 is not a valid
	// level for IPv4; on an AF_INET6 socket it returns the v6-only flag
	// (0 means dual-stack, 1 means v6-only).
	v6only, err := windows.GetsockoptInt(
		socket, windows.IPPROTO_IPV6, windows.IPV6_V6ONLY)
	if err != nil {
		// AF_INET socket: bind the IPv4 routing only.
		if err := windows.SetsockoptInt(
			socket,
			windows.IPPROTO_IP,
			sockoptBoundInterface,
			ifIndexBE); err != nil {
			return errors.Trace(err)
		}
		return nil
	}

	// AF_INET6 socket: always bind the IPv6 routing. On a dual-stack
	// socket (v6only == 0, which is Go's default for "udp" listens on
	// Windows), IPv4-mapped traffic uses the IPv4 routing table and is
	// not constrained by IPV6_UNICAST_IF alone, so IP_UNICAST_IF is also
	// set. IP_UNICAST_IF is not set on v6-only sockets, where some
	// Windows versions reject IPPROTO_IP options with WSAEINVAL.
	if err := windows.SetsockoptInt(
		socket,
		windows.IPPROTO_IPV6,
		sockoptBoundInterface,
		iface.Index); err != nil {
		return errors.Trace(err)
	}
	if v6only == 0 {
		if err := windows.SetsockoptInt(
			socket,
			windows.IPPROTO_IP,
			sockoptBoundInterface,
			ifIndexBE); err != nil {
			return errors.Trace(err)
		}
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
