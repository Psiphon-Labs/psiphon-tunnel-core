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
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"github.com/Psiphon-Inc/gocapability/capability"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
)

const (
	DEFAULT_PUBLIC_INTERFACE_NAME = "eth0"
)

func makeDeviceInboundBuffer(MTU int) []byte {
	return make([]byte, MTU)
}

func makeDeviceOutboundBuffer(MTU int) []byte {
	// On Linux, no outbound buffer is used.
	return nil
}

func createTunDevice() (io.ReadWriteCloser, string, error) {

	// Prevent fork between creating fd and setting CLOEXEC
	syscall.ForkLock.RLock()
	defer syscall.ForkLock.RUnlock()

	// Requires process to run as root or have CAP_NET_ADMIN.

	// This code follows snippets in this thread:
	// https://groups.google.com/forum/#!msg/golang-nuts/x_c_pZ6p95c/8T0JBZLpTwAJ

	file, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, "", common.ContextError(err)
	}

	// Set CLOEXEC so file descriptor not leaked to network config command subprocesses
	syscall.CloseOnExec(int(file.Fd()))

	// Definitions from <linux/if.h>, <linux/if_tun.h>

	// Note: using IFF_NO_PI, so packets have no size/flags header. This does mean
	// that if the MTU is changed after the tun device is initialized, packets could
	// be truncated when read.

	const (
		IFNAMSIZ        = 16
		IF_REQ_PAD_SIZE = 40 - 18
		IFF_TUN         = 0x0001
		IFF_NO_PI       = 0x1000
	)

	var ifName [IFNAMSIZ]byte
	copy(ifName[:], []byte("tun%d"))

	ifReq := struct {
		name  [IFNAMSIZ]byte
		flags uint16
		pad   [IF_REQ_PAD_SIZE]byte
	}{
		ifName,
		uint16(IFF_TUN | IFF_NO_PI),
		[IF_REQ_PAD_SIZE]byte{},
	}

	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		file.Fd(),
		uintptr(syscall.TUNSETIFF),
		uintptr(unsafe.Pointer(&ifReq)))
	if errno != 0 {
		return nil, "", common.ContextError(errno)
	}

	deviceName := strings.Trim(string(ifReq.name[:]), "\x00")

	return file, deviceName, nil
}

func (device *Device) readTunPacket() (int, int, error) {

	// Assumes MTU passed to makeDeviceInboundBuffer is actual MTU and
	// so buffer is sufficiently large to always read a complete packet.

	n, err := device.deviceIO.Read(device.inboundBuffer)
	if err != nil {
		return 0, 0, common.ContextError(err)
	}
	return 0, n, nil
}

func (device *Device) writeTunPacket(packet []byte) error {

	// Doesn't need outboundBuffer since there's no header; write directly to device.

	_, err := device.deviceIO.Write(packet)
	if err != nil {
		return common.ContextError(err)
	}
	return nil
}

func configureNetworkConfigSubprocessCapabilities() error {

	// If this process has CAP_NET_ADMIN, make it available to be inherited
	// be child processes via ambient mechanism described here:
	// https://github.com/torvalds/linux/commit/58319057b7847667f0c9585b9de0e8932b0fdb08
	//
	// The ambient mechanim is available in Linux kernel 4.3 and later.

	// When using capabilities, this process should have CAP_NET_ADMIN in order
	// to create tun devices. And the subprocess operations such as using "ifconfig"
	// and "iptables" for network config require the same CAP_NET_ADMIN capability.

	cap, err := capability.NewPid(0)
	if err != nil {
		return common.ContextError(err)
	}

	if cap.Get(capability.EFFECTIVE, capability.CAP_NET_ADMIN) {

		cap.Set(capability.INHERITABLE|capability.AMBIENT, capability.CAP_NET_ADMIN)

		err = cap.Apply(capability.AMBIENT)
		if err != nil {
			return common.ContextError(err)
		}
	}

	return nil
}

func resetNATTables(
	config *ServerConfig,
	IPAddress net.IP) error {

	// Uses the "conntrack" command, which is often not installed by default.

	// conntrack --delete -src-nat --orig-src <address> will clear NAT tables of existing
	// connections, making it less likely that traffic for a previous client using the
	// specified address will be forwarded to a new client using this address. This is in
	// the already unlikely event that there's still in-flight traffic when the address is
	// recycled.

	err := runNetworkConfigCommand(
		config.Logger,
		config.SudoNetworkConfigCommands,
		"conntrack",
		"--delete",
		"--src-nat",
		"--orig-src",
		IPAddress.String())
	if err != nil {
		return common.ContextError(err)
	}

	return nil
}

func configureServerInterface(
	config *ServerConfig,
	tunDeviceName string) error {

	// Set tun device network addresses and MTU

	IPv4Address, IPv4Netmask, err := splitIPMask(serverIPv4AddressCIDR)
	if err != nil {
		return common.ContextError(err)
	}

	err = runNetworkConfigCommand(
		config.Logger,
		config.SudoNetworkConfigCommands,
		"ifconfig",
		tunDeviceName,
		IPv4Address, "netmask", IPv4Netmask,
		"mtu", strconv.Itoa(getMTU(config.MTU)),
		"up")
	if err != nil {
		return common.ContextError(err)
	}

	err = runNetworkConfigCommand(
		config.Logger,
		config.SudoNetworkConfigCommands,
		"ifconfig",
		tunDeviceName,
		"add", serverIPv6AddressCIDR)
	if err != nil {
		return common.ContextError(err)
	}

	egressInterface := config.EgressInterface
	if egressInterface == "" {
		egressInterface = DEFAULT_PUBLIC_INTERFACE_NAME
	}

	// NAT tun device to external interface

	// TODO: need only set forwarding for specific interfaces?

	err = runNetworkConfigCommand(
		config.Logger,
		config.SudoNetworkConfigCommands,
		"sysctl",
		"net.ipv4.conf.all.forwarding=1")
	if err != nil {
		return common.ContextError(err)
	}

	err = runNetworkConfigCommand(
		config.Logger,
		config.SudoNetworkConfigCommands,
		"sysctl",
		"net.ipv6.conf.all.forwarding=1")
	if err != nil {
		return common.ContextError(err)
	}

	// To avoid duplicates, first try to drop existing rule, then add

	for _, mode := range []string{"-D", "-A"} {

		err = runNetworkConfigCommand(
			config.Logger,
			config.SudoNetworkConfigCommands,
			"iptables",
			"-t", "nat",
			mode, "POSTROUTING",
			"-s", privateSubnetIPv4.String(),
			"-o", egressInterface,
			"-j", "MASQUERADE")
		if mode != "-D" && err != nil {
			return common.ContextError(err)
		}

		err = runNetworkConfigCommand(
			config.Logger,
			config.SudoNetworkConfigCommands,
			"ip6tables",
			"-t", "nat",
			mode, "POSTROUTING",
			"-s", privateSubnetIPv6.String(),
			"-o", egressInterface,
			"-j", "MASQUERADE")
		if mode != "-D" && err != nil {
			return common.ContextError(err)
		}
	}

	return nil
}

func configureClientInterface(
	config *ClientConfig,
	tunDeviceName string) error {

	// Set tun device network addresses and MTU

	IPv4Address, IPv4Netmask, err := splitIPMask(config.IPv4AddressCIDR)
	if err != nil {
		return common.ContextError(err)
	}

	err = runNetworkConfigCommand(
		config.Logger,
		config.SudoNetworkConfigCommands,
		"ifconfig",
		tunDeviceName,
		IPv4Address,
		"netmask", IPv4Netmask,
		"mtu", strconv.Itoa(getMTU(config.MTU)),
		"up")
	if err != nil {
		return common.ContextError(err)
	}

	err = runNetworkConfigCommand(
		config.Logger,
		config.SudoNetworkConfigCommands,
		"ifconfig",
		tunDeviceName,
		"add", config.IPv6AddressCIDR)
	if err != nil {
		return common.ContextError(err)
	}

	// Set routing. Routes set here should automatically
	// drop when the tun device is removed.

	// TODO: appear to need explict routing only for IPv6?

	for _, destination := range config.RouteDestinations {

		// Destination may be host (IP) or network (CIDR)

		IP := net.ParseIP(destination)
		if IP == nil {
			var err error
			IP, _, err = net.ParseCIDR(destination)
			if err != nil {
				return common.ContextError(err)
			}
		}
		if IP.To4() != nil {
			continue
		}

		// Note: use "replace" instead of "add" as route from
		// previous run (e.g., tun_test case) may not yet be cleared.

		err = runNetworkConfigCommand(
			config.Logger,
			config.SudoNetworkConfigCommands,
			"ip",
			"-6",
			"route", "replace",
			destination,
			"dev", tunDeviceName)
		if err != nil {
			return common.ContextError(err)
		}
	}

	return nil
}

func fixBindToDevice(logger common.Logger, useSudo bool, tunDeviceName string) error {

	// Fix the problem described here:
	// https://stackoverflow.com/questions/24011205/cant-perform-tcp-handshake-through-a-nat-between-two-nics-with-so-bindtodevice/

	err := runNetworkConfigCommand(
		logger,
		useSudo,
		"sysctl",
		"net.ipv4.conf.all.accept_local=1")
	if err != nil {
		return common.ContextError(err)
	}

	err = runNetworkConfigCommand(
		logger,
		useSudo,
		"sysctl",
		"net.ipv4.conf.all.rp_filter=0")
	if err != nil {
		return common.ContextError(err)
	}

	err = runNetworkConfigCommand(
		logger,
		useSudo,
		"sysctl",
		fmt.Sprintf("net.ipv4.conf.%s.rp_filter=0", tunDeviceName))
	if err != nil {
		return common.ContextError(err)
	}

	return nil
}
