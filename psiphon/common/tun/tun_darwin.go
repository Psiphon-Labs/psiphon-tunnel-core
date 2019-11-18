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

// Darwin utun code based on https://github.com/songgao/water:
/*
Copyright (c) 2016, Song Gao <song@gao.io>
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice,
  this list of conditions and the following disclaimer in the documentation
  and/or other materials provided with the distribution.

* Neither the name of water nor the names of its contributors may be used to
  endorse or promote products derived from this software without specific prior
  written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

package tun

import (
	std_errors "errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"strconv"
	"syscall"
	"unsafe"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
)

const (
	DEFAULT_PUBLIC_INTERFACE_NAME = "en0"
)

func IsSupported() bool {
	return true
}

func makeDeviceInboundBuffer(MTU int) []byte {
	// 4 extra bytes to read a utun packet header
	return make([]byte, 4+MTU)
}

func makeDeviceOutboundBuffer(MTU int) []byte {
	// 4 extra bytes to write a utun packet header
	return make([]byte, 4+MTU)
}

// OpenTunDevice opens a file for performing device I/O with
// either a specified tun device, or a new tun device (when
// name is "").
func OpenTunDevice(name string) (*os.File, string, error) {

	// Prevent fork between creating fd and setting CLOEXEC
	syscall.ForkLock.RLock()
	defer syscall.ForkLock.RUnlock()

	unit := uint32(0)
	if name != "" {
		n, err := fmt.Sscanf(name, "utun%d", &unit)
		if err == nil && n != 1 {
			err = std_errors.New("failed to scan device name")
		}
		if err != nil {
			return nil, "", errors.Trace(err)
		}
	}

	// Darwin utun code based on:
	// https://github.com/songgao/water/blob/70591d249921d075889cc49aaef072987e6b354a/syscalls_darwin.go

	// Definitions from <ioctl.h>, <sys/socket.h>, <sys/sys_domain.h>

	const (
		TUN_CONTROL_NAME = "com.apple.net.utun_control"
		CTLIOCGINFO      = (0x40000000 | 0x80000000) | ((100 & 0x1fff) << 16) | uint32(byte('N'))<<8 | 3
		TUNSIFMODE       = (0x80000000) | ((4 & 0x1fff) << 16) | uint32(byte('t'))<<8 | 94
		PF_SYSTEM        = syscall.AF_SYSTEM
		SYSPROTO_CONTROL = 2
		AF_SYS_CONTROL   = 2
		UTUN_OPT_IFNAME  = 2
	)

	fd, err := syscall.Socket(
		PF_SYSTEM,
		syscall.SOCK_DGRAM,
		SYSPROTO_CONTROL)
	if err != nil {
		return nil, "", errors.Trace(err)
	}

	// Set CLOEXEC so file descriptor not leaked to network config command subprocesses
	syscall.CloseOnExec(fd)

	var tunControlName [96]byte
	copy(tunControlName[:], TUN_CONTROL_NAME)

	ctlInfo := struct {
		ctlID   uint32
		ctlName [96]byte
	}{
		0,
		tunControlName,
	}

	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		uintptr(fd),
		uintptr(CTLIOCGINFO),
		uintptr(unsafe.Pointer(&ctlInfo)))
	if errno != 0 {
		return nil, "", errors.Trace(errno)
	}

	sockaddrCtlSize := 32
	sockaddrCtl := struct {
		scLen      uint8
		scFamily   uint8
		ssSysaddr  uint16
		scID       uint32
		scUnit     uint32
		scReserved [5]uint32
	}{
		uint8(sockaddrCtlSize),
		syscall.AF_SYSTEM,
		AF_SYS_CONTROL,
		ctlInfo.ctlID,
		unit,
		[5]uint32{},
	}

	_, _, errno = syscall.RawSyscall(
		syscall.SYS_CONNECT,
		uintptr(fd),
		uintptr(unsafe.Pointer(&sockaddrCtl)),
		uintptr(sockaddrCtlSize))
	if errno != 0 {
		return nil, "", errors.Trace(errno)
	}

	ifNameSize := uintptr(16)
	ifName := struct {
		name [16]byte
	}{}

	_, _, errno = syscall.Syscall6(
		syscall.SYS_GETSOCKOPT,
		uintptr(fd),
		SYSPROTO_CONTROL,
		UTUN_OPT_IFNAME,
		uintptr(unsafe.Pointer(&ifName)),
		uintptr(unsafe.Pointer(&ifNameSize)),
		0)
	if errno != 0 {
		return nil, "", errors.Trace(errno)
	}

	deviceName := string(ifName.name[:ifNameSize-1])
	file := os.NewFile(uintptr(fd), deviceName)

	return file, deviceName, nil
}

func (device *Device) readTunPacket() (int, int, error) {

	// Assumes MTU passed to makeDeviceInboundBuffer is actual MTU and
	// so buffer is sufficiently large to always read a complete packet,
	// along with the 4 byte utun header.

	n, err := device.deviceIO.Read(device.inboundBuffer)
	if err != nil {
		return 0, 0, errors.Trace(err)
	}

	if n < 4 {
		return 0, 0, errors.TraceNew("missing packet prefix")
	}

	return 4, n - 4, nil
}

func (device *Device) writeTunPacket(packet []byte) error {

	// Note: can't use writev via net.Buffers. os.File isn't
	// a net.Conn and can't wrap with net.FileConn due to
	// fd type. So writes use an intermediate buffer to add
	// the header.

	// Assumes:
	// - device.outboundBuffer[0..2] will be 0, the zero value
	// - packet already validated as 4 or 6
	// - max len(packet) won't exceed MTU, prellocated size of
	//   outboundBuffer.

	// Write utun header
	if len(packet) > 0 && packet[0]>>4 == 4 {
		device.outboundBuffer[3] = syscall.AF_INET
	} else { // IPv6
		device.outboundBuffer[3] = syscall.AF_INET6
	}

	copy(device.outboundBuffer[4:], packet)

	size := 4 + len(packet)

	_, err := device.deviceIO.Write(device.outboundBuffer[:size])
	if err != nil {
		return errors.Trace(err)
	}

	return nil
}

func configureNetworkConfigSubprocessCapabilities() error {
	// Not supported on Darwin
	return nil
}

func resetNATTables(_ *ServerConfig, _ net.IP) error {
	// Not supported on Darwin
	// TODO: could use pfctl -K?
	return nil
}

func configureServerInterface(
	config *ServerConfig,
	tunDeviceName string) error {

	// TODO: fix or remove the following broken code
	return errors.Trace(errUnsupported)

	// Set tun device network addresses and MTU

	IPv4Address, IPv4Netmask, err := splitIPMask(serverIPv4AddressCIDR)
	if err != nil {
		return errors.Trace(err)
	}

	err = runNetworkConfigCommand(
		config.Logger,
		config.SudoNetworkConfigCommands,
		"ifconfig",
		tunDeviceName,
		IPv4Address, IPv4Address, IPv4Netmask,
		"mtu", strconv.Itoa(getMTU(config.MTU)),
		"up")
	if err != nil {
		return errors.Trace(err)
	}

	IPv6Address, IPv6Prefixlen, err := splitIPPrefixLen(serverIPv6AddressCIDR)
	if err != nil {
		return errors.Trace(err)
	}

	err = runNetworkConfigCommand(
		config.Logger,
		config.SudoNetworkConfigCommands,
		"ifconfig",
		tunDeviceName,
		"inet6", IPv6Address, "prefixlen", IPv6Prefixlen)
	if err != nil {
		return errors.Trace(err)
	}

	// NAT tun device to external interface
	//
	// Uses configuration described here:
	// https://discussions.apple.com/thread/5538749

	egressInterface := config.EgressInterface
	if egressInterface == "" {
		egressInterface = DEFAULT_PUBLIC_INTERFACE_NAME
	}

	err = runNetworkConfigCommand(
		config.Logger,
		config.SudoNetworkConfigCommands,
		"sysctl",
		"net.inet.ip.forwarding=1")
	if err != nil {
		return errors.Trace(err)
	}

	err = runNetworkConfigCommand(
		config.Logger,
		config.SudoNetworkConfigCommands,
		"sysctl",
		"net.inet6.ip6.forwarding=1")
	if err != nil {
		return errors.Trace(err)
	}

	// TODO:
	// - should use -E and preserve existing pf state?
	// - OR should use "-F all" to reset everything?

	pfConf := fmt.Sprintf(
		"nat on %s from %s to any -> (%s)\n"+
			"nat on %s from %s to any -> (%s)\n"+
			"pass from %s to any keep state\n"+
			"pass from %s to any keep state\n\n",
		egressInterface, privateSubnetIPv4.String(), egressInterface,
		egressInterface, privateSubnetIPv6.String(), egressInterface,
		privateSubnetIPv4.String(),
		privateSubnetIPv6.String())

	tempFile, err := ioutil.TempFile("", "tun_pf_conf")
	if err != nil {
		return errors.Trace(err)
	}
	defer os.Remove(tempFile.Name())

	_, err = tempFile.Write([]byte(pfConf))
	if err != nil {
		return errors.Trace(err)
	}

	tempFile.Close()

	config.Logger.WithTraceFields(common.LogFields{
		"content": pfConf,
	}).Debug("pf.conf")

	// Disable first to avoid "pfctl: pf already enabled"
	_ = runNetworkConfigCommand(
		config.Logger,
		config.SudoNetworkConfigCommands,
		"pfctl",
		"-q",
		"-d")

	err = runNetworkConfigCommand(
		config.Logger,
		config.SudoNetworkConfigCommands,
		"pfctl",
		"-q",
		"-e",
		"-f", tempFile.Name())
	if err != nil {
		return errors.Trace(err)
	}

	return nil
}

func configureClientInterface(
	config *ClientConfig,
	tunDeviceName string) error {

	// TODO: fix or remove the following broken code
	return errors.Trace(errUnsupported)

	// Set tun device network addresses and MTU

	IPv4Address, IPv4Netmask, err := splitIPMask(config.IPv4AddressCIDR)
	if err != nil {
		return errors.Trace(err)
	}

	err = runNetworkConfigCommand(
		config.Logger,
		config.SudoNetworkConfigCommands,
		"ifconfig",
		tunDeviceName,
		IPv4Address, IPv4Address,
		"netmask", IPv4Netmask,
		"mtu", strconv.Itoa(getMTU(config.MTU)),
		"up")
	if err != nil {
		return errors.Trace(err)
	}

	IPv6Address, IPv6Prefixlen, err := splitIPPrefixLen(serverIPv6AddressCIDR)
	if err != nil {
		return errors.Trace(err)
	}

	err = runNetworkConfigCommand(
		config.Logger,
		config.SudoNetworkConfigCommands,
		"ifconfig",
		tunDeviceName,
		"inet6", IPv6Address, "prefixlen", IPv6Prefixlen)
	if err != nil {
		return errors.Trace(err)
	}

	// Set routing. Routes set here should automatically
	// drop when the tun device is removed.

	for _, destination := range config.RouteDestinations {

		// TODO: IPv6

		err = runNetworkConfigCommand(
			config.Logger,
			config.SudoNetworkConfigCommands,
			"route",
			"add",
			"-ifscope", tunDeviceName,
			destination,
			IPv4Address)
		if err != nil {
			return errors.Trace(err)
		}
	}

	return nil
}

// BindToDevice binds a socket to the specified interface.
func BindToDevice(fd int, deviceName string) error {

	netInterface, err := net.InterfaceByName(deviceName)
	if err != nil {
		return errors.Trace(err)
	}

	// IP_BOUND_IF definition from <netinet/in.h>

	const IP_BOUND_IF = 25

	err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, IP_BOUND_IF, netInterface.Index)
	if err != nil {
		return errors.Trace(err)
	}

	return nil
}

func fixBindToDevice(_ common.Logger, _ bool, _ string) error {
	// Not required on Darwin
	return nil
}
