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
	"syscall"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
)

func bindToDevice(fd int, deviceName string) error {
	err := syscall.BindToDevice(fd, deviceName)
	if err != nil {
		return common.ContextError(err)
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
