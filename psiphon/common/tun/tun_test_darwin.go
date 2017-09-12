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
	"syscall"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
)

func bindToDevice(fd int, deviceName string) error {

	netInterface, err := net.InterfaceByName(deviceName)
	if err != nil {
		return common.ContextError(err)
	}

	// IP_BOUND_IF definition from <netinet/in.h>

	const IP_BOUND_IF = 25

	err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, IP_BOUND_IF, netInterface.Index)
	if err != nil {
		return common.ContextError(err)
	}

	return nil
}

func fixBindToDevice(_ common.Logger, _ bool, _ string) error {
	// Not required on Darwin
	return nil
}
