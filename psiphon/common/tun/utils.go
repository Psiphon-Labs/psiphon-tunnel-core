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
	"net"
	"os/exec"
	"strconv"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
)

func runCommand(logger common.Logger, name string, args ...string) error {

	// configureSubprocessCapabilities will set inheritable
	// capabilities on platforms which support that (Linux).
	// Specifically, CAP_NET_ADMIN will be transferred from
	// this process to the child command.

	err := configureSubprocessCapabilities()
	if err != nil {
		return common.ContextError(err)
	}

	// TODO: use CommandContext to interrupt on server shutdown?
	// (the commands currently being issued shouldn't block...)

	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()

	logger.WithContextFields(common.LogFields{
		"command": name,
		"args":    args,
		"output":  string(output),
		"error":   err,
	}).Debug("exec")

	if err != nil {
		err := fmt.Errorf("command %s %+v failed with %s", name, args, string(output))
		return common.ContextError(err)
	}
	return nil
}

func splitIPMask(IPAddressCIDR string) (string, string, error) {

	IP, IPNet, err := net.ParseCIDR(IPAddressCIDR)
	if err != nil {
		return "", "", common.ContextError(err)
	}

	var netmask string
	IPv4Mask := net.IP(IPNet.Mask).To4()
	if IPv4Mask != nil {
		netmask = fmt.Sprintf(
			"%d.%d.%d.%d", IPv4Mask[0], IPv4Mask[1], IPv4Mask[2], IPv4Mask[3])
	} else {
		netmask = IPNet.Mask.String()
	}

	return IP.String(), netmask, nil
}

func splitIPPrefixLen(IPAddressCIDR string) (string, string, error) {

	IP, IPNet, err := net.ParseCIDR(IPAddressCIDR)
	if err != nil {
		return "", "", common.ContextError(err)
	}

	prefixLen, _ := IPNet.Mask.Size()

	return IP.String(), strconv.Itoa(prefixLen), nil
}

func getMTU(configMTU int) int {
	if configMTU <= 0 {
		return DEFAULT_MTU
	} else if configMTU > 65536 {
		return 65536
	}
	return configMTU
}
