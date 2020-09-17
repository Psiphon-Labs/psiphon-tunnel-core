/*
 * Copyright (c) 2020, Psiphon Inc.
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

package common

import (
	"fmt"
	"os/exec"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
)

// RunNetworkConfigCommand execs a network config command, such as "ifconfig"
// or "iptables". On platforms that support capabilities, the network config
// capabilities of the current process is made available to the command
// subprocess. Alternatively, "sudo" will be used when useSudo is true.
func RunNetworkConfigCommand(
	logger Logger,
	useSudo bool,
	commandName string, commandArgs ...string) error {

	// configureSubprocessCapabilities will set inheritable
	// capabilities on platforms which support that (Linux).
	// Specifically, CAP_NET_ADMIN will be transferred from
	// this process to the child command.

	err := configureNetworkConfigSubprocessCapabilities()
	if err != nil {
		return errors.Trace(err)
	}

	// TODO: use CommandContext to interrupt on process shutdown?
	// (the commands currently being issued shouldn't block...)

	if useSudo {
		commandArgs = append([]string{commandName}, commandArgs...)
		commandName = "sudo"
	}

	cmd := exec.Command(commandName, commandArgs...)
	output, err := cmd.CombinedOutput()

	logger.WithTraceFields(LogFields{
		"command": commandName,
		"args":    commandArgs,
		"output":  string(output),
		"error":   err,
	}).Debug("exec")

	if err != nil {
		err := fmt.Errorf(
			"command %s %+v failed with %s", commandName, commandArgs, string(output))
		return errors.Trace(err)
	}
	return nil
}
