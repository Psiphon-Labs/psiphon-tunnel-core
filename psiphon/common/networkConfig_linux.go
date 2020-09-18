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
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/syndtr/gocapability/capability"
)

func configureNetworkConfigSubprocessCapabilities() error {

	// If this process has CAP_NET_ADMIN, make it available to be inherited
	// be child processes via ambient mechanism described here:
	// https://github.com/torvalds/linux/commit/58319057b7847667f0c9585b9de0e8932b0fdb08
	//
	// The ambient mechanism is available in Linux kernel 4.3 and later.

	// When using capabilities, this process should have CAP_NET_ADMIN in order
	// to create tun devices. And the subprocess operations such as using "ifconfig"
	// and "iptables" for network config require the same CAP_NET_ADMIN capability.

	cap, err := capability.NewPid(0)
	if err != nil {
		return errors.Trace(err)
	}

	if cap.Get(capability.EFFECTIVE, capability.CAP_NET_ADMIN) {

		cap.Set(capability.INHERITABLE|capability.AMBIENT, capability.CAP_NET_ADMIN)

		err = cap.Apply(capability.AMBIENT)
		if err != nil {
			return errors.Trace(err)
		}
	}

	return nil
}
