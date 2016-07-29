/*
 * Copyright (c) 2015, Psiphon Inc.
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

package psiphon

import (
	"errors"
	"net"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
)

// Take in an interface name ("lo", "eth0", "any") passed from either
// a config setting, by using the -listenInterface flag on client or
// -interface flag on server from the command line and return the IP
// address associated with it.
// If no interface is provided use the default loopback interface (127.0.0.1).
// If "any" is passed then listen on 0.0.0.0 for client (invalid with server)
func GetInterfaceIPAddress(listenInterface string) (string, error) {
	var ip net.IP
	if listenInterface == "" {
		ip = net.ParseIP("127.0.0.1")
		return ip.String(), nil
	} else if listenInterface == "any" {
		ip = net.ParseIP("0.0.0.0")
		return ip.String(), nil
	} else {
		availableInterfaces, err := net.InterfaceByName(listenInterface)
		if err != nil {
			return "", common.ContextError(err)
		}

		addrs, err := availableInterfaces.Addrs()
		if err != nil {
			return "", common.ContextError(err)
		}
		for _, addr := range addrs {
			iptype := addr.(*net.IPNet)
			if iptype == nil {
				continue
			}
			// TODO: IPv6 support
			ip = iptype.IP.To4()
			if ip == nil {
				continue
			}
			return ip.String(), nil
		}
	}

	return "", common.ContextError(errors.New("Could not find IP address of specified interface"))

}
