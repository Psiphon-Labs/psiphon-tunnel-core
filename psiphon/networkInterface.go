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
	"net"
)

func GetInterfaceIPAddress(interfaceName string) string {
	var selectedInterface net.Interface
	var ip net.IP

	//Get a list of interfaces
	availableInterfaces, err := net.Interfaces()
	if err != nil {
		NoticeAlert("%s", ContextError(err))
	}

	if interfaceName == "any" {
		ip = net.ParseIP("0.0.0.0")
	} else {
		for _, networkInterface := range availableInterfaces {
			if interfaceName == networkInterface.Name {
				NoticeAlert("Using interface: %s", networkInterface.Name)
				selectedInterface = networkInterface
				break
			}
		}
	}

	if ip.To4() == nil {
		if selectedInterface.Name == "" {
			selectedInterface = availableInterfaces[0]
			NoticeAlert("No interface found, using %s", selectedInterface.Name)
		}
	}

	netAddrs, err := selectedInterface.Addrs()
	if err != nil {
		NoticeAlert("Error : %s", err.Error())
	}

	for _, ipAddr := range netAddrs {
		ip, _, err = net.ParseCIDR(ipAddr.String())
		if err != nil {
			NoticeAlert("Error parsing address %s", err.Error())
		}
		if ip.To4() != nil {
			break
		}
	}

	return ip.String()
}
