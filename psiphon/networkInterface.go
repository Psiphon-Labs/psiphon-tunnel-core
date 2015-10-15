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

// Take in an interface name ("lo", "eth0", "any") passed from either
// a config setting or by -interface command line flag and return the IP
// address associated with it.
// If no interface is provided use the default loopback interface (127.0.0.1).
// If "any" is passed then listen on 0.0.0.0
func GetInterfaceIPAddress(listenInterface string) (string, error) {
	var ip net.IP

	if listenInterface == "" {
		ip = net.ParseIP("127.0.0.1")
	} else if listenInterface == "any" {
		ip = net.ParseIP("0.0.0.0")
	} else {
		//Get a list of interfaces
		availableInterfaces, err := net.Interfaces()
		if err != nil {
			return "", ContextError(err)
		}

		var selectedInterface net.Interface
		found := false
		for _, networkInterface := range availableInterfaces {
			if listenInterface == networkInterface.Name {
				NoticeInfo("Using interface: %s", networkInterface.Name)
				selectedInterface = networkInterface
				found = true
				break
			}
		}
		if !found {
			NoticeAlert("Interface not found: %s", listenInterface)
			ip = net.ParseIP("127.0.0.1")
		} else {
			netAddrs, err := selectedInterface.Addrs()
			if err != nil {
				return "", ContextError(err)
			}

			for _, ipAddr := range netAddrs {
				ip, _, err = net.ParseCIDR(ipAddr.String())
				if err != nil {
					return "", ContextError(err)
				}
				if ip.To4() != nil {
					break
				}
			}
		}
	}

	NoticeInfo("Listening on IP address: %s", ip.String())

	return ip.String(), nil
}
