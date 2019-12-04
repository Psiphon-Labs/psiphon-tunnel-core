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

package common

import (
	"net"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
)

// GetInterfaceIPAddresses takes an interface name, such as "eth0", and returns
// the first IPv4 and IPv6 addresses associated with it. Either of the IPv4 or
// IPv6 address may be nil. If neither type of address is found, an error
// is returned.
func GetInterfaceIPAddresses(interfaceName string) (net.IP, net.IP, error) {

	var IPv4Address, IPv6Address net.IP

	availableInterfaces, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return nil, nil, errors.Trace(err)
	}

	addrs, err := availableInterfaces.Addrs()
	if err != nil {
		return nil, nil, errors.Trace(err)
	}

	for _, addr := range addrs {

		ipNet := addr.(*net.IPNet)
		if ipNet == nil {
			continue
		}

		if ipNet.IP.To4() != nil {
			if IPv4Address == nil {
				IPv4Address = ipNet.IP
			}
		} else {
			if IPv6Address == nil {
				IPv6Address = ipNet.IP
			}
		}

		if IPv4Address != nil && IPv6Address != nil {
			break
		}
	}

	if IPv4Address != nil || IPv6Address != nil {
		return IPv4Address, IPv6Address, nil
	}

	return nil, nil, errors.Tracef("could not find any IP address for interface %s", interfaceName)
}

// GetRoutableInterfaceIPAddresses returns GetInterfaceIPAddresses values for
// the first non-loopback, non-point-to-point network interface on the host
// that has an IP address.
func GetRoutableInterfaceIPAddresses() (net.IP, net.IP, error) {

	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, nil, errors.Trace(err)
	}

	for i, in := range interfaces {
		if (in.Flags&net.FlagUp == 0) ||
			(in.Flags&(net.FlagLoopback|net.FlagPointToPoint)) != 0 {
			continue
		}
		IPv4Address, IPv6Address, err := GetInterfaceIPAddresses(in.Name)
		if err == nil {
			return IPv4Address, IPv6Address, nil
		} else if i == len(interfaces)-1 {
			return nil, nil, errors.Trace(err)
		}
	}
	return nil, nil, errors.TraceNew("no candidate interfaces found")
}
