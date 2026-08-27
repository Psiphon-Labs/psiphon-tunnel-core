//go:build (darwin && cgo) || (linux && !android)

/*
 * Copyright (c) 2026, Psiphon Inc.
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

package networkid

import (
	"net"
	"strings"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
)

func Enabled() bool {
	return true
}

// Get returns the compound network ID; see [psiphon.NetworkIDGetter] for
// details. interfaceName selects the network to describe; when it is empty, the
// interface carrying the default route is used.
//
// This serves iOS as well, as the ios target implies darwin, where it is a
// fallback for when the native network ID implementation is unavailable.
func Get(interfaceName string) (string, error) {

	iface, err := getInterface(interfaceName)
	if err != nil {
		return "", errors.Trace(err)
	}

	connectionType := getConnectionType(iface)

	// The connection type alone remains a valid network ID.
	ip, err := getInterfaceIP(iface)
	if err != nil {
		return connectionType, nil
	}

	return connectionType + "-" + ip.String(), nil
}

// getInterfaceIP returns the address distinguishing one network from another on
// the same interface. IPv4 is preferred, as IPv6 privacy addresses are
// periodically regenerated, presenting a stable network as a new one.
func getInterfaceIP(iface *net.Interface) (net.IP, error) {

	addrs, err := iface.Addrs()
	if err != nil {
		return nil, errors.Trace(err)
	}

	var ipv6 net.IP

	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok || ipNet.IP.IsLinkLocalUnicast() {
			continue
		}
		if ipNet.IP.To4() != nil {
			return ipNet.IP, nil
		}
		if ipv6 == nil {
			ipv6 = ipNet.IP
		}
	}

	if ipv6 != nil {
		return ipv6, nil
	}

	return nil, errors.TraceNew("no address found")
}

// isVPNInterfaceName reports whether the interface name is one used for
// tunnelled networks. The name is checked because these interfaces are not
// otherwise distinguishable: they report no media type on Darwin, and tap
// devices are indistinguishable from ethernet on Linux.
func isVPNInterfaceName(interfaceName string) bool {
	for _, prefix := range []string{"utun", "tun", "tap", "ipsec", "ppp", "wg"} {
		if strings.HasPrefix(interfaceName, prefix) {
			return true
		}
	}
	return false
}
