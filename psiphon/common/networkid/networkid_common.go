//go:build (darwin && !ios && cgo) || (linux && !android) || windows

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
	"net/netip"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
)

// getInterface returns the named interface, or the one carrying the default
// route when interfaceName is empty.
func getInterface(interfaceName string) (*net.Interface, error) {

	if interfaceName != "" {
		iface, err := net.InterfaceByName(interfaceName)
		if err != nil {
			return nil, errors.Trace(err)
		}
		return iface, nil
	}

	localAddr, err := getDefaultLocalAddr()
	if err != nil {
		return nil, errors.Trace(err)
	}

	iface, err := getInterfaceForLocalIP(localAddr)
	if err != nil {
		return nil, errors.Trace(err)
	}

	return iface, nil
}

// Get address associated with the default interface.
func getDefaultLocalAddr() (net.IP, error) {
	// This approach is described in psiphon/common/inproxy/pionNetwork.Interfaces()
	// The basic idea is that we initialize a UDP connection and see what local
	// address the system decides to use.
	// Note that no actual network request is made by these calls. They can be performed
	// with no network connectivity at all.
	// TODO: Use common test IP addresses in that function and this.

	// We'll prefer IPv4 and check it first (both might be available)
	ipv4UDPAddr := net.UDPAddrFromAddrPort(netip.MustParseAddrPort("93.184.216.34:3478"))
	ipv4UDPConn, ipv4Err := net.DialUDP("udp4", nil, ipv4UDPAddr)
	if ipv4Err == nil {
		ip := ipv4UDPConn.LocalAddr().(*net.UDPAddr).IP
		ipv4UDPConn.Close()
		return ip, nil
	}

	ipv6UDPAddr := net.UDPAddrFromAddrPort(netip.MustParseAddrPort("[2606:2800:220:1:248:1893:25c8:1946]:3478"))
	ipv6UDPConn, ipv6Err := net.DialUDP("udp6", nil, ipv6UDPAddr)
	if ipv6Err == nil {
		ip := ipv6UDPConn.LocalAddr().(*net.UDPAddr).IP
		ipv6UDPConn.Close()
		return ip, nil
	}

	return nil, errors.Trace(ipv4Err)
}

// Given the IP of a local interface, get that interface info.
func getInterfaceForLocalIP(ip net.IP) (*net.Interface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, errors.Trace(err)
	}

	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			return nil, errors.Trace(err)
		}

		for _, addr := range addrs {
			addrIP, _, err := net.ParseCIDR(addr.String())
			if err != nil {
				return nil, errors.Trace(err)
			}

			if addrIP.Equal(ip) {
				return &iface, nil
			}
		}
	}

	return nil, errors.TraceNew("not found")
}
