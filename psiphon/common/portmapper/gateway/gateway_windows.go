//go:build windows

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

// This file is part of a hard fork of Tailscale's gateway discovery; see the
// package documentation in gateway.go. Based on tailscale v1.98.5:
//
//	https://github.com/tailscale/tailscale/blob/v1.98.5/net/netmon/interfaces_windows.go
//
// The original Tailscale code is licensed as follows:
//
//	Copyright (c) Tailscale Inc & contributors
//	SPDX-License-Identifier: BSD-3-Clause

package gateway

import (
	"net"
	"net/netip"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// gatewayForInterface returns the gateway IPv4 address from the Windows IPv4
// forwarding table: the next hop of the lowest-metric default route
// (0.0.0.0/0) on one interface: the named one when ifaceName is non-empty,
// otherwise the one the stack routes Internet-bound traffic through.
//
// The interface is selected before the default routes are compared because
// the forwarding table alone does not say which of several default routes
// is in use: the stack ranks them by route metric plus interface metric and
// resolves ties itself. A gateway on any other interface is not on the path
// return traffic takes, so a mapping obtained from it would carry nothing.
func gatewayForInterface(ifaceName string) (netip.Addr, bool) {
	var wantIndex uint32
	if ifaceName != "" {
		iface, err := net.InterfaceByName(ifaceName)
		if err != nil {
			return netip.Addr{}, false
		}
		wantIndex = uint32(iface.Index)
	} else {
		var ok bool
		wantIndex, ok = internetInterfaceIndex()
		if !ok {
			return netip.Addr{}, false
		}
	}

	rows, err := winipcfg.GetIPForwardTable2(windows.AF_INET)
	if err != nil {
		return netip.Addr{}, false
	}
	return defaultRouteGateway(rows, wantIndex)
}

// internetInterfaceIndex returns the index of the interface the stack would
// send Internet-bound IPv4 traffic through. The destination is a TEST-NET-1
// address, which no local route is more specific than, so the lookup
// resolves to the default route; nothing is sent to it.
func internetInterfaceIndex() (uint32, bool) {
	var index uint32
	err := windows.GetBestInterfaceEx(&windows.SockaddrInet4{Addr: [4]byte{192, 0, 2, 1}}, &index)
	if err != nil || index == 0 {
		return 0, false
	}
	return index, true
}

// defaultRouteGateway returns the next hop of the lowest-metric IPv4 default
// route on the interface with index ifIndex, if it is a private address.
// Routes on one interface share its interface metric, so the route metric
// alone orders them.
func defaultRouteGateway(rows []winipcfg.MibIPforwardRow2, ifIndex uint32) (netip.Addr, bool) {
	v4unspec := netip.IPv4Unspecified()
	var best netip.Addr
	var bestMetric uint32
	for i := range rows {
		r := &rows[i]
		if r.Loopback || r.DestinationPrefix.PrefixLength != 0 {
			// Not a default route.
			continue
		}
		if r.DestinationPrefix.Prefix().Addr().Unmap() != v4unspec {
			continue
		}
		if r.InterfaceIndex != ifIndex {
			continue
		}
		gw := r.NextHop.Addr().Unmap()
		if !gw.IsValid() || !gw.Is4() {
			continue
		}
		if !best.IsValid() || r.Metric < bestMetric {
			best, bestMetric = gw, r.Metric
		}
	}

	if best.IsValid() && best.IsPrivate() {
		return best, true
	}
	return netip.Addr{}, false
}
