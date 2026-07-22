//go:build darwin || freebsd || openbsd

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
//	https://github.com/tailscale/tailscale/blob/v1.98.5/net/netmon/interfaces_bsd.go
//
// The original Tailscale code is licensed as follows:
//
//	Copyright (c) Tailscale Inc & contributors
//	SPDX-License-Identifier: BSD-3-Clause

package gateway

import (
	"net"
	"net/netip"
	"syscall"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// gatewayForInterface returns the gateway IPv4 address from the BSD/Darwin
// routing table (RIB). If ifaceName is non-empty, only default routes on that
// interface are considered.
func gatewayForInterface(ifaceName string) (netip.Addr, bool) {
	rib, err := fetchRoutingTable()
	if err != nil {
		return netip.Addr{}, false
	}
	msgs, err := parseRoutingTable(rib)
	if err != nil {
		return netip.Addr{}, false
	}

	wantIndex := -1
	if ifaceName != "" {
		iface, err := net.InterfaceByName(ifaceName)
		if err != nil {
			return netip.Addr{}, false
		}
		wantIndex = iface.Index
	}

	// When an interface is explicitly requested (split-interface mode), accept
	// interface-scoped default routes (RTF_IFSCOPE). On macOS, the default
	// route of a non-primary interface is typically scoped to that interface,
	// so rejecting scoped routes would make HomeRouterIP("enX") fail even when
	// enX has a usable gateway. In default-route mode (ifaceName == "") scoped
	// routes are still rejected, matching the upstream heuristic of finding the
	// system's primary default route. The rm.Index filter below ensures only
	// scoped routes on the requested interface are accepted.
	allowScoped := wantIndex >= 0

	for _, m := range msgs {
		rm, ok := m.(*route.RouteMessage)
		if !ok {
			continue
		}
		if wantIndex >= 0 && rm.Index != wantIndex {
			continue
		}
		if !isDefaultGateway(rm, allowScoped) {
			continue
		}
		gwAddr, ok := rm.Addrs[unix.RTAX_GATEWAY].(*route.Inet4Addr)
		if !ok {
			continue
		}
		gw := netip.AddrFrom4(gwAddr.IP)
		if gw.IsPrivate() {
			return gw, true
		}
	}
	return netip.Addr{}, false
}

var (
	v4default = [4]byte{0, 0, 0, 0}
	v6default = [16]byte{}
)

// isDefaultGateway reports whether rm is a default route (0.0.0.0/0 or ::/0)
// via a gateway. Unless allowScoped is true, interface-scoped routes
// (RTF_IFSCOPE) are rejected; see the caller for why allowScoped is set only
// when a specific interface was requested.
func isDefaultGateway(rm *route.RouteMessage, allowScoped bool) bool {
	if rm.Flags&unix.RTF_GATEWAY == 0 {
		return false
	}
	// Defined locally because FreeBSD does not have unix.RTF_IFSCOPE.
	const RTF_IFSCOPE = 0x1000000
	if !allowScoped && rm.Flags&RTF_IFSCOPE != 0 {
		return false
	}

	// Addrs is [RTAX_DST, RTAX_GATEWAY, RTAX_NETMASK, ...]
	if len(rm.Addrs) <= unix.RTAX_NETMASK {
		return false
	}

	dst := rm.Addrs[unix.RTAX_DST]
	netmask := rm.Addrs[unix.RTAX_NETMASK]
	if dst == nil || netmask == nil {
		return false
	}

	if dst.Family() == syscall.AF_INET && netmask.Family() == syscall.AF_INET {
		dstAddr, dstOk := dst.(*route.Inet4Addr)
		nmAddr, nmOk := netmask.(*route.Inet4Addr)
		if dstOk && nmOk && dstAddr.IP == v4default && nmAddr.IP == v4default {
			return true
		}
	}

	if dst.Family() == syscall.AF_INET6 && netmask.Family() == syscall.AF_INET6 {
		dstAddr, dstOk := dst.(*route.Inet6Addr)
		nmAddr, nmOk := netmask.(*route.Inet6Addr)
		if dstOk && nmOk && dstAddr.IP == v6default && nmAddr.IP == v6default {
			return true
		}
	}

	return false
}
