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

// Package gateway discovers the local network's gateway (home router) IPv4
// address and this machine's own IPv4 address on the LAN reached through that
// gateway. It is used to supply portmapper.Config.GatewayLookupFunc, i.e. the
// destination for UPnP/NAT-PMP/PCP queries.
//
// This package is a hard fork of the gateway-discovery code in Tailscale's
// net/netmon package (LikelyHomeRouterIP and the per-OS likelyHomeRouterIP
// implementations), copied from tailscale v1.98.5:
//
//	https://github.com/tailscale/tailscale/blob/v1.98.5/net/netmon/state.go
//	https://github.com/tailscale/tailscale/blob/v1.98.5/net/netmon/interfaces_linux.go
//	https://github.com/tailscale/tailscale/blob/v1.98.5/net/netmon/interfaces_android.go
//	https://github.com/tailscale/tailscale/blob/v1.98.5/net/netmon/interfaces_bsd.go
//	https://github.com/tailscale/tailscale/blob/v1.98.5/net/netmon/interfaces_darwin.go
//	https://github.com/tailscale/tailscale/blob/v1.98.5/net/netmon/interfaces_windows.go
//
// It differs from the upstream code in two ways:
//
//   - It is self-contained: it depends only on the standard library and
//     golang.org/x (for the per-OS routing-table reads), with none of
//     Tailscale's internal helper packages.
//
//   - HomeRouterIP accepts an interface name. With an empty name it finds the
//     system default route's gateway (parity with the upstream behavior). With
//     a non-empty name it restricts the lookup to the default route(s) on that
//     interface, which is what split-interface configurations require: the
//     port mapper must target the gateway on a specific (e.g. downstream/ICE)
//     NIC rather than whichever interface holds the default route.
//
// The original Tailscale code is licensed as follows:
//
//	Copyright (c) Tailscale Inc & contributors
//	SPDX-License-Identifier: BSD-3-Clause
package gateway

import (
	"net"
	"net/netip"
)

// HomeRouterIP returns the likely gateway (home router) IPv4 address and this
// machine's own IPv4 address on the LAN reached through that gateway.
//
// If ifaceName is "", the system default route is used. If ifaceName is
// non-empty, the lookup is restricted to the default route(s) on that
// interface (split-interface mode).
//
// ok is false if no suitable gateway is found. The returned gateway is always
// a private IPv4 address, matching the assumption that UPnP/NAT-PMP/PCP
// services live on a residential router.
func HomeRouterIP(ifaceName string) (gateway, myIP netip.Addr, ok bool) {
	gw, ok := gatewayForInterface(ifaceName)
	if !ok || !gw.IsValid() || !gw.Is4() || !gw.IsPrivate() {
		return netip.Addr{}, netip.Addr{}, false
	}

	myIP, ok = selfIP(ifaceName, gw)
	if !ok {
		return netip.Addr{}, netip.Addr{}, false
	}
	return gw, myIP, true
}

// selfIP returns this machine's IPv4 address on the subnet that reaches gw.
//
// If ifaceName is non-empty, only that interface's addresses are considered;
// otherwise all "up" interfaces are scanned. Within the candidate
// interface(s), it prefers an address whose subnet contains gw; failing that,
// when an explicit interface was named, it falls back to that interface's
// first IPv4 address.
func selfIP(ifaceName string, gw netip.Addr) (netip.Addr, bool) {
	var ifaces []net.Interface
	if ifaceName != "" {
		iface, err := net.InterfaceByName(ifaceName)
		if err != nil {
			return netip.Addr{}, false
		}
		ifaces = []net.Interface{*iface}
	} else {
		all, err := net.Interfaces()
		if err != nil {
			return netip.Addr{}, false
		}
		ifaces = all
	}

	gwIP := net.IP(gw.AsSlice())
	var fallback netip.Addr
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipNet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip, ok := netip.AddrFromSlice(ipNet.IP)
			if !ok {
				continue
			}
			ip = ip.Unmap()
			if !ip.Is4() {
				continue
			}
			// Use net.IPNet.Contains, which masks correctly regardless of
			// whether the OS returned a 4- or 16-byte IP/mask for this IPv4
			// address (building a netip.Prefix from a 16-byte mask would
			// yield an invalid /N>32 prefix).
			if ipNet.Contains(gwIP) {
				return ip, true
			}
			if ifaceName != "" && !fallback.IsValid() {
				fallback = ip
			}
		}
	}
	if fallback.IsValid() {
		return fallback, true
	}
	return netip.Addr{}, false
}
