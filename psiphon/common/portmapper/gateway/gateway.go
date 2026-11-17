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
// It differs from the upstream code in these ways:
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
//   - Candidates enumerates every default-route gateway rather than picking
//     one, for hosts with several default routes; see its documentation.
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

// Candidate is one home-router path: an "up" interface with an IPv4 default
// route whose next hop is a private address, that gateway, and this
// machine's IPv4 address on that interface.
type Candidate struct {
	InterfaceName string
	Gateway       netip.Addr
	LocalIP       netip.Addr
}

// Candidates returns every home-router path, most preferred first, where
// preference is the OS's own ranking of its default routes. A gateway that
// HomeRouterIP finds is among the candidates' gateways; the candidates can
// also include paths its lookup does not see.
//
// A host with several default routes may hold them at equal cost, in which
// case the OS sends to different destinations through different gateways
// (Windows hashes the destination across equal-cost routes), so no single
// gateway is "the" default; and one interface may have default routes
// through several routers. A caller that needs a port mapping can then try
// each candidate's gateway in turn and keep the first that answers.
//
// A non-empty ifaceName restricts the result to that interface, as for
// HomeRouterIP.
func Candidates(ifaceName string) []Candidate {
	return candidatesFromRoutes(defaultRoutes(ifaceName), interfaceAddrs)
}

// defaultRoute is one IPv4 default route, as read from the routing table by
// the per-OS defaultRoutes: the interface its routing entry names, and its
// gateway. candidatesFromRoutes drops the ones whose gateway is not private.
type defaultRoute struct {
	ifaceName string
	gateway   netip.Addr
}

func (r defaultRoute) String() string {
	return r.ifaceName + " via " + r.gateway.String()
}

// interfaceAddrs returns the addresses of the named interface if it is up.
func interfaceAddrs(ifaceName string) ([]net.Addr, bool) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil || iface.Flags&net.FlagUp == 0 {
		return nil, false
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, false
	}
	return addrs, true
}

// candidatesFromRoutes pairs each route with this machine's IPv4 address on
// the route's own interface: the one whose subnet contains the gateway, or
// failing that the interface's first. The interface comes from the routing
// entry, never from a subnet search across interfaces, which on a host with
// overlapping subnets (an Ethernet and a Wi-Fi link to the same LAN) could
// name an interface that holds no default route at all.
func candidatesFromRoutes(
	routes []defaultRoute, addrs func(ifaceName string) ([]net.Addr, bool)) []Candidate {

	var candidates []Candidate
	seen := make(map[defaultRoute]bool)
	for _, r := range routes {
		if seen[r] || !r.gateway.Is4() || !r.gateway.IsPrivate() {
			continue
		}
		seen[r] = true
		ifaceAddrs, ok := addrs(r.ifaceName)
		if !ok {
			continue
		}
		local, ok := localIPOnInterface(ifaceAddrs, r.gateway)
		if !ok {
			continue
		}
		candidates = append(candidates, Candidate{
			InterfaceName: r.ifaceName, Gateway: r.gateway, LocalIP: local})
	}
	return candidates
}

// localIPOnInterface picks, from one interface's addresses, the IPv4 address
// on the subnet that contains gw, or failing that the first IPv4 address.
func localIPOnInterface(addrs []net.Addr, gw netip.Addr) (netip.Addr, bool) {
	gwIP := net.IP(gw.AsSlice())
	var fallback netip.Addr
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
		if ipNet.Contains(gwIP) {
			return ip, true
		}
		if !fallback.IsValid() {
			fallback = ip
		}
	}
	return fallback, fallback.IsValid()
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
