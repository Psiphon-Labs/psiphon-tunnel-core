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
	"sort"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// gatewayForInterface returns the gateway IPv4 address from the Windows IPv4
// forwarding table, picking the default route (0.0.0.0/0) with the lowest
// route metric. If ifaceName is non-empty, only default routes on that
// interface are considered.
func gatewayForInterface(ifaceName string) (netip.Addr, bool) {
	rows, err := winipcfg.GetIPForwardTable2(windows.AF_INET)
	if err != nil {
		return netip.Addr{}, false
	}

	var wantIndex uint32 // 0 means "any"
	if ifaceName != "" {
		iface, err := net.InterfaceByName(ifaceName)
		if err != nil {
			return netip.Addr{}, false
		}
		wantIndex = uint32(iface.Index)
	}

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
		if wantIndex != 0 && r.InterfaceIndex != wantIndex {
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

// defaultRoutes returns every IPv4 default route to a private gateway from
// the forwarding table, ordered as the stack ranks routes: by route metric
// plus interface metric, with equal-cost routes in table order. Routes are
// named by the interface index of their forwarding entry. gatewayForInterface
// above is deliberately not changed to use this ranking: it keeps the
// default-route pick the in-proxy path has always made.
func defaultRoutes(ifaceName string) []defaultRoute {
	rows, err := winipcfg.GetIPForwardTable2(windows.AF_INET)
	if err != nil {
		return nil
	}
	ifaces, err := winipcfg.GetIPInterfaceTable(windows.AF_INET)
	if err != nil {
		return nil
	}
	ifaceMetrics := make(map[uint32]uint32, len(ifaces))
	for i := range ifaces {
		ifaceMetrics[ifaces[i].InterfaceIndex] = ifaces[i].Metric
	}
	var routes []defaultRoute
	names := make(map[uint32]string)
	for _, r := range rankedDefaultRoutes(rows, ifaceMetrics) {
		name, ok := names[r.ifIndex]
		if !ok {
			iface, err := net.InterfaceByIndex(int(r.ifIndex))
			if err != nil {
				continue
			}
			name = iface.Name
			names[r.ifIndex] = name
		}
		if ifaceName != "" && name != ifaceName {
			continue
		}
		routes = append(routes, defaultRoute{ifaceName: name, gateway: r.gateway})
	}
	return routes
}

// indexedRoute is a default route keyed by interface index, before the
// index is resolved to a name.
type indexedRoute struct {
	ifIndex uint32
	gateway netip.Addr
}

// rankedDefaultRoutes returns the distinct (interface, gateway) pairs that
// hold an IPv4 default route to a private next hop, ordered by the lowest
// total metric (route plus interface) of such a route for each pair. One
// interface may route through several routers; each is kept.
func rankedDefaultRoutes(
	rows []winipcfg.MibIPforwardRow2, ifaceMetrics map[uint32]uint32) []indexedRoute {

	v4unspec := netip.IPv4Unspecified()
	var routes []indexedRoute
	bestMetric := make(map[indexedRoute]uint64)
	for i := range rows {
		r := &rows[i]
		if r.Loopback || r.DestinationPrefix.PrefixLength != 0 {
			continue
		}
		if r.DestinationPrefix.Prefix().Addr().Unmap() != v4unspec {
			continue
		}
		gw := r.NextHop.Addr().Unmap()
		if !gw.IsValid() || !gw.Is4() || !gw.IsPrivate() {
			continue
		}
		key := indexedRoute{ifIndex: r.InterfaceIndex, gateway: gw}
		metric := uint64(r.Metric) + uint64(ifaceMetrics[r.InterfaceIndex])
		if best, seen := bestMetric[key]; !seen {
			routes = append(routes, key)
			bestMetric[key] = metric
		} else if metric < best {
			bestMetric[key] = metric
		}
	}
	sort.SliceStable(routes, func(i, j int) bool {
		return bestMetric[routes[i]] < bestMetric[routes[j]]
	})
	return routes
}
