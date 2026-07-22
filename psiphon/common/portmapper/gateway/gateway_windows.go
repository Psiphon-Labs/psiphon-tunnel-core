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
