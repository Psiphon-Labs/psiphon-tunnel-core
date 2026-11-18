//go:build android

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
//	https://github.com/tailscale/tailscale/blob/v1.98.5/net/netmon/interfaces_android.go
//
// The original Tailscale code is licensed as follows:
//
//	Copyright (c) Tailscale Inc & contributors
//	SPDX-License-Identifier: BSD-3-Clause

package gateway

import (
	"bufio"
	"net/netip"
	"os/exec"
	"strings"
)

// gatewayForInterface returns the gateway IPv4 address on Android. It first
// tries /proc/net/route, then falls back to parsing `ip route`, since Android
// apps often lack permission to read /proc/net/route.
//
// Note: Psiphon's split-interface mode is desktop-only; on Android ifaceName
// is expected to be "" (default route). The ifaceName filter is still honored
// best-effort for API uniformity.
func gatewayForInterface(ifaceName string) (netip.Addr, bool) {
	if gw, ok := parseProcNetRoute(ifaceName); ok {
		return gw, true
	}
	return androidIPRouteGateway(ifaceName)
}

// defaultRoutes returns every IPv4 default route, from /proc/net/route when
// readable and otherwise from `ip route`, as gatewayForInterface does.
func defaultRoutes(ifaceName string) []defaultRoute {
	if routes := procNetDefaultRoutes(ifaceName); len(routes) > 0 {
		return routes
	}
	return androidIPRoutes(ifaceName)
}

// androidIPRouteGateway returns the first IPv4 default gateway reported by
// `ip route`; see androidIPRoutes.
func androidIPRouteGateway(ifaceName string) (netip.Addr, bool) {
	routes := androidIPRoutes(ifaceName)
	if len(routes) == 0 {
		return netip.Addr{}, false
	}
	return routes[0].gateway, true
}

// androidIPRoutes parses the output of `/system/bin/ip route show table 0`,
// collecting lines like:
//
//	default via 10.0.2.2 dev radio0 table 1016 proto static mtu 1500
//
// If ifaceName is non-empty, only matching "dev" lines are used.
func androidIPRoutes(ifaceName string) []defaultRoute {
	cmd := exec.Command("/system/bin/ip", "route", "show", "table", "0")
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil
	}
	if err := cmd.Start(); err != nil {
		return nil
	}
	defer func() {
		cmd.Process.Kill()
		cmd.Wait()
	}()

	var routes []defaultRoute
	sc := bufio.NewScanner(out)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		// Expect "default via <ip> dev <iface> ..."
		if len(fields) < 5 || fields[0] != "default" || fields[1] != "via" || fields[3] != "dev" {
			continue
		}
		if ifaceName != "" && fields[4] != ifaceName {
			continue
		}
		ip, err := netip.ParseAddr(fields[2])
		if err != nil || !ip.Is4() {
			continue
		}
		routes = append(routes, defaultRoute{ifaceName: fields[4], gateway: ip})
	}
	return routes
}
