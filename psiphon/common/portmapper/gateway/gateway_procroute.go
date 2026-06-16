//go:build linux

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
//	https://github.com/tailscale/tailscale/blob/v1.98.5/net/netmon/interfaces_linux.go
//
// The original Tailscale code is licensed as follows:
//
//	Copyright (c) Tailscale Inc & contributors
//	SPDX-License-Identifier: BSD-3-Clause

package gateway

import (
	"bufio"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

const procNetRoutePath = "/proc/net/route"

// maxProcNetRouteRead is the max number of lines to read from /proc/net/route
// looking for a default route, matching the upstream limit. Past this we
// assume we're not on a home system and give up.
const maxProcNetRouteRead = 1000

// Linux route flags, from <linux/route.h>. Inlined to avoid a
// golang.org/x/sys/unix dependency for this trivial parse.
const (
	rtfUp      = 0x0001
	rtfGateway = 0x0002
)

// parseProcNetRoute reads /proc/net/route and returns the first private IPv4
// gateway of an up gateway route. If ifaceName is non-empty, only routes on
// that interface are considered.
//
// /proc/net/route columns are:
//
//	Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT
//
// with the Gateway in little-endian hex (e.g. 0100000A == 10.0.0.1).
func parseProcNetRoute(ifaceName string) (netip.Addr, bool) {
	f, err := os.Open(procNetRoutePath)
	if err != nil {
		return netip.Addr{}, false
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	lineNum := 0
	for sc.Scan() {
		lineNum++
		if lineNum == 1 {
			// Skip header line.
			continue
		}
		if lineNum > maxProcNetRouteRead {
			break
		}
		fields := strings.Fields(sc.Text())
		if len(fields) < 4 {
			continue
		}
		iface, gwHex, flagsHex := fields[0], fields[2], fields[3]
		if ifaceName != "" && iface != ifaceName {
			continue
		}
		flags, err := strconv.ParseUint(flagsHex, 16, 16)
		if err != nil {
			continue
		}
		if uint16(flags)&(rtfUp|rtfGateway) != (rtfUp | rtfGateway) {
			continue
		}
		ipu32, err := strconv.ParseUint(gwHex, 16, 32)
		if err != nil {
			continue
		}
		ip := netip.AddrFrom4([4]byte{
			byte(ipu32), byte(ipu32 >> 8), byte(ipu32 >> 16), byte(ipu32 >> 24)})
		if ip.IsPrivate() {
			return ip, true
		}
	}
	return netip.Addr{}, false
}
