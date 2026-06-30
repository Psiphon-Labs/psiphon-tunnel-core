//go:build !linux && !darwin && !freebsd && !openbsd && !windows

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
// package documentation in gateway.go.
//
// On platforms without a supported routing-table reader (e.g. js/wasm, plan9),
// gateway discovery is unavailable and callers must supply their own
// portmapper.Config.GatewayLookupFunc.

package gateway

import "net/netip"

// gatewayForInterface always reports no gateway on unsupported platforms.
func gatewayForInterface(string) (netip.Addr, bool) {
	return netip.Addr{}, false
}
