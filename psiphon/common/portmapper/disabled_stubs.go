//go:build js

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

// This file is part of a hard fork of Tailscale's net/portmapper; see the
// package documentation in portmapper.go. Copied from tailscale v1.98.5:
//
//	https://github.com/tailscale/tailscale/blob/v1.98.5/net/portmapper/disabled_stubs.go
//
// The original Tailscale code is licensed as follows:
//
//	Copyright (c) Tailscale Inc & contributors
//	SPDX-License-Identifier: BSD-3-Clause

package portmapper

import (
	"context"
	"net/netip"
)

type upnpClient any

type uPnPDiscoResponse struct{}

func parseUPnPDiscoResponse([]byte) (uPnPDiscoResponse, error) {
	return uPnPDiscoResponse{}, nil
}

func processUPnPResponses(metas []uPnPDiscoResponse) []uPnPDiscoResponse {
	return metas
}

func (c *Client) getUPnPPortMapping(
	ctx context.Context,
	gw netip.Addr,
	internal netip.AddrPort,
	prevPort uint16,
) (external netip.AddrPort, ok bool) {
	return netip.AddrPort{}, false
}
