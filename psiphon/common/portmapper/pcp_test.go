//go:build !js

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
//	https://github.com/tailscale/tailscale/blob/v1.98.5/net/portmapper/pcp_test.go
//
// The original Tailscale code is licensed as follows:
//
//	Copyright (c) Tailscale Inc & contributors
//	SPDX-License-Identifier: BSD-3-Clause

package portmapper

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

var examplePCPMapResponse = []byte{2, 129, 0, 0, 0, 0, 28, 32, 0, 2, 155, 237, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 129, 112, 9, 24, 241, 208, 251, 45, 157, 76, 10, 188, 17, 0, 0, 0, 4, 210, 4, 210, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 135, 180, 175, 246}

func TestParsePCPMapResponse(t *testing.T) {
	mapping, err := parsePCPMapResponse(examplePCPMapResponse)
	if err != nil {
		t.Fatalf("failed to parse PCP Map Response: %v", err)
	}
	if mapping == nil {
		t.Fatalf("got nil mapping when expected non-nil")
	}
	expectedAddr := netip.MustParseAddrPort("135.180.175.246:1234")
	if mapping.external != expectedAddr {
		t.Errorf("mismatched external address, got: %v, want: %v", mapping.external, expectedAddr)
	}
}

const (
	serverResponseBit = 1 << 7
	fakeLifetimeSec   = 1<<31 - 1
)

func buildPCPDiscoResponse(req []byte) []byte {
	out := make([]byte, 24)
	out[0] = pcpVersion
	out[1] = req[1] | serverResponseBit
	out[3] = 0
	// Do not put an epoch time in 8:12, when we start using it, tests that use it should fail.
	return out
}

func buildPCPMapResponse(req []byte) []byte {
	out := make([]byte, 24+36)
	out[0] = pcpVersion
	out[1] = req[1] | serverResponseBit
	out[3] = 0
	binary.BigEndian.PutUint32(out[4:8], 1<<30)
	// Do not put an epoch time in 8:12, when we start using it, tests that use it should fail.
	mapResp := out[24:]
	mapReq := req[24:]
	// copy nonce, protocol and internal port
	copy(mapResp[:13], mapReq[:13])
	copy(mapResp[16:18], mapReq[16:18])
	// assign external port
	binary.BigEndian.PutUint16(mapResp[18:20], 4242)
	assignedIP := netaddrIPv4(127, 0, 0, 1)
	assignedIP16 := assignedIP.As16()
	copy(mapResp[20:36], assignedIP16[:])
	return out
}
