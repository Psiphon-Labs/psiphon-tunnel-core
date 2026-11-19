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
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"
)

var examplePCPMapResponse = []byte{2, 129, 0, 0, 0, 0, 28, 32, 0, 2, 155, 237, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 129, 112, 9, 24, 241, 208, 251, 45, 157, 76, 10, 188, 17, 0, 0, 0, 4, 210, 4, 210, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 135, 180, 175, 246}

func TestParsePCPMapResponse(t *testing.T) {
	// The example response carries the UDP protocol (17).
	mapping, err := parsePCPMapResponse(examplePCPMapResponse, MapProtocolUDP, time.Now())
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
	if mapping.protocol != MapProtocolUDP {
		t.Errorf("mismatched protocol, got: %v, want: UDP", mapping.protocol)
	}
	if got, want := mapping.nonce[:], examplePCPMapResponse[24:36]; !bytes.Equal(got, want) {
		t.Errorf("mismatched nonce, got: %x, want: %x", got, want)
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

// TestPCPRenewAndReleaseReuseNonce checks that a renewal and a release carry
// the nonce of the request that created the mapping, and that the release
// zeroes the suggested external port and address (RFC 6887 section 15.1).
func TestPCPRenewAndReleaseReuseNonce(t *testing.T) {
	gateway, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer gateway.Close()

	mapRequests := make(chan []byte, 8)
	go func() {
		buf := make([]byte, 1500)
		for {
			n, src, err := gateway.ReadFrom(buf)
			if err != nil {
				return
			}
			pkt := append([]byte(nil), buf[:n]...)
			if len(pkt) < 24 || pkt[0] != pcpVersion {
				continue
			}
			switch pkt[1] {
			case pcpOpAnnounce:
				gateway.WriteTo(buildPCPDiscoResponse(pkt), src)
			case pcpOpMap:
				if len(pkt) < 60 {
					continue
				}
				mapRequests <- pkt
				if binary.BigEndian.Uint32(pkt[4:8]) != 0 {
					gateway.WriteTo(buildPCPMapResponse(pkt), src)
				}
			}
		}
	}()
	nextMapRequest := func() []byte {
		t.Helper()
		select {
		case pkt := <-mapRequests:
			return pkt
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for a PCP MAP request")
			return nil
		}
	}

	igd, err := NewTestIGD(t, TestIGDOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer igd.Close()
	c := newTestClient(t, igd)
	c.testPxPPort = uint16(gateway.LocalAddr().(*net.UDPAddr).Port)
	c.SetLocalPort(12345)

	ctx := context.Background()
	res, err := c.Probe(ctx)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if !res.PCP {
		t.Fatalf("didn't detect PCP: %+v", res)
	}

	if _, _, err := c.createOrGetMapping(ctx); err != nil {
		t.Fatalf("createOrGetMapping: %v", err)
	}
	create := nextMapRequest()
	nonce := create[24:36]
	if bytes.Equal(nonce, make([]byte, 12)) {
		t.Error("create request has an all-zero nonce")
	}

	c.mu.Lock()
	m, ok := c.mapping.(*pcpMapping)
	if ok {
		m.renewAfter = time.Now().Add(-time.Second)
	}
	c.mu.Unlock()
	if !ok {
		t.Fatal("mapping is not a PCP mapping")
	}
	if _, _, err := c.createOrGetMapping(ctx); err != nil {
		t.Fatalf("createOrGetMapping (renew): %v", err)
	}
	if renew := nextMapRequest(); !bytes.Equal(renew[24:36], nonce) {
		t.Errorf("renew nonce = %x, want %x", renew[24:36], nonce)
	}

	c.Close()
	release := nextMapRequest()
	if got := binary.BigEndian.Uint32(release[4:8]); got != 0 {
		t.Errorf("release lifetime = %d, want 0", got)
	}
	if !bytes.Equal(release[24:36], nonce) {
		t.Errorf("release nonce = %x, want %x", release[24:36], nonce)
	}
	if got := binary.BigEndian.Uint16(release[24+18 : 24+20]); got != 0 {
		t.Errorf("release suggested external port = %d, want 0", got)
	}
	zeroExtAddr := netip.IPv4Unspecified().As16()
	if !bytes.Equal(release[24+20:24+36], zeroExtAddr[:]) {
		t.Errorf("release suggested external address = %x, want %x", release[24+20:24+36], zeroExtAddr)
	}
}
