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
//	https://github.com/tailscale/tailscale/blob/v1.98.5/net/portmapper/pcp.go
//
// The original Tailscale code is licensed as follows:
//
//	Copyright (c) Tailscale Inc & contributors
//	SPDX-License-Identifier: BSD-3-Clause

package portmapper

import (
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"
	"time"
)

// References:
//
// https://www.rfc-editor.org/rfc/pdfrfc/rfc6887.txt.pdf
// https://tools.ietf.org/html/rfc6887

// pcpresultcode_string.go is generated from pcpResultCode with
// golang.org/x/tools/cmd/stringer (-type=pcpResultCode -trimprefix=pcpCode).
// It rarely needs regenerating; if the constants change, run stringer manually
// (e.g. with -mod=mod) and re-apply the Psiphon file header. The upstream
// code-generation directive was removed because it referenced Tailscale
// tooling that this fork no longer vendors and would overwrite the Psiphon
// header.

type pcpResultCode uint8

// PCP constants
const (
	pcpVersion     = 2
	pcpDefaultPort = 5351

	// Use the same lifetime as NAT-PMP given that we don't know how long
	// the IP assignment is valid for.
	pcpMapLifetimeSec = 7200

	pcpCodeOK                 pcpResultCode = 0
	pcpCodeUnsupportedVersion pcpResultCode = 1
	pcpCodeNotAuthorized      pcpResultCode = 2
	// From RFC 6887:
	// ADDRESS_MISMATCH: The source IP address of the request packet does
	// not match the contents of the PCP Client's IP Address field, due
	// to an unexpected NAT on the path between the PCP client and the
	// PCP-controlled NAT or firewall.
	pcpCodeAddressMismatch pcpResultCode = 12

	pcpOpReply    = 0x80 // OR'd into request's op code on response
	pcpOpAnnounce = 0
	pcpOpMap      = 1

	pcpUDPMapping = 17 // portmap UDP
	pcpTCPMapping = 6  // portmap TCP
)

// A pcpNonce is a cookie assigned by the router when issuing a mapping, that
// the client retains in order to release or update the mapping later.
type pcpNonce [12]byte

type pcpMapping struct {
	c        *Client
	gw       netip.AddrPort
	internal netip.AddrPort
	external netip.AddrPort
	protocol MapProtocol

	renewAfter time.Time
	goodUntil  time.Time

	epoch uint32
	nonce pcpNonce
}

func (p *pcpMapping) MappingType() string      { return "pcp" }
func (p *pcpMapping) GoodUntil() time.Time     { return p.goodUntil }
func (p *pcpMapping) RenewAfter() time.Time    { return p.renewAfter }
func (p *pcpMapping) External() netip.AddrPort { return p.external }
func (p *pcpMapping) MappingDebug() string {
	return fmt.Sprintf("pcpMapping{gw:%v, external:%v, internal:%v, protocol:%v, renewAfter:%d, goodUntil:%d, nonce:%x}",
		p.gw, p.external, p.internal, p.protocol,
		p.renewAfter.Unix(), p.goodUntil.Unix(), p.nonce)
}

func (p *pcpMapping) Release(ctx context.Context) {
	uc, err := p.c.listenPacket(ctx, "udp4", ":0")
	if err != nil {
		return
	}
	defer uc.Close()
	// Per RFC 6887 section 15.1 (with Errata ID 3621), a mapping-delete
	// request (lifetime 0) MUST set the Suggested External Port to zero and
	// the Suggested External Address to the all-zeros address of the family
	// being deleted: ::ffff:0.0.0.0 for IPv4, :: for IPv6.
	zeroExtAddr := netip.IPv4Unspecified()
	if p.external.Addr().Is6() {
		zeroExtAddr = netip.IPv6Unspecified()
	}
	pkt := buildPCPRequestMappingPacket(p.internal.Addr(), p.internal.Port(), 0, 0, zeroExtAddr, p.nonce, p.protocol)
	uc.WriteToUDPAddrPort(pkt, p.gw)
}

// pcpMapProtocol returns the PCP protocol number for the given MapProtocol.
func pcpMapProtocol(protocol MapProtocol) byte {
	if protocol == MapProtocolTCP {
		return pcpTCPMapping
	}
	return pcpUDPMapping
}

// buildPCPRequestMappingPacket generates a PCP packet with a MAP opcode.
// To create a packet which deletes a mapping, lifetimeSec, prevPort and prevExternalIP should be set to 0.
// If prevPort is not known, it should be set to 0.
// If prevExternalIP is not known, it should be set to 0.0.0.0.
// Renewing or deleting a mapping must reuse the nonce from the original response.
func buildPCPRequestMappingPacket(
	myIP netip.Addr,
	localPort, prevPort uint16,
	lifetimeSec uint32,
	prevExternalIP netip.Addr,
	nonce pcpNonce,
	protocol MapProtocol,
) (pkt []byte) {
	// 24 byte common PCP header + 36 bytes of MAP-specific fields
	pkt = make([]byte, 24+36)
	pkt[0] = pcpVersion
	pkt[1] = pcpOpMap
	binary.BigEndian.PutUint32(pkt[4:8], lifetimeSec)
	myIP16 := myIP.As16()
	copy(pkt[8:24], myIP16[:])

	mapOp := pkt[24:]
	copy(mapOp[:12], nonce[:])

	// PCP also supports mapping "all protocols" with a 0 protocol number, but
	// that mode does not allow specifying a local port, so we always map a
	// single protocol (UDP or TCP).
	mapOp[12] = pcpMapProtocol(protocol)
	binary.BigEndian.PutUint16(mapOp[16:18], localPort)
	binary.BigEndian.PutUint16(mapOp[18:20], prevPort)

	prevExternalIP16 := prevExternalIP.As16()
	copy(mapOp[20:], prevExternalIP16[:])
	return pkt
}

// parsePCPMapResponse parses resp into a partially populated pcpMapping.
// In particular, its Client is not populated.
//
// expectedProtocol is the protocol that was requested; the MAP response echoes
// the protocol in its opcode-specific data, and a response whose protocol does
// not match (e.g. a stale or mismatched response) is rejected so that a mapping
// is never recorded under the wrong protocol.
//
// now is the time the response was received, from which the mapping's
// lifetime runs.
func parsePCPMapResponse(resp []byte, expectedProtocol MapProtocol, now time.Time) (*pcpMapping, error) {
	if len(resp) < 60 {
		return nil, fmt.Errorf("Does not appear to be PCP MAP response")
	}
	res, ok := parsePCPResponse(resp[:24])
	if !ok {
		return nil, fmt.Errorf("Invalid PCP common header")
	}
	if res.ResultCode == pcpCodeNotAuthorized {
		return nil, fmt.Errorf("PCP is implemented but not enabled in the router")
	}
	if res.ResultCode != pcpCodeOK {
		return nil, fmt.Errorf("PCP response not ok, code %d", res.ResultCode)
	}

	// The MAP-specific data begins at offset 24; the protocol field is at
	// offset 12 within it, matching buildPCPRequestMappingPacket.
	var protocol MapProtocol
	switch resp[24+12] {
	case pcpTCPMapping:
		protocol = MapProtocolTCP
	case pcpUDPMapping:
		protocol = MapProtocolUDP
	default:
		return nil, fmt.Errorf("PCP MAP response has unexpected protocol %d", resp[24+12])
	}
	if protocol != expectedProtocol {
		return nil, fmt.Errorf(
			"PCP MAP response protocol %v does not match requested %v",
			protocol, expectedProtocol)
	}

	externalPort := binary.BigEndian.Uint16(resp[42:44])
	externalIPBytes := [16]byte{}
	copy(externalIPBytes[:], resp[44:])
	externalIP := netip.AddrFrom16(externalIPBytes).Unmap()

	external := netip.AddrPortFrom(externalIP, externalPort)

	lifetime := time.Second * time.Duration(res.Lifetime)
	mapping := &pcpMapping{
		external:   external,
		protocol:   protocol,
		renewAfter: now.Add(lifetime / 2),
		goodUntil:  now.Add(lifetime),
		epoch:      res.Epoch,
	}
	copy(mapping.nonce[:], resp[24:36])

	return mapping, nil
}

// pcpAnnounceRequest generates a PCP packet with an ANNOUNCE opcode.
func pcpAnnounceRequest(myIP netip.Addr) []byte {
	// See https://tools.ietf.org/html/rfc6887#section-7.1
	pkt := make([]byte, 24)
	pkt[0] = pcpVersion
	pkt[1] = pcpOpAnnounce
	myIP16 := myIP.As16()
	copy(pkt[8:], myIP16[:])
	return pkt
}

type pcpResponse struct {
	OpCode     uint8
	ResultCode pcpResultCode
	Lifetime   uint32
	Epoch      uint32
}

func parsePCPResponse(b []byte) (res pcpResponse, ok bool) {
	if len(b) < 24 || b[0] != pcpVersion {
		return
	}
	res.OpCode = b[1]
	res.ResultCode = pcpResultCode(b[3])
	res.Lifetime = binary.BigEndian.Uint32(b[4:])
	res.Epoch = binary.BigEndian.Uint32(b[8:])
	return res, true
}
