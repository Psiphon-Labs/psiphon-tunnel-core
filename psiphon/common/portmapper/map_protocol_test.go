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

package portmapper

import (
	"context"
	"encoding/binary"
	"encoding/xml"
	"net/http"
	"net/netip"
	"sync/atomic"
	"testing"
)

// TestMapProtocolHelpers verifies the per-protocol conversion helpers and the
// MapProtocol String method.
func TestMapProtocolHelpers(t *testing.T) {
	if got := MapProtocolUDP.String(); got != "UDP" {
		t.Errorf("MapProtocolUDP.String() = %q, want UDP", got)
	}
	if got := MapProtocolTCP.String(); got != "TCP" {
		t.Errorf("MapProtocolTCP.String() = %q, want TCP", got)
	}

	if got := pmpMapOp(MapProtocolUDP); got != pmpOpMapUDP {
		t.Errorf("pmpMapOp(UDP) = %d, want %d", got, pmpOpMapUDP)
	}
	if got := pmpMapOp(MapProtocolTCP); got != pmpOpMapTCP {
		t.Errorf("pmpMapOp(TCP) = %d, want %d", got, pmpOpMapTCP)
	}

	if got := pcpMapProtocol(MapProtocolUDP); got != pcpUDPMapping {
		t.Errorf("pcpMapProtocol(UDP) = %d, want %d", got, pcpUDPMapping)
	}
	if got := pcpMapProtocol(MapProtocolTCP); got != pcpTCPMapping {
		t.Errorf("pcpMapProtocol(TCP) = %d, want %d", got, pcpTCPMapping)
	}

	if got := upnpProtocol(MapProtocolUDP); got != "UDP" {
		t.Errorf("upnpProtocol(UDP) = %q, want UDP", got)
	}
	if got := upnpProtocol(MapProtocolTCP); got != "TCP" {
		t.Errorf("upnpProtocol(TCP) = %q, want TCP", got)
	}
}

// TestBuildPMPRequestMappingPacketProtocol verifies the NAT-PMP map request
// opcode byte reflects the requested protocol.
func TestBuildPMPRequestMappingPacketProtocol(t *testing.T) {
	udp := buildPMPRequestMappingPacket(1234, 4321, 7200, MapProtocolUDP)
	if udp[1] != pmpOpMapUDP {
		t.Errorf("UDP packet opcode = %d, want %d", udp[1], pmpOpMapUDP)
	}
	tcp := buildPMPRequestMappingPacket(1234, 4321, 7200, MapProtocolTCP)
	if tcp[1] != pmpOpMapTCP {
		t.Errorf("TCP packet opcode = %d, want %d", tcp[1], pmpOpMapTCP)
	}
	// The remaining fields must be identical regardless of protocol.
	if binary.BigEndian.Uint16(tcp[4:]) != 1234 {
		t.Errorf("local port = %d, want 1234", binary.BigEndian.Uint16(tcp[4:]))
	}
	if binary.BigEndian.Uint16(tcp[6:]) != 4321 {
		t.Errorf("prev port = %d, want 4321", binary.BigEndian.Uint16(tcp[6:]))
	}
}

// TestParsePMPResponseTCP verifies that a NAT-PMP TCP map reply is parsed the
// same way as a UDP map reply (same wire structure, different opcode).
func TestParsePMPResponseTCP(t *testing.T) {
	pkt := make([]byte, 16)
	pkt[0] = pmpVersion
	pkt[1] = pmpOpReply | pmpOpMapTCP
	// result code 0 at pkt[2:4]
	binary.BigEndian.PutUint32(pkt[4:8], 12345)  // seconds since epoch
	binary.BigEndian.PutUint16(pkt[8:10], 1234)  // internal port
	binary.BigEndian.PutUint16(pkt[10:12], 4321) // external port
	binary.BigEndian.PutUint32(pkt[12:16], 7200) // mapping valid seconds

	res, ok := parsePMPResponse(pkt)
	if !ok {
		t.Fatal("parsePMPResponse failed for a TCP map reply")
	}
	if res.OpCode != pmpOpReply|pmpOpMapTCP {
		t.Errorf("OpCode = 0x%x, want 0x%x", res.OpCode, pmpOpReply|pmpOpMapTCP)
	}
	if res.InternalPort != 1234 {
		t.Errorf("InternalPort = %d, want 1234", res.InternalPort)
	}
	if res.ExternalPort != 4321 {
		t.Errorf("ExternalPort = %d, want 4321", res.ExternalPort)
	}
	if res.MappingValidSeconds != 7200 {
		t.Errorf("MappingValidSeconds = %d, want 7200", res.MappingValidSeconds)
	}
}

// TestBuildPCPRequestMappingPacketProtocol verifies the PCP MAP request
// protocol number reflects the requested protocol.
func TestBuildPCPRequestMappingPacketProtocol(t *testing.T) {
	myIP := netip.MustParseAddr("192.168.1.2")

	udp := buildPCPRequestMappingPacket(myIP, 1234, 0, 7200, wildcardIP, MapProtocolUDP)
	if got := udp[24:][12]; got != pcpUDPMapping {
		t.Errorf("UDP PCP protocol = %d, want %d", got, pcpUDPMapping)
	}
	tcp := buildPCPRequestMappingPacket(myIP, 1234, 0, 7200, wildcardIP, MapProtocolTCP)
	if got := tcp[24:][12]; got != pcpTCPMapping {
		t.Errorf("TCP PCP protocol = %d, want %d", got, pcpTCPMapping)
	}
	// The local port field must be unaffected by the protocol.
	if got := binary.BigEndian.Uint16(tcp[24:][16:18]); got != 1234 {
		t.Errorf("local port = %d, want 1234", got)
	}
}

// TestParsePCPMapResponseProtocol verifies that parsePCPMapResponse reads the
// protocol from the MAP response and rejects responses whose protocol does not
// match the requested protocol (or is unknown).
func TestParsePCPMapResponseProtocol(t *testing.T) {
	build := func(protocol byte) []byte {
		resp := make([]byte, 60)
		resp[0] = pcpVersion
		resp[1] = pcpOpMap | serverResponseBit
		resp[3] = byte(pcpCodeOK)
		binary.BigEndian.PutUint32(resp[4:8], 7200) // lifetime
		resp[24+12] = protocol                      // MAP protocol field
		binary.BigEndian.PutUint16(resp[42:44], 4242)
		return resp
	}

	// TCP response, TCP requested: accepted, recorded as TCP.
	m, err := parsePCPMapResponse(build(pcpTCPMapping), MapProtocolTCP)
	if err != nil {
		t.Fatalf("TCP response/expect TCP: unexpected error: %v", err)
	}
	if m.protocol != MapProtocolTCP {
		t.Errorf("protocol = %v, want TCP", m.protocol)
	}

	// UDP response, UDP requested: accepted, recorded as UDP.
	m, err = parsePCPMapResponse(build(pcpUDPMapping), MapProtocolUDP)
	if err != nil {
		t.Fatalf("UDP response/expect UDP: unexpected error: %v", err)
	}
	if m.protocol != MapProtocolUDP {
		t.Errorf("protocol = %v, want UDP", m.protocol)
	}

	// UDP response when TCP was requested: rejected.
	if _, err := parsePCPMapResponse(build(pcpUDPMapping), MapProtocolTCP); err == nil {
		t.Error("expected error for UDP MAP response when TCP was requested, got nil")
	}

	// Unknown protocol number: rejected.
	if _, err := parsePCPMapResponse(build(99), MapProtocolTCP); err == nil {
		t.Error("expected error for unknown response protocol, got nil")
	}
}

// TestGetUPnPPortMappingTCP exercises a full UPnP mapping with the TCP protocol
// selected, asserting the gateway receives Protocol="TCP" and that the stored
// mapping records TCP (so renewal/release use TCP).
func TestGetUPnPPortMappingTCP(t *testing.T) {
	igd, err := NewTestIGD(t, TestIGDOptions{UPnP: true})
	if err != nil {
		t.Fatal(err)
	}
	defer igd.Close()

	var sawRequestWithLease atomic.Bool
	handlers := map[string]any{
		"AddPortMapping": func(body []byte) (int, string) {
			var req struct {
				Protocol      string `xml:"NewProtocol"`
				LeaseDuration string `xml:"NewLeaseDuration"`
			}
			if err := xml.Unmarshal(body, &req); err != nil {
				t.Errorf("bad request: %v", err)
				return http.StatusBadRequest, "bad request"
			}
			if req.Protocol != "TCP" {
				t.Errorf(`got Protocol=%q, want "TCP"`, req.Protocol)
			}
			if req.LeaseDuration != "0" {
				// Force the permanent-lease fallback path, mirroring the
				// existing UDP test.
				sawRequestWithLease.Store(true)
				return http.StatusOK, testAddPortMappingPermanentLease
			}
			return http.StatusOK, testAddPortMappingResponse
		},
		"GetExternalIPAddress": testGetExternalIPAddressResponse,
		"GetStatusInfo":        testGetStatusInfoResponse,
		"DeletePortMapping":    "", // Do nothing for test
	}

	igd.SetUPnPHandler(&upnpServer{
		t:    t,
		Desc: testRootDesc,
		Control: map[string]map[string]any{
			"/ctl/IPConn":                          handlers,
			"/upnp/control/yomkmsnooi/wanipconn-1": handlers,
		},
	})

	ctx := context.Background()
	c := newTestClient(t, igd)
	c.debug.VerboseLogs = true
	c.SetProtocol(MapProtocolTCP)

	mustProbeUPnP(t, ctx, c)

	gw, myIP, ok := c.gatewayAndSelfIP()
	if !ok {
		t.Fatalf("could not get gateway and self IP")
	}

	ext, ok := c.getUPnPPortMapping(ctx, gw, netip.AddrPortFrom(myIP, 12345), 0)
	if !ok {
		t.Fatal("could not get UPnP port mapping")
	}
	if got, want := ext.Addr(), netip.MustParseAddr("123.123.123.123"); got != want {
		t.Errorf("bad external address; got %v want %v", got, want)
	}
	if !sawRequestWithLease.Load() {
		t.Errorf("wanted request with lease, but didn't see one")
	}

	if c.mapping == nil {
		t.Fatal("expected a stored mapping after getUPnPPortMapping")
	}
	um, ok := c.mapping.(*upnpMapping)
	if !ok {
		t.Fatalf("expected *upnpMapping, got %T", c.mapping)
	}
	if um.protocol != MapProtocolTCP {
		t.Errorf("stored mapping protocol = %v, want TCP", um.protocol)
	}
}
