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

package gateway

import (
	"net"
	"net/netip"
	"reflect"
	"testing"
)

// TestHomeRouterIPDefault is a smoke test for default-route gateway discovery.
// It does not assert that a gateway is found, since the test environment may
// have no private gateway (e.g. CI), but when one is found it validates the
// returned values are internally consistent.
func TestHomeRouterIPDefault(t *testing.T) {
	gw, myIP, ok := HomeRouterIP("")
	t.Logf("HomeRouterIP(\"\") = gw=%v myIP=%v ok=%v", gw, myIP, ok)
	if !ok {
		t.Skip("no default gateway discovered in this environment")
	}
	if !gw.IsValid() || !gw.Is4() {
		t.Errorf("gateway not a valid IPv4 address: %v", gw)
	}
	if !gw.IsPrivate() {
		t.Errorf("gateway not private: %v", gw)
	}
	if !myIP.IsValid() || !myIP.Is4() {
		t.Errorf("myIP not a valid IPv4 address: %v", myIP)
	}
}

// TestHomeRouterIPUnknownInterface verifies that asking for a non-existent
// interface fails cleanly rather than panicking.
func TestHomeRouterIPUnknownInterface(t *testing.T) {
	gw, myIP, ok := HomeRouterIP("psiphon-no-such-iface0")
	if ok {
		t.Errorf("expected ok=false for unknown interface, got gw=%v myIP=%v", gw, myIP)
	}
	if candidates := Candidates("psiphon-no-such-iface0"); len(candidates) != 0 {
		t.Errorf("expected no candidates for unknown interface, got %+v", candidates)
	}
}

// TestCandidatesConsistent verifies that every candidate is a private
// gateway on an up interface that holds the candidate's LAN address, and
// that HomeRouterIP, wherever it finds a gateway, finds one of the
// candidates. The converse is not required: Candidates can see paths that
// HomeRouterIP's lookup cannot, such as the other next hops of a Linux
// multipath route (see TestNetlinkDefaultRoutesMatchesProc).
func TestCandidatesConsistent(t *testing.T) {
	candidates := Candidates("")
	t.Logf("Candidates(\"\") = %+v", candidates)
	seen := make(map[Candidate]bool)
	for _, c := range candidates {
		if seen[c] {
			t.Errorf("duplicate candidate: %+v", c)
		}
		seen[c] = true
		if !c.Gateway.Is4() || !c.Gateway.IsPrivate() {
			t.Errorf("candidate gateway is not a private IPv4 address: %+v", c)
		}
		addrs, ok := interfaceAddrs(c.InterfaceName)
		if !ok {
			t.Errorf("candidate interface %q is not up: %+v", c.InterfaceName, c)
			continue
		}
		holdsLocalIP := false
		for _, a := range addrs {
			if ipNet, ok := a.(*net.IPNet); ok && ipNet.IP.Equal(net.IP(c.LocalIP.AsSlice())) {
				holdsLocalIP = true
			}
		}
		if !holdsLocalIP {
			t.Errorf("interface %q does not hold candidate address %v", c.InterfaceName, c.LocalIP)
		}
	}
	// HomeRouterIP("") may pick its address with a subnet search across
	// interfaces, so only its gateway is compared.
	if gw, _, ok := HomeRouterIP(""); ok {
		found := false
		for _, c := range candidates {
			found = found || c.Gateway == gw
		}
		if !found {
			t.Errorf("HomeRouterIP(\"\") gateway %v is not among candidates", gw)
		}
	}
	// Pinned to an interface, HomeRouterIP reads the address from that
	// interface, as Candidates does.
	for _, c := range candidates {
		gw, myIP, ok := HomeRouterIP(c.InterfaceName)
		if ok && !seen[Candidate{c.InterfaceName, gw, myIP}] {
			t.Errorf("HomeRouterIP(%q) = %v %v is not among candidates", c.InterfaceName, gw, myIP)
		}
	}
}

func ipNet(cidr string) net.Addr {
	ip, n, err := net.ParseCIDR(cidr)
	if err != nil {
		panic(err)
	}
	n.IP = ip
	return n
}

// TestCandidatesFromRoutes verifies that a candidate's interface is the one
// its routing entry names, and its LAN address is taken from that interface.
func TestCandidatesFromRoutes(t *testing.T) {
	addrs := map[string][]net.Addr{
		// Overlapping subnets: the Ethernet link is on the router's LAN but
		// holds no default route; only Wi-Fi does. A subnet search across
		// interfaces would name eth0.
		"eth0":  {ipNet("192.168.1.5/24")},
		"wlan0": {ipNet("fe80::1/64"), ipNet("192.168.1.7/24")},
		// A second router on wlan0's LAN, and a link whose gateway is off
		// its own subnet (a point-to-point style assignment).
		"ppp0": {ipNet("10.9.8.7/32")},
	}
	lookup := func(name string) ([]net.Addr, bool) {
		a, ok := addrs[name]
		return a, ok
	}
	gw := netip.MustParseAddr
	routes := []defaultRoute{
		{"wlan0", gw("192.168.1.1")},
		{"wlan0", gw("192.168.1.1")}, // duplicate entry
		{"wlan0", gw("192.168.1.254")},
		{"down0", gw("192.168.2.1")}, // not up: no addresses
		{"ppp0", gw("100.64.0.1")},   // carrier-grade NAT: not private
		{"ppp0", gw("10.0.0.1")},
	}
	got := candidatesFromRoutes(routes, lookup)
	want := []Candidate{
		{"wlan0", gw("192.168.1.1"), gw("192.168.1.7")},
		{"wlan0", gw("192.168.1.254"), gw("192.168.1.7")},
		{"ppp0", gw("10.0.0.1"), gw("10.9.8.7")},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}
