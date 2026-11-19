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

package gateway

import (
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

// A /proc/net/route with default routes on two interfaces (wlan0 preferred),
// a second router on eth0, a down default route, a non-default route and a
// carrier-grade NAT gateway.
const testProcNetRoute = `Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
wlan0	00000000	0101A8C0	0003	0	0	600	00000000	0	0	0
eth0	00000000	0108A8C0	0003	0	0	100	00000000	0	0	0
eth0	00000000	FE08A8C0	0003	0	0	200	00000000	0	0	0
eth1	00000000	0102A8C0	0002	0	0	0	00000000	0	0	0
eth0	0008A8C0	00000000	0001	0	0	100	00FFFFFF	0	0	0
ppp0	00000000	0100400C	0003	0	0	700	00000000	0	0	0
`

func TestParseProcNetRoutes(t *testing.T) {
	gw := netip.MustParseAddr
	got := parseProcNetRoutes(strings.NewReader(testProcNetRoute), "")
	want := []defaultRoute{
		{"wlan0", gw("192.168.1.1")},
		{"eth0", gw("192.168.8.1")},
		{"eth0", gw("192.168.8.254")},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	got = parseProcNetRoutes(strings.NewReader(testProcNetRoute), "eth0")
	if !reflect.DeepEqual(got, want[1:]) {
		t.Fatalf("eth0: got %+v, want %+v", got, want[1:])
	}
	if got := parseProcNetRoutes(strings.NewReader(testProcNetRoute), "eth1"); len(got) != 0 {
		t.Fatalf("eth1 (down): got %+v", got)
	}
}
