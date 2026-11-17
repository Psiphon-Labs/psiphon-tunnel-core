//go:build windows

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
	"testing"

	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

func forwardRow(t *testing.T, ifIndex uint32, prefix, nextHop string, metric uint32) winipcfg.MibIPforwardRow2 {
	t.Helper()
	var row winipcfg.MibIPforwardRow2
	row.InterfaceIndex = ifIndex
	row.Metric = metric
	if err := row.DestinationPrefix.SetPrefix(netip.MustParsePrefix(prefix)); err != nil {
		t.Fatal(err)
	}
	if err := row.NextHop.SetAddr(netip.MustParseAddr(nextHop)); err != nil {
		t.Fatal(err)
	}
	return row
}

func TestRankedDefaultRoutes(t *testing.T) {
	rows := []winipcfg.MibIPforwardRow2{
		// A carrier-grade NAT uplink: not a private gateway, never a candidate.
		forwardRow(t, 6, "0.0.0.0/0", "100.64.0.1", 0),
		// A home router with a worse route metric but a better interface
		// metric than the second router.
		forwardRow(t, 4, "0.0.0.0/0", "192.168.8.1", 10),
		// A second router on another interface.
		forwardRow(t, 7, "0.0.0.0/0", "10.0.0.1", 0),
		// A second, worse router on the home router's interface: a distinct
		// candidate, since it may be the one that offers port mapping.
		forwardRow(t, 4, "0.0.0.0/0", "192.168.8.254", 50),
		// A duplicate entry for the home router, which must not repeat it.
		forwardRow(t, 4, "0.0.0.0/0", "192.168.8.1", 60),
		// Not default routes.
		forwardRow(t, 4, "192.168.8.0/24", "0.0.0.0", 0),
		forwardRow(t, 7, "10.0.0.0/8", "10.0.0.1", 0),
	}
	route := func(ifIndex uint32, gw string) indexedRoute {
		return indexedRoute{ifIndex: ifIndex, gateway: netip.MustParseAddr(gw)}
	}

	// Totals: if4/.1 = 10+5 = 15, if7 = 0+25 = 25, if4/.254 = 50+5 = 55.
	got := rankedDefaultRoutes(rows, map[uint32]uint32{4: 5, 6: 25, 7: 25})
	want := []indexedRoute{route(4, "192.168.8.1"), route(7, "10.0.0.1"), route(4, "192.168.8.254")}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}

	// Equal cost keeps forwarding-table order.
	got = rankedDefaultRoutes(rows, map[uint32]uint32{4: 15, 6: 25, 7: 25})
	want = []indexedRoute{route(4, "192.168.8.1"), route(7, "10.0.0.1"), route(4, "192.168.8.254")}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("equal cost: got %v, want %v", got, want)
	}
	rows[1], rows[2] = rows[2], rows[1]
	got = rankedDefaultRoutes(rows, map[uint32]uint32{4: 15, 6: 25, 7: 25})
	want = []indexedRoute{route(7, "10.0.0.1"), route(4, "192.168.8.1"), route(4, "192.168.8.254")}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("equal cost, reordered: got %v, want %v", got, want)
	}

	if got := rankedDefaultRoutes(rows[5:], nil); len(got) != 0 {
		t.Fatalf("no default routes: got %v", got)
	}
}
