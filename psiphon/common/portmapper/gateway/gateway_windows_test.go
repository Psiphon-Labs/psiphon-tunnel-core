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

func TestDefaultRouteGateway(t *testing.T) {
	rows := []winipcfg.MibIPforwardRow2{
		// Two default routes with equal metrics on different interfaces:
		// a home router and a carrier-grade NAT uplink.
		forwardRow(t, 4, "0.0.0.0/0", "192.168.8.1", 0),
		forwardRow(t, 6, "0.0.0.0/0", "100.64.0.1", 0),
		// A second, worse default route on the home router's interface.
		forwardRow(t, 4, "0.0.0.0/0", "192.168.8.254", 10),
		// Not default routes.
		forwardRow(t, 4, "192.168.8.0/24", "0.0.0.0", 0),
		forwardRow(t, 7, "10.0.0.0/8", "10.0.0.1", 0),
	}

	tests := []struct {
		name    string
		ifIndex uint32
		want    string
	}{
		{"home router interface", 4, "192.168.8.1"},
		{"carrier-grade NAT interface", 6, ""},
		{"interface with no default route", 7, ""},
		{"unknown interface", 9, ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			gw, ok := defaultRouteGateway(rows, test.ifIndex)
			if test.want == "" {
				if ok {
					t.Fatalf("got gateway %v, want none", gw)
				}
				return
			}
			if !ok || gw.String() != test.want {
				t.Fatalf("got gateway %v (ok=%v), want %s", gw, ok, test.want)
			}
		})
	}
}

// TestInternetInterfaceIndex checks that the stack names an interface at all;
// which one depends on the machine.
func TestInternetInterfaceIndex(t *testing.T) {
	index, ok := internetInterfaceIndex()
	t.Logf("internetInterfaceIndex() = %d ok=%v", index, ok)
	if !ok {
		t.Skip("no Internet route in this environment")
	}
}
