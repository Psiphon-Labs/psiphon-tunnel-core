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
}
