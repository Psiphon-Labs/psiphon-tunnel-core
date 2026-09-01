//go:build (darwin && !ios && cgo) || (linux && !android)

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

package networkid

import (
	"net"
	"strings"
	"testing"
)

// Get("") requires a default route, which an isolated environment may not have.
func skipWithoutDefaultRoute(t *testing.T) {
	t.Helper()
	if _, err := getDefaultLocalAddr(); err != nil {
		t.Skipf("no default route: %v", err)
	}
}

func TestGet(t *testing.T) {

	skipWithoutDefaultRoute(t)

	networkID, err := Get("")
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	prefix, suffix, found := strings.Cut(networkID, "-")
	if !found {
		t.Fatalf("no suffix in network ID")
	}

	assertConnectionType(t, prefix)

	if net.ParseIP(suffix) == nil {
		t.Errorf("suffix is not an IP address")
	}
}

func assertConnectionType(t *testing.T, connectionType string) {
	t.Helper()
	switch connectionType {
	case "WIFI", "MOBILE", "WIRED", "VPN", "UNKNOWN":
	default:
		t.Errorf("unexpected network type %q", connectionType)
	}
}

// An interface with no address yields the connection type alone.
func TestGetTypeOnly(t *testing.T) {

	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	for _, iface := range ifaces {
		if _, err := getInterfaceIP(&iface); err == nil {
			continue
		}
		networkID, err := Get(iface.Name)
		if err != nil {
			t.Fatalf("%s: error: %v", iface.Name, err)
		}
		if strings.Contains(networkID, "-") {
			t.Errorf("%s: expected type only, got %q", iface.Name, networkID)
		}
		assertConnectionType(t, networkID)
		return
	}

	t.Skip("no interface without an address")
}

func TestGetInterfaceNotFound(t *testing.T) {
	if _, err := Get("no-such-interface"); err == nil {
		t.Error("unexpected success")
	}
}

func TestIsVPNInterfaceName(t *testing.T) {
	for name, expected := range map[string]bool{
		"utun4":  true,
		"tun0":   true,
		"ipsec0": true,
		"ppp0":   true,
		"wg0":    true,
		"en0":    false,
		"eth0":   false,
		"wlan0":  false,
		"lo0":    false,
	} {
		if isVPNInterfaceName(name) != expected {
			t.Errorf("%s: expected %t", name, expected)
		}
	}
}
