//go:build (darwin && cgo) || (linux && !android)

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

func TestGet(t *testing.T) {

	networkID, err := Get()
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	prefix, suffix, found := strings.Cut(networkID, "-")
	if !found {
		t.Fatalf("no suffix in network ID")
	}

	switch prefix {
	case "WIFI", "MOBILE", "WIRED", "VPN", "UNKNOWN":
	default:
		t.Errorf("unexpected network type %q", prefix)
	}

	if net.ParseIP(suffix) == nil {
		t.Errorf("suffix is not an IP address")
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
