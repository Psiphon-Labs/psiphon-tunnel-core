//go:build linux && !android

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
	"os"
	"path/filepath"
	"testing"
)

func TestConnectionTypeFromDevType(t *testing.T) {
	for devType, expected := range map[string]string{
		"wlan":      "WIFI",
		"wwan":      "MOBILE",
		"wireguard": "VPN",
		"bridge":    "",
		"vlan":      "",
		"bond":      "",
		"":          "",
	} {
		if connectionTypeFromDevType(devType) != expected {
			t.Errorf("devtype %s: expected %s, got %s",
				devType, expected, connectionTypeFromDevType(devType))
		}
	}
}

func TestConnectionTypeFromARPType(t *testing.T) {
	for arpType, expected := range map[string]string{
		"1":     "WIRED",
		"512":   "VPN",
		"65534": "VPN",
		"772":   "UNKNOWN",
		"":      "UNKNOWN",
	} {
		if connectionTypeFromARPType(arpType) != expected {
			t.Errorf("arptype %s: expected %s, got %s",
				arpType, expected, connectionTypeFromARPType(arpType))
		}
	}
}

func TestGetConnectionType(t *testing.T) {

	root := t.TempDir()
	sysClassNet = root
	defer func() { sysClassNet = "/sys/class/net" }()

	for _, testCase := range []struct {
		name     string
		devType  string
		arpType  string
		wireless bool
		expected string
	}{
		{name: "eth0", arpType: "1", expected: "WIRED"},
		{name: "ens5", arpType: "1", expected: "WIRED"},
		{name: "wlan0", devType: "wlan", arpType: "1", expected: "WIFI"},
		{name: "wwan0", devType: "wwan", arpType: "1", expected: "MOBILE"},
		{name: "vpn0", devType: "wireguard", arpType: "65534", expected: "VPN"},
		{name: "tun0", expected: "VPN"},
		{name: "mytun", arpType: "65534", expected: "VPN"},
		{name: "ppp-isp", arpType: "512", expected: "VPN"},
		{name: "lo", arpType: "772", expected: "UNKNOWN"},
		{name: "unnumbered", expected: "UNKNOWN"},

		// A wireless driver setting no DEVTYPE must be identified before the ARP
		// type, which reports it as ethernet.
		{name: "wl-legacy", arpType: "1", wireless: true, expected: "WIFI"},

		// Virtual ethernet-like interfaces are deliberately treated as wired.
		{name: "br0", devType: "bridge", arpType: "1", expected: "WIRED"},
		{name: "eth0.7", devType: "vlan", arpType: "1", expected: "WIRED"},
	} {
		dir := filepath.Join(root, testCase.name)
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatalf("error: %v", err)
		}
		uevent := "INTERFACE=" + testCase.name + "\n"
		if testCase.devType != "" {
			uevent += "DEVTYPE=" + testCase.devType + "\n"
		}
		if err := os.WriteFile(filepath.Join(dir, "uevent"), []byte(uevent), 0600); err != nil {
			t.Fatalf("error: %v", err)
		}
		if testCase.arpType != "" {
			if err := os.WriteFile(filepath.Join(dir, "type"), []byte(testCase.arpType+"\n"), 0600); err != nil {
				t.Fatalf("error: %v", err)
			}
		}
		if testCase.wireless {
			if err := os.MkdirAll(filepath.Join(dir, "wireless"), 0700); err != nil {
				t.Fatalf("error: %v", err)
			}
		}

		connectionType := getConnectionType(&net.Interface{Name: testCase.name})
		if connectionType != testCase.expected {
			t.Errorf("%s: expected %s, got %s",
				testCase.name, testCase.expected, connectionType)
		}
	}
}
