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
	"regexp"
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

// defaultInterfaceAddress is the default route interface and the address
// selected from it, which is empty when none qualifies.
type defaultInterfaceAddress struct {
	interfaceName string
	address       string
}

// observeDefaultInterfaceAddress returns false if the default route interface
// or its addresses cannot be read.
func observeDefaultInterfaceAddress() (defaultInterfaceAddress, bool) {
	iface, err := getInterface("")
	if err != nil {
		return defaultInterfaceAddress{}, false
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return defaultInterfaceAddress{}, false
	}
	address, _ := selectInterfaceAddress(addrs)
	return defaultInterfaceAddress{iface.Name, address}, true
}

func TestGet(t *testing.T) {

	before, beforeOK := observeDefaultInterfaceAddress()
	networkID, err := Get("")
	after, afterOK := observeDefaultInterfaceAddress()
	if err != nil {
		skipWithoutDefaultRoute(t)
		t.Fatalf("error: %v", err)
	}

	// An interface with no qualifying address yields the connection type
	// alone.
	prefix, suffix, found := strings.Cut(networkID, "-")
	assertConnectionType(t, prefix)
	if found && net.ParseIP(suffix).To4() == nil && !ipv6PrefixPattern.MatchString(suffix) {
		t.Errorf("suffix is neither an IPv4 address nor an IPv6 /32 prefix: %q", networkID)
	}

	// The exact suffix is checked only when the default interface and its
	// address were the same before and after Get.
	if beforeOK && afterOK && before == after && suffix != before.address {
		t.Errorf("%s: expected address %q, got network ID %q", before.interfaceName, before.address, networkID)
	}
}

// A loopback interface's IPv4 address is stable, so it checks that Get
// appends a qualifying address to a named interface even without a default
// route, when TestGet is skipped.
func TestGetLoopback(t *testing.T) {

	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	for _, iface := range ifaces {
		if iface.Flags&(net.FlagUp|net.FlagLoopback) != net.FlagUp|net.FlagLoopback {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			t.Fatalf("%s: error: %v", iface.Name, err)
		}
		if address, ok := selectInterfaceAddress(addrs); !ok || net.ParseIP(address).To4() == nil {
			continue
		}

		networkID, err := Get(iface.Name)
		if err != nil {
			t.Fatalf("%s: error: %v", iface.Name, err)
		}
		prefix, suffix, found := strings.Cut(networkID, "-")
		if !found {
			t.Fatalf("%s: no suffix in network ID %q", iface.Name, networkID)
		}
		assertConnectionType(t, prefix)
		if net.ParseIP(suffix).To4() == nil {
			t.Errorf("%s: suffix is not an IPv4 address: %q", iface.Name, networkID)
		}
		return
	}

	t.Skip("no up loopback interface with a qualifying IPv4 address")
}

var ipv6PrefixPattern = regexp.MustCompile(`^(0|[1-9a-f][0-9a-f]{0,3}):(0|[1-9a-f][0-9a-f]{0,3})::/32$`)

func assertConnectionType(t *testing.T, connectionType string) {
	t.Helper()
	switch connectionType {
	case "WIFI", "MOBILE", "WIRED", "VPN", "UNKNOWN":
	default:
		t.Errorf("unexpected network type %q", connectionType)
	}
}

// An interface with no qualifying address yields the connection type alone.
func TestGetTypeOnly(t *testing.T) {

	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	for _, iface := range ifaces {
		if _, err := getInterfaceAddress(&iface); err == nil {
			continue
		}
		networkID, err := Get(iface.Name)
		if err != nil {
			// Tolerate only an interface removed since it was listed.
			if _, lookupErr := net.InterfaceByName(iface.Name); lookupErr != nil {
				continue
			}
			t.Fatalf("%s: error: %v", iface.Name, err)
		}
		if strings.Contains(networkID, "-") {
			// Tolerate only an interface that has since gained an address.
			if _, err := getInterfaceAddress(&iface); err == nil {
				continue
			}
			t.Errorf("%s: expected type only, got %q", iface.Name, networkID)
		}
		assertConnectionType(t, networkID)
		return
	}

	t.Skip("no interface without a qualifying address")
}

func TestSelectInterfaceAddress(t *testing.T) {

	for _, testCase := range []struct {
		name     string
		addrs    []string
		expected string
	}{
		// Format.
		{"format global", []string{"2001:0db8:85a3::1/64"}, "2001:db8::/32"},
		{"format unique local", []string{"fd12:3456:789a:1::5/64"}, "fd12:3456::/32"},
		{"format mobile", []string{"2607:fb90:1234::1/64"}, "2607:fb90::/32"},
		{"format zero group", []string{"2001:0000:1::1/64"}, "2001:0::/32"},

		// Unique local is preferred over global.
		{"unique local after global", []string{"2001:db8::1/64", "fd12:3456::1/64"}, "fd12:3456::/32"},
		{"unique local before global", []string{"fd12:3456::1/64", "2001:db8::1/64"}, "fd12:3456::/32"},

		// Lowest prefix within a class.
		{"global lowest last", []string{"2607:fb90::1/64", "2001:db8::1/64"}, "2001:db8::/32"},
		{"global lowest first", []string{"2001:db8::1/64", "2607:fb90::1/64"}, "2001:db8::/32"},
		{"unique local lowest last", []string{"fdff:1::1/64", "fc00:2::1/64"}, "fc00:2::/32"},
		{"unique local lowest first", []string{"fc00:2::1/64", "fdff:1::1/64"}, "fc00:2::/32"},
		{"same prefix", []string{"2001:db8:1::1/64", "2001:db8:2::1/64"}, "2001:db8::/32"},

		// Range boundaries.
		{"below global", []string{"1fff:ffff::1/64"}, ""},
		{"global lower bound", []string{"2000:0::1/64"}, "2000:0::/32"},
		{"global upper bound", []string{"3fff:ffff::1/64"}, "3fff:ffff::/32"},
		{"above global", []string{"4000::1/64"}, ""},
		{"below unique local", []string{"fbff:ffff::1/64"}, ""},
		{"unique local lower bound", []string{"fc00:0::1/64"}, "fc00:0::/32"},
		{"unique local upper bound", []string{"fdff:ffff::1/64"}, "fdff:ffff::/32"},
		{"above unique local", []string{"fe00::1/64"}, ""},

		// Ignored addresses.
		{"link-local", []string{"fe80::1/64"}, ""},
		{"loopback", []string{"::1/128"}, ""},
		{"multicast", []string{"ff02::1/128"}, ""},
		{"unspecified", []string{"::/128"}, ""},
		{"ignored then global", []string{"fe80::1/64", "::1/128", "ff02::1/128", "2001:db8::1/64"}, "2001:db8::/32"},

		// IPv4 is preferred and used in full, as the first that is not link-local.
		{"IPv4 after IPv6", []string{"fd12:3456::1/64", "192.168.1.10/24"}, "192.168.1.10"},
		{"IPv4 before IPv6", []string{"192.168.1.10/24", "fd12:3456::1/64"}, "192.168.1.10"},
		{"first IPv4", []string{"10.0.0.2/8", "192.168.1.10/24"}, "10.0.0.2"},
		{"IPv4 link-local skipped", []string{"169.254.1.1/16", "10.0.0.2/8"}, "10.0.0.2"},
		{"IPv4 link-local only", []string{"169.254.1.1/16", "2001:db8::1/64"}, "2001:db8::/32"},
		{"IPv4 loopback", []string{"127.0.0.1/8"}, "127.0.0.1"},

		// Nothing qualifies.
		{"no addresses", nil, ""},
		{"nothing qualifies", []string{"169.254.1.1/16", "fe80::1/64", "::1/128"}, ""},
	} {
		t.Run(testCase.name, func(t *testing.T) {

			var addrs []net.Addr
			for _, s := range testCase.addrs {
				ip, ipNet, err := net.ParseCIDR(s)
				if err != nil {
					t.Fatalf("ParseCIDR: %v", err)
				}
				ipNet.IP = ip
				addrs = append(addrs, ipNet)
			}

			address, ok := selectInterfaceAddress(addrs)
			if ok != (testCase.expected != "") || address != testCase.expected {
				t.Errorf("got %q, %t; expected %q", address, ok, testCase.expected)
			}
			if strings.Contains(address, "-") {
				t.Errorf("address contains \"-\": %q", address)
			}
		})
	}
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
