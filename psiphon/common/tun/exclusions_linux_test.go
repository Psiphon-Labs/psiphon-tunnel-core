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

package tun

import (
	"net"
	"os"
	"testing"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/internal/testutils"
)

func TestGetHostIPv4Subnets(t *testing.T) {

	if _, err := getHostIPv4Subnets("tun-does-not-exist"); err == nil {
		t.Errorf("getHostIPv4Subnets: no error for a missing device")
	}
	config := &ServerConfig{Logger: testutils.NewTestLogger()}
	if _, err := makeExcludedIndexes(config, "tun-does-not-exist"); err == nil {
		t.Errorf("makeExcludedIndexes: no error for a missing device")
	}

	// With discovery off, the device isn't looked up.
	config.DisableHostSubnetDiscovery = true
	if _, err := makeExcludedIndexes(config, "tun-does-not-exist"); err != nil {
		t.Errorf("makeExcludedIndexes: discovery off: %v", err)
	}

	// TEST_TUN_DEVICE optionally names an existing device whose routes and
	// addresses must not be reported. By default, the loopback device stands
	// in for the tun device.
	tunDeviceName := os.Getenv("TEST_TUN_DEVICE")
	if tunDeviceName == "" {
		tunDeviceName = "lo"
	}

	subnets, err := getHostIPv4Subnets(tunDeviceName)
	if err != nil {
		t.Fatalf("getHostIPv4Subnets: %v", err)
	}

	tunAddrs := make(map[string]bool)
	if iface, err := net.InterfaceByName(tunDeviceName); err == nil {
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			tunAddrs[addr.String()] = true
		}
	}
	for _, subnet := range subnets {
		if tunAddrs[subnet.String()] {
			t.Errorf("tun device address %s reported", subnet)
		}
	}

	contains := func(want *net.IPNet) bool {
		for _, subnet := range subnets {
			if subnet.String() == want.String() {
				return true
			}
		}
		return false
	}

	// Every IPv4 interface address prefix must be reported.
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatalf("InterfaceAddrs: %v", err)
	}
	for _, addr := range addrs {
		IPNet, ok := addr.(*net.IPNet)
		if !ok || IPNet.IP.To4() == nil || tunAddrs[IPNet.String()] {
			continue
		}
		if !contains(IPNet) {
			t.Errorf("interface address %s not reported", IPNet)
		}
	}

	t.Logf("host subnets: %v", subnets)
	t.Logf("excluded: %s", newExcludedIndexes(subnets))
}
