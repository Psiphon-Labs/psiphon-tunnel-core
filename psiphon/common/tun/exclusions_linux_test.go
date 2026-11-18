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

func TestExclusionsGetHostIPv4Subnets(t *testing.T) {

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

	// The tun device's own routes include its address prefix, its
	// address, and its broadcast address. None may be reported.
	tunIface, err := net.InterfaceByName(tunDeviceName)
	if err != nil {
		t.Fatalf("InterfaceByName: %v", err)
	}
	tunAddrs, err := tunIface.Addrs()
	if err != nil {
		t.Fatalf("Addrs: %v", err)
	}
	tunSubnets := make(map[string]bool)
	for _, addr := range tunAddrs {
		IPNet, ok := addr.(*net.IPNet)
		if !ok || IPNet.IP.To4() == nil {
			continue
		}
		IP := IPNet.IP.To4()
		broadcast := make(net.IP, 4)
		for i := range IP {
			broadcast[i] = IP[i] | ^IPNet.Mask[i]
		}
		tunSubnets[IPNet.String()] = true
		tunSubnets[(&net.IPNet{IP: IP.Mask(IPNet.Mask), Mask: IPNet.Mask}).String()] = true
		tunSubnets[hostSubnet(IP).String()] = true
		tunSubnets[hostSubnet(broadcast).String()] = true
	}
	if len(tunSubnets) == 0 {
		t.Fatalf("%s has no IPv4 address", tunDeviceName)
	}
	for _, subnet := range subnets {
		if tunSubnets[subnet.String()] {
			t.Errorf("tun device subnet %s reported", subnet)
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

	// Every IPv4 interface address prefix must be reported. Point-to-point
	// interfaces are skipped, since the standard library and netlink
	// report their addresses differently.
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatalf("Interfaces: %v", err)
	}
	for _, iface := range ifaces {
		if iface.Name == tunDeviceName || iface.Flags&net.FlagPointToPoint != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			t.Fatalf("Addrs: %v", err)
		}
		for _, addr := range addrs {
			IPNet, ok := addr.(*net.IPNet)
			if !ok || IPNet.IP.To4() == nil {
				continue
			}
			if !contains(IPNet) {
				t.Errorf("interface address %s not reported", IPNet)
			}
		}
	}

	t.Logf("host subnets: %v", subnets)
	t.Logf("excluded: %s", newExcludedIndexes(subnets))
}

func hostSubnet(IP net.IP) *net.IPNet {
	return &net.IPNet{IP: IP, Mask: net.CIDRMask(32, 32)}
}
