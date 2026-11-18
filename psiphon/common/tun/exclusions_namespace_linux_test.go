//go:build !race

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
	"runtime"
	"testing"

	"github.com/tailscale/netlink"
	"golang.org/x/sys/unix"
)

// This test isn't built with the race detector, which enables pointer
// checks: the vendored netlink package converts each multipath next hop to
// a struct that needs 8-byte alignment, at an offset that may be only
// 4-byte aligned, and the check stops the test binary. The fields it reads
// are 4-byte aligned.

// TestExclusionsGetHostIPv4SubnetsNamespace sets up interfaces, addresses
// and routes in a new network namespace, and checks which subnets are
// reported. It must run as root.
func TestExclusionsGetHostIPv4SubnetsNamespace(t *testing.T) {

	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}

	// The network namespace applies to the current OS thread only. The
	// thread is left locked, so that it exits with the test goroutine
	// rather than running other goroutines in the test namespace.
	runtime.LockOSThread()
	err := unix.Unshare(unix.CLONE_NEWNET)
	if err != nil {
		t.Fatalf("Unshare: %v", err)
	}

	addLink := func(name string) netlink.Link {
		err := netlink.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name}})
		if err != nil {
			t.Fatalf("LinkAdd %s: %v", name, err)
		}
		link, err := netlink.LinkByName(name)
		if err != nil {
			t.Fatalf("LinkByName %s: %v", name, err)
		}
		err = netlink.LinkSetUp(link)
		if err != nil {
			t.Fatalf("LinkSetUp %s: %v", name, err)
		}
		return link
	}
	subnet := func(cidr string) *net.IPNet {
		return mustParseSubnets(t, cidr)[0]
	}
	addAddr := func(link netlink.Link, addr *netlink.Addr) {
		err := netlink.AddrAdd(link, addr)
		if err != nil {
			t.Fatalf("AddrAdd %s: %v", addr, err)
		}
	}
	addRoute := func(route *netlink.Route) {
		err := netlink.RouteAdd(route)
		if err != nil {
			t.Fatalf("RouteAdd %s: %v", route, err)
		}
	}

	// tun0 stands in for the tun device, with the server's address, and
	// eth1 for another interface.
	tun := addLink("tun0")
	tunIndex := tun.Attrs().Index
	ethernet := addLink("eth1")
	ethernetIndex := ethernet.Attrs().Index

	addr, err := netlink.ParseAddr(serverIPv4AddressCIDR)
	if err != nil {
		t.Fatalf("ParseAddr: %v", err)
	}
	addAddr(tun, addr)
	addAddr(ethernet, &netlink.Addr{IPNet: &net.IPNet{
		IP: net.ParseIP("10.130.0.5").To4(), Mask: net.CIDRMask(16, 32)}})

	// A point-to-point address with no prefix route.
	addAddr(ethernet, &netlink.Addr{
		IPNet: hostSubnet(net.ParseIP("10.220.0.1").To4()),
		Peer:  subnet("10.230.0.0/24"),
		Flags: unix.IFA_F_NOPREFIXROUTE,
	})

	// A route through a gateway in another routing table.
	addRoute(&netlink.Route{
		Dst: subnet("10.140.0.0/16"), Gw: net.ParseIP("10.130.0.254"),
		LinkIndex: ethernetIndex, Table: 100})

	// A route with no interface.
	addRoute(&netlink.Route{
		Dst: subnet("10.150.0.0/24"), Type: unix.RTN_BLACKHOLE})

	// A gateway outside any subnet of the interface.
	addRoute(&netlink.Route{
		Dst: subnet("10.170.0.0/16"), Gw: net.ParseIP("10.160.0.9"),
		LinkIndex: ethernetIndex, Flags: int(netlink.FLAG_ONLINK)})

	// A multipath route through eth1.
	addRoute(&netlink.Route{
		Dst: subnet("10.180.0.0/16"),
		MultiPath: []*netlink.NexthopInfo{
			{LinkIndex: ethernetIndex, Gw: net.ParseIP("10.130.0.10")},
			{LinkIndex: ethernetIndex, Gw: net.ParseIP("10.130.0.11")},
		}})

	// A route through the tun device in another routing table.
	addRoute(&netlink.Route{
		Dst: subnet("10.190.0.0/16"), LinkIndex: tunIndex, Table: 100})

	// A multipath route through eth1 and the tun device.
	addRoute(&netlink.Route{
		Dst: subnet("10.200.0.0/16"),
		MultiPath: []*netlink.NexthopInfo{
			{LinkIndex: ethernetIndex, Gw: net.ParseIP("10.130.0.12")},
			{LinkIndex: tunIndex, Gw: net.ParseIP("10.0.0.9")},
		}})

	// A multipath route through the tun device only.
	addRoute(&netlink.Route{
		Dst: subnet("10.210.0.0/16"),
		MultiPath: []*netlink.NexthopInfo{
			{LinkIndex: tunIndex, Gw: net.ParseIP("10.0.0.10")},
			{LinkIndex: tunIndex, Gw: net.ParseIP("10.0.0.11")},
		}})

	subnets, err := getHostIPv4Subnets("tun0")
	if err != nil {
		t.Fatalf("getHostIPv4Subnets: %v", err)
	}
	t.Logf("host subnets: %v", subnets)

	// Nothing on the tun device is reported: its 10.0.0.0/8 route, its
	// address, its broadcast address, or a gateway reached through it.
	for _, subnet := range subnets {
		prefixLength, _ := subnet.Mask.Size()
		IP := subnet.IP.To4()
		if IP != nil && privateSubnetIPv4.Contains(IP) &&
			(prefixLength <= 8 || IP[1] == 0 || IP[1] == 255) {
			t.Errorf("tun device subnet %s reported", subnet)
		}
	}
	if containsPrivateSubnetIPv4(subnets) {
		t.Errorf("tun device route reported as a conflict")
	}

	// 10.220.0.255 is the broadcast address that netlink.AddrAdd sets for
	// the point-to-point address, from the peer prefix.
	want := "10.130.0.0/16,10.140.0.0/16,10.150.0.0/24,10.160.0.9/32," +
		"10.170.0.0/16,10.180.0.0/16,10.200.0.0/16,10.220.0.1/32," +
		"10.220.0.255/32,10.230.0.0/24"
	if got := newExcludedIndexes(subnets).String(); got != want {
		t.Errorf("excluded: got %s, want %s", got, want)
	}

	// A 10.0.0.0/8 route through eth1 is reported, and found as a
	// conflict.
	addRoute(&netlink.Route{
		Dst: privateSubnetIPv4, LinkIndex: ethernetIndex, Table: 101})
	subnets, err = getHostIPv4Subnets("tun0")
	if err != nil {
		t.Fatalf("getHostIPv4Subnets: %v", err)
	}
	if !containsPrivateSubnetIPv4(subnets) {
		t.Errorf("10.0.0.0/8 route through eth1 not found")
	}
}
