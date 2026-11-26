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
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/internal/testutils"
	"github.com/tailscale/netlink"
	"golang.org/x/sys/unix"
)

// These tests read the host's routes, or routes they set up, and aren't
// built with the race detector. It enables pointer checks that stop the
// test binary when the vendored netlink package reads a multipath route;
// see getHostIPv4Subnets.

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

	// The tun device's own routes include its address prefix, its address,
	// and its broadcast address. None may be reported.
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

	t.Logf("excluded: %s", newExcludedIndexes(subnets))
}

func hostSubnet(IP net.IP) *net.IPNet {
	return &net.IPNet{IP: IP, Mask: net.CIDRMask(32, 32)}
}

// TestExclusionsGetHostIPv4SubnetsNamespace sets up interfaces, addresses
// and routes in a new network namespace, and checks which subnets are
// reported. It must run as root. The namespace starts empty and is removed
// when the test ends, so the test doesn't change the host's network
// configuration, and the reported subnets are exactly those it sets up.
func TestExclusionsGetHostIPv4SubnetsNamespace(t *testing.T) {

	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}

	// The network namespace applies to the current OS thread only. The
	// thread is left locked, so that it exits with the test goroutine
	// rather than running other goroutines in the test namespace.
	runtime.LockOSThread()
	err := unix.Unshare(unix.CLONE_NEWNET)
	if err == unix.EPERM {
		t.Skip("requires CAP_SYS_ADMIN")
	}
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

	// A multipath route through eth1, with gateways outside any subnet of
	// the interface.
	addRoute(&netlink.Route{
		Dst: subnet("10.185.0.0/16"),
		MultiPath: []*netlink.NexthopInfo{
			{LinkIndex: ethernetIndex, Gw: net.ParseIP("10.161.0.1"),
				Flags: int(netlink.FLAG_ONLINK)},
			{LinkIndex: ethernetIndex, Gw: net.ParseIP("10.162.0.1"),
				Flags: int(netlink.FLAG_ONLINK)},
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

	// Each multipath next-hop gateway not on the tun device is reported
	// as a /32. The summary below omits those inside 10.130.0.0/16.
	reported := make(map[string]bool)
	for _, subnet := range subnets {
		reported[subnet.String()] = true
	}
	for _, gateway := range []string{
		"10.130.0.10", "10.130.0.11", "10.130.0.12", "10.161.0.1", "10.162.0.1"} {
		if !reported[gateway+"/32"] {
			t.Errorf("multipath gateway %s not reported", gateway)
		}
	}

	// 10.220.0.255 is the broadcast address that netlink.AddrAdd sets for
	// the point-to-point address, from the peer prefix.
	want := "10.130.0.0/16,10.140.0.0/16,10.150.0.0/24,10.160.0.9/32," +
		"10.161.0.1/32,10.162.0.1/32,10.170.0.0/16,10.180.0.0/16," +
		"10.185.0.0/16,10.200.0.0/16,10.220.0.1/32,10.220.0.255/32," +
		"10.230.0.0/24"
	if got := newExcludedIndexes(subnets).String(); got != want {
		t.Errorf("excluded: got %s, want %s", got, want)
	}

	// A 10.0.0.0/8 route through eth1 is reported, and found as a conflict.
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

// TestExclusionsClientConnectedResetsNAT checks that ClientConnected clears
// NAT state left for the IPv4 and IPv6 addresses it assigns, as when those
// addresses were last used by an expired session, and that NewServer's only
// startup warning is for the few addresses the configured subnets leave. It
// runs a server in a new network namespace. It must run as root, and needs
// /dev/net/tun, iptables and ip6tables; without them it fails, as the root
// tests in tun_test.go do.
func TestExclusionsClientConnectedResetsNAT(t *testing.T) {

	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}

	// See TestExclusionsGetHostIPv4SubnetsNamespace.
	runtime.LockOSThread()
	err := unix.Unshare(unix.CLONE_NEWNET)
	if err == unix.EPERM {
		t.Skip("requires CAP_SYS_ADMIN")
	}
	if err != nil {
		t.Fatalf("Unshare: %v", err)
	}

	addAddr := func(link netlink.Link, IPNet *net.IPNet, flags int) {
		err := netlink.AddrAdd(link, &netlink.Addr{IPNet: IPNet, Flags: flags})
		if err != nil {
			t.Fatalf("AddrAdd %s: %v", IPNet, err)
		}
	}

	// eth0 stands in for the server's egress interface, the default
	// ServerConfig.EgressInterface. IFA_F_NODAD makes an IPv6 address
	// usable at once, without duplicate address detection.
	egress := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "eth0"}}
	err = netlink.LinkAdd(egress)
	if err != nil {
		t.Fatalf("LinkAdd: %v", err)
	}
	err = netlink.LinkSetUp(egress)
	if err != nil {
		t.Fatalf("LinkSetUp: %v", err)
	}
	egressIPv4 := net.ParseIP("198.51.100.1").To4()
	egressIPv6 := net.ParseIP("2001:db8::1")
	addAddr(egress, &net.IPNet{IP: egressIPv4, Mask: net.CIDRMask(24, 32)}, 0)
	addAddr(egress, &net.IPNet{IP: egressIPv6, Mask: net.CIDRMask(64, 128)}, unix.IFA_F_NODAD)

	// Leave one client address, 10.0.0.3, so that the test knows which
	// addresses ClientConnected assigns. AllowNoIPv6NetworkConfiguration is
	// left false, so that NewServer fails unless the server's IPv6
	// masquerading rule is in place.
	logger := &recordingLogger{}
	t.Cleanup(func() {
		if t.Failed() {
			logger.mutex.Lock()
			defer logger.mutex.Unlock()
			for _, entry := range logger.entries {
				t.Logf("%s: %s %+v", entry.level, entry.message, entry.fields)
			}
		}
	})
	configured := mustParseSubnets(t, excludeAllBut(t, "10.0.0.0/30")...)
	config := &ServerConfig{
		Logger:                      logger,
		GetDNSResolverIPv4Addresses: func() []net.IP { return nil },
		GetDNSResolverIPv6Addresses: func() []net.IP { return nil },
		ExcludedIPv4Subnets:         configured,
	}
	server, err := NewServer(config)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	// Discovery runs and skips the server's own tun device, so it finds
	// nothing in 10.0.0.0/8: the only warning is for the few addresses that
	// the configured subnets leave.
	var warnings []logEntry
	for _, entry := range logger.entries {
		if entry.level == "warning" {
			warnings = append(warnings, entry)
		}
	}
	wantExcluded := newExcludedIndexes(configured).String()
	if len(warnings) != 1 ||
		warnings[0].message != "packet tunnel excluded subnets leave few client addresses" ||
		warnings[0].fields["excludedSubnets"] != wantExcluded ||
		warnings[0].fields["hostSubnetDiscovery"] != true {
		t.Fatalf("NewServer warnings: got %+v, want only few addresses left, excluding %s",
			warnings, wantExcluded)
	}

	server.Start()
	defer server.Stop()

	clients := []struct {
		network string
		IP      net.IP
		peer    net.IP
		egress  net.IP
	}{
		{"udp4", net.ParseIP("10.0.0.3").To4(), net.ParseIP("198.51.100.2"), egressIPv4},
		{"udp6", server.convertIndexToIPv6Address(index("10.0.0.3")), net.ParseIP("2001:db8::2"), egressIPv6},
	}

	// Create NAT state for each client address: a UDP packet from it,
	// through the egress interface, which the server's masquerading rules
	// translate. The addresses are added after NewServer, so that discovery
	// doesn't exclude them.
	loopback, err := netlink.LinkByName("lo")
	if err != nil {
		t.Fatalf("LinkByName: %v", err)
	}
	err = netlink.LinkSetUp(loopback)
	if err != nil {
		t.Fatalf("LinkSetUp: %v", err)
	}
	for _, client := range clients {
		bits := 8 * len(client.IP)
		addAddr(loopback, &net.IPNet{IP: client.IP, Mask: net.CIDRMask(bits, bits)}, unix.IFA_F_NODAD)
		conn, err := net.DialUDP(client.network,
			&net.UDPAddr{IP: client.IP}, &net.UDPAddr{IP: client.peer, Port: 9})
		if err != nil {
			t.Fatalf("DialUDP %s: %v", client.IP, err)
		}
		_, err = conn.Write([]byte{0})
		conn.Close()
		if err != nil {
			t.Fatalf("Write %s: %v", client.IP, err)
		}
	}

	// natState returns the conntrack entry for traffic from IP, if any.
	natState := func(IP net.IP) *netlink.ConntrackFlow {
		var family netlink.InetFamily = unix.AF_INET
		if IP.To4() == nil {
			family = unix.AF_INET6
		}
		flows, err := netlink.ConntrackTableList(netlink.ConntrackTable, family)
		if err != nil {
			t.Fatalf("ConntrackTableList: %v", err)
		}
		for _, flow := range flows {
			if flow.Forward.SrcIP.Equal(IP) {
				return flow
			}
		}
		return nil
	}
	for _, client := range clients {
		flow := natState(client.IP)
		if flow == nil {
			t.Fatalf("no conntrack entry for %s", client.IP)
		}
		// Replies go to the egress address only once masquerading has
		// translated the flow.
		if !flow.Reverse.DstIP.Equal(client.egress) {
			t.Fatalf("conntrack entry for %s not masqueraded: replies to %s",
				client.IP, flow.Reverse.DstIP)
		}
	}

	transport, peer := net.Pipe()
	defer peer.Close()
	allowPort := func(net.IP, int) bool { return true }
	err = server.ClientConnected(
		"session-0",
		transport,
		allowPort,
		allowPort,
		func(string) bool { return true },
		func(bool, string, net.IP) []FlowActivityUpdater { return nil },
		func(int64, int64, int64, int64) {},
		func(bool, time.Duration, net.IP) {})
	if err != nil {
		t.Fatalf("ClientConnected: %v", err)
	}
	defer server.ClientDisconnected("session-0")

	assigned, ok := server.sessionIDToIndex.Load("session-0")
	if !ok || assigned.(int32) != index("10.0.0.3") {
		t.Fatalf("ClientConnected: assigned index %v, want %d", assigned, index("10.0.0.3"))
	}
	for _, client := range clients {
		if natState(client.IP) != nil {
			t.Errorf("conntrack entry for %s not cleared", client.IP)
		}
	}
}
