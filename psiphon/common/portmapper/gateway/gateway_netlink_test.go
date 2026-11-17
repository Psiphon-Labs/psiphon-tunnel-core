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

package gateway

import (
	"encoding/binary"
	"net/netip"
	"reflect"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func rtAttr(typ uint16, value []byte) []byte {
	b := make([]byte, rtaAlign(unix.SizeofRtAttr+len(value)))
	binary.NativeEndian.PutUint16(b[0:2], uint16(unix.SizeofRtAttr+len(value)))
	binary.NativeEndian.PutUint16(b[2:4], typ)
	copy(b[unix.SizeofRtAttr:], value)
	return b
}

func u32(v uint32) []byte {
	b := make([]byte, 4)
	binary.NativeEndian.PutUint32(b, v)
	return b
}

func nextHop(ifIndex int32, gateway string) []byte {
	var attrs []byte
	if gateway != "" {
		ip := netip.MustParseAddr(gateway).As4()
		attrs = rtAttr(unix.RTA_GATEWAY, ip[:])
	}
	b := make([]byte, unix.SizeofRtNexthop, unix.SizeofRtNexthop+len(attrs))
	binary.NativeEndian.PutUint16(b[0:2], uint16(unix.SizeofRtNexthop+len(attrs)))
	binary.NativeEndian.PutUint32(b[4:8], uint32(ifIndex))
	return append(b, attrs...)
}

// routeMessage builds an RTM_NEWROUTE with the given rtmsg fields and
// attributes.
func routeMessage(family, dstLen, table, typ uint8, attrs ...[]byte) syscall.NetlinkMessage {
	data := make([]byte, unix.SizeofRtMsg)
	data[0], data[1], data[4], data[7] = family, dstLen, table, typ
	for _, a := range attrs {
		data = append(data, a...)
	}
	return syscall.NetlinkMessage{
		Header: syscall.NlMsghdr{Type: unix.RTM_NEWROUTE},
		Data:   data,
	}
}

func TestParseNetlinkRoutes(t *testing.T) {
	gw := func(s string) []byte { ip := netip.MustParseAddr(s).As4(); return ip[:] }
	msgs := []syscall.NetlinkMessage{
		// A multipath default route: two routers on different interfaces,
		// and an on-link next hop without a gateway, which is skipped.
		routeMessage(unix.AF_INET, 0, unix.RT_TABLE_MAIN, unix.RTN_UNICAST,
			rtAttr(unix.RTA_PRIORITY, u32(100)),
			rtAttr(unix.RTA_MULTIPATH, append(append(
				nextHop(2, "192.168.1.1"), nextHop(3, "192.168.2.1")...), nextHop(4, "")...))),
		// An ordinary default route with a better metric: sorts first.
		routeMessage(unix.AF_INET, 0, unix.RT_TABLE_MAIN, unix.RTN_UNICAST,
			rtAttr(unix.RTA_OIF, u32(5)), rtAttr(unix.RTA_GATEWAY, gw("10.0.0.1")),
			rtAttr(unix.RTA_PRIORITY, u32(50))),
		// Not default routes of the main table: a /24, a local-table route,
		// a non-unicast type, an IPv6 route, and a non-route message.
		routeMessage(unix.AF_INET, 24, unix.RT_TABLE_MAIN, unix.RTN_UNICAST,
			rtAttr(unix.RTA_OIF, u32(5)), rtAttr(unix.RTA_GATEWAY, gw("10.0.0.2"))),
		routeMessage(unix.AF_INET, 0, unix.RT_TABLE_LOCAL, unix.RTN_UNICAST,
			rtAttr(unix.RTA_OIF, u32(5)), rtAttr(unix.RTA_GATEWAY, gw("10.0.0.3"))),
		routeMessage(unix.AF_INET, 0, unix.RT_TABLE_MAIN, unix.RTN_BLACKHOLE,
			rtAttr(unix.RTA_OIF, u32(5)), rtAttr(unix.RTA_GATEWAY, gw("10.0.0.4"))),
		routeMessage(unix.AF_INET6, 0, unix.RT_TABLE_MAIN, unix.RTN_UNICAST),
		{Header: syscall.NlMsghdr{Type: unix.NLMSG_DONE}},
	}
	noNexthops := func(uint32) ([]netlinkRoute, bool) { return nil, false }
	got, err := parseNetlinkRoutes(msgs, noNexthops)
	if err != nil {
		t.Fatal(err)
	}
	want := []netlinkRoute{
		{5, netip.MustParseAddr("10.0.0.1"), 50},
		{2, netip.MustParseAddr("192.168.1.1"), 100},
		{3, netip.MustParseAddr("192.168.2.1"), 100},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func nexthopMessage(attrs ...[]byte) syscall.NetlinkMessage {
	data := make([]byte, unix.SizeofNhmsg)
	for _, a := range attrs {
		data = append(data, a...)
	}
	return syscall.NetlinkMessage{
		Header: syscall.NlMsghdr{Type: unix.RTM_NEWNEXTHOP},
		Data:   data,
	}
}

func nexthopGroup(ids ...uint32) []byte {
	var b []byte
	for _, id := range ids {
		member := make([]byte, unix.SizeofNexthopGrp)
		binary.NativeEndian.PutUint32(member[0:4], id)
		member[4] = 1 // weight
		b = append(b, member...)
	}
	return b
}

// TestParseNetlinkRoutesNexthopObjects covers routes that reference nexthop
// objects (RTA_NH_ID) without inline gateway attributes, as dumped when
// net.ipv4.nexthop_compat_mode is off: a single nexthop, a group, and an
// unknown reference, which must fail rather than drop the route silently.
func TestParseNetlinkRoutesNexthopObjects(t *testing.T) {
	gw := func(s string) []byte { ip := netip.MustParseAddr(s).As4(); return ip[:] }
	nexthops := parseNexthops([]syscall.NetlinkMessage{
		nexthopMessage(rtAttr(unix.NHA_ID, u32(1)), rtAttr(unix.NHA_OIF, u32(2)), rtAttr(unix.NHA_GATEWAY, gw("192.168.1.1"))),
		nexthopMessage(rtAttr(unix.NHA_ID, u32(2)), rtAttr(unix.NHA_OIF, u32(3)), rtAttr(unix.NHA_GATEWAY, gw("192.168.2.1"))),
		// A blackhole nexthop: no gateway, omitted from its group.
		nexthopMessage(rtAttr(unix.NHA_ID, u32(3)), rtAttr(unix.NHA_BLACKHOLE, nil)),
		nexthopMessage(rtAttr(unix.NHA_ID, u32(10)), rtAttr(unix.NHA_GROUP, nexthopGroup(1, 3, 2))),
		// A group with an unknown member.
		nexthopMessage(rtAttr(unix.NHA_ID, u32(11)), rtAttr(unix.NHA_GROUP, nexthopGroup(1, 99))),
	})
	route := func(nhID uint32) syscall.NetlinkMessage {
		return routeMessage(unix.AF_INET, 0, unix.RT_TABLE_MAIN, unix.RTN_UNICAST,
			rtAttr(rtaNHID, u32(nhID)), rtAttr(unix.RTA_PRIORITY, u32(100)))
	}

	got, err := parseNetlinkRoutes([]syscall.NetlinkMessage{route(10), route(2)}, nexthops.resolve)
	if err != nil {
		t.Fatal(err)
	}
	want := []netlinkRoute{
		{2, netip.MustParseAddr("192.168.1.1"), 100},
		{3, netip.MustParseAddr("192.168.2.1"), 100},
		{3, netip.MustParseAddr("192.168.2.1"), 100},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	for _, id := range []uint32{11, 99} {
		if _, err := parseNetlinkRoutes([]syscall.NetlinkMessage{route(id)}, nexthops.resolve); err != errUnresolvedNexthop {
			t.Fatalf("nexthop %d: got %v, want %v", id, err, errUnresolvedNexthop)
		}
	}
	// With nexthop_compat_mode on, the route also carries inline attributes,
	// which are used as they are and need no resolution.
	got, err = parseNetlinkRoutes([]syscall.NetlinkMessage{
		routeMessage(unix.AF_INET, 0, unix.RT_TABLE_MAIN, unix.RTN_UNICAST,
			rtAttr(rtaNHID, u32(99)), rtAttr(unix.RTA_OIF, u32(2)), rtAttr(unix.RTA_GATEWAY, gw("192.168.1.1"))),
	}, func(uint32) ([]netlinkRoute, bool) { t.Fatal("resolved an inline route"); return nil, false })
	if inline := []netlinkRoute{{2, netip.MustParseAddr("192.168.1.1"), 0}}; err != nil || !reflect.DeepEqual(got, inline) {
		t.Fatalf("compat route: got %+v, %v; want %+v", got, err, inline)
	}
}

// TestNetlinkDefaultRoutesMatchesProc checks the live dump against
// /proc/net/route: every route the latter reports (a multipath route's first
// next hop, nexthop objects resolved) must be among the former, and every
// route the former reports beyond those -- the other next hops of a
// multipath route, invisible to HomeRouterIP's /proc/net/route lookup --
// must be a candidate.
func TestNetlinkDefaultRoutesMatchesProc(t *testing.T) {
	routes, err := netlinkDefaultRoutes("")
	if err != nil {
		t.Skipf("netlink unavailable: %v", err)
	}
	t.Logf("netlink: %v", routes)
	proc := procNetDefaultRoutes("")
	t.Logf("/proc/net/route: %v", proc)
	contains := func(routes []defaultRoute, r defaultRoute) bool {
		for _, x := range routes {
			if x == r {
				return true
			}
		}
		return false
	}
	for _, p := range proc {
		if !contains(routes, p) {
			t.Errorf("/proc/net/route route %v missing from netlink routes", p)
		}
	}
	candidates := Candidates("")
	for _, r := range routes {
		if contains(proc, r) || !r.gateway.IsPrivate() {
			continue
		}
		t.Logf("route beyond /proc/net/route: %v", r)
		found := false
		for _, c := range candidates {
			if c.InterfaceName == r.ifaceName && c.Gateway == r.gateway {
				found = true
			}
		}
		if !found {
			t.Errorf("route %v beyond /proc/net/route is not a candidate: %+v", r, candidates)
		}
	}
}

// TestReadNetlinkDumpSpanningDatagrams verifies that messages from an
// earlier datagram survive the receive buffer being reused for later ones.
func TestReadNetlinkDumpSpanningDatagrams(t *testing.T) {
	const seq, pid = 1, 4242
	datagram := func(msgs ...syscall.NetlinkMessage) []byte {
		var b []byte
		for _, m := range msgs {
			hdr := make([]byte, unix.NLMSG_HDRLEN)
			binary.NativeEndian.PutUint32(hdr[0:4], uint32(unix.NLMSG_HDRLEN+len(m.Data)))
			binary.NativeEndian.PutUint16(hdr[4:6], m.Header.Type)
			binary.NativeEndian.PutUint32(hdr[8:12], seq)
			binary.NativeEndian.PutUint32(hdr[12:16], pid)
			b = append(b, hdr...)
			b = append(b, m.Data...)
			b = append(b, make([]byte, rtaAlign(len(m.Data))-len(m.Data))...)
		}
		return b
	}
	gw := func(s string) []byte { ip := netip.MustParseAddr(s).As4(); return ip[:] }
	first := nexthopMessage(rtAttr(unix.NHA_ID, u32(1)), rtAttr(unix.NHA_OIF, u32(2)), rtAttr(unix.NHA_GATEWAY, gw("192.168.1.1")))
	second := nexthopMessage(rtAttr(unix.NHA_ID, u32(2)), rtAttr(unix.NHA_OIF, u32(3)), rtAttr(unix.NHA_GATEWAY, gw("192.168.2.1")))
	done := syscall.NetlinkMessage{Header: syscall.NlMsghdr{Type: unix.NLMSG_DONE}, Data: make([]byte, 4)}
	datagrams := [][]byte{datagram(first), datagram(second, done)}
	recv := func(buf []byte) (int, error) {
		d := datagrams[0]
		datagrams = datagrams[1:]
		// Overwrite the whole buffer, as a longer later datagram would.
		for i := range buf {
			buf[i] = 0xff
		}
		return copy(buf, d), nil
	}

	msgs, err := readNetlinkDump(recv, seq, pid)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 2 || !reflect.DeepEqual(msgs[0].Data, first.Data) || !reflect.DeepEqual(msgs[1].Data, second.Data) {
		t.Fatalf("got %+v, want the two nexthop messages intact", msgs)
	}
	table := parseNexthops(msgs)
	hops, ok := table.resolve(1)
	if !ok || len(hops) != 1 || hops[0].gateway != netip.MustParseAddr("192.168.1.1") {
		t.Fatalf("nexthop 1 from the first datagram: %+v, %v", hops, ok)
	}
}
