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
	"errors"
	"net"
	"net/netip"
	"sort"
	"syscall"

	"golang.org/x/sys/unix"
)

// netlinkRoute is one next hop of an IPv4 default route in the main table,
// before its interface index is resolved to a name.
type netlinkRoute struct {
	ifIndex  int32
	gateway  netip.Addr
	priority uint32
}

// rtaNHID is RTA_NH_ID from <linux/rtnetlink.h>, the attribute by which a
// route references a nexthop object; not yet in golang.org/x/sys/unix.
const rtaNHID = 30

// errUnresolvedNexthop reports a route that references a nexthop object
// which could not be dumped or resolved.
var errUnresolvedNexthop = errors.New("unresolved nexthop object")

// netlinkDefaultRoutes returns every IPv4 default route in the main routing
// table, from an rtnetlink route dump, with a multipath (ECMP) route expanded
// into one entry per next hop. /proc/net/route cannot express those: the
// kernel prints only a route's first next hop there (fib_route_seq_show,
// nexthop 0), so the other gateways of a multipath default route are
// invisible to procNetDefaultRoutes.
//
// A route that references a nexthop object (RTA_NH_ID) carries no inline
// gateway once net.ipv4.nexthop_compat_mode is off; such references are
// resolved through a nexthop dump, groups included. If one cannot be
// resolved, an error is returned so the caller can fall back.
//
// Routes are ordered by metric, equal metrics in dump order, and a multipath
// route's next hops in their own order. If ifaceName is non-empty, only next
// hops on that interface are returned.
func netlinkDefaultRoutes(ifaceName string) ([]defaultRoute, error) {
	rib, err := syscall.NetlinkRIB(unix.RTM_GETROUTE, unix.AF_INET)
	if err != nil {
		return nil, err
	}
	msgs, err := syscall.ParseNetlinkMessage(rib)
	if err != nil {
		return nil, err
	}

	// Nexthop objects are dumped only if a route refers to one.
	var nexthops nexthopTable
	loaded := false
	resolve := func(id uint32) ([]netlinkRoute, bool) {
		if !loaded {
			loaded = true
			// nhmsg with family AF_UNSPEC: a family filter would omit groups.
			msgs, err := netlinkDump(unix.RTM_GETNEXTHOP, make([]byte, unix.SizeofNhmsg))
			if err == nil {
				nexthops = parseNexthops(msgs)
			}
		}
		return nexthops.resolve(id)
	}

	parsed, err := parseNetlinkRoutes(msgs, resolve)
	if err != nil {
		return nil, err
	}
	var routes []defaultRoute
	names := make(map[int32]string)
	for _, r := range parsed {
		name, ok := names[r.ifIndex]
		if !ok {
			iface, err := net.InterfaceByIndex(int(r.ifIndex))
			if err != nil {
				continue
			}
			name = iface.Name
			names[r.ifIndex] = name
		}
		if ifaceName != "" && name != ifaceName {
			continue
		}
		routes = append(routes, defaultRoute{ifaceName: name, gateway: r.gateway})
	}
	return routes, nil
}

// parseNetlinkRoutes extracts the next hops of the IPv4 unicast default
// routes in the main table from RTM_NEWROUTE messages, sorted by metric. A
// route without inline next hops that references a nexthop object is
// resolved through resolve; errUnresolvedNexthop is returned if that fails.
func parseNetlinkRoutes(
	msgs []syscall.NetlinkMessage,
	resolve func(id uint32) ([]netlinkRoute, bool)) ([]netlinkRoute, error) {

	var routes []netlinkRoute
	for i := range msgs {
		m := &msgs[i]
		if m.Header.Type != unix.RTM_NEWROUTE || len(m.Data) < unix.SizeofRtMsg {
			continue
		}
		// struct rtmsg: family, dst_len, src_len, tos, table, protocol,
		// scope, type, flags.
		if m.Data[0] != unix.AF_INET || m.Data[1] != 0 ||
			m.Data[4] != unix.RT_TABLE_MAIN || m.Data[7] != unix.RTN_UNICAST {
			continue
		}
		var (
			ifIndex   int32
			gateway   netip.Addr
			priority  uint32
			multipath []byte
			nhID      uint32
			hasNHID   bool
		)
		walkRtAttrs(m.Data[unix.SizeofRtMsg:], func(typ uint16, value []byte) {
			switch typ {
			case unix.RTA_OIF:
				if len(value) == 4 {
					ifIndex = int32(binary.NativeEndian.Uint32(value))
				}
			case unix.RTA_GATEWAY:
				if len(value) == 4 {
					gateway = netip.AddrFrom4([4]byte(value))
				}
			case unix.RTA_PRIORITY:
				if len(value) == 4 {
					priority = binary.NativeEndian.Uint32(value)
				}
			case unix.RTA_MULTIPATH:
				multipath = value
			case rtaNHID:
				if len(value) == 4 {
					nhID, hasNHID = binary.NativeEndian.Uint32(value), true
				}
			}
		})
		var hops []netlinkRoute
		switch {
		case multipath != nil:
			hops = parseMultipath(multipath)
		case gateway.IsValid():
			hops = []netlinkRoute{{ifIndex: ifIndex, gateway: gateway}}
		case hasNHID:
			var ok bool
			if hops, ok = resolve(nhID); !ok {
				return nil, errUnresolvedNexthop
			}
		}
		for _, hop := range hops {
			hop.priority = priority
			routes = append(routes, hop)
		}
	}
	sort.SliceStable(routes, func(i, j int) bool {
		return routes[i].priority < routes[j].priority
	})
	return routes, nil
}

// parseMultipath decodes an RTA_MULTIPATH value: a sequence of struct
// rtnexthop (len, flags, hops, ifindex), each followed by that next hop's
// own attributes, of which RTA_GATEWAY gives its gateway. Next hops without
// a gateway (on-link) are omitted.
func parseMultipath(b []byte) []netlinkRoute {
	var hops []netlinkRoute
	for len(b) >= unix.SizeofRtNexthop {
		length := int(binary.NativeEndian.Uint16(b[0:2]))
		if length < unix.SizeofRtNexthop || length > len(b) {
			break
		}
		hop := netlinkRoute{ifIndex: int32(binary.NativeEndian.Uint32(b[4:8]))}
		walkRtAttrs(b[unix.SizeofRtNexthop:length], func(typ uint16, value []byte) {
			if typ == unix.RTA_GATEWAY && len(value) == 4 {
				hop.gateway = netip.AddrFrom4([4]byte(value))
			}
		})
		if hop.gateway.IsValid() {
			hops = append(hops, hop)
		}
		b = b[min(rtaAlign(length), len(b)):]
	}
	return hops
}

// nexthop is one nexthop object: a gateway on an interface, or a group of
// other nexthop objects.
type nexthop struct {
	ifIndex int32
	gateway netip.Addr
	group   []uint32
}

type nexthopTable map[uint32]nexthop

// parseNexthops indexes RTM_NEWNEXTHOP messages by nexthop ID.
func parseNexthops(msgs []syscall.NetlinkMessage) nexthopTable {
	table := make(nexthopTable)
	for i := range msgs {
		m := &msgs[i]
		if m.Header.Type != unix.RTM_NEWNEXTHOP || len(m.Data) < unix.SizeofNhmsg {
			continue
		}
		var id uint32
		var nh nexthop
		walkRtAttrs(m.Data[unix.SizeofNhmsg:], func(typ uint16, value []byte) {
			switch typ {
			case unix.NHA_ID:
				if len(value) == 4 {
					id = binary.NativeEndian.Uint32(value)
				}
			case unix.NHA_OIF:
				if len(value) == 4 {
					nh.ifIndex = int32(binary.NativeEndian.Uint32(value))
				}
			case unix.NHA_GATEWAY:
				if len(value) == 4 {
					nh.gateway = netip.AddrFrom4([4]byte(value))
				}
			case unix.NHA_GROUP:
				// An array of struct nexthop_grp: id, weight, reserved.
				for len(value) >= unix.SizeofNexthopGrp {
					nh.group = append(nh.group, binary.NativeEndian.Uint32(value[0:4]))
					value = value[unix.SizeofNexthopGrp:]
				}
			}
		})
		if id != 0 {
			table[id] = nh
		}
	}
	return table
}

// resolve returns the gateway next hops of nexthop object id: its own, or
// those of its group's members. Members without a gateway (blackhole or
// on-link nexthops, or IPv6 ones) are omitted. ok is false if id or a member
// is unknown.
func (t nexthopTable) resolve(id uint32) ([]netlinkRoute, bool) {
	nh, ok := t[id]
	if !ok {
		return nil, false
	}
	if nh.group == nil {
		if !nh.gateway.IsValid() {
			return nil, true
		}
		return []netlinkRoute{{ifIndex: nh.ifIndex, gateway: nh.gateway}}, true
	}
	var hops []netlinkRoute
	for _, member := range nh.group {
		m, ok := t[member]
		if !ok {
			return nil, false
		}
		if m.gateway.IsValid() {
			hops = append(hops, netlinkRoute{ifIndex: m.ifIndex, gateway: m.gateway})
		}
	}
	return hops, true
}

// walkRtAttrs calls fn for each struct rtattr (len, type, value) in b.
func walkRtAttrs(b []byte, fn func(typ uint16, value []byte)) {
	for len(b) >= unix.SizeofRtAttr {
		length := int(binary.NativeEndian.Uint16(b[0:2]))
		typ := binary.NativeEndian.Uint16(b[2:4])
		if length < unix.SizeofRtAttr || length > len(b) {
			return
		}
		fn(typ, b[unix.SizeofRtAttr:length])
		b = b[min(rtaAlign(length), len(b)):]
	}
}

func rtaAlign(n int) int {
	return (n + unix.RTA_ALIGNTO - 1) &^ (unix.RTA_ALIGNTO - 1)
}

// netlinkDump requests a dump of msgType with the given message header
// (e.g. an nhmsg) and returns the reply messages. It is syscall.NetlinkRIB
// for requests whose header is not an rtgenmsg.
func netlinkDump(msgType uint16, header []byte) ([]syscall.NetlinkMessage, error) {
	s, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return nil, err
	}
	defer unix.Close(s)
	sa := &unix.SockaddrNetlink{Family: unix.AF_NETLINK}
	if err := unix.Bind(s, sa); err != nil {
		return nil, err
	}
	const seq = 1
	req := make([]byte, unix.NLMSG_HDRLEN+rtaAlign(len(header)))
	binary.NativeEndian.PutUint32(req[0:4], uint32(len(req)))
	binary.NativeEndian.PutUint16(req[4:6], msgType)
	binary.NativeEndian.PutUint16(req[6:8], unix.NLM_F_DUMP|unix.NLM_F_REQUEST)
	binary.NativeEndian.PutUint32(req[8:12], seq)
	copy(req[unix.NLMSG_HDRLEN:], header)
	if err := unix.Sendto(s, req, 0, sa); err != nil {
		return nil, err
	}
	lsa, err := unix.Getsockname(s)
	if err != nil {
		return nil, err
	}
	local, ok := lsa.(*unix.SockaddrNetlink)
	if !ok {
		return nil, unix.EINVAL
	}
	return readNetlinkDump(func(buf []byte) (int, error) {
		n, _, err := unix.Recvfrom(s, buf, 0)
		return n, err
	}, seq, local.Pid)
}

// readNetlinkDump reads datagrams with recv until the dump's NLMSG_DONE,
// returning the messages received before it. A dump larger than one
// datagram arrives in several; each message's payload is copied out of the
// receive buffer, which syscall.ParseNetlinkMessage only slices and the next
// recv overwrites.
func readNetlinkDump(
	recv func(buf []byte) (int, error), seq, pid uint32) ([]syscall.NetlinkMessage, error) {

	var msgs []syscall.NetlinkMessage
	buf := make([]byte, 64<<10)
	for {
		n, err := recv(buf)
		if err != nil {
			return nil, err
		}
		if n < unix.NLMSG_HDRLEN {
			return nil, unix.EINVAL
		}
		batch, err := syscall.ParseNetlinkMessage(buf[:n])
		if err != nil {
			return nil, err
		}
		for _, m := range batch {
			if m.Header.Seq != seq || m.Header.Pid != pid {
				return nil, unix.EINVAL
			}
			switch m.Header.Type {
			case unix.NLMSG_DONE:
				return msgs, nil
			case unix.NLMSG_ERROR:
				return nil, unix.EINVAL
			}
			m.Data = append([]byte(nil), m.Data...)
			msgs = append(msgs, m)
		}
	}
}
