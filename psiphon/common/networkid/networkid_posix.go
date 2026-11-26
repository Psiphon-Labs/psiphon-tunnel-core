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
	"encoding/binary"
	"fmt"
	"net"
	"strings"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
)

func Enabled() bool {
	return true
}

// Get returns the compound network ID; see [psiphon.NetworkIDGetter] for
// details. interfaceName selects the network to describe; when it is empty, the
// interface carrying the default route is used.
func Get(interfaceName string) (string, error) {

	iface, err := getInterface(interfaceName)
	if err != nil {
		return "", errors.Trace(err)
	}

	connectionType := getConnectionType(iface)

	// The connection type alone remains a valid network ID.
	address, err := getInterfaceAddress(iface)
	if err != nil {
		return connectionType, nil
	}

	return connectionType + "-" + address, nil
}

// getInterfaceAddress returns the value distinguishing one network from
// another on the same interface, chosen from the interface's addresses with
// selectInterfaceAddress.
func getInterfaceAddress(iface *net.Interface) (string, error) {

	addrs, err := iface.Addrs()
	if err != nil {
		return "", errors.Trace(err)
	}

	address, ok := selectInterfaceAddress(addrs)
	if !ok {
		return "", errors.TraceNew("no address found")
	}

	return address, nil
}

// selectInterfaceAddress returns the network ID value for a list of interface
// addresses, or false when no address qualifies.
//
// The first IPv4 address that is not link-local is returned in full. IPv4 is
// preferred, as IPv6 privacy addresses are periodically regenerated.
//
// Otherwise only unique local (fc00::/7) and global unicast (2000::/3) IPv6
// addresses are considered. Unique local is preferred over global, as the
// local router chooses it and it does not change with the ISP's prefix. Within
// the preferred class, the address whose first 32 bits are numerically lowest
// is selected, so the result does not depend on the order of addrs. Only those
// 32 bits are returned, formatted by formatIPv6Prefix.
//
// A full IPv6 address changes with the delegated prefix and with privacy
// address rotation, so the same network would keep getting new IDs and losing
// its stored state. A coarse prefix trades precision for stability: two
// networks may share an ID, but one network should keep its ID.
//
// The IPv6 selection and format are intended to match
// NetworkInterfaceSelectAddress and NetworkInterfaceFormatIPv6Prefix in the
// iOS library and selectIPv6NetworkIDPrefix in the Android library, though
// nothing compares IDs across platforms. One difference: an IPv4-mapped IPv6
// address (::ffff:a.b.c.d) is returned here in full as IPv4, as before, while
// the iOS library ignores it and Android never sees it as IPv6. For IPv4, the
// iOS library also skips 192.0.0.0/29.
func selectInterfaceAddress(addrs []net.Addr) (string, bool) {

	var selectedPrefix uint32
	selectedIsUniqueLocal := false
	selected := false

	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok || ipNet.IP.IsLinkLocalUnicast() {
			continue
		}
		if ipNet.IP.To4() != nil {
			return ipNet.IP.String(), true
		}
		ip := ipNet.IP.To16()
		if ip == nil {
			continue
		}
		isUniqueLocal := ip[0]&0xfe == 0xfc
		isGlobal := ip[0]&0xe0 == 0x20
		if !isUniqueLocal && !isGlobal {
			continue
		}
		prefix := binary.BigEndian.Uint32(ip[:4])
		if !selected ||
			(isUniqueLocal && !selectedIsUniqueLocal) ||
			(isUniqueLocal == selectedIsUniqueLocal && prefix < selectedPrefix) {
			selectedPrefix = prefix
			selectedIsUniqueLocal = isUniqueLocal
			selected = true
		}
	}

	if !selected {
		return "", false
	}

	return formatIPv6Prefix(selectedPrefix), true
}

// formatIPv6Prefix formats the first 32 bits of an IPv6 address as a /32
// prefix: the two leading 16-bit groups in lowercase hexadecimal without
// leading zeros, followed by "::/32". For example, 2001:db8:85a3::1 gives
// "2001:db8::/32" and 2001:0:1::1 gives "2001:0::/32". This matches the mobile
// libraries rather than netip.Prefix, which would print "2001::/32". The result
// never contains "-".
func formatIPv6Prefix(prefix uint32) string {
	return fmt.Sprintf("%x:%x::/32", prefix>>16, prefix&0xffff)
}

// isVPNInterfaceName reports whether the interface name is one used for
// tunnelled networks. The name is checked because these interfaces are not
// otherwise distinguishable: they report no media type on Darwin, and tap
// devices are indistinguishable from ethernet on Linux.
func isVPNInterfaceName(interfaceName string) bool {
	for _, prefix := range []string{"utun", "tun", "tap", "ipsec", "ppp", "wg"} {
		if strings.HasPrefix(interfaceName, prefix) {
			return true
		}
	}
	return false
}
