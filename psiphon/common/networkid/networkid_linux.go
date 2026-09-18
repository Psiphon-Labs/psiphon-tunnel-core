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
	"strings"
)

// Overridden by tests.
var sysClassNet = "/sys/class/net"

// getConnectionType returns the connection type ("WIRED", "WIFI", "MOBILE",
// "VPN") of the network reached through the given interface, or "UNKNOWN".
func getConnectionType(iface *net.Interface) string {

	if isVPNInterfaceName(iface.Name) {
		return "VPN"
	}

	if connectionType := connectionTypeFromDevType(
		getInterfaceDevType(iface.Name)); connectionType != "" {
		return connectionType
	}

	// Wireless drivers setting no DEVTYPE still have this directory, and must be
	// identified before the ARP type, which reports Wi-Fi as ethernet.
	if _, err := os.Stat(filepath.Join(sysClassNet, iface.Name, "wireless")); err == nil {
		return "WIFI"
	}

	// Ordinary ethernet interfaces carry no DEVTYPE. Virtual ethernet-like
	// interfaces, such as vlan and bridge, report ARPHRD_ETHER for themselves and
	// are treated as wired regardless of the medium they ultimately traverse.
	return connectionTypeFromARPType(
		readInterfaceFile(iface.Name, "type"))
}

// Values from <uapi/linux/if_arp.h>.
func connectionTypeFromARPType(arpType string) string {
	switch arpType {
	case "1": // ARPHRD_ETHER
		return "WIRED"
	case "512", "65534": // ARPHRD_PPP, ARPHRD_NONE
		return "VPN"
	}
	return "UNKNOWN"
}

// connectionTypeFromDevType returns "" for device types that do not establish
// the medium, such as bridge and vlan, leaving those to the checks that follow.
func connectionTypeFromDevType(devType string) string {
	switch devType {
	case "wlan":
		return "WIFI"
	case "wwan":
		return "MOBILE"
	case "wireguard":
		return "VPN"
	}
	return ""
}

func getInterfaceDevType(interfaceName string) string {

	for _, line := range strings.Split(readInterfaceFile(interfaceName, "uevent"), "\n") {
		if devType, ok := strings.CutPrefix(line, "DEVTYPE="); ok {
			return devType
		}
	}

	return ""
}

func readInterfaceFile(interfaceName, fileName string) string {

	value, err := os.ReadFile(filepath.Join(sysClassNet, interfaceName, fileName))
	if err != nil {
		return ""
	}

	return strings.TrimSpace(string(value))
}
