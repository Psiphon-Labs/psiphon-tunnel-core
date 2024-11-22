/*
 * Copyright (c) 2024, Psiphon Inc.
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

func Enabled() bool {
	return true
}

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"syscall"
	"unsafe"

	"github.com/go-ole/go-ole"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
	"tailscale.com/wgengine/winnet"
)

/*
Here are the values we want, to construct our "network type" value:
- ID that uniquely identifies the currently connected network, aka "network ID". We want this to be
  stable for the same network over time.
- Internet connection type: wi-fi, wired, or mobile. (TODO: Bluetooth? USB?)
- Whether the internet connection is being tunneled through a VPN.

We will define "currently connected network" as those with the default routes.

1. Get the interfaces associated with the default routes. There might be more than one interface;
   this can happen if there's also a VPN. Prefer IPv4 interfaces.
2. Get the IP addresses associated with each interface. We'll need these to map the interface to
   their adapters. (Recall that interfaces are logical and adapters are physical or virtual (VPNs).)
3. For each interface, get the "interface type". This contributes to determining connection type
   and VPN status.
4. When determining which interface to get what data from, consider the metric (which determines
   routing priority).
5. Use interface IP addresses to find the associated adapter. From the adapter, get the **network ID**
   and adapter description (which we'll use to check for VPN connection).
6. Using interface type and adapter description, determine **connection type** and **VPN status**.
*/

type defaultRouteInfo struct {
	interfaceLUID winipcfg.LUID
	metric        uint32
	family        winipcfg.AddressFamily
	ifType        winipcfg.IfType
}

type interfaceInfo struct {
	luid           winipcfg.LUID
	description    string
	ifType         winipcfg.IfType
	metric         uint32
	addresses      []netip.Addr
	networkID      string
	connectionType string
	isVPN          bool
}

// Gets information about the default routes (i.e., 0.0.0.0/0 for IPv4, ::/0 for IPv6),
// for the given address family in metric order.
func getDefaultRoutes(family winipcfg.AddressFamily) ([]defaultRouteInfo, error) {
	adaptersAddrs, err := winipcfg.GetAdaptersAddresses(family, winipcfg.GAAFlagIncludeAllInterfaces)
	if err != nil {
		return nil, fmt.Errorf("GetAdaptersAddresses: %w", err)
	}
	if len(adaptersAddrs) == 0 {
		return nil, fmt.Errorf("no adapters found")
	}

	ipForwardTable, err := winipcfg.GetIPForwardTable2(family)
	if err != nil {
		return nil, fmt.Errorf("GetIPForwardTable2: %w", err)
	}

	var defaultRoutes []defaultRouteInfo
	for _, route := range ipForwardTable {
		if route.DestinationPrefix.PrefixLength != 0 ||
			(route.DestinationPrefix.RawPrefix.Family != windows.AF_INET &&
				route.DestinationPrefix.RawPrefix.Family != windows.AF_INET6) {
			// Not a default route.
			continue
		}

		var adapterAddrs *winipcfg.IPAdapterAddresses
		for _, iface := range adaptersAddrs {
			if iface.LUID == route.InterfaceLUID {
				// Found the interface for this route.
				adapterAddrs = iface
				break
			}
		}
		if adapterAddrs == nil {
			// No adapter found for this route.
			continue
		}

		// Don't add duplicates
		dup := slices.ContainsFunc(defaultRoutes, func(dr defaultRouteInfo) bool {
			return dr.interfaceLUID == route.InterfaceLUID
		})
		if dup {
			continue
		}

		// Microsoft docs say:
		//
		// "The actual route metric used to compute the route preferences for IPv4 is the
		// summation of the route metric offset specified in the Metric member of the
		// MIB_IPFORWARD_ROW2 structure and the interface metric specified in this member
		// for IPv4"
		metric := route.Metric
		switch family {
		case windows.AF_INET:
			metric += adapterAddrs.Ipv4Metric
		case windows.AF_INET6:
			metric += adapterAddrs.Ipv6Metric
		}

		defaultRoutes = append(defaultRoutes, defaultRouteInfo{
			family:        route.DestinationPrefix.RawPrefix.Family,
			interfaceLUID: route.InterfaceLUID,
			metric:        metric,
			ifType:        adapterAddrs.IfType,
		})
	}

	slices.SortFunc(defaultRoutes, func(a, b defaultRouteInfo) int {
		if a.metric < b.metric {
			return -1
		} else if a.metric > b.metric {
			return 1
		}
		return 0
	})

	return defaultRoutes, nil
}

// The default routes (0.0.0.0/0 for IPv4, ::/0 for IPv6) have one or more interfaces associated
// with them; more than one generally means there's an active VPN connection affecting all traffic.
// This function returns the interfaces associated with the default routes. If there IPv4 routes
// and interfaces, only those will be returned; otherwise, IPv6 interfaces will be returned.
func getDefaultRouteInterfaces() ([]interfaceInfo, error) {
	var family winipcfg.AddressFamily = windows.AF_INET
	routes, err := getDefaultRoutes(family)
	if err != nil {
		return nil, fmt.Errorf("getDefaultRoutes(ipv4): %w", err)
	}

	if len(routes) == 0 {
		// No IPv4 default routes, try IPv6.
		family = windows.AF_INET6
		routes, err = getDefaultRoutes(family)
		if err != nil {
			return nil, fmt.Errorf("getDefaultRoutes(ipv6): %w", err)
		}
	}

	if len(routes) == 0 {
		// TODO: return an error or an empty slice?
		return nil, fmt.Errorf("no default routes found")
	}

	// Now we have the default routes, in metric order

	unicastIPAddresses, err := winipcfg.GetUnicastIPAddressTable(family)
	if err != nil {
		return nil, fmt.Errorf("GetAdaptersAddresses: %w", err)
	}

	interfaces := make([]interfaceInfo, 0, len(routes))
	for _, route := range routes {
		ifaceInfo := interfaceInfo{
			luid:   route.interfaceLUID,
			metric: route.metric,
			ifType: route.ifType,
		}

		for _, addr := range unicastIPAddresses {
			if addr.InterfaceLUID == route.interfaceLUID {
				ifaceInfo.addresses = append(ifaceInfo.addresses, addr.Address.Addr())
			}
		}

		interfaces = append(interfaces, ifaceInfo)
	}

	return interfaces, nil
}

// For the given set of interface IP addresses, get the network ID and description.
func getNetworkInfo(interfaceIPAddrs []netip.Addr) (networkID, description string, err error) {
	if len(interfaceIPAddrs) == 0 {
		return "", "", fmt.Errorf("no addresses")
	}

	// The set of IP addresses seems to be the only reliable way to map an interface to an
	// adapter. (Remember that adapters and interfaces are not identical and have a
	// many-to-many relationship.)
	// We need the adapter to get the network ID.

	// Assume all provided addresses are the same family
	var family winipcfg.AddressFamily = windows.AF_INET
	if interfaceIPAddrs[0].Is6() {
		family = windows.AF_INET6
	}

	adapterAddrs, err := winipcfg.GetAdaptersAddresses(family, winipcfg.GAAFlagIncludeAllInterfaces)
	if err != nil {
		return "", "", fmt.Errorf("GetAdaptersAddresses: %w", err)
	}

	var adapterGUID string
adapterAddrsLoop:
	for _, adapterAddr := range adapterAddrs {
		for unicast := adapterAddr.FirstUnicastAddress; unicast != nil; unicast = unicast.Next {
			unicastNetIP, _ := netip.AddrFromSlice(unicast.Address.IP())
			for _, addr := range interfaceIPAddrs {
				if addr == unicastNetIP {
					// IP matches; found the adapter.
					// We are making the assumption that a single IP is enough to uniquely
					// identify an adapter, rather than the whole set of them. This seems
					// reasonable.
					guid, err := adapterAddr.LUID.GUID()
					if err != nil {
						return "", "", fmt.Errorf("cannot convert adapter LUID to GUID")
					}
					if guid == nil {
						return "", "", fmt.Errorf("adapter LUID has no GUID")
					}

					adapterGUID = guid.String()
					description = adapterAddr.Description() + " " + adapterAddr.FriendlyName()
					break adapterAddrsLoop
				}
			}
		}
	}

	// We have the description and the adapter GUID, which we can use to get the network ID.

	var c ole.Connection
	nlm, err := winnet.NewNetworkListManager(&c)
	if err != nil {
		return "", "", fmt.Errorf("NewNetworkListManager: %w", err)
	}
	defer nlm.Release()

	netConns, err := nlm.GetNetworkConnections()
	if err != nil {
		return "", "", fmt.Errorf("GetNetworkConnections: %w", err)
	}
	defer netConns.Release()

	for _, nc := range netConns {
		adapterID, err := nc.GetAdapterId()
		if err != nil {
			return "", "", fmt.Errorf("GetAdapterId: %w", err)
		}
		if adapterID != adapterGUID {
			continue
		}

		// Found the INetworkConnection for the target adapter.
		// Get its network and network ID.

		n, err := nc.GetNetwork()
		if err != nil {
			return "", "", fmt.Errorf("GetNetwork: %w", err)
		}
		defer n.Release()

		guid := ole.GUID{}
		hr, _, _ := syscall.SyscallN(
			n.VTable().GetNetworkId,
			uintptr(unsafe.Pointer(n)),
			uintptr(unsafe.Pointer(&guid)))
		if hr != 0 {
			return "", "", fmt.Errorf("GetNetworkId failed: %08x", hr)
		}

		networkID = guid.String()
		break
	}

	return networkID, description, nil
}

// Get the connection type ("WIRED", "WIFI", "MOBILE", "VPN") of the network with the given
// interface type and description, and determine if it is a VPN.
// If the correct connection type can not be determined, connectionType will be set to "UNKNOWN".
func GetConnectionType(ifType winipcfg.IfType, description string) (connectionType string, isVPN bool) {
	switch ifType {
	case winipcfg.IfTypeEthernetCSMACD:
		connectionType = "WIRED"
	case winipcfg.IfTypeIEEE80211:
		connectionType = "WIFI"
	case winipcfg.IfTypeWwanpp, winipcfg.IfTypeWwanpp2:
		connectionType = "MOBILE"
	case winipcfg.IfTypePPP, winipcfg.IfTypePropVirtual, winipcfg.IfTypeTunnel:
		connectionType = "VPN"
		isVPN = true
	default:
		connectionType = "UNKNOWN"
	}

	if !isVPN {
		// The ifType doesn't indicate a VPN, but that's not well-defined, so we'll fall
		// back to checking for certain words in the description. This feels like a hack,
		// but research suggests that it's the best we can do.

		description = strings.ToLower(description)
		if strings.Contains(description, "vpn") ||
			strings.Contains(description, "tunnel") ||
			strings.Contains(description, "virtual") ||
			strings.Contains(description, "tap") ||
			strings.Contains(description, "l2tp") ||
			strings.Contains(description, "sstp") ||
			strings.Contains(description, "pptp") ||
			strings.Contains(description, "openvpn") {
			isVPN = true
		}
	}

	return connectionType, isVPN
}

// Get information about the current active network connection(s).
// networkID: Unique ID for the highest-priority (lowest metric) network connection.
// connectionType: The connection type ("WIRED", "WIFI", "MOBILE", "VPN") of the
// active network connection(s). (Guaranteed to be non-empty on success, but may be "UNKNOWN".)
// isVPN: True if the active network connection is a VPN.
func getNetworkType() (networkID, connectionType string, isVPN bool, err error) {
	// Initialize COM library
	err = windows.CoInitializeEx(0, windows.COINIT_APARTMENTTHREADED)
	if err != nil {
		return "", "", false, fmt.Errorf("CoInitializeEx: %w", err)
	}
	defer windows.CoUninitialize()

	interfaces, err := getDefaultRouteInterfaces()
	if err != nil {
		return "", "", false, fmt.Errorf("getDefaultRouteInterfaces: %w", err)
	}

	if len(interfaces) == 0 {
		return "", "", false, fmt.Errorf("no default route interfaces found")
	}

	// If we have a VPN but it is not the lowest metric, we will consider it to be not in use.
	// The lowest-metric non-VPN interface with a valid connection type (WIRED, WIFI, MOBILE) will be the one we use for that.

	lowestMetric := true
	for _, iface := range interfaces {
		iface.networkID, iface.description, err = getNetworkInfo(iface.addresses)
		if err != nil {
			return "", "", false, fmt.Errorf("getNetworkInfo: %w", err)
		}

		iface.connectionType, iface.isVPN = GetConnectionType(iface.ifType, iface.description)

		if lowestMetric {
			networkID = iface.networkID
			connectionType = iface.connectionType
			isVPN = iface.isVPN
		} else if connectionType == "" || connectionType == "UNKNOWN" || (connectionType == "VPN" && iface.connectionType != "UNKNOWN") {
			// We got a better value for connection type
			connectionType = iface.connectionType
		}
		// else this is a higher-metric interface, and the lower ones already told us what we need to know.

		lowestMetric = false
	}

	return networkID, connectionType, isVPN, nil
}

// Get returns the compound network ID; see [psiphon.NetworkIDGetter] for details.
// In that string, "VPN" takes precendence over "WIRED", "WIFI", and "MOBILE"; in that
// case connectionType can be used to determine the underlying network type. (It might be
// desirable to put that value into feedback, say.)
func Get() (compoundID, connectionType string, isVPN bool, err error) {
	 networkID, connectionType, isVPN, err := getNetworkType()
	 if err != nil {
		 return "", "", false, fmt.Errorf("getNetworkType: %w", err)
	 }

	 compoundID = connectionType + "-" + strings.Trim(networkID, "{}")

	 return compoundID, connectionType, isVPN, nil
}
