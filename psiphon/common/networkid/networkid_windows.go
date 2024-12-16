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

import (
	"net"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/go-ole/go-ole"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
	"tailscale.com/wgengine/winnet"
)

func Enabled() bool {
	return true
}

// Get address associated with the default interface.
func getDefaultLocalAddr() (net.IP, error) {
	// Note that this function has no Windows-specific code and could be used elsewhere.

	// This approach is described in psiphon/common/inproxy/pionNetwork.Interfaces()
	// The basic idea is that we initialize a UDP connection and see what local
	// address the system decides to use.
	// Note that no actual network request is made by these calls. They can be performed
	// with no network connectivity at all.
	// TODO: Use common test IP addresses in that function and this.

	// We'll prefer IPv4 and check it first (both might be available)
	ipv4UDPAddr := net.UDPAddrFromAddrPort(netip.MustParseAddrPort("93.184.216.34:3478"))
	ipv4UDPConn, ipv4Err := net.DialUDP("udp4", nil, ipv4UDPAddr)
	if ipv4Err == nil {
		ip := ipv4UDPConn.LocalAddr().(*net.UDPAddr).IP
		ipv4UDPConn.Close()
		return ip, nil
	}

	ipv6UDPAddr := net.UDPAddrFromAddrPort(netip.MustParseAddrPort("[2606:2800:220:1:248:1893:25c8:1946]:3478"))
	ipv6UDPConn, ipv6Err := net.DialUDP("udp6", nil, ipv6UDPAddr)
	if ipv6Err == nil {
		ip := ipv6UDPConn.LocalAddr().(*net.UDPAddr).IP
		ipv6UDPConn.Close()
		return ip, nil
	}

	return nil, errors.Trace(ipv4Err)
}

// Given the IP of a local interface, get that interface info.
func getInterfaceForLocalIP(ip net.IP) (*net.Interface, error) {
	// Note that this function has no Windows-specific code and could be used elsewhere.

	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, errors.Trace(err)
	}

	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			return nil, errors.Trace(err)
		}

		for _, addr := range addrs {
			addrIP, _, err := net.ParseCIDR(addr.String())
			if err != nil {
				return nil, errors.Trace(err)
			}

			if addrIP.Equal(ip) {
				return &iface, nil
			}
		}
	}

	return nil, errors.TraceNew("not found")
}

// Given the interface index, get info about the interface and its network.
func getInterfaceInfo(index int) (networkID, description string, ifType winipcfg.IfType, err error) {
	luid, err := winipcfg.LUIDFromIndex(uint32(index))
	if err != nil {
		return "", "", 0, errors.Trace(err)
	}

	ifrow, err := luid.Interface()
	if err != nil {
		return "", "", 0, errors.Trace(err)
	}

	description = ifrow.Description() + " " + ifrow.Alias()

	ifType = ifrow.Type

	var c ole.Connection
	nlm, err := winnet.NewNetworkListManager(&c)
	if err != nil {
		return "", "", 0, errors.Trace(err)
	}
	defer nlm.Release()

	netConns, err := nlm.GetNetworkConnections()
	if err != nil {
		return "", "", 0, errors.Trace(err)
	}
	defer netConns.Release()

	for _, nc := range netConns {
		ncAdapterID, err := nc.GetAdapterId()
		if err != nil {
			return "", "", 0, errors.Trace(err)
		}
		if ncAdapterID != ifrow.InterfaceGUID.String() {
			continue
		}

		// Found the INetworkConnection for the target adapter.
		// Get its network and network ID.

		n, err := nc.GetNetwork()
		if err != nil {
			return "", "", 0, errors.Trace(err)
		}
		defer n.Release()

		guid := ole.GUID{}
		hr, _, _ := syscall.SyscallN(
			n.VTable().GetNetworkId,
			uintptr(unsafe.Pointer(n)),
			uintptr(unsafe.Pointer(&guid)))
		if hr != 0 {
			return "", "", 0, errors.Tracef("GetNetworkId failed: %08x", hr)
		}

		networkID = guid.String()
		return networkID, description, ifType, nil
	}

	return "", "", 0, errors.Tracef("network connection not found for interface %d", index)
}

// Get the connection type ("WIRED", "WIFI", "MOBILE", "VPN") of the network with the given
// interface type and description.
// If the correct connection type can not be determined, "UNKNOWN" will be returned.
func getConnectionType(ifType winipcfg.IfType, description string) string {
	var connectionType string

	switch ifType {
	case winipcfg.IfTypeEthernetCSMACD, winipcfg.IfTypeEthernet3Mbit, winipcfg.IfTypeFastether, winipcfg.IfTypeFastetherFX, winipcfg.IfTypeGigabitethernet, winipcfg.IfTypeIEEE80212, winipcfg.IfTypeDigitalpowerline:
		connectionType = "WIRED"
	case winipcfg.IfTypeIEEE80211:
		connectionType = "WIFI"
	case winipcfg.IfTypeWwanpp, winipcfg.IfTypeWwanpp2:
		connectionType = "MOBILE"
	case winipcfg.IfTypePPP, winipcfg.IfTypePropVirtual, winipcfg.IfTypeTunnel:
		connectionType = "VPN"
	default:
		connectionType = "UNKNOWN"
	}

	if connectionType != "VPN" {
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
			connectionType = "VPN"
		}
	}

	return connectionType
}

func getNetworkID() (string, error) {
	localAddr, err := getDefaultLocalAddr()
	if err != nil {
		return "", errors.Trace(err)
	}

	iface, err := getInterfaceForLocalIP(localAddr)
	if err != nil {
		return "", errors.Trace(err)
	}

	networkID, description, ifType, err := getInterfaceInfo(iface.Index)
	if err != nil {
		return "", errors.Trace(err)
	}

	connectionType := getConnectionType(ifType, description)

	compoundID := connectionType + "-" + strings.Trim(networkID, "{}")

	return compoundID, nil
}

type result struct {
	networkID string
	err       error
}

var workThread struct {
	init sync.Once
	reqs chan (chan<- result)
	err  error
}

// Get returns the compound network ID; see [psiphon.NetworkIDGetter] for details.
// This function is safe to call concurrently from multiple goroutines.
// Note that if this function is called immediately after a network change (within ~2000ms)
// a transitory Network ID may be returned that will change on the next call. The caller
// may wish to delay responding to a new Network ID until the value is confirmed.
func Get() (string, error) {

	// It is not clear if the COM NetworkListManager calls are threadsafe.
	// We're using them read-only and they're probably fine, but we're not
	// sure. We'll restrict our work to single thread.
	workThread.init.Do(func() {
		workThread.reqs = make(chan (chan<- result))

		go func() {
			// Go can switch the execution of a goroutine from one OS thread to another
			// at (almost) any time. This may or may not be risky to do for our win32
			// (and especially COM) calls, so we're going to explicitly lock this goroutine
			// to a single OS thread. This shouldn't have any real impact on performance
			// and will help protect against difficult-to-reproduce errors.
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()

			if err := windows.CoInitializeEx(0, windows.COINIT_MULTITHREADED); err != nil {
				workThread.err = errors.Trace(err)
				close(workThread.reqs)
				return
			}
			defer windows.CoUninitialize()

			for resCh := range workThread.reqs {
				networkID, err := getNetworkID()
				resCh <- result{networkID, err}
			}
		}()
	})

	resCh := make(chan result)
	workThread.reqs <- resCh
	res := <-resCh

	if res.err != nil {
		return "", errors.Trace(res.err)
	}

	return res.networkID, nil
}
