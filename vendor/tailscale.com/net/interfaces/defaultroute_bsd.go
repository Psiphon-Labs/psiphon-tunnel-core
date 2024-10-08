// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Common code for FreeBSD and Darwin. This might also work on other
// BSD systems (e.g. OpenBSD) but has not been tested.
// Not used on iOS. See defaultroute_ios.go.

//go:build !ios && (darwin || freebsd)

package interfaces

import "net"

func defaultRoute() (d DefaultRouteDetails, err error) {
	idx, err := DefaultRouteInterfaceIndex()
	if err != nil {
		return d, err
	}
	iface, err := net.InterfaceByIndex(idx)
	if err != nil {
		return d, err
	}
	d.InterfaceName = iface.Name
	d.InterfaceIndex = idx
	return d, nil
}
