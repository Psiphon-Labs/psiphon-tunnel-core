//go:build windows
// +build windows

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
	"errors"
	"testing"

	"golang.org/x/sys/windows"
)

// TestGetsockoptIPV6_V6ONLYFamilyProbe verifies the precondition that
// BindToDevice relies on for address-family detection: getsockopt with
// level IPPROTO_IPV6 + IPV6_V6ONLY succeeds on a freshly created AF_INET6
// socket and fails with WSAENOPROTOOPT on a freshly created AF_INET
// socket. The sockets are not bound or connected, mirroring the state
// they're in when BindToDevice is called from a net.Dialer.Control or
// net.ListenConfig.Control callback.
func TestGetsockoptIPV6_V6ONLYFamilyProbe(t *testing.T) {

	t.Run("AF_INET6", func(t *testing.T) {
		s, err := windows.Socket(
			windows.AF_INET6, windows.SOCK_DGRAM, windows.IPPROTO_UDP)
		if err != nil {
			t.Fatalf("Socket(AF_INET6) failed: %s", err)
		}
		defer windows.Closesocket(s)

		v6only, err := windows.GetsockoptInt(
			s, windows.IPPROTO_IPV6, windows.IPV6_V6ONLY)
		if err != nil {
			t.Fatalf("GetsockoptInt on AF_INET6 socket failed: %s", err)
		}
		if v6only != 0 && v6only != 1 {
			t.Fatalf("unexpected IPV6_V6ONLY value: %d", v6only)
		}
	})

	t.Run("AF_INET", func(t *testing.T) {
		s, err := windows.Socket(
			windows.AF_INET, windows.SOCK_DGRAM, windows.IPPROTO_UDP)
		if err != nil {
			t.Fatalf("Socket(AF_INET) failed: %s", err)
		}
		defer windows.Closesocket(s)

		_, err = windows.GetsockoptInt(
			s, windows.IPPROTO_IPV6, windows.IPV6_V6ONLY)
		if err == nil {
			t.Fatalf("expected GetsockoptInt on AF_INET socket to fail")
		}
		// We don't strictly require WSAENOPROTOOPT here -- the contract
		// our code relies on is just "err != nil for IPv4 sockets" --
		// but if it ever isn't WSAENOPROTOOPT it's worth knowing about.
		if !errors.Is(err, windows.WSAENOPROTOOPT) {
			t.Logf("note: GetsockoptInt on AF_INET returned %v (expected WSAENOPROTOOPT)", err)
		}
	})
}
