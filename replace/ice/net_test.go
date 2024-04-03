// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package ice

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsSupportedIPv6(t *testing.T) {
	if isSupportedIPv6(net.IP{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1}) {
		t.Errorf("isSupportedIPv6 return true with IPv4-compatible IPv6 address")
	}

	if isSupportedIPv6(net.ParseIP("fec0::2333")) {
		t.Errorf("isSupportedIPv6 return true with IPv6 site-local unicast address")
	}

	if isSupportedIPv6(net.ParseIP("fe80::2333")) {
		t.Errorf("isSupportedIPv6 return true with IPv6 link-local address")
	}

	if isSupportedIPv6(net.ParseIP("ff02::2333")) {
		t.Errorf("isSupportedIPv6 return true with IPv6 link-local multicast address")
	}

	if !isSupportedIPv6(net.ParseIP("2001::1")) {
		t.Errorf("isSupportedIPv6 return false with IPv6 global unicast address")
	}
}

func TestCreateAddr(t *testing.T) {
	ipv4 := net.IP{127, 0, 0, 1}
	ipv6 := net.IP{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	port := 9000

	assert.Equal(t, &net.UDPAddr{IP: ipv4, Port: port}, createAddr(NetworkTypeUDP4, ipv4, port))
	assert.Equal(t, &net.UDPAddr{IP: ipv6, Port: port}, createAddr(NetworkTypeUDP6, ipv6, port))
	assert.Equal(t, &net.TCPAddr{IP: ipv4, Port: port}, createAddr(NetworkTypeTCP4, ipv4, port))
	assert.Equal(t, &net.TCPAddr{IP: ipv6, Port: port}, createAddr(NetworkTypeTCP6, ipv6, port))
}
