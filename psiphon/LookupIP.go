// +build android linux darwin

/*
 * Copyright (c) 2015, Psiphon Inc.
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

package psiphon

import (
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
)

// LookupIP resolves a hostname. When BindToDevice is not required, it
// simply uses net.LookupIP.
// When BindToDevice is required, LookupIP explicitly creates a UDP
// socket, binds it to the device, and makes an explicit DNS request
// to the specified DNS resolver.
func LookupIP(host string, config *DialConfig) (addrs []net.IP, err error) {

	// When the input host is an IP address, echo it back
	ipAddr := net.ParseIP(host)
	if ipAddr != nil {
		return []net.IP{ipAddr}, nil
	}

	if config.DeviceBinder != nil {
		addrs, err = bindLookupIP(host, config.DnsServerGetter.GetPrimaryDnsServer(), config)
		if err == nil {
			if len(addrs) == 0 {
				err = errors.New("empty address list")
			} else {
				return addrs, err
			}
		}
		NoticeAlert("retry resolve host %s: %s", host, err)
		dnsServer := config.DnsServerGetter.GetSecondaryDnsServer()
		if dnsServer == "" {
			return addrs, err
		}
		return bindLookupIP(host, dnsServer, config)
	}
	return net.LookupIP(host)
}

// bindLookupIP implements the BindToDevice LookupIP case.
// To implement socket device binding, the lower-level syscall APIs are used.
// The sequence of syscalls in this implementation are taken from:
// https://code.google.com/p/go/issues/detail?id=6966
func bindLookupIP(host, dnsServer string, config *DialConfig) (addrs []net.IP, err error) {

	// config.DnsServerGetter.GetDnsServers() must return IP addresses
	ipAddr := net.ParseIP(dnsServer)
	if ipAddr == nil {
		return nil, common.ContextError(errors.New("invalid IP address"))
	}

	var ipv4 [4]byte
	var ipv6 [16]byte
	var domain int

	// Get address type (IPv4 or IPv6)
	if ipAddr.To4() != nil {
		copy(ipv4[:], ipAddr.To4())
		domain = syscall.AF_INET
	} else if ipAddr.To16() != nil {
		copy(ipv6[:], ipAddr.To16())
		domain = syscall.AF_INET6
	} else {
		return nil, common.ContextError(fmt.Errorf("Got invalid IP address for dns server: %s", ipAddr.String()))
	}

	socketFd, err := syscall.Socket(domain, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return nil, common.ContextError(err)
	}
	defer syscall.Close(socketFd)

	err = config.DeviceBinder.BindToDevice(socketFd)
	if err != nil {
		return nil, common.ContextError(fmt.Errorf("BindToDevice failed: %s", err))
	}

	// Connect socket to the server's IP address
	// Note: no timeout or interrupt for this connect, as it's a datagram socket
	if domain == syscall.AF_INET {
		sockAddr := syscall.SockaddrInet4{Addr: ipv4, Port: DNS_PORT}
		err = syscall.Connect(socketFd, &sockAddr)
	} else if domain == syscall.AF_INET6 {
		sockAddr := syscall.SockaddrInet6{Addr: ipv6, Port: DNS_PORT}
		err = syscall.Connect(socketFd, &sockAddr)
	}
	if err != nil {
		return nil, common.ContextError(err)
	}

	// Convert the syscall socket to a net.Conn, for use in the dns package
	file := os.NewFile(uintptr(socketFd), "")
	defer file.Close()
	conn, err := net.FileConn(file)
	if err != nil {
		return nil, common.ContextError(err)
	}

	// Set DNS query timeouts, using the ConnectTimeout from the overall Dial
	if config.ConnectTimeout != 0 {
		conn.SetReadDeadline(time.Now().Add(config.ConnectTimeout))
		conn.SetWriteDeadline(time.Now().Add(config.ConnectTimeout))
	}

	addrs, _, err = ResolveIP(host, conn)
	return
}
