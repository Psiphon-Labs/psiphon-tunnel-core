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
)

// LookupIP resolves a hostname. When BindToDevice is not required, it
// simply uses net.LookupIP.
// When BindToDevice is required, LookupIP explicitly creates a UDP
// socket, binds it to the device, and makes an explicit DNS request
// to the specified DNS resolver.
func LookupIP(host string, config *DialConfig) (addrs []net.IP, err error) {
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

	// When the input host is an IP address, echo it back
	ipAddr := net.ParseIP(host)
	if ipAddr != nil {
		return []net.IP{ipAddr}, nil
	}

	socketFd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return nil, ContextError(err)
	}
	defer syscall.Close(socketFd)

	err = config.DeviceBinder.BindToDevice(socketFd)
	if err != nil {
		return nil, ContextError(fmt.Errorf("BindToDevice failed: %s", err))
	}

	// config.DnsServerGetter.GetDnsServers() must return IP addresses
	ipAddr = net.ParseIP(dnsServer)
	if ipAddr == nil {
		return nil, ContextError(errors.New("invalid IP address"))
	}

	// TODO: IPv6 support
	var ip [4]byte
	copy(ip[:], ipAddr.To4())
	sockAddr := syscall.SockaddrInet4{Addr: ip, Port: DNS_PORT}
	// Note: no timeout or interrupt for this connect, as it's a datagram socket
	err = syscall.Connect(socketFd, &sockAddr)
	if err != nil {
		return nil, ContextError(err)
	}

	// Convert the syscall socket to a net.Conn, for use in the dns package
	file := os.NewFile(uintptr(socketFd), "")
	defer file.Close()
	conn, err := net.FileConn(file)
	if err != nil {
		return nil, ContextError(err)
	}

	// Set DNS query timeouts, using the ConnectTimeout from the overall Dial
	if config.ConnectTimeout != 0 {
		conn.SetReadDeadline(time.Now().Add(config.ConnectTimeout))
		conn.SetWriteDeadline(time.Now().Add(config.ConnectTimeout))
	}

	addrs, _, err = ResolveIP(host, conn)
	return
}
