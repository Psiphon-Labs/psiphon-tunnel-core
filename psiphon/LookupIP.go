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
	"context"
	std_errors "errors"
	"net"
	"os"
	"syscall"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
)

// LookupIP resolves a hostname. When BindToDevice is not required, it
// simply uses net.LookupIP.
// When BindToDevice is required, LookupIP explicitly creates a UDP
// socket, binds it to the device, and makes an explicit DNS request
// to the specified DNS resolver.
func LookupIP(ctx context.Context, host string, config *DialConfig) ([]net.IP, error) {

	ip := net.ParseIP(host)
	if ip != nil {
		return []net.IP{ip}, nil
	}

	if config.DeviceBinder != nil {

		dnsServer := config.DnsServerGetter.GetPrimaryDnsServer()

		ips, err := bindLookupIP(ctx, host, dnsServer, config)
		if err == nil {
			if len(ips) == 0 {
				err = std_errors.New("empty address list")
			} else {
				return ips, err
			}
		}

		dnsServer = config.DnsServerGetter.GetSecondaryDnsServer()
		if dnsServer == "" {
			return ips, err
		}

		if GetEmitNetworkParameters() {
			NoticeWarning("retry resolve host %s: %s", host, err)
		}

		return bindLookupIP(ctx, host, dnsServer, config)
	}

	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)

	// Remove domain names from "net" error messages.
	if err != nil && !GetEmitNetworkParameters() {
		err = RedactNetError(err)
	}

	if err != nil {
		return nil, errors.Trace(err)
	}

	ips := make([]net.IP, len(addrs))
	for i, addr := range addrs {
		ips[i] = addr.IP
	}

	return ips, nil
}

// bindLookupIP implements the BindToDevice LookupIP case.
// To implement socket device binding, the lower-level syscall APIs are used.
func bindLookupIP(
	ctx context.Context, host, dnsServer string, config *DialConfig) ([]net.IP, error) {

	// config.DnsServerGetter.GetDnsServers() must return IP addresses
	ipAddr := net.ParseIP(dnsServer)
	if ipAddr == nil {
		return nil, errors.TraceNew("invalid IP address")
	}

	// When configured, attempt to synthesize an IPv6 address from
	// an IPv4 address for compatibility on DNS64/NAT64 networks.
	// If synthesize fails, try the original address.
	if config.IPv6Synthesizer != nil && ipAddr.To4() != nil {
		synthesizedIPAddress := config.IPv6Synthesizer.IPv6Synthesize(dnsServer)
		if synthesizedIPAddress != "" {
			synthesizedAddr := net.ParseIP(synthesizedIPAddress)
			if synthesizedAddr != nil {
				ipAddr = synthesizedAddr
			}
		}
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
		return nil, errors.TraceNew("invalid IP address for DNS server")
	}

	socketFd, err := syscall.Socket(domain, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return nil, errors.Trace(err)
	}

	_, err = config.DeviceBinder.BindToDevice(socketFd)
	if err != nil {
		syscall.Close(socketFd)
		return nil, errors.Tracef("BindToDevice failed with %s", err)
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
		syscall.Close(socketFd)
		return nil, errors.Trace(err)
	}

	// Convert the syscall socket to a net.Conn, for use in the dns package
	// This code block is from:
	// https://github.com/golang/go/issues/6966

	file := os.NewFile(uintptr(socketFd), "")
	netConn, err := net.FileConn(file) // net.FileConn() dups socketFd
	file.Close()                       // file.Close() closes socketFd
	if err != nil {
		return nil, errors.Trace(err)
	}

	type resolveIPResult struct {
		ips []net.IP
		err error
	}

	resultChannel := make(chan resolveIPResult)

	go func() {
		ips, _, err := ResolveIP(host, netConn)
		netConn.Close()
		resultChannel <- resolveIPResult{ips: ips, err: err}
	}()

	var result resolveIPResult

	select {
	case result = <-resultChannel:
	case <-ctx.Done():
		result.err = ctx.Err()
		// Interrupt the goroutine
		netConn.Close()
		<-resultChannel
	}

	if result.err != nil {
		return nil, errors.Trace(err)
	}

	return result.ips, nil
}
