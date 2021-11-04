//go:build android || linux || darwin
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
	"fmt"
	"net"
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

	dialer := &net.Dialer{
		Control: func(_, _ string, c syscall.RawConn) error {
			var controlErr error
			err := c.Control(func(fd uintptr) {

				socketFD := int(fd)

				_, err := config.DeviceBinder.BindToDevice(socketFD)
				if err != nil {
					controlErr = errors.Tracef("BindToDevice failed: %s", err)
					return
				}
			})
			if controlErr != nil {
				return errors.Trace(controlErr)
			}
			return errors.Trace(err)
		},
	}

	netConn, err := dialer.DialContext(
		ctx, "udp", fmt.Sprintf("%s:%d", ipAddr.String(), DNS_PORT))
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
