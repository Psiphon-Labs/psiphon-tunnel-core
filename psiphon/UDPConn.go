/*
 * Copyright (c) 2018, Psiphon Inc.
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
	"math/rand"
	"net"
	"strconv"
	"syscall"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
)

// NewUDPConn resolves addr and configures a new UDP conn. The UDP socket is
// created using options in DialConfig, including DeviceBinder. The returned
// UDPAddr uses DialConfig options IPv6Synthesizer and ResolvedIPCallback.
//
// The UDP conn is not dialed; it is intended for use with WriteTo using the
// returned UDPAddr, not Write.
//
// The returned conn is not a Closer; the caller is expected to wrap this conn
// with another higher-level conn that provides that interface.
func NewUDPConn(
	ctx context.Context, addr string, config *DialConfig) (net.PacketConn, *net.UDPAddr, error) {

	host, strPort, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, nil, errors.Trace(err)
	}
	port, err := strconv.Atoi(strPort)
	if err != nil {
		return nil, nil, errors.Trace(err)
	}

	if port <= 0 || port >= 65536 {
		return nil, nil, errors.Tracef("invalid destination port: %d", port)
	}

	ipAddrs, err := LookupIP(ctx, host, config)
	if err != nil {
		return nil, nil, errors.Trace(err)
	}
	if len(ipAddrs) < 1 {
		return nil, nil, errors.TraceNew("no IP address")
	}

	ipAddr := ipAddrs[rand.Intn(len(ipAddrs))]

	if config.IPv6Synthesizer != nil {
		if ipAddr.To4() != nil {
			synthesizedIPAddress := config.IPv6Synthesizer.IPv6Synthesize(ipAddr.String())
			if synthesizedIPAddress != "" {
				synthesizedAddr := net.ParseIP(synthesizedIPAddress)
				if synthesizedAddr != nil {
					ipAddr = synthesizedAddr
				}
			}
		}
	}

	var domain int
	if ipAddr != nil && ipAddr.To4() != nil {
		domain = syscall.AF_INET
	} else if ipAddr != nil && ipAddr.To16() != nil {
		domain = syscall.AF_INET6
	} else {
		return nil, nil, errors.Tracef("invalid IP address: %s", ipAddr.String())
	}

	conn, err := newUDPConn(domain, config)
	if err != nil {
		return nil, nil, errors.Trace(err)
	}

	if config.ResolvedIPCallback != nil {
		config.ResolvedIPCallback(ipAddr.String())
	}

	return conn, &net.UDPAddr{IP: ipAddr, Port: port}, nil
}
