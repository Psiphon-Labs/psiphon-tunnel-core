// Copyright 2023 Jigsaw Operations LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package transport

import (
	"fmt"
	"net"
)

type domainAddr struct {
	network string
	address string
}

func (a *domainAddr) Network() string {
	return a.network
}

func (a *domainAddr) String() string {
	return a.address
}

var _ net.Addr = (*domainAddr)(nil)

// MakeNetAddr returns a [net.Addr] based on the network and address.
// This is a helper for code that needs to return or provide a [net.Addr].
// The address must be in "host:port" format with the host being a domain name, IPv4 or IPv6.
// The network must be "tcp" or "udp".
// For IP hosts, the returned address will be of type [*net.TCPAddr] or [*net.UDPAddr], based on the network argument.
// This is important because some of the standard library functions inspect the type of the address and might return an
// "invalid argument" error if the type is not the correct one.
func MakeNetAddr(network, address string) (net.Addr, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	portnum, err := net.LookupPort(network, port)
	if err != nil {
		return nil, err
	}
	hostIp := net.ParseIP(host)
	if hostIp != nil {
		switch network {
		case "tcp":
			return &net.TCPAddr{IP: hostIp, Port: portnum}, nil
		case "udp":
			return &net.UDPAddr{IP: hostIp, Port: portnum}, nil
		default:
			return nil, net.UnknownNetworkError(network)
		}
	}
	return &domainAddr{network: network, address: net.JoinHostPort(host, fmt.Sprint(portnum))}, nil
}
