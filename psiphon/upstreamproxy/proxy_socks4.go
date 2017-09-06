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
/*
 * Copyright (c) 2014, Yawning Angel <yawning at torproject dot org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  * Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 *  * Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * This is inspired by go.net/proxy/socks5.go:
 *
 * Copyright 2011 The Go Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

package upstreamproxy

import (
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"

	"golang.org/x/net/proxy"
)

// socks4Proxy is a SOCKS4 proxy.
type socks4Proxy struct {
	hostPort string
	username string
	forward  proxy.Dialer
}

const (
	socks4Version        = 0x04
	socks4CommandConnect = 0x01
	socks4Null           = 0x00
	socks4ReplyVersion   = 0x00

	socks4Granted                = 0x5a
	socks4Rejected               = 0x5b
	socks4RejectedIdentdFailed   = 0x5c
	socks4RejectedIdentdMismatch = 0x5d
)

func newSOCKS4(uri *url.URL, forward proxy.Dialer) (proxy.Dialer, error) {
	s := new(socks4Proxy)
	s.hostPort = uri.Host
	s.forward = forward
	if uri.User != nil {
		s.username = uri.User.Username()
	}
	return s, nil
}

func (s *socks4Proxy) Dial(network, addr string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" {
		return nil, proxyError(fmt.Errorf("invalid network type"))
	}

	// Deal with the destination address/string.
	hostStr, portStr, err := net.SplitHostPort(addr)
	domainDest := ""
	if err != nil {
		return nil, proxyError(fmt.Errorf("parsing destination address: %v", err))
	}
	ip := net.ParseIP(hostStr)
	if ip == nil {
		// hostStr is not representing an IP, probably a domain name
		// try to put an invalid IP into DSTIP field and
		// append domain name terminated by '\x00' at the end of request
		ip = net.IPv4(0, 0, 0, 1)
		domainDest = hostStr
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return nil, proxyError(fmt.Errorf("destination address is not IPv4"))
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, proxyError(fmt.Errorf("failed to parse destination port: %v", err))
	}

	// Connect to the proxy.
	c, err := s.forward.Dial("tcp", s.hostPort)
	if err != nil {
		return nil, proxyError(fmt.Errorf("failed to dial SOCKS4a proxy: %v", err))
	}

	// Make/write the request:
	//  +----+----+----+----+----+----+----+----+----+----+....+----+
	//  | VN | CD | DSTPORT |      DSTIP        | USERID       |NULL|
	//  +----+----+----+----+----+----+----+----+----+----+....+----+

	req := make([]byte, 0, 9+len(s.username))
	req = append(req, socks4Version)
	req = append(req, socks4CommandConnect)
	req = append(req, byte(port>>8), byte(port))
	req = append(req, ip4...)
	if s.username != "" {
		req = append(req, s.username...)
	}
	req = append(req, socks4Null)
	if domainDest != "" {
		req = append(req, domainDest...)
		req = append(req, socks4Null)
	}
	_, err = c.Write(req)
	if err != nil {
		c.Close()
		return nil, proxyError(fmt.Errorf("failed to write to SOCKS4a proxy: %v", err))
	}

	// Read the response:
	// +----+----+----+----+----+----+----+----+
	// | VN | CD | DSTPORT |      DSTIP        |
	// +----+----+----+----+----+----+----+----+

	var resp [8]byte
	_, err = io.ReadFull(c, resp[:])
	if err != nil {
		c.Close()
		return nil, proxyError(fmt.Errorf("failed to read SOCKS4a proxy response: %v", err))
	}
	if resp[0] != socks4ReplyVersion {
		c.Close()
		return nil, proxyError(fmt.Errorf("proxy returned invalid SOCKS4 version"))
	}
	if resp[1] != socks4Granted {
		c.Close()
		return nil, proxyError(fmt.Errorf("proxy error: %s", socks4ErrorToString(resp[1])))
	}

	return c, nil
}

func socks4ErrorToString(code byte) string {
	switch code {
	case socks4Rejected:
		return "request rejected or failed"
	case socks4RejectedIdentdFailed:
		return "request rejected because SOCKS server cannot connect to identd on the client"
	case socks4RejectedIdentdMismatch:
		return "request rejected because the client program and identd report different user-ids"
	default:
		return fmt.Sprintf("unknown failure code %x", code)
	}
}

func init() {
	proxy.RegisterDialerType("socks4a", newSOCKS4)
}
