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

package upstreamproxy

import (
	"fmt"
	"net"
	"net/http"
	"net/url"

	"golang.org/x/net/proxy"
)

type DialFunc func(string, string) (net.Conn, error)

type Error struct {
	error
}

func proxyError(err error) error {
	// Avoid multiple upstream.Error wrapping
	if _, ok := err.(*Error); ok {
		return err
	}
	return &Error{error: fmt.Errorf("upstreamproxy error: %s", err)}
}

type UpstreamProxyConfig struct {
	ForwardDialFunc DialFunc
	ProxyURIString  string
	CustomHeaders   http.Header
}

// UpstreamProxyConfig implements proxy.Dialer interface
// so we can pass it to proxy.FromURL
func (u *UpstreamProxyConfig) Dial(network, addr string) (net.Conn, error) {
	return u.ForwardDialFunc(network, addr)
}

func NewProxyDialFunc(config *UpstreamProxyConfig) DialFunc {
	if config.ProxyURIString == "" {
		return config.ForwardDialFunc
	}
	proxyURI, err := url.Parse(config.ProxyURIString)
	if err != nil {
		return func(network, addr string) (net.Conn, error) {
			return nil, proxyError(fmt.Errorf("proxyURI url.Parse: %v", err))
		}
	}

	dialer, err := proxy.FromURL(proxyURI, config)
	if err != nil {
		return func(network, addr string) (net.Conn, error) {
			return nil, proxyError(fmt.Errorf("proxy.FromURL: %v", err))
		}
	}
	return dialer.Dial
}
