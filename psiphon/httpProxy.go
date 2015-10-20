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
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

// HttpProxy is a HTTP server that relays HTTP requests through the Psiphon tunnel.
// It includes support for HTTP CONNECT.
//
// This proxy also offers a "URL proxy" mode that relays requests for HTTP or HTTPS
// or URLs specified in the proxy request path. This mode relays either through the
// Psiphon tunnel, or directly.
//
// An example use case for tunneled URL proxy relays is to craft proxied URLs to pass to
// components that don't support HTTP or SOCKS proxy settings. For example, the
// Android Media Player (http://developer.android.com/reference/android/media/MediaPlayer.html).
// To make the Media Player use the Psiphon tunnel, construct a URL such as:
// "http://127.0.0.1:<proxy-port>/tunneled/<origin media URL>"; and pass this to the player.
// TODO: add ICY protocol to support certain streaming media (e.g., https://gist.github.com/tulskiy/1008126)
//
// An example use case for direct, untunneled, relaying is to make use of Go's TLS
// stack for HTTPS requests in cases where the native TLS stack is lacking (e.g.,
// WinHTTP on Windows XP). The URL for direct relaying is:
// "http://127.0.0.1:<proxy-port>/direct/<origin URL>".
//
// Origin URLs must include the scheme prefix ("http://" or "https://") and must be
// URL encoded.
//
type HttpProxy struct {
	tunneler               Tunneler
	listener               net.Listener
	serveWaitGroup         *sync.WaitGroup
	httpProxyTunneledRelay *http.Transport
	urlProxyTunneledRelay  *http.Transport
	urlProxyTunneledClient *http.Client
	urlProxyDirectRelay    *http.Transport
	urlProxyDirectClient   *http.Client
	openConns              *Conns
	stopListeningBroadcast chan struct{}
}

var _HTTP_PROXY_TYPE = "HTTP"

// NewHttpProxy initializes and runs a new HTTP proxy server.
func NewHttpProxy(
	config *Config,
	untunneledDialConfig *DialConfig,
	tunneler Tunneler,
	listenIP string) (proxy *HttpProxy, err error) {

	listener, err := net.Listen(
		"tcp", fmt.Sprintf("%s:%d", listenIP, config.LocalHttpProxyPort))
	if err != nil {
		if IsAddressInUseError(err) {
			NoticeHttpProxyPortInUse(config.LocalHttpProxyPort)
		}
		return nil, ContextError(err)
	}

	tunneledDialer := func(_, addr string) (conn net.Conn, err error) {
		// downstreamConn is not set in this case, as there is not a fixed
		// association between a downstream client connection and a particular
		// tunnel.
		// TODO: connect timeout?
		return tunneler.Dial(addr, false, nil)
	}
	directDialer := func(_, addr string) (conn net.Conn, err error) {
		return DialTCP(addr, untunneledDialConfig)
	}

	// TODO: could HTTP proxy share a tunneled transport with URL proxy?
	// For now, keeping them distinct just to be conservative.
	httpProxyTunneledRelay := &http.Transport{
		Dial:                  tunneledDialer,
		MaxIdleConnsPerHost:   HTTP_PROXY_MAX_IDLE_CONNECTIONS_PER_HOST,
		ResponseHeaderTimeout: HTTP_PROXY_ORIGIN_SERVER_TIMEOUT,
	}

	// Note: URL proxy relays use http.Client for upstream requests, so
	// redirects will be followed. HTTP proxy should not follow redirects
	// and simply uses http.Transport directly.

	urlProxyTunneledRelay := &http.Transport{
		Dial:                  tunneledDialer,
		MaxIdleConnsPerHost:   HTTP_PROXY_MAX_IDLE_CONNECTIONS_PER_HOST,
		ResponseHeaderTimeout: HTTP_PROXY_ORIGIN_SERVER_TIMEOUT,
	}
	urlProxyTunneledClient := &http.Client{
		Transport: urlProxyTunneledRelay,
		Jar:       nil, // TODO: cookie support for URL proxy?

		// Note: don't use this timeout -- it interrupts downloads of large response bodies
		//Timeout:   HTTP_PROXY_ORIGIN_SERVER_TIMEOUT,
	}

	urlProxyDirectRelay := &http.Transport{
		Dial:                  directDialer,
		MaxIdleConnsPerHost:   HTTP_PROXY_MAX_IDLE_CONNECTIONS_PER_HOST,
		ResponseHeaderTimeout: HTTP_PROXY_ORIGIN_SERVER_TIMEOUT,
	}
	urlProxyDirectClient := &http.Client{
		Transport: urlProxyDirectRelay,
		Jar:       nil,
	}

	proxy = &HttpProxy{
		tunneler:               tunneler,
		listener:               listener,
		serveWaitGroup:         new(sync.WaitGroup),
		httpProxyTunneledRelay: httpProxyTunneledRelay,
		urlProxyTunneledRelay:  urlProxyTunneledRelay,
		urlProxyTunneledClient: urlProxyTunneledClient,
		urlProxyDirectRelay:    urlProxyDirectRelay,
		urlProxyDirectClient:   urlProxyDirectClient,
		openConns:              new(Conns),
		stopListeningBroadcast: make(chan struct{}),
	}
	proxy.serveWaitGroup.Add(1)
	go proxy.serve()

	// TODO: NoticeListeningHttpProxyPort is emitted after net.Listen
	// but before go proxy.server() and httpServer.Serve(), and this
	// appears to cause client connections to the HTTP proxy to fail
	// (in controller_test.go, only when a tunnel is established very quickly
	// and NoticeTunnels is emitted and the client makes a request -- all
	// before the proxy.server() goroutine runs).
	// This condition doesn't arise in Go 1.4, just in Go tip (pre-1.5).
	// Note that httpServer.Serve() blocks so the fix can't be to emit
	// NoticeListeningHttpProxyPort after that call.
	// Also, check the listen backlog queue length -- shouldn't it be possible
	// to enqueue pending connections between net.Listen() and httpServer.Serve()?
	NoticeListeningHttpProxyPort(proxy.listener.Addr().(*net.TCPAddr).Port)

	return proxy, nil
}

// Close terminates the HTTP server.
func (proxy *HttpProxy) Close() {
	close(proxy.stopListeningBroadcast)
	proxy.listener.Close()
	proxy.serveWaitGroup.Wait()
	// Close local->proxy persistent connections
	proxy.openConns.CloseAll()
	// Close idle proxy->origin persistent connections
	// TODO: also close active connections
	proxy.httpProxyTunneledRelay.CloseIdleConnections()
	proxy.urlProxyTunneledRelay.CloseIdleConnections()
	proxy.urlProxyDirectRelay.CloseIdleConnections()
}

// ServeHTTP receives HTTP requests and proxies them. CONNECT requests
// are hijacked and all data is relayed. Other HTTP requests are proxied
// with explicit round trips. In both cases, the tunnel is used for proxied
// traffic.
//
// Implementation is based on:
//
// https://github.com/justmao945/mallory
// Copyright (c) 2014 JianjunMao
// The MIT License (MIT)
//
// https://golang.org/src/pkg/net/http/httputil/reverseproxy.go
// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//
func (proxy *HttpProxy) ServeHTTP(responseWriter http.ResponseWriter, request *http.Request) {
	if request.Method == "CONNECT" {
		hijacker, _ := responseWriter.(http.Hijacker)
		conn, _, err := hijacker.Hijack()
		if err != nil {
			NoticeAlert("%s", ContextError(err))
			http.Error(responseWriter, "", http.StatusInternalServerError)
			return
		}
		go func() {
			err := proxy.httpConnectHandler(conn, request.URL.Host)
			if err != nil {
				NoticeAlert("%s", ContextError(err))
			}
		}()
	} else if request.URL.IsAbs() {
		proxy.httpProxyHandler(responseWriter, request)
	} else {
		proxy.urlProxyHandler(responseWriter, request)
	}
}

func (proxy *HttpProxy) httpConnectHandler(localConn net.Conn, target string) (err error) {
	defer localConn.Close()
	defer proxy.openConns.Remove(localConn)
	proxy.openConns.Add(localConn)
	// Setting downstreamConn so localConn.Close() will be called when remoteConn.Close() is called.
	// This ensures that the downstream client (e.g., web browser) doesn't keep waiting on the
	// open connection for data which will never arrive.
	remoteConn, err := proxy.tunneler.Dial(target, false, localConn)
	if err != nil {
		return ContextError(err)
	}
	defer remoteConn.Close()
	_, err = localConn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
	if err != nil {
		return ContextError(err)
	}
	LocalProxyRelay(_HTTP_PROXY_TYPE, localConn, remoteConn)
	return nil
}

func (proxy *HttpProxy) httpProxyHandler(responseWriter http.ResponseWriter, request *http.Request) {
	relayHttpRequest(nil, proxy.httpProxyTunneledRelay, request, responseWriter)
}

const (
	URL_PROXY_TUNNELED_REQUEST_PATH = "/tunneled/"
	URL_PROXY_DIRECT_REQUEST_PATH   = "/direct/"
)

func (proxy *HttpProxy) urlProxyHandler(responseWriter http.ResponseWriter, request *http.Request) {

	var client *http.Client
	var originUrl string
	var err error

	// Request URL should be "/tunneled/<origin URL>" or  "/direct/<origin URL>" and the
	// origin URL must be URL encoded.
	switch {
	case strings.HasPrefix(request.URL.Path, URL_PROXY_TUNNELED_REQUEST_PATH):
		originUrl, err = url.QueryUnescape(request.URL.Path[len(URL_PROXY_TUNNELED_REQUEST_PATH):])
		client = proxy.urlProxyTunneledClient
	case strings.HasPrefix(request.URL.Path, URL_PROXY_DIRECT_REQUEST_PATH):
		originUrl, err = url.QueryUnescape(request.URL.Path[len(URL_PROXY_DIRECT_REQUEST_PATH):])
		client = proxy.urlProxyDirectClient
	default:
		err = errors.New("missing origin URL")
	}
	if err != nil {
		NoticeAlert("%s", ContextError(FilterUrlError(err)))
		forceClose(responseWriter)
		return
	}

	// Origin URL must be well-formed, absolute, and have a scheme of  "http" or "https"
	url, err := url.ParseRequestURI(originUrl)
	if err != nil {
		NoticeAlert("%s", ContextError(FilterUrlError(err)))
		forceClose(responseWriter)
		return
	}
	if !url.IsAbs() || (url.Scheme != "http" && url.Scheme != "https") {
		NoticeAlert("invalid origin URL")
		forceClose(responseWriter)
		return
	}

	// Transform received request to directly reference the origin URL
	request.Host = url.Host
	request.URL = url

	relayHttpRequest(client, nil, request, responseWriter)
}

func relayHttpRequest(
	client *http.Client,
	transport *http.Transport,
	request *http.Request,
	responseWriter http.ResponseWriter) {

	// Transform received request struct before using as input to relayed request
	request.Close = false
	request.RequestURI = ""
	for _, key := range hopHeaders {
		request.Header.Del(key)
	}

	// Relay the HTTP request and get the response. Use a client when supplied,
	// otherwise a transport. A client handles cookies and redirects, and a
	// transport does not.
	var response *http.Response
	var err error
	if client != nil {
		response, err = client.Do(request)
	} else {
		response, err = transport.RoundTrip(request)
	}

	if err != nil {
		NoticeAlert("%s", ContextError(FilterUrlError(err)))
		forceClose(responseWriter)
		return
	}
	defer response.Body.Close()

	// Relay the remote response headers
	for _, key := range hopHeaders {
		response.Header.Del(key)
	}
	for key, _ := range responseWriter.Header() {
		responseWriter.Header().Del(key)
	}
	for key, values := range response.Header {
		for _, value := range values {
			responseWriter.Header().Add(key, value)
		}
	}

	// Relay the response code and body
	responseWriter.WriteHeader(response.StatusCode)
	_, err = io.Copy(responseWriter, response.Body)
	if err != nil {
		NoticeAlert("%s", ContextError(err))
		forceClose(responseWriter)
		return
	}
}

// forceClose hijacks and closes persistent connections. This is used
// to ensure local persistent connections into the HTTP proxy are closed
// when ServeHTTP encounters an error.
func forceClose(responseWriter http.ResponseWriter) {
	hijacker, _ := responseWriter.(http.Hijacker)
	conn, _, err := hijacker.Hijack()
	if err == nil {
		conn.Close()
	}
}

// From https://golang.org/src/pkg/net/http/httputil/reverseproxy.go:
// Hop-by-hop headers. These are removed when sent to the backend.
// http://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html
var hopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Proxy-Connection", // see: http://homepage.ntlworld.com/jonathan.deboynepollard/FGA/web-proxy-connection-header.html
	"Te",               // canonicalized version of "TE"
	"Trailers",
	"Transfer-Encoding",
	"Upgrade",
}

// httpConnStateCallback is called by http.Server when the state of a local->proxy
// connection changes. Open connections are tracked so that all local->proxy persistent
// connections can be closed by HttpProxy.Close()
// TODO: if the HttpProxy is decoupled from a single Tunnel instance and
// instead uses the "current" Tunnel, it may not be necessary to close
// local persistent connections when the tunnel reconnects.
func (proxy *HttpProxy) httpConnStateCallback(conn net.Conn, connState http.ConnState) {
	switch connState {
	case http.StateNew:
		proxy.openConns.Add(conn)
	case http.StateActive, http.StateIdle:
		// No action
	case http.StateHijacked, http.StateClosed:
		proxy.openConns.Remove(conn)
	}
}

func (proxy *HttpProxy) serve() {
	defer proxy.listener.Close()
	defer proxy.serveWaitGroup.Done()
	httpServer := &http.Server{
		Handler:   proxy,
		ConnState: proxy.httpConnStateCallback,
	}
	// Note: will be interrupted by listener.Close() call made by proxy.Close()
	err := httpServer.Serve(proxy.listener)
	// Can't check for the exact error that Close() will cause in Accept(),
	// (see: https://code.google.com/p/go/issues/detail?id=4373). So using an
	// explicit stop signal to stop gracefully.
	select {
	case <-proxy.stopListeningBroadcast:
	default:
		if err != nil {
			proxy.tunneler.SignalComponentFailure()
			NoticeLocalProxyError(_HTTP_PROXY_TYPE, ContextError(err))
		}
	}
	NoticeInfo("HTTP proxy stopped")
}
