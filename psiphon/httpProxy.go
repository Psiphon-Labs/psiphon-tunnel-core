/*
 * Copyright (c) 2014, Psiphon Inc.
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
	"sync"
)

// HttpProxy is a HTTP server that relays HTTP requests through
// the tunnel SSH client.
type HttpProxy struct {
	tunnel        *Tunnel
	stoppedSignal chan struct{}
	listener      net.Listener
	waitGroup     *sync.WaitGroup
	httpRelay     *http.Transport
}

// NewHttpProxy initializes and runs a new HTTP proxy server.
func NewHttpProxy(listenPort int, tunnel *Tunnel, stoppedSignal chan struct{}) (proxy *HttpProxy, err error) {
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", listenPort))
	if err != nil {
		return nil, err
	}
	tunnelledDialer := func(_, targetAddress string) (conn net.Conn, err error) {
		// TODO: connect timeout?
		return tunnel.sshClient.Dial("tcp", targetAddress)
	}
	transport := &http.Transport{
		Dial:                  tunnelledDialer,
		MaxIdleConnsPerHost:   HTTP_PROXY_MAX_IDLE_CONNECTIONS_PER_HOST,
		ResponseHeaderTimeout: HTTP_PROXY_ORIGIN_SERVER_TIMEOUT,
	}
	proxy = &HttpProxy{
		tunnel:        tunnel,
		stoppedSignal: stoppedSignal,
		listener:      listener,
		waitGroup:     new(sync.WaitGroup),
		httpRelay:     transport,
	}
	proxy.waitGroup.Add(1)
	go proxy.serveHttpRequests()
	Notice(NOTICE_HTTP_PROXY, "local HTTP proxy running at address %s", proxy.listener.Addr().String())
	return proxy, nil
}

// Close terminates the HTTP server.
func (proxy *HttpProxy) Close() {
	proxy.listener.Close()
	proxy.waitGroup.Wait()
	proxy.httpRelay.CloseIdleConnections()
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
			Notice(NOTICE_ALERT, "%s", ContextError(err))
			http.Error(responseWriter, "", http.StatusInternalServerError)
			return
		}
		go func() {
			err := httpConnectHandler(proxy.tunnel, conn, request.URL.Host)
			if err != nil {
				Notice(NOTICE_ALERT, "%s", ContextError(err))
			}
		}()
		return
	}
	if !request.URL.IsAbs() {
		Notice(NOTICE_ALERT, "%s", ContextError(errors.New("no domain in request URL")))
		http.Error(responseWriter, "", http.StatusInternalServerError)
		return
	}
	// Transform request struct before using as input to relayed request
	request.Close = false
	request.RequestURI = ""
	for _, key := range hopHeaders {
		request.Header.Del(key)
	}
	// Relay the HTTP request and get the response
	response, err := proxy.httpRelay.RoundTrip(request)
	if err != nil {
		Notice(NOTICE_ALERT, "%s", ContextError(err))
		http.Error(responseWriter, "", http.StatusInternalServerError)
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
		Notice(NOTICE_ALERT, "%s", ContextError(err))
		http.Error(responseWriter, "", http.StatusInternalServerError)
		return
	}
}

// From // https://golang.org/src/pkg/net/http/httputil/reverseproxy.go:
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

func httpConnectHandler(tunnel *Tunnel, localHttpConn net.Conn, target string) (err error) {
	defer localHttpConn.Close()
	remoteSshForward, err := tunnel.sshClient.Dial("tcp", target)
	if err != nil {
		return ContextError(err)
	}
	defer remoteSshForward.Close()
	_, err = localHttpConn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
	if err != nil {
		return ContextError(err)
	}
	relayPortForward(localHttpConn, remoteSshForward)
	return nil
}

func (proxy *HttpProxy) serveHttpRequests() {
	defer proxy.listener.Close()
	defer proxy.waitGroup.Done()
	httpServer := &http.Server{
		Handler: proxy,
	}
	// Note: will be interrupted by listener.Close() call made by proxy.Close()
	err := httpServer.Serve(proxy.listener)
	if err != nil {
		select {
		case proxy.stoppedSignal <- *new(struct{}):
		default:
		}
		Notice(NOTICE_ALERT, "%s", ContextError(err))
		return
	}
	Notice(NOTICE_HTTP_PROXY, "HTTP proxy stopped")
}
