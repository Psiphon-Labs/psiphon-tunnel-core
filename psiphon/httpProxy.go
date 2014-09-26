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
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"unicode"
)

// HttpProxy is a HTTP server that relays HTTP requests through
// the tunnel SSH client.
type HttpProxy struct {
	tunnel        *Tunnel
	failureSignal chan bool
	listener      net.Listener
	waitGroup     *sync.WaitGroup
	httpRelay     *http.Transport
}

// NewHttpProxy initializes and runs a new HTTP proxy server.
func NewHttpProxy(tunnel *Tunnel, failureSignal chan bool) (proxy *HttpProxy, err error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	tunneledDialer := func(_, targetAddress string) (conn net.Conn, err error) {
		return tunnel.sshClient.Dial("tcp", targetAddress)
	}
	proxy = &HttpProxy{
		tunnel:        tunnel,
		failureSignal: failureSignal,
		listener:      listener,
		waitGroup:     new(sync.WaitGroup),
		httpRelay:     &http.Transport{Dial: tunneledDialer},
	}
	proxy.waitGroup.Add(1)
	go proxy.serveHttpRequests()
	log.Printf("local HTTP proxy running at address %s", proxy.listener.Addr().String())
	return proxy, nil
}

// Close terminates the HTTP server.
func (proxy *HttpProxy) Close() {
	proxy.listener.Close()
	proxy.waitGroup.Wait()
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
func (proxy *HttpProxy) ServeHTTP(responseWriter http.ResponseWriter, request *http.Request) {
	if request.Method == "CONNECT" {
		hijacker, _ := responseWriter.(http.Hijacker)
		conn, _, err := hijacker.Hijack()
		if err != nil {
			log.Print(ContextError(err))
			http.Error(responseWriter, "", http.StatusInternalServerError)
			return
		}
		go func() {
			err := httpConnectHandler(proxy.tunnel, conn, request.URL.Host)
			if err != nil {
				log.Printf("%s", err)
			}
		}()
		return
	}
	if !request.URL.IsAbs() {
		log.Print(ContextError(errors.New("no domain in request URL")))
		http.Error(responseWriter, "", http.StatusInternalServerError)
		return
	}
	// Transform request struct before using as input to relayed request:
	// Scheme: must be lower case.
	// RequestURI: cleared as docs state "It is an error to set this
	// field in an HTTP client request".
	// Accept-Encoding: removed to allow Go's RoundTripper to do its own
	// encoding.
	// Connection (and the bogus Proxy-Connection): inputs to the proxy
	// only and not to be passed along.
	request.URL.Scheme = strings.Map(unicode.ToLower, request.URL.Scheme)
	request.RequestURI = ""
	request.Header.Del("Accept-Encoding")
	request.Header.Del("Proxy-Connection")
	request.Header.Del("Connection")
	// Relay the HTTP request and get the response
	response, err := proxy.httpRelay.RoundTrip(request)
	if err != nil {
		log.Print(ContextError(err))
		http.Error(responseWriter, "", http.StatusInternalServerError)
		return
	}
	defer response.Body.Close()
	// Relay the remote response headers (first removing any proxy server headers)
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
		log.Print(ContextError(err))
		http.Error(responseWriter, "", http.StatusInternalServerError)
		return
	}
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
		Handler:      proxy,
		ReadTimeout:  HTTP_PROXY_READ_TIMEOUT,
		WriteTimeout: HTTP_PROXY_WRITE_TIMEOUT,
	}
	// Note: will be interrupted by listener.Close() call made by proxy.Close()
	err := httpServer.Serve(proxy.listener)
	if err != nil {
		select {
		case proxy.failureSignal <- true:
		default:
		}
		log.Printf("HTTP proxy server error: %s", err)
		return
	}
	log.Printf("HTTP proxy stopped")
}
