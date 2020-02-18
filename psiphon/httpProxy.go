/*
 * Copyright (c) 2016, Psiphon Inc.
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
	"bytes"
	"compress/gzip"
	"crypto/tls"
	std_errors "errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/parameters"
	"github.com/grafov/m3u8"
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
// The <origin media URL> must be escaped in such a way that it can be used inside a URL query.
//
// An example use case for direct, untunneled, relaying is to make use of Go's TLS
// stack for HTTPS requests in cases where the native TLS stack is lacking (e.g.,
// WinHTTP on Windows XP). The URL for direct relaying is:
// "http://127.0.0.1:<proxy-port>/direct/<origin URL>".
// Again, the <origin URL> must be escaped in such a way that it can be used inside a URL query.
//
// An example use case for tunneled relaying with rewriting (/tunneled-rewrite/) is when the
// content of retrieved files contains URLs that also need to be modified to be tunneled.
// For example, in iOS 10 the UIWebView media player does not put requests through the
// NSURLProtocol, so they are not tunneled. Instead, we rewrite those URLs to use the URL
// proxy, and rewrite retrieved playlist files so they also contain proxied URLs.
//
// The URL proxy offers /tunneled-icy/ which is compatible with both HTTP and ICY protocol
// resources.
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
	responseHeaderTimeout  time.Duration
	openConns              *common.Conns
	stopListeningBroadcast chan struct{}
	listenIP               string
	listenPort             int
}

var _HTTP_PROXY_TYPE = "HTTP"

// NewHttpProxy initializes and runs a new HTTP proxy server.
func NewHttpProxy(
	config *Config,
	tunneler Tunneler,
	listenIP string) (proxy *HttpProxy, err error) {

	listener, err := net.Listen(
		"tcp", fmt.Sprintf("%s:%d", listenIP, config.LocalHttpProxyPort))
	if err != nil {
		if IsAddressInUseError(err) {
			NoticeHttpProxyPortInUse(config.LocalHttpProxyPort)
		}
		return nil, errors.Trace(err)
	}

	tunneledDialer := func(_, addr string) (conn net.Conn, err error) {
		// downstreamConn is not set in this case, as there is not a fixed
		// association between a downstream client connection and a particular
		// tunnel.
		return tunneler.Dial(addr, false, nil)
	}
	directDialer := func(_, addr string) (conn net.Conn, err error) {
		return tunneler.DirectDial(addr)
	}

	p := config.GetClientParameters().Get()
	responseHeaderTimeout := p.Duration(parameters.HTTPProxyOriginServerTimeout)
	maxIdleConnsPerHost := p.Int(parameters.HTTPProxyMaxIdleConnectionsPerHost)

	// TODO: could HTTP proxy share a tunneled transport with URL proxy?
	// For now, keeping them distinct just to be conservative.
	httpProxyTunneledRelay := &http.Transport{
		Dial:                  tunneledDialer,
		MaxIdleConnsPerHost:   maxIdleConnsPerHost,
		ResponseHeaderTimeout: responseHeaderTimeout,
	}

	// Note: URL proxy relays use http.Client for upstream requests, so
	// redirects will be followed. HTTP proxy should not follow redirects
	// and simply uses http.Transport directly.

	urlProxyTunneledRelay := &http.Transport{
		Dial:                  tunneledDialer,
		MaxIdleConnsPerHost:   maxIdleConnsPerHost,
		ResponseHeaderTimeout: responseHeaderTimeout,
	}
	urlProxyTunneledClient := &http.Client{
		Transport: urlProxyTunneledRelay,
		Jar:       nil, // TODO: cookie support for URL proxy?

		// Leaving original value in the note below:
		// Note: don't use this timeout -- it interrupts downloads of large response bodies
		//Timeout:   HTTP_PROXY_ORIGIN_SERVER_TIMEOUT,
	}

	urlProxyDirectRelay := &http.Transport{
		Dial:                  directDialer,
		MaxIdleConnsPerHost:   maxIdleConnsPerHost,
		ResponseHeaderTimeout: responseHeaderTimeout,
	}
	urlProxyDirectClient := &http.Client{
		Transport: urlProxyDirectRelay,
		Jar:       nil,
	}

	proxyIP, proxyPortString, _ := net.SplitHostPort(listener.Addr().String())
	proxyPort, _ := strconv.Atoi(proxyPortString)

	proxy = &HttpProxy{
		tunneler:               tunneler,
		listener:               listener,
		serveWaitGroup:         new(sync.WaitGroup),
		httpProxyTunneledRelay: httpProxyTunneledRelay,
		urlProxyTunneledRelay:  urlProxyTunneledRelay,
		urlProxyTunneledClient: urlProxyTunneledClient,
		urlProxyDirectRelay:    urlProxyDirectRelay,
		urlProxyDirectClient:   urlProxyDirectClient,
		responseHeaderTimeout:  responseHeaderTimeout,
		openConns:              common.NewConns(),
		stopListeningBroadcast: make(chan struct{}),
		listenIP:               proxyIP,
		listenPort:             proxyPort,
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
	NoticeListeningHttpProxyPort(proxy.listenPort)

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
		conn := hijack(responseWriter)
		if conn == nil {
			// hijack emits an alert notice
			http.Error(responseWriter, "", http.StatusInternalServerError)
			return
		}
		go func() {
			err := proxy.httpConnectHandler(conn, request.URL.Host)
			if err != nil {
				NoticeWarning("%s", errors.Trace(err))
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
		return errors.Trace(err)
	}
	defer remoteConn.Close()
	_, err = localConn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
	if err != nil {
		return errors.Trace(err)
	}
	LocalProxyRelay(_HTTP_PROXY_TYPE, localConn, remoteConn)
	return nil
}

func (proxy *HttpProxy) httpProxyHandler(responseWriter http.ResponseWriter, request *http.Request) {
	proxy.relayHTTPRequest(nil, proxy.httpProxyTunneledRelay, request, responseWriter, nil, nil)
}

const (
	URL_PROXY_TUNNELED_REQUEST_PATH         = "/tunneled/"
	URL_PROXY_TUNNELED_REWRITE_REQUEST_PATH = "/tunneled-rewrite/"
	URL_PROXY_TUNNELED_ICY_REQUEST_PATH     = "/tunneled-icy/"
	URL_PROXY_DIRECT_REQUEST_PATH           = "/direct/"
)

func (proxy *HttpProxy) urlProxyHandler(responseWriter http.ResponseWriter, request *http.Request) {

	var client *http.Client
	var rewriteICYStatus *rewriteICYStatus
	var originURLString string
	var err error
	var rewrites url.Values

	// Request URL should be "/tunneled/<origin URL>" or  "/direct/<origin URL>" and the
	// origin URL must be URL encoded.
	switch {
	case strings.HasPrefix(request.URL.RawPath, URL_PROXY_TUNNELED_REQUEST_PATH):
		originURLString, err = url.QueryUnescape(request.URL.RawPath[len(URL_PROXY_TUNNELED_REQUEST_PATH):])
		client = proxy.urlProxyTunneledClient

	case strings.HasPrefix(request.URL.RawPath, URL_PROXY_TUNNELED_REWRITE_REQUEST_PATH):
		originURLString, err = url.QueryUnescape(request.URL.RawPath[len(URL_PROXY_TUNNELED_REWRITE_REQUEST_PATH):])
		client = proxy.urlProxyTunneledClient
		rewrites = request.URL.Query()

	case strings.HasPrefix(request.URL.RawPath, URL_PROXY_TUNNELED_ICY_REQUEST_PATH):
		originURLString, err = url.QueryUnescape(request.URL.RawPath[len(URL_PROXY_TUNNELED_ICY_REQUEST_PATH):])
		client, rewriteICYStatus = proxy.makeRewriteICYClient()
		rewrites = request.URL.Query()

	case strings.HasPrefix(request.URL.RawPath, URL_PROXY_DIRECT_REQUEST_PATH):
		originURLString, err = url.QueryUnescape(request.URL.RawPath[len(URL_PROXY_DIRECT_REQUEST_PATH):])
		client = proxy.urlProxyDirectClient

	default:
		err = std_errors.New("missing origin URL")
	}
	if err != nil {
		NoticeWarning("%s", errors.Trace(FilterUrlError(err)))
		forceClose(responseWriter)
		return
	}

	// Origin URL must be well-formed, absolute, and have a scheme of "http" or "https"
	originURL, err := url.ParseRequestURI(originURLString)
	if err != nil {
		NoticeWarning("%s", errors.Trace(FilterUrlError(err)))
		forceClose(responseWriter)
		return
	}
	if !originURL.IsAbs() || (originURL.Scheme != "http" && originURL.Scheme != "https") {
		NoticeWarning("invalid origin URL")
		forceClose(responseWriter)
		return
	}

	// Transform received request to directly reference the origin URL
	request.Host = originURL.Host
	request.URL = originURL

	proxy.relayHTTPRequest(client, nil, request, responseWriter, rewrites, rewriteICYStatus)
}

// rewriteICYConn rewrites an ICY procotol responses to that it may be
// consumed by Go's http package. rewriteICYConn expects the ICY response to
// be equivalent to HTTP/1.1 with the exception of the protocol name in the
// status line, which is the one part that is rewritten. Responses that are
// already HTTP are passed through unmodified.
type rewriteICYConn struct {
	net.Conn
	doneRewriting int32
	isICY         *int32
}

func (conn *rewriteICYConn) Read(b []byte) (int, error) {

	if !atomic.CompareAndSwapInt32(&conn.doneRewriting, 0, 1) {
		return conn.Conn.Read(b)
	}

	if len(b) < 3 {
		// Don't attempt to rewrite the protocol when insufficient
		// buffer space. This is not expected to happen in practise
		// when Go's http reads the response, so for now we just
		// skip the rewrite instead of tracking state accross Reads.
		return conn.Conn.Read(b)
	}

	// Expect to read either "ICY" or "HTT".

	n, err := conn.Conn.Read(b[:3])
	if err != nil {
		return n, err
	}

	if bytes.Equal(b[:3], []byte("ICY")) {
		atomic.StoreInt32(conn.isICY, 1)
		protocol := "HTTP/1.0"
		copy(b, []byte(protocol))
		return len(protocol), nil
	}

	return n, nil
}

type rewriteICYStatus struct {
	isFirstConnICY int32
}

func (status *rewriteICYStatus) isICY() bool {
	return atomic.LoadInt32(&status.isFirstConnICY) == 1
}

// makeRewriteICYClient creates an http.Client with a Transport configured to
// use rewriteICYConn. Both HTTP and HTTPS are handled. The http.Client is
// intended to be used for one single request. The client disables keep alives
// as rewriteICYConn can only rewrite the first response in a connection. The
// returned rewriteICYStatus indicates whether the first response for the first
// request was ICY, allowing the downstream relayed response to replicate the
// ICY protocol.
func (proxy *HttpProxy) makeRewriteICYClient() (*http.Client, *rewriteICYStatus) {

	rewriteICYStatus := &rewriteICYStatus{}

	tunneledDialer := func(_, addr string) (conn net.Conn, err error) {
		// See comment in NewHttpProxy regarding downstreamConn
		return proxy.tunneler.Dial(addr, false, nil)
	}

	dial := func(network, address string) (net.Conn, error) {

		conn, err := tunneledDialer(network, address)
		if err != nil {
			return nil, errors.Trace(err)
		}

		return &rewriteICYConn{
			Conn:  conn,
			isICY: &rewriteICYStatus.isFirstConnICY,
		}, nil
	}

	dialTLS := func(network, address string) (net.Conn, error) {

		conn, err := tunneledDialer(network, address)
		if err != nil {
			return nil, errors.Trace(err)
		}

		serverName, _, err := net.SplitHostPort(address)
		if err != nil {
			conn.Close()
			return nil, errors.Trace(err)
		}

		tlsConn := tls.Client(conn, &tls.Config{ServerName: serverName})

		resultChannel := make(chan error, 1)

		timeout := proxy.responseHeaderTimeout
		afterFunc := time.AfterFunc(timeout, func() {
			resultChannel <- errors.TraceNew("TLS handshake timeout")
		})
		defer afterFunc.Stop()

		go func() {
			resultChannel <- tlsConn.Handshake()
		}()

		err = <-resultChannel
		if err != nil {
			conn.Close()
			return nil, errors.Trace(err)
		}

		err = tlsConn.VerifyHostname(serverName)
		if err != nil {
			conn.Close()
			return nil, errors.Trace(err)
		}

		return &rewriteICYConn{
			Conn:  tlsConn,
			isICY: &rewriteICYStatus.isFirstConnICY,
		}, nil

	}

	return &http.Client{
		Transport: &http.Transport{
			Dial:                  dial,
			DialTLS:               dialTLS,
			DisableKeepAlives:     true,
			ResponseHeaderTimeout: proxy.responseHeaderTimeout,
		},
	}, rewriteICYStatus
}

func (proxy *HttpProxy) relayHTTPRequest(
	client *http.Client,
	transport *http.Transport,
	request *http.Request,
	responseWriter http.ResponseWriter,
	rewrites url.Values,
	rewriteICYStatus *rewriteICYStatus) {

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
		NoticeWarning("%s", errors.Trace(FilterUrlError(err)))
		forceClose(responseWriter)
		return
	}

	defer response.Body.Close()

	// Note: Rewrite functions are responsible for leaving response.Body in
	// a valid, readable state if there's no error.

	for key := range rewrites {
		var err error

		switch key {
		case "m3u8":
			err = rewriteM3U8(proxy.listenIP, proxy.listenPort, response)
		}

		if err != nil {
			NoticeWarning("URL proxy rewrite failed for %s: %s", key, errors.Trace(err))
			forceClose(responseWriter)
			response.Body.Close()
			return
		}
	}

	// Relay the remote response headers

	for _, key := range hopHeaders {
		response.Header.Del(key)
	}
	for key := range responseWriter.Header() {
		responseWriter.Header().Del(key)
	}
	for key, values := range response.Header {
		for _, value := range values {
			responseWriter.Header().Add(key, value)
		}
	}

	// Send the response downstream

	if rewriteICYStatus != nil && rewriteICYStatus.isICY() {

		// Custom ICY response, using "ICY" as the protocol name
		// but otherwise equivalent to the HTTP response.

		// As the ICY http.Transport has disabled keep-alives,
		// hijacking here does not disrupt an otherwise persistent
		// connection.

		conn := hijack(responseWriter)
		if conn == nil {
			// hijack emits an alert notice
			return
		}

		_, err := fmt.Fprintf(
			conn,
			"ICY %d %s\r\n",
			response.StatusCode,
			http.StatusText(response.StatusCode))
		if err != nil {
			NoticeWarning("write status line failed: %s", errors.Trace(err))
			conn.Close()
			return
		}

		err = responseWriter.Header().Write(conn)
		if err != nil {
			NoticeWarning("write headers failed: %s", errors.Trace(err))
			conn.Close()
			return
		}

		_, err = io.Copy(conn, response.Body)
		if err != nil {
			NoticeWarning("write body failed: %s", errors.Trace(err))
			conn.Close()
			return
		}

	} else {

		// Standard HTTP response.

		responseWriter.WriteHeader(response.StatusCode)
		_, err = io.Copy(responseWriter, response.Body)
		if err != nil {
			NoticeWarning("%s", errors.Trace(err))
			forceClose(responseWriter)
			return
		}
	}
}

// forceClose hijacks and closes persistent connections. This is used
// to ensure local persistent connections into the HTTP proxy are closed
// when ServeHTTP encounters an error.
func forceClose(responseWriter http.ResponseWriter) {
	conn := hijack(responseWriter)
	if conn != nil {
		conn.Close()
	}
}

func hijack(responseWriter http.ResponseWriter) net.Conn {
	hijacker, ok := responseWriter.(http.Hijacker)
	if !ok {
		NoticeWarning("%s", errors.TraceNew("responseWriter is not an http.Hijacker"))
		return nil
	}
	conn, _, err := hijacker.Hijack()
	if err != nil {
		NoticeWarning("%s", errors.Tracef("responseWriter hijack failed: %s", err))
		return nil
	}
	return conn
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
			NoticeLocalProxyError(_HTTP_PROXY_TYPE, errors.Trace(err))
		}
	}
	NoticeInfo("HTTP proxy stopped")
}

//
// Rewrite functions
//

// toAbsoluteURL takes a base URL and a relative URL and constructs an appropriate absolute URL.
func toAbsoluteURL(baseURL *url.URL, relativeURLString string) string {
	relativeURL, err := url.Parse(relativeURLString)

	if err != nil {
		return ""
	}

	if relativeURL.IsAbs() {
		return relativeURL.String()
	}

	return baseURL.ResolveReference(relativeURL).String()
}

// proxifyURL takes an absolute URL and rewrites it to go through the local URL proxy.
// urlProxy port is the local HTTP proxy port.
//
// If rewriteParams is nil, then no rewriting will be done. Otherwise, it should contain
// supported rewriting flags (like "m3u8").
func proxifyURL(localHTTPProxyIP string, localHTTPProxyPort int, urlString string, rewriteParams []string) string {

	// Note that we need to use the "opaque" form of URL so that it doesn't double-escape the path. See: https://github.com/golang/go/issues/10887

	// TODO: IPv6 support
	if localHTTPProxyIP == "0.0.0.0" {
		localHTTPProxyIP = "127.0.0.1"
	}

	proxyPath := URL_PROXY_TUNNELED_REQUEST_PATH
	if rewriteParams != nil {
		proxyPath = URL_PROXY_TUNNELED_REWRITE_REQUEST_PATH
	}
	opaqueFormat := fmt.Sprintf("//%%s:%%d%s%%s", proxyPath)

	var proxifiedURL url.URL

	proxifiedURL.Scheme = "http"
	proxifiedURL.Opaque = fmt.Sprintf(opaqueFormat, localHTTPProxyIP, localHTTPProxyPort, url.QueryEscape(urlString))

	qp := proxifiedURL.Query()
	for _, rewrite := range rewriteParams {
		qp.Set(rewrite, "")
	}
	proxifiedURL.RawQuery = qp.Encode()

	return proxifiedURL.String()
}

// Rewrite the contents of the M3U8 file in body to be compatible with URL proxying.
// If error is returned, response body may not be valid for reading.
func rewriteM3U8(localHTTPProxyIP string, localHTTPProxyPort int, response *http.Response) error {
	// Check URL path extension
	extension := filepath.Ext(response.Request.URL.Path)
	var shouldHandle = (extension == ".m3u8")

	// If not .m3u8 then check content type
	if !shouldHandle {
		contentType := strings.ToLower(response.Header.Get("Content-Type"))
		shouldHandle = (contentType == "application/x-mpegurl" || contentType == "vnd.apple.mpegurl")
	}

	if !shouldHandle {
		return nil
	}

	var reader io.ReadCloser

	switch response.Header.Get("Content-Encoding") {
	case "gzip":
		var err error

		reader, err = gzip.NewReader(response.Body)
		if err != nil {
			return errors.Trace(err)
		}

		// Unset Content-Encoding.
		// There's is no point in deflating the decoded/rewritten content
		response.Header.Del("Content-Encoding")
		defer reader.Close()
	default:
		reader = response.Body
	}

	contentBodyBytes, err := ioutil.ReadAll(reader)
	response.Body.Close()

	if err != nil {
		return errors.Trace(err)
	}

	p, listType, err := m3u8.Decode(*bytes.NewBuffer(contentBodyBytes), true)
	if err != nil {
		// Don't pass this error up. Just don't change anything.
		response.Body = ioutil.NopCloser(bytes.NewReader(contentBodyBytes))
		response.Header.Set("Content-Length", strconv.FormatInt(int64(len(contentBodyBytes)), 10))
		return nil
	}

	var rewrittenBodyBytes []byte

	switch listType {
	case m3u8.MEDIA:
		mediapl := p.(*m3u8.MediaPlaylist)
		for _, segment := range mediapl.Segments {
			if segment == nil {
				break
			}

			if segment.URI != "" {
				segment.URI = proxifyURL(localHTTPProxyIP, localHTTPProxyPort, toAbsoluteURL(response.Request.URL, segment.URI), nil)
			}

			if segment.Key != nil && segment.Key.URI != "" {
				segment.Key.URI = proxifyURL(localHTTPProxyIP, localHTTPProxyPort, toAbsoluteURL(response.Request.URL, segment.Key.URI), nil)
			}

			if segment.Map != nil && segment.Map.URI != "" {
				segment.Map.URI = proxifyURL(localHTTPProxyIP, localHTTPProxyPort, toAbsoluteURL(response.Request.URL, segment.Map.URI), nil)
			}
		}
		rewrittenBodyBytes = []byte(mediapl.String())
	case m3u8.MASTER:
		masterpl := p.(*m3u8.MasterPlaylist)
		for _, variant := range masterpl.Variants {
			if variant == nil {
				break
			}

			if variant.URI != "" {
				variant.URI = proxifyURL(localHTTPProxyIP, localHTTPProxyPort, toAbsoluteURL(response.Request.URL, variant.URI), []string{"m3u8"})
			}

			for _, alternative := range variant.Alternatives {
				if alternative == nil {
					break
				}

				if alternative.URI != "" {
					alternative.URI = proxifyURL(localHTTPProxyIP, localHTTPProxyPort, toAbsoluteURL(response.Request.URL, alternative.URI), []string{"m3u8"})
				}
			}
		}
		rewrittenBodyBytes = []byte(masterpl.String())
	}

	var responseBodyBytes []byte

	if len(rewrittenBodyBytes) == 0 {
		responseBodyBytes = contentBodyBytes[:]
	} else {
		responseBodyBytes = rewrittenBodyBytes[:]
		// When rewriting the original URL so that it was URL-proxied, we lost the
		// file extension of it. That means we'd better make sure the Content-Type is set.
		response.Header.Set("Content-Type", "application/x-mpegurl")
	}

	response.Header.Set("Content-Length", strconv.FormatInt(int64(len(responseBodyBytes)), 10))
	response.Body = ioutil.NopCloser(bytes.NewReader(responseBodyBytes))

	return nil
}
