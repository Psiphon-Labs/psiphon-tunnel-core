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
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
	"sync"
)

const HTTP_STAT_LINE_LENGTH = 12

// ProxyAuthTransport provides support for proxy authentication when doing plain HTTP
// by tapping into HTTP conversation and adding authentication headers to the requests
// when requested by server
type ProxyAuthTransport struct {
	*http.Transport
	Username      string
	Password      string
	Authenticator HttpAuthenticator
	mu            sync.Mutex
	CustomHeaders http.Header
}

func NewProxyAuthTransport(
	rawTransport *http.Transport,
	customHeaders http.Header) (*ProxyAuthTransport, error) {

	if rawTransport.DialContext == nil {
		return nil, fmt.Errorf("rawTransport must have DialContext")
	}

	if rawTransport.Proxy == nil {
		return nil, fmt.Errorf("rawTransport must have Proxy")
	}

	tr := &ProxyAuthTransport{
		Transport:     rawTransport,
		CustomHeaders: customHeaders,
	}

	// Wrap the original transport's custom dialed conns in transportConns,
	// which handle connection-based authentication.
	originalDialContext := rawTransport.DialContext
	rawTransport.DialContext = func(
		ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := originalDialContext(ctx, "tcp", addr)
		if err != nil {
			return nil, err
		}
		// Any additional dials made by transportConn are within
		// the original dial context.
		return newTransportConn(ctx, conn, tr), nil
	}

	proxyUrl, err := rawTransport.Proxy(nil)
	if err != nil {
		return nil, err
	}
	if proxyUrl.Scheme != "http" {
		return nil, fmt.Errorf("%s unsupported", proxyUrl.Scheme)
	}
	if proxyUrl.User != nil {
		tr.Username = proxyUrl.User.Username()
		tr.Password, _ = proxyUrl.User.Password()
	}
	// strip username and password from the proxyURL because
	// we do not want the wrapped transport to handle authentication
	proxyUrl.User = nil
	rawTransport.Proxy = http.ProxyURL(proxyUrl)

	return tr, nil
}

func (tr *ProxyAuthTransport) preAuthenticateRequest(req *http.Request) error {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	if tr.Authenticator == nil {
		return nil
	}
	return tr.Authenticator.PreAuthenticate(req)
}

func (tr *ProxyAuthTransport) RoundTrip(req *http.Request) (resp *http.Response, err error) {
	if req.URL.Scheme != "http" {
		return nil, fmt.Errorf("%s unsupported", req.URL.Scheme)
	}
	err = tr.preAuthenticateRequest(req)
	if err != nil {
		return nil, err
	}

	var ha HttpAuthenticator

	// Clone request early because RoundTrip will destroy request Body
	// Also add custom headers to the cloned request
	newReq := cloneRequest(req, tr.CustomHeaders)

	resp, err = tr.Transport.RoundTrip(newReq)

	if err != nil {
		return resp, proxyError(err)
	}

	if resp.StatusCode == 407 {
		tr.mu.Lock()
		defer tr.mu.Unlock()
		ha, err = NewHttpAuthenticator(resp, tr.Username, tr.Password)
		if err != nil {
			return nil, err
		}
		if ha.IsConnectionBased() {
			return nil, proxyError(fmt.Errorf("Connection based auth was not handled by transportConn!"))
		}
		tr.Authenticator = ha
	authenticationLoop:
		for {
			newReq = cloneRequest(req, tr.CustomHeaders)
			err = tr.Authenticator.Authenticate(newReq, resp)
			if err != nil {
				return nil, err
			}
			resp, err = tr.Transport.RoundTrip(newReq)

			if err != nil {
				return resp, proxyError(err)
			}
			if resp.StatusCode != 407 {
				if tr.Authenticator != nil && tr.Authenticator.IsComplete() {
					tr.Authenticator.Reset()
				}
				break authenticationLoop
			} else {
			}
		}
	}
	return resp, err

}

// Based on https://github.com/golang/oauth2/blob/master/transport.go
// Copyright 2014 The Go Authors. All rights reserved.
func cloneRequest(r *http.Request, ch http.Header) *http.Request {
	// shallow copy of the struct
	r2 := new(http.Request)
	*r2 = *r
	// deep copy of the Header
	r2.Header = make(http.Header)
	for k, s := range r.Header {
		r2.Header[k] = s
	}

	//Add custom headers to the cloned request
	for k, s := range ch {
		// handle special Host header case
		if k == "Host" {
			if len(s) > 0 {
				// hack around special case when http proxy is used:
				// https://golang.org/src/net/http/request.go#L474
				// using URL.Opaque, see URL.RequestURI() https://golang.org/src/net/url/url.go#L915
				if r2.URL.Opaque == "" {
					r2.URL.Opaque = r2.URL.Scheme + "://" + r2.Host + r2.URL.RequestURI()
				}
				r2.Host = s[0]
			}
		} else {
			r2.Header[k] = s
		}
	}

	if r.Body != nil {
		body, _ := ioutil.ReadAll(r.Body)
		defer r.Body.Close()
		// restore original request Body
		// drained by ReadAll()
		r.Body = ioutil.NopCloser(bytes.NewReader(body))

		r2.Body = ioutil.NopCloser(bytes.NewReader(body))
	}

	// A replayed request inherits the original request's deadline (and interruptability).
	r2 = r2.WithContext(r.Context())

	return r2
}

type transportConn struct {
	net.Conn
	ctx                context.Context
	requestInterceptor io.Writer
	reqDone            chan struct{}
	errChannel         chan error
	lastRequest        *http.Request
	authenticator      HttpAuthenticator
	transport          *ProxyAuthTransport
}

func newTransportConn(
	ctx context.Context,
	c net.Conn,
	tr *ProxyAuthTransport) *transportConn {

	// TODOs:
	//
	// - Additional dials made by transportConn, for authentication, use the
	//   original conn's dial context. If authentication can be requested at any
	//   time, instead of just at the start of a connection, then any deadline for
	//   this context will be inappropriate.
	//
	// - The "intercept" goroutine spawned below will never terminate? Even if the
	//   transportConn is closed, nothing will unblock reads of the pipe made by
	//   http.ReadRequest. There should be a call to pw.Close() in transportConn.Close().
	//
	// - The ioutil.ReadAll in the "intercept" goroutine allocates new buffers for
	//   every request. To avoid GC churn it should use a byte.Buffer to reuse a
	//   single buffer. In practise, there will be a reasonably small maximum request
	//   body size, so its better to retain and reuse a buffer than to continously
	//   reallocate.
	//
	// - transportConn.Read will not do anything if the caller passes in a very small
	//   read buffer. This should be documented, as its assuming that the caller is
	//   fully reading at least HTTP_STAT_LINE_LENGTH at the start of request.
	//
	// - As a net.Conn, transportConn.Read should always be interrupted by a call to
	//   Close, but it may be possible for Read to remain blocked:
	//   1. caller writes less than a full request to Write
	//   2. "intercept" call to http.ReadRequest will not return
	//   3. caller calls Close, which just calls transportConn.Conn.Close
	//   4. any existing call to Read remains blocked in the select

	tc := &transportConn{
		Conn:       c,
		ctx:        ctx,
		reqDone:    make(chan struct{}),
		errChannel: make(chan error),
		transport:  tr,
	}
	// Intercept outgoing request as it is written out to server and store it
	// in case it needs to be authenticated and replayed
	//NOTE that pipelining is currently not supported
	pr, pw := io.Pipe()
	tc.requestInterceptor = pw
	requestReader := bufio.NewReader(pr)
	go func() {
	requestInterceptLoop:
		for {
			req, err := http.ReadRequest(requestReader)
			if err != nil {
				tc.Conn.Close()
				pr.Close()
				pw.Close()
				tc.errChannel <- fmt.Errorf("intercept request loop http.ReadRequest error: %s", err)
				break requestInterceptLoop
			}
			//read and copy entire body
			body, _ := ioutil.ReadAll(req.Body)
			tc.lastRequest = req
			tc.lastRequest.Body = ioutil.NopCloser(bytes.NewReader(body))
			//Signal when we have a complete request
			tc.reqDone <- struct{}{}
		}
	}()
	return tc
}

// Read peeks into the new response and checks if the proxy requests authentication
// If so, the last intercepted request is authenticated against the response
// in case of connection based auth scheme(i.e. NTLM)
// All the non-connection based schemes are handled by the ProxyAuthTransport.RoundTrip()
func (tc *transportConn) Read(p []byte) (n int, readErr error) {
	n, readErr = tc.Conn.Read(p)
	if n < HTTP_STAT_LINE_LENGTH {
		return
	}
	select {
	case _ = <-tc.reqDone:
		line := string(p[:HTTP_STAT_LINE_LENGTH])
		//This is a new response
		//Let's see if proxy requests authentication
		f := strings.SplitN(line, " ", 2)

		readBufferReader := io.NewSectionReader(bytes.NewReader(p), 0, int64(n))
		responseReader := bufio.NewReader(readBufferReader)
		if (f[0] == "HTTP/1.0" || f[0] == "HTTP/1.1") && f[1] == "407" {
			resp, err := http.ReadResponse(responseReader, nil)
			if err != nil {
				return 0, err
			}
			ha, err := NewHttpAuthenticator(resp, tc.transport.Username, tc.transport.Password)
			if err != nil {
				return 0, err
			}
			// If connection based auth is requested, we are going to
			// authenticate request on this very connection
			// otherwise just return what we read
			if !ha.IsConnectionBased() {
				return
			}

			// Drain the rest of the response
			// in order to perform auth handshake
			// on the connection
			readBufferReader.Seek(0, 0)
			responseReader = bufio.NewReader(io.MultiReader(readBufferReader, tc.Conn))
			resp, err = http.ReadResponse(responseReader, nil)
			if err != nil {
				return 0, err
			}

			ioutil.ReadAll(resp.Body)
			resp.Body.Close()

			if tc.authenticator == nil {
				tc.authenticator = ha
			}

			if resp.Close == true {
				// Server side indicated that it is closing this connection,
				// dial a new one
				addr := tc.Conn.RemoteAddr()
				tc.Conn.Close()

				// Additional dials are made within the context of the dial of the
				// outer conn this transportConn is wrapping, so the scope of outer
				// dial timeouts includes these additional dials. This is also to
				// ensure these dials are interrupted when the context is canceled.

				tc.Conn, err = tc.transport.Transport.DialContext(
					tc.ctx, addr.Network(), addr.String())

				if err != nil {
					return 0, err
				}
			}

			// Authenticate and replay the request on the connection
			err = tc.authenticator.Authenticate(tc.lastRequest, resp)
			if err != nil {
				return 0, err
			}
			tc.lastRequest.WriteProxy(tc)
			return tc.Read(p)
		}
	case err := <-tc.errChannel:
		return 0, err
	default:
	}
	return
}

func (tc *transportConn) Write(p []byte) (n int, err error) {
	n, err = tc.Conn.Write(p)
	//also write data to the request interceptor
	tc.requestInterceptor.Write(p[:n])
	return n, err
}
