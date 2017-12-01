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
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
)

// ProxyAuthTransport provides support for proxy authentication when doing plain HTTP
// by tapping into HTTP conversation and adding authentication headers to the requests
// when requested by server
//
// Limitation: in violation of https://golang.org/pkg/net/http/#RoundTripper,
// ProxyAuthTransport is _not_ safe for concurrent RoundTrip calls. This is acceptable
// for its use in Psiphon to provide upstream proxy support for meek, which makes only
// serial RoundTrip calls. Concurrent RoundTrip calls will result in data race conditions
// and undefined behavior during an authentication handshake.
type ProxyAuthTransport struct {
	*http.Transport
	username         string
	password         string
	authenticator    HttpAuthenticator
	customHeaders    http.Header
	clonedBodyBuffer bytes.Buffer
}

func NewProxyAuthTransport(
	rawTransport *http.Transport,
	customHeaders http.Header) (*ProxyAuthTransport, error) {

	if rawTransport.Proxy == nil {
		return nil, fmt.Errorf("rawTransport must have Proxy")
	}

	tr := &ProxyAuthTransport{
		Transport:     rawTransport,
		customHeaders: customHeaders,
	}

	proxyUrl, err := rawTransport.Proxy(nil)
	if err != nil {
		return nil, err
	}
	if proxyUrl.Scheme != "http" {
		return nil, fmt.Errorf("%s unsupported", proxyUrl.Scheme)
	}
	if proxyUrl.User != nil {
		tr.username = proxyUrl.User.Username()
		tr.password, _ = proxyUrl.User.Password()
	}
	// strip username and password from the proxyURL because
	// we do not want the wrapped transport to handle authentication
	proxyUrl.User = nil
	rawTransport.Proxy = http.ProxyURL(proxyUrl)

	return tr, nil
}

func (tr *ProxyAuthTransport) RoundTrip(request *http.Request) (*http.Response, error) {

	if request.URL.Scheme != "http" {
		return nil, fmt.Errorf("%s unsupported", request.URL.Scheme)
	}

	// Notes:
	//
	// - The 407 authentication loop assumes no concurrent calls of RoundTrip
	//   and additionally assumes that serial RoundTrip calls will always
	//   resuse any existing HTTP persistent conn. The entire authentication
	//   handshake must occur on the same HTTP persistent conn.
	//
	// - Requests are cloned for the lifetime of the ProxyAuthTransport,
	//   since we don't know when the next initial RoundTrip may need to enter
	//   the 407 authentication loop, which requires the initial request to be
	//   cloned and replayable. Even if we hook into the Close call for any
	//   existing HTTP persistent conn, it could be that it closes only after
	//   RoundTrip is called.
	//
	// - Cloning reuses a buffer (clonedBodyBuffer) to store the request body
	//   to avoid excessive allocations.

	var cachedRequestBody []byte
	if request.Body != nil {
		tr.clonedBodyBuffer.Reset()
		tr.clonedBodyBuffer.ReadFrom(request.Body)
		request.Body.Close()
		cachedRequestBody = tr.clonedBodyBuffer.Bytes()
	}

	clonedRequest := cloneRequest(
		request, tr.customHeaders, cachedRequestBody)

	if tr.authenticator != nil {

		// For some authentication schemes (e.g., non-connection-based), once
		// an initial 407 has been handled, add necessary and sufficient
		// authentication headers to every request.

		err := tr.authenticator.PreAuthenticate(clonedRequest)
		if err != nil {
			return nil, err
		}
	}

	response, err := tr.Transport.RoundTrip(clonedRequest)
	if err != nil {
		return response, proxyError(err)
	}

	if response.StatusCode == 407 {

		authenticator, err := NewHttpAuthenticator(
			response, tr.username, tr.password)
		if err != nil {
			response.Body.Close()
			return nil, err
		}

		for {
			clonedRequest = cloneRequest(
				request, tr.customHeaders, cachedRequestBody)

			err = authenticator.Authenticate(clonedRequest, response)
			response.Body.Close()
			if err != nil {
				return nil, err
			}

			response, err = tr.Transport.RoundTrip(clonedRequest)
			if err != nil {
				return nil, proxyError(err)
			}

			if response.StatusCode != 407 {

				// Save the authenticator result to use for PreAuthenticate.

				tr.authenticator = authenticator
				break
			}
		}
	}

	return response, nil
}

// Based on https://github.com/golang/oauth2/blob/master/transport.go
// Copyright 2014 The Go Authors. All rights reserved.
func cloneRequest(r *http.Request, ch http.Header, body []byte) *http.Request {
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

	if body != nil {
		r2.Body = ioutil.NopCloser(bytes.NewReader(body))
	}

	// A replayed request inherits the original request's deadline (and interruptability).
	r2 = r2.WithContext(r.Context())

	return r2
}
