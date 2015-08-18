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
	Dial          DialFunc
	Username      string
	Password      string
	Authenticator HttpAuthenticator
	mu            sync.Mutex
}

func NewProxyAuthTransport(rawTransport *http.Transport) (*ProxyAuthTransport, error) {
	dialFn := rawTransport.Dial
	if dialFn == nil {
		dialFn = net.Dial
	}
	tr := &ProxyAuthTransport{Dial: dialFn}
	proxyUrlFn := rawTransport.Proxy
	if proxyUrlFn != nil {
		wrappedDialFn := tr.wrapTransportDial()
		rawTransport.Dial = wrappedDialFn
		proxyUrl, err := proxyUrlFn(nil)
		if err != nil {
			return nil, err
		}
		if proxyUrl.Scheme != "http" {
			return nil, fmt.Errorf("Only HTTP proxy supported, for SOCKS use http.Transport with custom dialers & upstreamproxy.NewProxyDialFunc")
		}
		if proxyUrl.User != nil {
			tr.Username = proxyUrl.User.Username()
			tr.Password, _ = proxyUrl.User.Password()
		}
		// strip username and password from the proxyURL because
		// we do not want the wrapped transport to handle authentication
		proxyUrl.User = nil
		rawTransport.Proxy = http.ProxyURL(proxyUrl)
	}

	tr.Transport = rawTransport
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
		return nil, fmt.Errorf("Only plain HTTP supported, for HTTPS use http.Transport with DialTLS & upstreamproxy.NewProxyDialFunc")
	}
	err = tr.preAuthenticateRequest(req)
	if err != nil {
		return nil, err
	}

	var ha HttpAuthenticator = nil

	//Clone request early because RoundTrip will destroy request Body
	newReq := cloneRequest(req)

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
			newReq = cloneRequest(req)
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

// wrapTransportDial wraps original transport Dial function
// and returns a new net.Conn interface provided by transportConn
// that allows us to intercept both outgoing requests and incoming
// responses and examine / mutate them
func (tr *ProxyAuthTransport) wrapTransportDial() DialFunc {
	return func(network, addr string) (net.Conn, error) {
		c, err := tr.Dial("tcp", addr)
		if err != nil {
			return nil, err
		}
		tc := newTransportConn(c, tr)
		return tc, nil
	}
}

func cloneRequest(r *http.Request) *http.Request {
	// shallow copy of the struct
	r2 := new(http.Request)
	*r2 = *r
	// deep copy of the Header
	r2.Header = make(http.Header)
	for k, s := range r.Header {
		r2.Header[k] = s
	}

	if r.Body != nil {
		body, _ := ioutil.ReadAll(r.Body)
		defer r.Body.Close()
		// restore original request Body
		// drained by ReadAll()
		r.Body = ioutil.NopCloser(bytes.NewReader(body))

		r2.Body = ioutil.NopCloser(bytes.NewReader(body))
	}
	return r2
}

type transportConn struct {
	net.Conn
	requestInterceptor io.Writer
	reqDone            chan struct{}
	errChannel         chan error
	lastRequest        *http.Request
	authenticator      HttpAuthenticator
	transport          *ProxyAuthTransport
}

func newTransportConn(c net.Conn, tr *ProxyAuthTransport) *transportConn {
	tc := &transportConn{
		Conn:       c,
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
func (tc *transportConn) Read(p []byte) (n int, read_err error) {
	n, read_err = tc.Conn.Read(p)
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
				tc.Conn, err = tc.transport.Dial(addr.Network(), addr.String())
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
