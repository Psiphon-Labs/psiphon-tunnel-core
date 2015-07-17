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
)

type ProxyAuthTransport struct {
	*http.Transport
	Dial     DialFunc
	Username string
	Password string
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
		proxyUrl, err := proxyUrlFn(nil)
		if err != nil {
			return nil, err
		}
		if proxyUrl.Scheme != "http" {
			return nil, fmt.Errorf("Only HTTP proxy supported, for SOCKS use http.Transport with custom dialers & upstreamproxy.NewProxyDialFunc")
		}
		tr.Username = proxyUrl.User.Username()
		tr.Password, _ = proxyUrl.User.Password()
		rawTransport.Dial = wrappedDialFn
	}

	tr.Transport = rawTransport
	return tr, nil
}

func (tr *ProxyAuthTransport) RoundTrip(req *http.Request) (resp *http.Response, err error) {
	if req.URL.Scheme != "http" {
		return nil, fmt.Errorf("Only plain HTTP supported, for HTTPS use http.Transport with DialTLS & upstreamproxy.NewProxyDialFunc")
	}
	return tr.Transport.RoundTrip(req)
}

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

type transportConn struct {
	net.Conn
	requestWriter io.Writer
	reqDone       chan struct{}
	errChannel    chan error
	connReader    *bufio.Reader
	lastRequest   *http.Request
	authenticator HttpAuthenticator
	authState     HttpAuthState
	transport     *ProxyAuthTransport
}

func newTransportConn(c net.Conn, tr *ProxyAuthTransport) *transportConn {
	tc := &transportConn{
		Conn:       c,
		reqDone:    make(chan struct{}),
		errChannel: make(chan error),
		connReader: bufio.NewReader(c),
		transport:  tr,
	}
	pr, pw := io.Pipe()
	tc.requestWriter = pw
	go func() {
	requestInterceptLoop:
		for {
			req, err := http.ReadRequest(bufio.NewReader(pr))
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
			tc.reqDone <- struct{}{}
		}
	}()
	return tc
}

func (tc *transportConn) Read(p []byte) (int, error) {
	/*
	   The first Read on a new RoundTrip will occur *before* Write and
	   will block until request is written out completely and response
	   headers are read in

	   Peek will actually call Read and buffer read data
	*/
	peeked, err := tc.connReader.Peek(12)
	if err != nil {
		return 0, err
	}
	line := string(peeked)
	select {
	case _ = <-tc.reqDone:
		//Brand new response
		f := strings.SplitN(line, " ", 2)
		if (f[0] == "HTTP/1.0" || f[0] == "HTTP/1.1") && f[1] == "407" {
			resp, err := http.ReadResponse(tc.connReader, nil)
			if err != nil {
				return 0, err
			}
			// make sure we read the body of the response so that
			// we don't block the reader
			ioutil.ReadAll(resp.Body)
			resp.Body.Close()

			if tc.authState == HTTP_AUTH_STATE_UNCHALLENGED {
				tc.authenticator, err = NewHttpAuthenticator(resp)
				if err != nil {
					return 0, err
				}
				tc.authState = HTTP_AUTH_STATE_CHALLENGED
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
				tc.connReader = bufio.NewReader(tc.Conn)
			}

			err = tc.authenticator.Authenticate(tc.lastRequest, resp, tc.transport.Username, tc.transport.Password)
			if err != nil {
				return 0, err
			}

			//Replay authenticated request
			tc.lastRequest.WriteProxy(tc)
			return tc.Read(p)
		}
	case err = <-tc.errChannel:
		return 0, err
	default:
	}
	n, err := tc.connReader.Read(p)
	return n, err
}

func (tc *transportConn) Write(p []byte) (n int, err error) {
	n, err = tc.Conn.Write(p)
	tc.requestWriter.Write(p[:n])
	return n, err
}
