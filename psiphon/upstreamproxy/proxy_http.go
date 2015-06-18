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
 */

package upstreamproxy

import (
	"bufio"
	"errors"
	"fmt"
	"golang.org/x/net/proxy"
	//"io/ioutil"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"
)

type HttpAuthState int

const (
	HTTP_AUTH_STATE_UNCHALLENGED HttpAuthState = iota
	HTTP_AUTH_STATE_CHALLENGED
	HTTP_AUTH_STATE_FAILURE
	HTTP_AUTH_STATE_SUCCESS
)

func authenticateRequest(req *http.Request, resp *http.Response, username, pasword string) error {
	challenges := make(map[string]string)
	headers := resp.Header[http.CanonicalHeaderKey("proxy-authenticate")]

	for _, val := range headers {
		s := strings.SplitN(val, " ", 2)
		if len(s) == 2 {
			challenges[s[0]] = s[1]
		}
		if len(s) == 1 && s[0] != "" {
			challenges[s[0]] = ""
		}
	}
	if len(challenges) == 0 {
		return fmt.Errorf("No valid challenges in the Proxy-Authenticate header")
	}
	// NTLM > Digest > Basic
	if challenge, ok := challenges["NTLM"]; ok {
		return ntlmAuthenticate(req, challenge, username, pasword)
	} else if challenge, ok := challenges["Digest"]; ok {
		return digestAuthenticate(req, challenge, username, pasword)
	} else if challenge, ok := challenges["Basic"]; ok {
		return basicAuthenticate(req, challenge, username, pasword)
	}

	//Unsupported scheme
	schemes := make([]string, 0, len(challenges))
	for scheme := range challenges {
		schemes = append(schemes, scheme)
	}
	return fmt.Errorf("Unsupported proxy authentication scheme in %v", schemes)
}

// httpProxy is a HTTP connect proxy.
type httpProxy struct {
	hostPort string
	username string
	password string
	forward  proxy.Dialer
}

func newHTTP(uri *url.URL, forward proxy.Dialer) (proxy.Dialer, error) {
	hp := new(httpProxy)
	hp.hostPort = uri.Host
	hp.forward = forward
	if uri.User != nil {
		hp.username = uri.User.Username()
		hp.password, _ = uri.User.Password()
	}

	return hp, nil
}

func (hp *httpProxy) Dial(network, addr string) (net.Conn, error) {
	// Dial and create the http client connection.

	pc := &proxyConn{authState: HTTP_AUTH_STATE_UNCHALLENGED}
	err := pc.makeNewClientConn(hp.forward, hp.hostPort)
	if err != nil {
		return nil, fmt.Errorf("makeNewClientConn error: %v", err)
	}

	//TODO: count handshake attempts
	for {
		err := pc.handshake(addr, hp.username, hp.password)
		switch pc.authState {
		case HTTP_AUTH_STATE_SUCCESS:
			pc.hijackedConn, pc.staleReader = pc.httpClientConn.Hijack()
			return pc, nil
		case HTTP_AUTH_STATE_FAILURE:
			return nil, err
		case HTTP_AUTH_STATE_CHALLENGED:
			// the server may send Connection: close,
			// at this point we just going to create a new
			// ClientConn and continue the handshake
			if err == httputil.ErrPersistEOF {
				err = pc.makeNewClientConn(hp.forward, hp.hostPort)
				if err != nil {
					return nil, fmt.Errorf("makeNewClientConn error: %v", err)
				}
			}
			continue
		default:
			panic("Illegal proxy handshake auth state")
		}
	}
	return nil, fmt.Errorf("Unknown handshake error")

}

type proxyConn struct {
	httpClientConn *httputil.ClientConn
	hijackedConn   net.Conn
	staleReader    *bufio.Reader
	authResponse   *http.Response
	authState      HttpAuthState
}

func (pc *proxyConn) handshake(addr, username, password string) error {
	// HACK HACK HACK HACK.  http.ReadRequest also does this.
	reqURL, err := url.Parse("http://" + addr)
	if err != nil {
		pc.httpClientConn.Close()
		pc.authState = HTTP_AUTH_STATE_FAILURE
		return err
	}
	reqURL.Scheme = ""

	req, err := http.NewRequest("CONNECT", reqURL.String(), nil)
	if err != nil {
		pc.httpClientConn.Close()
		pc.authState = HTTP_AUTH_STATE_FAILURE
		return err
	}
	req.Close = false
	req.Header.Set("User-Agent", "")

	if pc.authState == HTTP_AUTH_STATE_CHALLENGED {
		err := authenticateRequest(req, pc.authResponse, username, password)
		if err != nil {
			pc.authState = HTTP_AUTH_STATE_FAILURE
			return err
		}
	}

	resp, err := pc.httpClientConn.Do(req)

	if err != nil && err != httputil.ErrPersistEOF {
		pc.httpClientConn.Close()
		pc.authState = HTTP_AUTH_STATE_FAILURE
		return err
	}

	if resp.StatusCode == 200 {
		pc.authState = HTTP_AUTH_STATE_SUCCESS
		return nil
	}

	if resp.StatusCode == 407 {
		pc.authState = HTTP_AUTH_STATE_CHALLENGED
		pc.authResponse = resp
		if username == "" {
			pc.httpClientConn.Close()
			pc.authState = HTTP_AUTH_STATE_FAILURE
			return errors.New("No credentials provided for proxy auth")
		}
		return err
	}
	pc.authState = HTTP_AUTH_STATE_FAILURE
	return err
}

func (pc *proxyConn) makeNewClientConn(dialer proxy.Dialer, addr string) error {
	c, err := dialer.Dial("tcp", addr)
	if pc.httpClientConn != nil {
		pc.httpClientConn.Close()
	}
	if err != nil {
		return err
	}
	pc.httpClientConn = httputil.NewClientConn(c, nil)
	return nil
}

func (pc *proxyConn) Read(b []byte) (int, error) {
	if pc.staleReader != nil {
		if pc.staleReader.Buffered() > 0 {
			return pc.staleReader.Read(b)
		}
		pc.staleReader = nil
	}
	return pc.hijackedConn.Read(b)
}

func (pc *proxyConn) Write(b []byte) (int, error) {
	return pc.hijackedConn.Write(b)
}

func (pc *proxyConn) Close() error {
	return pc.hijackedConn.Close()
}

func (pc *proxyConn) LocalAddr() net.Addr {
	return nil
}

func (pc *proxyConn) RemoteAddr() net.Addr {
	return nil
}

func (pc *proxyConn) SetDeadline(t time.Time) error {
	return errors.New("not supported")
}

func (pc *proxyConn) SetReadDeadline(t time.Time) error {
	return errors.New("not supported")
}

func (pc *proxyConn) SetWriteDeadline(t time.Time) error {
	return errors.New("not supported")
}

func init() {
	proxy.RegisterDialerType("http", newHTTP)
}
