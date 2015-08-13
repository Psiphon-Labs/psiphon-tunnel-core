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
	"encoding/base64"
	"fmt"
	"net/http"
)

type BasicHttpAuthState int

const (
	BASIC_HTTP_AUTH_STATE_CHALLENGE_RECEIVED BasicHttpAuthState = iota
	BASIC_HTTP_AUTH_STATE_RESPONSE_GENERATED
)

type BasicHttpAuthenticator struct {
	state    BasicHttpAuthState
	username string
	password string
}

func newBasicAuthenticator(username, password string) *BasicHttpAuthenticator {
	return &BasicHttpAuthenticator{
		state:    BASIC_HTTP_AUTH_STATE_CHALLENGE_RECEIVED,
		username: username,
		password: password,
	}
}

func (a *BasicHttpAuthenticator) Authenticate(req *http.Request, resp *http.Response) error {
	if a.state == BASIC_HTTP_AUTH_STATE_CHALLENGE_RECEIVED {
		a.state = BASIC_HTTP_AUTH_STATE_RESPONSE_GENERATED
		return a.PreAuthenticate(req)
	} else {
		return proxyError(fmt.Errorf("Authorization is not accepted by the proxy server"))
	}
}

func (a *BasicHttpAuthenticator) IsConnectionBased() bool {
	return false
}

func (a *BasicHttpAuthenticator) IsComplete() bool {
	return a.state == BASIC_HTTP_AUTH_STATE_RESPONSE_GENERATED
}

func (a *BasicHttpAuthenticator) Reset() {
	a.state = BASIC_HTTP_AUTH_STATE_CHALLENGE_RECEIVED
}

func (a *BasicHttpAuthenticator) PreAuthenticate(req *http.Request) error {
	auth := a.username + ":" + a.password
	req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(auth)))
	return nil
}
