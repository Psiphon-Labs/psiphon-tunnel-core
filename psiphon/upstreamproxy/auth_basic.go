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
	"errors"
	"net/http"
)

type BasicHttpAuthState int

const (
	BASIC_HTTP_AUTH_STATE_CHALLENGE_RECEIVED BasicHttpAuthState = iota
	BASIC_HTTP_AUTH_STATE_RESPONSE_GENERATED
)

type BasicHttpAuthenticator struct {
	state BasicHttpAuthState
}

func newBasicAuthenticator() *BasicHttpAuthenticator {
	return &BasicHttpAuthenticator{state: BASIC_HTTP_AUTH_STATE_CHALLENGE_RECEIVED}
}

func (a *BasicHttpAuthenticator) Authenticate(req *http.Request, resp *http.Response, username, password string) error {
	if a.state == BASIC_HTTP_AUTH_STATE_CHALLENGE_RECEIVED {
		auth := username + ":" + password
		req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(auth)))
		a.state = BASIC_HTTP_AUTH_STATE_RESPONSE_GENERATED
		return nil
	} else {
		return errors.New("upstreamproxy: Authorization is not accepted by the proxy server")
	}
}
