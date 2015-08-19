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
	"fmt"
	"net/http"
	"strings"
)

type HttpAuthState int

const (
	HTTP_AUTH_STATE_UNCHALLENGED HttpAuthState = iota
	HTTP_AUTH_STATE_CHALLENGED
	HTTP_AUTH_STATE_FAILURE
	HTTP_AUTH_STATE_SUCCESS
)

type HttpAuthenticator interface {
	PreAuthenticate(req *http.Request) error
	Authenticate(req *http.Request, resp *http.Response) error
	IsConnectionBased() bool
	IsComplete() bool
	Reset()
}

func parseAuthChallenge(resp *http.Response) (map[string]string, error) {
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
		return nil, proxyError(fmt.Errorf("No valid challenges in the Proxy-Authenticate header"))
	}
	return challenges, nil
}

func NewHttpAuthenticator(resp *http.Response, username, password string) (HttpAuthenticator, error) {

	challenges, err := parseAuthChallenge(resp)
	if err != nil {
		//Already wrapped in proxyError
		return nil, err
	}

	// NTLM > Digest > Basic
	if _, ok := challenges["NTLM"]; ok {
		return newNTLMAuthenticator(username, password), nil
	} else if _, ok := challenges["Digest"]; ok {
		return newDigestAuthenticator(username, password), nil
	} else if _, ok := challenges["Basic"]; ok {
		return newBasicAuthenticator(username, password), nil
	}

	//Unsupported scheme
	schemes := make([]string, 0, len(challenges))
	for scheme := range challenges {
		schemes = append(schemes, scheme)
	}
	return nil, proxyError(fmt.Errorf("Unsupported proxy authentication scheme in %v", schemes))
}
