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
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/upstreamproxy/go-ntlm/ntlm"
	"net/http"
	"strings"
)

type NTLMHttpAuthState int

const (
	NTLM_HTTP_AUTH_STATE_CHALLENGE_RECEIVED NTLMHttpAuthState = iota
	NTLM_HTTP_AUTH_STATE_RESPONSE_TYPE1_GENERATED
	NTLM_HTTP_AUTH_STATE_RESPONSE_TYPE3_GENERATED
)

type NTLMHttpAuthenticator struct {
	state    NTLMHttpAuthState
	username string
	password string
}

func newNTLMAuthenticator(username, password string) *NTLMHttpAuthenticator {
	return &NTLMHttpAuthenticator{
		state:    NTLM_HTTP_AUTH_STATE_CHALLENGE_RECEIVED,
		username: username,
		password: password,
	}
}

func (a *NTLMHttpAuthenticator) Authenticate(req *http.Request, resp *http.Response) error {
	if a.state == NTLM_HTTP_AUTH_STATE_RESPONSE_TYPE3_GENERATED {
		return proxyError(fmt.Errorf("Authorization is not accepted by the proxy server"))
	}
	challenges, err := parseAuthChallenge(resp)

	challenge, ok := challenges["NTLM"]
	if challenge == "" {
		a.state = NTLM_HTTP_AUTH_STATE_CHALLENGE_RECEIVED
	} else {
		a.state = NTLM_HTTP_AUTH_STATE_RESPONSE_TYPE1_GENERATED
	}
	if !ok {
		return proxyError(fmt.Errorf("Bad proxy response, no NTLM challenge for NTLMHttpAuthenticator"))
	}

	var ntlmMsg []byte

	session, err := ntlm.CreateClientSession(ntlm.Version2, ntlm.ConnectionOrientedMode)
	if err != nil {
		return proxyError(err)
	}
	if a.state == NTLM_HTTP_AUTH_STATE_CHALLENGE_RECEIVED {
		//generate TYPE 1 message
		negotiate, err := session.GenerateNegotiateMessage()
		if err != nil {
			return proxyError(err)
		}
		ntlmMsg = negotiate.Bytes()
		a.state = NTLM_HTTP_AUTH_STATE_RESPONSE_TYPE1_GENERATED
		req.Header.Set("Proxy-Authorization", "NTLM "+base64.StdEncoding.EncodeToString(ntlmMsg))
		return nil
	} else if a.state == NTLM_HTTP_AUTH_STATE_RESPONSE_TYPE1_GENERATED {
		// Parse username for domain in form DOMAIN\username
		var NTDomain, NTUser string
		parts := strings.SplitN(a.username, "\\", 2)
		if len(parts) == 2 {
			NTDomain = parts[0]
			NTUser = parts[1]
		} else {
			NTDomain = ""
			NTUser = a.username
		}
		challengeBytes, err := base64.StdEncoding.DecodeString(challenge)
		if err != nil {
			return proxyError(fmt.Errorf("NTLM challeenge base 64 decoding: %v", err))
		}
		session.SetUserInfo(NTUser, a.password, NTDomain)
		ntlmChallenge, err := ntlm.ParseChallengeMessage(challengeBytes)
		if err != nil {
			return proxyError(err)
		}
		session.ProcessChallengeMessage(ntlmChallenge)
		authenticate, err := session.GenerateAuthenticateMessage()
		if err != nil {
			return proxyError(err)
		}
		ntlmMsg = authenticate.Bytes()
		a.state = NTLM_HTTP_AUTH_STATE_RESPONSE_TYPE3_GENERATED
		req.Header.Set("Proxy-Authorization", "NTLM "+base64.StdEncoding.EncodeToString(ntlmMsg))
		return nil
	}

	return proxyError(fmt.Errorf("Authorization is not accepted by the proxy server"))
}

func (a *NTLMHttpAuthenticator) IsConnectionBased() bool {
	return true
}

func (a *NTLMHttpAuthenticator) IsComplete() bool {
	return a.state == NTLM_HTTP_AUTH_STATE_RESPONSE_TYPE3_GENERATED
}

func (a *NTLMHttpAuthenticator) Reset() {
	a.state = NTLM_HTTP_AUTH_STATE_CHALLENGE_RECEIVED
}

func (a *NTLMHttpAuthenticator) PreAuthenticate(req *http.Request) error {
	return nil
}
