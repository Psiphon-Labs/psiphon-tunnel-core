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
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
)

type DigestHttpAuthState int

const (
	DIGEST_HTTP_AUTH_STATE_CHALLENGE_RECEIVED DigestHttpAuthState = iota
	DIGEST_HTTP_AUTH_STATE_RESPONSE_GENERATED
)

type DigestHttpAuthenticator struct {
	state         DigestHttpAuthState
	username      string
	password      string
	digestHeaders *DigestHeaders
}

func newDigestAuthenticator(username, password string) *DigestHttpAuthenticator {
	return &DigestHttpAuthenticator{
		state:    DIGEST_HTTP_AUTH_STATE_CHALLENGE_RECEIVED,
		username: username,
		password: password,
	}
}

/* Adapted from https://github.com/ryanjdew/http-digest-auth-client */

type DigestHeaders struct {
	Realm     string
	Qop       string
	Method    string
	Nonce     string
	Opaque    string
	Algorithm string
	HA1       string
	HA2       string
	Cnonce    string
	Uri       string
	Nc        int16
	Username  string
	Password  string
}

// ApplyAuth adds proper auth header to the passed request
func (d *DigestHeaders) ApplyAuth(req *http.Request) {
	d.Nc += 0x1
	d.Method = req.Method
	d.digestChecksum()
	response := h(strings.Join([]string{d.HA1, d.Nonce, fmt.Sprintf("%08x", d.Nc),
		d.Cnonce, d.Qop, d.HA2}, ":"))
	AuthHeader := fmt.Sprintf(`Digest username="%s", realm="%s", nonce="%s", uri="%s", response="%s", qop=%s, nc=%08x, cnonce="%s", algorithm=%s`,
		d.Username, d.Realm, d.Nonce, d.Uri, response, d.Qop, d.Nc, d.Cnonce, d.Algorithm)
	if d.Opaque != "" {
		AuthHeader = fmt.Sprintf(`%s, opaque="%s"`, AuthHeader, d.Opaque)
	}
	req.Header.Set("Proxy-Authorization", AuthHeader)
}

func (d *DigestHeaders) digestChecksum() {
	var A1 string
	switch d.Algorithm {
	case "MD5":
		// HA1=MD5(username:realm:password)
		A1 = fmt.Sprintf("%s:%s:%s", d.Username, d.Realm, d.Password)

	case "MD5-sess":
		// HA1=MD5(MD5(username:realm:password):nonce:cnonce)
		str := fmt.Sprintf("%s:%s:%s", d.Username, d.Realm, d.Password)
		A1 = fmt.Sprintf("%s:%s:%s", h(str), d.Nonce, d.Cnonce)
	default:
		// Token
	}
	if A1 == "" {
		return
	}
	// HA1
	d.HA1 = h(A1)
	// HA2
	A2 := fmt.Sprintf("%s:%s", d.Method, d.Uri)
	d.HA2 = h(A2)

}

func randomKey() string {
	k := make([]byte, 12)
	for bytes := 0; bytes < len(k); {
		n, err := rand.Read(k[bytes:])
		if err != nil {
			panic("rand.Read() failed")
		}
		k[bytes] = byte(bytes)
		bytes += n
	}
	return base64.StdEncoding.EncodeToString(k)
}

/*
H function for MD5 algorithm (returns a lower-case hex MD5 digest)
*/
func h(data string) string {
	digest := md5.New()
	digest.Write([]byte(data))
	return fmt.Sprintf("%x", digest.Sum(nil))
}

func (a *DigestHttpAuthenticator) Authenticate(req *http.Request, resp *http.Response) error {
	if a.state != DIGEST_HTTP_AUTH_STATE_CHALLENGE_RECEIVED {
		return proxyError(fmt.Errorf("authorization is not accepted by the proxy server"))
	}
	challenges, err := parseAuthChallenge(resp)
	if err != nil {
		// Already wrapped in proxyError
		return err
	}
	challenge := challenges["Digest"]
	if len(challenge) == 0 {
		return proxyError(fmt.Errorf("digest authentication challenge is empty"))
	}
	// Parse challenge
	digestParams := map[string]string{}
	for _, keyval := range strings.Split(challenge, ",") {
		param := strings.SplitN(keyval, "=", 2)
		if len(param) != 2 {
			continue
		}
		digestParams[strings.Trim(param[0], "\" ")] = strings.Trim(param[1], "\" ")
	}
	if len(digestParams) == 0 {
		return proxyError(fmt.Errorf("digest authentication challenge is malformed"))
	}

	algorithm := digestParams["algorithm"]

	if stale, ok := digestParams["stale"]; ok && stale == "true" {
		// Server indicated that the nonce is stale
		// Reset auth cache and state
		a.digestHeaders = nil
		a.state = DIGEST_HTTP_AUTH_STATE_CHALLENGE_RECEIVED
		return nil
	}

	if a.digestHeaders == nil {
		d := &DigestHeaders{}
		if req.Method == "CONNECT" {
			d.Uri = req.URL.Host
		} else {
			d.Uri = req.URL.Scheme + "://" + req.URL.Host + req.URL.RequestURI()
		}
		d.Realm = digestParams["realm"]
		d.Qop = digestParams["qop"]
		d.Nonce = digestParams["nonce"]
		d.Opaque = digestParams["opaque"]
		if algorithm == "" {
			d.Algorithm = "MD5"
		} else {
			d.Algorithm = digestParams["algorithm"]
		}
		d.Nc = 0x0
		d.Cnonce = randomKey()
		d.Username = a.username
		d.Password = a.password
		a.digestHeaders = d
	}

	a.digestHeaders.ApplyAuth(req)
	a.state = DIGEST_HTTP_AUTH_STATE_RESPONSE_GENERATED
	return nil
}

func (a *DigestHttpAuthenticator) IsConnectionBased() bool {
	return false
}

func (a *DigestHttpAuthenticator) IsComplete() bool {
	return a.state == DIGEST_HTTP_AUTH_STATE_RESPONSE_GENERATED
}

func (a *DigestHttpAuthenticator) Reset() {
	a.state = DIGEST_HTTP_AUTH_STATE_CHALLENGE_RECEIVED
}

func (a *DigestHttpAuthenticator) PreAuthenticate(req *http.Request) error {
	if a.digestHeaders != nil {
		a.digestHeaders.ApplyAuth(req)
	}
	return nil
}
