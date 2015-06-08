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
	state        BasicHttpAuthState
	challengeStr string
}

func newBasicAuthenticator(str string) *BasicHttpAuthenticator {
	return &BasicHttpAuthenticator{state: BASIC_HTTP_AUTH_STATE_CHALLENGE_RECEIVED,
		challengeStr: str}
}

func (a BasicHttpAuthenticator) authenticate(req *http.Request, username, password string) error {
	if a.state == BASIC_HTTP_AUTH_STATE_CHALLENGE_RECEIVED {
		auth := username + ":" + password
		req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(auth)))
		a.state = BASIC_HTTP_AUTH_STATE_RESPONSE_GENERATED
		return nil
	} else {
		return errors.New("Authorization is not accepted by the proxy server")
	}
}
