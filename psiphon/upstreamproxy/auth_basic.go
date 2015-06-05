package upstreamproxy

import (
	"errors"
	"net/http"
)

type BasicHttpAuthState int

const (
	BASIC_HTTP_AUTH_STATE_CHALLENGE_RECEIVED BasicHttpAuthState = iota
	BASIC_HTTP_AUTH_STATE_RESPONSE_GENERATED
)

type BasicHttpAuthenticator struct {
	state     BasicHttpAuthState
	challenge string
}

func newBasicAuthenticator(challenge string) *BasicHttpAuthenticator {
	return &BasicHttpAuthenticator{state: BASIC_HTTP_AUTH_STATE_CHALLENGE_RECEIVED,
		challenge: challenge}
}

func (a BasicHttpAuthenticator) authenticate(req *http.Request, username, password string) error {
	if a.state == BASIC_HTTP_AUTH_STATE_CHALLENGE_RECEIVED {
		req.SetBasicAuth(username, password)
		a.state = BASIC_HTTP_AUTH_STATE_RESPONSE_GENERATED
		return nil
	} else {
		return errors.New("Authorization is not accepted by the proxy server")
	}
}
