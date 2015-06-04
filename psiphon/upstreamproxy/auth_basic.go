package upstreamproxy

import (
	"errors"
	"net/http"
)

type BasicHttpAuthState int

const (
	BASIC_HTTP_AUTH_STATE_NEW BasicHttpAuthState = iota
	BASIC_HTTP_AUTH_STATE_RESPONSE_GENERATED
)

type BasicHttpAuthenticator struct {
	state     BasicHttpAuthState
	challenge string
}

func newBasicAuthenticator(challenge string) *BasicHttpAuthenticator {
	return &BasicHttpAuthenticator{state: BASIC_HTTP_AUTH_STATE_NEW,
		challenge: challenge}
}

func (b BasicHttpAuthenticator) authenticate(req *http.Request, username, password string) error {
	if b.state == BASIC_HTTP_AUTH_STATE_NEW {
		b.state = BASIC_HTTP_AUTH_STATE_RESPONSE_GENERATED
		req.SetBasicAuth(username, password)
		return nil
	} else {
		return errors.New("Authentication is not accepted by the proxy server")
	}
}
