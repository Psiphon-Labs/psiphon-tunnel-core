package upstreamproxy

import (
	"errors"
	"net/http"
)

type DigestHttpAuthState int

const (
	DIGEST_HTTP_AUTH_STATE_NEW DigestHttpAuthState = iota
	DIGEST_HTTP_AUTH_STATE_RESPONSE_GENERATED
)

type DigestHttpAuthenticator struct {
	state     DigestHttpAuthState
	challenge string
}

func newDigestAuthenticator(challenge string) *DigestHttpAuthenticator {
	return &DigestHttpAuthenticator{state: DIGEST_HTTP_AUTH_STATE_NEW,
		challenge: challenge}
}

func (b DigestHttpAuthenticator) authenticate(req *http.Request, username, password string) error {
	return errors.New("Digest auth is not implemented")
}
