package upstreamproxy

import (
	"errors"
	"net/http"
)

type NTLMHttpAuthState int

const (
	NTLM_HTTP_AUTH_STATE_CHALLENGE_RECEIVED NTLMHttpAuthState = iota
	NTLM_HTTP_AUTH_STATE_RESPONSE_TYPE1_GENERATED
	NTLM_HTTP_AUTH_STATE_RESPONSE_TYPE3_GENERATED
)

type NTLMHttpAuthenticator struct {
	state     NTLMHttpAuthState
	challenge string
}

func newNTLMAuthenticator(challenge string) *NTLMHttpAuthenticator {
	return &NTLMHttpAuthenticator{state: NTLM_HTTP_AUTH_STATE_CHALLENGE_RECEIVED,
		challenge: challenge}
}

func (a NTLMHttpAuthenticator) authenticate(req *http.Request, username, password string) error {
	return errors.New("NTLM auth is not implemented")
}
