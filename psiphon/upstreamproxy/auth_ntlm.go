package upstreamproxy

import (
	"encoding/base64"
	"errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/upstreamproxy/ntlm"
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
	state        NTLMHttpAuthState
	challengeStr string
}

func newNTLMAuthenticator(str string) *NTLMHttpAuthenticator {
	return &NTLMHttpAuthenticator{state: NTLM_HTTP_AUTH_STATE_CHALLENGE_RECEIVED,
		challengeStr: str}
}

func (a NTLMHttpAuthenticator) authenticate(req *http.Request, username, password string) error {
	if a.state == NTLM_HTTP_AUTH_STATE_CHALLENGE_RECEIVED {
		//generate TYPE 1 message
		type1Msg := ntlm.Negotiate()
		req.Header.Set("Proxy-Authorization", base64.StdEncoding.EncodeToString(type1Msg))
		a.state = NTLM_HTTP_AUTH_STATE_RESPONSE_TYPE1_GENERATED
		return nil
	}
	if a.state == NTLM_HTTP_AUTH_STATE_RESPONSE_TYPE1_GENERATED {
		// Parse username for domain in form DOMAIN\username
		var NTDomain, NTUser string
		parts := strings.SplitN(username, "\\", 2)
		if len(parts) == 2 {
			NTDomain = parts[0]
			NTUser = parts[1]
		} else {
			NTDomain = ""
			NTUser = username
		}
		chlg, err := base64.StdEncoding.DecodeString(a.challengeStr)
		if err != nil {
			return err
		}
		type3Msg, err := ntlm.Authenticate(chlg, NTDomain, NTUser, password)
		if err != nil {
			return err
		}
		req.Header.Set("Proxy-Authorization", base64.StdEncoding.EncodeToString(type3Msg))
		a.state = NTLM_HTTP_AUTH_STATE_RESPONSE_TYPE3_GENERATED
		return nil
	}
	if a.state == NTLM_HTTP_AUTH_STATE_RESPONSE_TYPE3_GENERATED {
		return errors.New("Authorization is not accepted by the proxy server")
	}
	return errors.New("NTLM auth unknown error")
}
