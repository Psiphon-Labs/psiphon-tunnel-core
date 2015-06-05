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
	authenticate(req *http.Request, username, pasword string) error
}

func newHttpAuthenticator(resp *http.Response) (HttpAuthenticator, error) {

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
		return nil, fmt.Errorf("No valid challenges in the Proxy-Authenticate header")
	}
	// NTLM > Digest > Basic
	if challenge, ok := challenges["NTLM"]; ok {
		return newNTLMAuthenticator(challenge), nil
	} else if challenge, ok := challenges["Digest"]; ok {
		return newDigestAuthenticator(challenge), nil
	} else if challenge, ok := challenges["Basic"]; ok {
		return newBasicAuthenticator(challenge), nil
	}

	//Unsupported scheme
	schemes := make([]string, 0, len(challenges))
	for scheme := range challenges {
		schemes = append(schemes, scheme)
	}
	return nil, fmt.Errorf("Unsupported proxy authentication scheme in %v", schemes)
}
