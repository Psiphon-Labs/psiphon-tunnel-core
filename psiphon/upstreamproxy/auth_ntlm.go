package upstreamproxy

import (
	"encoding/base64"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/upstreamproxy/ntlm"
	"net/http"
	"strings"
)

func ntlmAuthenticate(req *http.Request, challenge, username, password string) error {
	if challenge == "" {
		//generate TYPE 1 message
		type1Msg := ntlm.Negotiate()
		req.Header.Set("Proxy-Authorization", base64.StdEncoding.EncodeToString(type1Msg))
		return nil
	} else {
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
		chlg, err := base64.StdEncoding.DecodeString(challenge)
		if err != nil {
			return err
		}
		type3Msg, err := ntlm.Authenticate(chlg, NTDomain, NTUser, password)
		if err != nil {
			return err
		}
		req.Header.Set("Proxy-Authorization", base64.StdEncoding.EncodeToString(type3Msg))
		return nil
	}
}
