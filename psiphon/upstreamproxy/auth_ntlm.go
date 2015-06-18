package upstreamproxy

import (
	"encoding/base64"
	"errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/upstreamproxy/go-ntlm/ntlm"
	"net/http"
	"strings"
)

func ntlmAuthenticate(req *http.Request, challenge, username, password string) error {
	err := errors.New("NTLM authentication unknown error")
	var ntlmMsg []byte

	session, err := ntlm.CreateClientSession(ntlm.Version2, ntlm.ConnectionOrientedMode)
	if err != nil {
		return err
	}
	if challenge == "" {
		//generate TYPE 1 message
		negotiate, err := session.GenerateNegotiateMessage()
		if err != nil {
			return err
		}
		ntlmMsg = negotiate.Bytes()
		err = nil
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
		challengeBytes, err := base64.StdEncoding.DecodeString(challenge)
		if err != nil {
			return err
		}
		session.SetUserInfo(NTUser, password, NTDomain)
		ntlmChallenge, err := ntlm.ParseChallengeMessage(challengeBytes)
		if err != nil {
			return err
		}
		session.ProcessChallengeMessage(ntlmChallenge)
		authenticate, err := session.GenerateAuthenticateMessage()
		if err != nil {
			return err
		}
		ntlmMsg = authenticate.Bytes()
		err = nil
	}
	req.Header.Set("Proxy-Authorization", "NTLM "+base64.StdEncoding.EncodeToString(ntlmMsg))
	return err
}
