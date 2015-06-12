package upstreamproxy

import (
	"encoding/base64"
	"net/http"
)

func basicAuthenticate(req *http.Request, challenge, username, password string) error {
	auth := username + ":" + password
	req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(auth)))
	return nil
}
