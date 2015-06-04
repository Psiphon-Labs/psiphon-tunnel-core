package upstreamproxy

/*

import (
	"net/http"
)
type Transport struct {
	Username  string
	Password  string
	Transport http.RoundTripper
}

func NewHttpTransport(username, password string, dialFn DialFunc) *Transport {
	t := &Transport{
		Username: username,
		Password: password,
	}
	t.Transport = &http.Transport{Dial: dialFn}
	return t
}

func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {

	resp, err := t.Transport.RoundTrip(req)
	if resp.StatusCode == http.StatusProxyAuthRequired {
		//read auth header
		//detect auth type
		//authenticate and call self
	}
	return resp, err
}
*/
