package upstreamproxy

import (
	"net/http"
)

type Transport struct {
	Username  string
	Password  string
	transport http.RoundTripper
}

func NewTransport(username, password string, dialFn DialFunc) *Transport {
	t := &Transport{
		Username: username,
		Password: password,
	}
	t.transport = &http.Transport{Dial: dialFn}
	return t
}

func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {

	// TODO: Check if we cached auth header for the transport ProxyURL
	resp, err := t.transport.RoundTrip(req)
	if resp.StatusCode == 407 {
		//TODO: Generate new auth header and cache it
		req2 := cloneRequest(req)
		err = authenticateRequest(req2, resp, t.Username, t.Password)
		if err != nil {
			return nil, err
		}
		return RoundTrip(req2)
	}
	return resp, err
}

func cloneRequest(r *http.Request) *http.Request {
	// shallow copy of the struct
	r2 := new(http.Request)
	*r2 = *r
	// deep copy of the Header
	r2.Header = make(http.Header, len(r.Header))
	for k, s := range r.Header {
		r2.Header[k] = append([]string(nil), s...)
	}
	return r2
}
