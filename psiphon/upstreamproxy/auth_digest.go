package upstreamproxy

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	//"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

/* Adapted from https://github.com/ryanjdew/http-digest-auth-client */

type DigestHeaders struct {
	Realm     string
	Qop       string
	Method    string
	Nonce     string
	Opaque    string
	Algorithm string
	HA1       string
	HA2       string
	Cnonce    string
	Path      string
	Nc        int16
	Username  string
	Password  string
}

// ApplyAuth adds proper auth header to the passed request
func (d *DigestHeaders) ApplyAuth(req *http.Request) {
	d.Nc += 0x1
	d.Cnonce = randomKey()
	d.Method = req.Method
	d.Path = req.URL.RequestURI()
	d.digestChecksum()
	response := h(strings.Join([]string{d.HA1, d.Nonce, fmt.Sprintf("%08x", d.Nc),
		d.Cnonce, d.Qop, d.HA2}, ":"))
	AuthHeader := fmt.Sprintf(`Digest username="%s", realm="%s", nonce="%s", uri="%s", cnonce="%s", nc=%08x, qop=%s, response="%s", algorithm=%s`,
		d.Username, d.Realm, d.Nonce, d.Path, d.Cnonce, d.Nc, d.Qop, response, d.Algorithm)
	if d.Opaque != "" {
		AuthHeader = fmt.Sprintf(`%s, opaque="%s"`, AuthHeader, d.Opaque)
	}
	req.Header.Set("Proxy-Authorization", AuthHeader)
}

func (d *DigestHeaders) digestChecksum() {
	switch d.Algorithm {
	case "MD5":
		// A1
		h := md5.New()
		A1 := fmt.Sprintf("%s:%s:%s", d.Username, d.Realm, d.Password)
		io.WriteString(h, A1)
		d.HA1 = fmt.Sprintf("%x", h.Sum(nil))

		// A2
		h = md5.New()
		A2 := fmt.Sprintf("%s:%s", d.Method, d.Path)
		io.WriteString(h, A2)
		d.HA2 = fmt.Sprintf("%x", h.Sum(nil))
	case "MD5-sess":
	default:
		//token
	}
}

func randomKey() string {
	k := make([]byte, 12)
	for bytes := 0; bytes < len(k); {
		n, err := rand.Read(k[bytes:])
		if err != nil {
			panic("rand.Read() failed")
		}
		bytes += n
	}
	return base64.StdEncoding.EncodeToString(k)
}

/*
H function for MD5 algorithm (returns a lower-case hex MD5 digest)
*/
func h(data string) string {
	digest := md5.New()
	digest.Write([]byte(data))
	return fmt.Sprintf("%x", digest.Sum(nil))
}

/* End of https://github.com/ryanjdew/http-digest-auth-client code adaptation */

type DigestHttpAuthState int

const (
	DIGEST_HTTP_AUTH_STATE_CHALLENGE_RECEIVED DigestHttpAuthState = iota
	DIGEST_HTTP_AUTH_STATE_RESPONSE_GENERATED
)

type DigestHttpAuthenticator struct {
	state     DigestHttpAuthState
	challenge string
}

func newDigestAuthenticator(challenge string) *DigestHttpAuthenticator {
	return &DigestHttpAuthenticator{state: DIGEST_HTTP_AUTH_STATE_CHALLENGE_RECEIVED,
		challenge: challenge}
}

func (a DigestHttpAuthenticator) authenticate(req *http.Request, username, password string) error {
	if a.state == DIGEST_HTTP_AUTH_STATE_CHALLENGE_RECEIVED {
		if len(challenge) == 0 {
			return errors.New("Digest authentication challenge is empty")
		}
		//parse challenge
		digestParams := map[string]string{}
		for _, keyval := range strings.Split(a.challenge, ",") {
			param := strings.SplitN(keyval, "=", 2)
			if len(param) != 2 {
				continue
			}
			digestParams[strings.Trim(param[0], "\" ")] = strings.Trim(param[1], "\" ")
		}
		if len(digestParams) == 0 {
			return errors.New("Digest authentication challenge is malformed")
		}

		algorithm := digestParams["algorithm"]

		d := &DigestHeaders{}
		d.Realm = digestParams["realm"]
		d.Qop = digestParams["qop"]
		d.Nonce = digestParams["nonce"]
		d.Opaque = digestParams["opaque"]
		if algorithm == "" {
			d.Algorithm = "MD5"
		} else {
			d.Algorithm = digestParams["algorithm"]
		}
		d.Nc = 0x0
		d.Username = username
		d.Password = password
		d.ApplyAuth(req)
		a.state = DIGEST_HTTP_AUTH_STATE_RESPONSE_GENERATED
		return nil

		return errors.New("Authorization is not accepted by the proxy server")
	}
}
