package upstreamproxy

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
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
	Uri       string
	Nc        int16
	Username  string
	Password  string
}

// ApplyAuth adds proper auth header to the passed request
func (d *DigestHeaders) ApplyAuth(req *http.Request) {
	d.Nc += 0x1
	d.Cnonce = randomKey()
	d.Method = req.Method
	d.digestChecksum()
	response := h(strings.Join([]string{d.HA1, d.Nonce, fmt.Sprintf("%08x", d.Nc),
		d.Cnonce, d.Qop, d.HA2}, ":"))
	AuthHeader := fmt.Sprintf(`Digest username="%s", realm="%s", nonce="%s", uri="%s", response="%s", qop=%s, nc=%08x, cnonce="%s", algorithm=%s`,
		d.Username, d.Realm, d.Nonce, d.Uri, response, d.Qop, d.Nc, d.Cnonce, d.Algorithm)
	if d.Opaque != "" {
		AuthHeader = fmt.Sprintf(`%s, opaque="%s"`, AuthHeader, d.Opaque)
	}
	req.Header.Set("Proxy-Authorization", AuthHeader)
}

func (d *DigestHeaders) digestChecksum() {
	var A1 string
	switch d.Algorithm {
	case "MD5":
		//HA1=MD5(username:realm:password)
		A1 = fmt.Sprintf("%s:%s:%s", d.Username, d.Realm, d.Password)

	case "MD5-sess":
		// HA1=MD5(MD5(username:realm:password):nonce:cnonce)
		str := fmt.Sprintf("%s:%s:%s", d.Username, d.Realm, d.Password)
		A1 = fmt.Sprintf("%s:%s:%s", h(str), d.Nonce, d.Cnonce)
	default:
		//token
	}
	if A1 == "" {
		return
	}
	//HA1
	d.HA1 = h(A1)
	// HA2
	A2 := fmt.Sprintf("%s:%s", d.Method, d.Uri)
	d.HA2 = h(A2)

}

func randomKey() string {
	k := make([]byte, 12)
	for bytes := 0; bytes < len(k); {
		n, err := rand.Read(k[bytes:])
		if err != nil {
			panic("rand.Read() failed")
		}
		k[bytes] = byte(bytes)
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

func digestAuthenticate(req *http.Request, challenge, username, password string) error {
	if len(challenge) == 0 {
		return errors.New("Digest authentication challenge is empty")
	}
	//parse challenge
	digestParams := map[string]string{}
	for _, keyval := range strings.Split(challenge, ",") {
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
	if req.Method == "CONNECT" {
		d.Uri = req.URL.Host
	} else {
		d.Uri = req.URL.Scheme + "://" + req.URL.Host + req.URL.RequestURI()
	}
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
	return nil
}
