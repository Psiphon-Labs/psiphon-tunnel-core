package tg

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/redjack/marionette"
)

type HTTPContentLengthCipher struct{}

func NewHTTPContentLengthCipher() *HTTPContentLengthCipher {
	return &HTTPContentLengthCipher{}
}

func (c *HTTPContentLengthCipher) Key() string {
	return "CONTENT-LENGTH"
}

func (c *HTTPContentLengthCipher) Capacity(fsm marionette.FSM) (int, error) {
	return 0, nil
}

func (c *HTTPContentLengthCipher) Encrypt(fsm marionette.FSM, template string, plaintext []byte) (ciphertext []byte, err error) {
	a := strings.SplitN(template, "\r\n\r\n", 2)
	if len(a) == 1 {
		return []byte("0"), nil
	}
	return []byte(strconv.Itoa(len(a[1]))), nil
}

func (c *HTTPContentLengthCipher) Decrypt(fsm marionette.FSM, ciphertext []byte) (plaintext []byte, err error) {
	return nil, nil
}

func httpHeaderValue(hdrs []string, key string) string {
	for _, hdr := range hdrs {
		if a := strings.SplitN(hdr, ": ", 2); a[0] == key {
			if len(a) > 1 {
				return a[1]
			}
			return ""
		}
	}
	return ""
}

func parseHTTPRequest(data string) map[string]string {
	if !strings.HasPrefix(data, "GET") {
		return nil
	} else if !strings.HasSuffix(data, "\r\n\r\n") {
		return nil
	}

	lines := lineBreakRegex.Split(data, -1)
	segments := strings.Split(lines[0][:len(lines[0])-9], "/")

	if strings.HasPrefix(data, "GET http") {
		return map[string]string{"URL": strings.Join(segments[3:], "/")}
	}
	return map[string]string{"URL": strings.Join(segments[1:], "/")}
}

func parseHTTPResponse(data string) map[string]string {
	if !strings.HasPrefix(data, "HTTP") {
		return nil
	}

	hdrs := strings.Split(data, "\r\n")
	hdrs = hdrs[1 : len(hdrs)-2]

	m := make(map[string]string)
	m["CONTENT-LENGTH"] = httpHeaderValue(hdrs, "Content-Length")
	m["COOKIE"] = httpHeaderValue(hdrs, "Cookie")
	if a := strings.SplitN(data, "\r\n\r\n", 2); len(a) > 1 {
		m["HTTP-RESPONSE-BODY"] = a[1]
	} else {
		m["HTTP-RESPONSE-BODY"] = ""
	}

	if m["CONTENT-LENGTH"] != strconv.Itoa(len(m["HTTP-RESPONSE-BODY"])) {
		return nil
	}
	return m
}

var lineBreakRegex = regexp.MustCompile(`\r\n`)
