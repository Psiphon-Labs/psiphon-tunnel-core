package tg

import (
	"strconv"
	"strings"

	"github.com/redjack/marionette"
)

type POP3ContentLengthCipher struct{}

func NewPOP3ContentLengthCipher() *POP3ContentLengthCipher {
	return &POP3ContentLengthCipher{}
}

func (c *POP3ContentLengthCipher) Key() string {
	return "CONTENT-LENGTH"
}

func (c *POP3ContentLengthCipher) Capacity(fsm marionette.FSM) (int, error) {
	return 0, nil
}

func (c *POP3ContentLengthCipher) Encrypt(fsm marionette.FSM, template string, plaintext []byte) (ciphertext []byte, err error) {
	a := strings.SplitN(template, "\n", 2)
	if len(a) == 1 {
		return []byte("0"), nil
	}
	return []byte(strconv.Itoa(len(a[1]))), nil
}

func (c *POP3ContentLengthCipher) Decrypt(fsm marionette.FSM, ciphertext []byte) (plaintext []byte, err error) {
	return nil, nil
}

func parsePOP3(data string) map[string]string {
	a := strings.Split(data, "\n\n")
	if len(a) < 2 {
		return nil
	}

	body := a[1]
	if !strings.HasSuffix(body, "\n.\n") {
		return nil
	}
	body = strings.TrimSuffix(body, "\n.\n")

	return map[string]string{
		"POP3-RESPONSE-BODY": body,
		"CONTENT-LENGTH":     strconv.Itoa(len(body)),
	}
}

func parsePOP3Password(data string) map[string]string {
	if !strings.HasPrefix(data, "PASS ") || !strings.HasSuffix(data, "\n") {
		return nil
	}
	data = strings.TrimPrefix(data, "PASS ")
	data = strings.TrimSuffix(data, "\n")
	return map[string]string{"PASSWORD": data}
}
