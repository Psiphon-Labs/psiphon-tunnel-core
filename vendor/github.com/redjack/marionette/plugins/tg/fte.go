package tg

import (
	"strings"

	"github.com/redjack/marionette"
	"github.com/redjack/marionette/fte"
)

type FTECipher struct {
	key         string
	regex       string
	msgLen      int
	useCapacity bool
}

func NewFTECipher(key, regex string, msgLen int, useCapacity bool) *FTECipher {
	return &FTECipher{
		key:         key,
		regex:       regex,
		msgLen:      msgLen,
		useCapacity: useCapacity,
	}
}

func (c *FTECipher) Key() string {
	return c.key
}

func (c *FTECipher) Capacity(fsm marionette.FSM) (int, error) {
	if !c.useCapacity && strings.HasSuffix(c.regex, ".+") {
		return marionette.MaxCellLength, nil
	}
	cipher, err := fsm.Cipher(c.regex, c.msgLen)
	if err != nil {
		return 0, err
	}
	return cipher.Capacity() - fte.COVERTEXT_HEADER_LEN_CIPHERTTEXT - fte.CTXT_EXPANSION, nil
}

func (c *FTECipher) Encrypt(fsm marionette.FSM, template string, data []byte) (ciphertext []byte, err error) {
	cipher, err := fsm.Cipher(c.regex, c.msgLen)
	if err != nil {
		return nil, err
	}
	return cipher.Encrypt(data)
}

func (c *FTECipher) Decrypt(fsm marionette.FSM, ciphertext []byte) (plaintext []byte, err error) {
	cipher, err := fsm.Cipher(c.regex, c.msgLen)
	if err != nil {
		return nil, err
	}
	plaintext, _, err = cipher.Decrypt(ciphertext)
	return plaintext, err
}
