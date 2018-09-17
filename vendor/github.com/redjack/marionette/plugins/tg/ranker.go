package tg

import (
	"math/big"

	"github.com/redjack/marionette"
)

type RankerCipher struct {
	key    string
	regex  string
	msgLen int
}

func NewRankerCipher(key, regex string, msgLen int) *RankerCipher {
	return &RankerCipher{
		key:    key,
		regex:  regex,
		msgLen: msgLen,
	}
}

func (c *RankerCipher) Key() string {
	return c.key
}

func (c *RankerCipher) Capacity(fsm marionette.FSM) (int, error) {
	dfa, err := fsm.DFA(c.regex, c.msgLen)
	if err != nil {
		return 0, err
	}
	return dfa.Capacity(), nil
}

func (c *RankerCipher) Encrypt(fsm marionette.FSM, template string, data []byte) (ciphertext []byte, err error) {
	rank := &big.Int{}
	rank.SetBytes(data)

	dfa, err := fsm.DFA(c.regex, c.msgLen)
	if err != nil {
		return nil, err
	}

	ret, err := dfa.Unrank(rank)
	if err != nil {
		return nil, err
	}
	return []byte(ret), nil
}

func (c *RankerCipher) Decrypt(fsm marionette.FSM, ciphertext []byte) (plaintext []byte, err error) {
	dfa, err := fsm.DFA(c.regex, c.msgLen)
	if err != nil {
		return nil, err
	}

	rank, err := dfa.Rank(string(ciphertext))
	if err != nil {
		return nil, err
	}

	capacity, err := c.Capacity(fsm)
	if err != nil {
		return nil, err
	}

	// Pad to capacity.
	plaintext = rank.Bytes()
	if len(plaintext) < capacity {
		plaintext = append(make([]byte, capacity-len(plaintext)), plaintext...)
	}
	return plaintext, nil
}
