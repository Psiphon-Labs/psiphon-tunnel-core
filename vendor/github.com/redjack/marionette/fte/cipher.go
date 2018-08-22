package fte

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
)

var (
	ErrInsufficientCapacity = errors.New("fte: insufficient capacity")
)

type Cipher struct {
	dfa *DFA
	enc *Encrypter
	dec *Decrypter
}

// NewCipher returns a new instance of Cipher.
func NewCipher(regex string, n int) (_ *Cipher, err error) {
	var c Cipher
	if c.enc, err = NewEncrypter(); err != nil {
		return nil, err
	} else if c.dec, err = NewDecrypter(); err != nil {
		return nil, err
	} else if c.dfa, err = NewDFA(regex, n); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Cipher) Close() error {
	if c.dfa != nil {
		err := c.dfa.Close()
		c.dfa = nil
		return err
	}
	return nil
}

// Capacity returns the capacity left in the encoder.
func (c *Cipher) Capacity() int {
	return c.dfa.Capacity()
}

// Encrypt encrypts plaintext into ciphertext.
func (c *Cipher) Encrypt(plaintext []byte) (ciphertext []byte, err error) {
	if len(plaintext) == 0 {
		return nil, nil
	}

	if ciphertext, err = c.enc.Encrypt(plaintext); err != nil {
		return nil, err
	}

	maximumBytesToRank := c.Capacity()
	unrank_payload_len := (maximumBytesToRank - COVERTEXT_HEADER_LEN_CIPHERTTEXT)
	if len(ciphertext) < unrank_payload_len {
		unrank_payload_len = len(ciphertext)
	}

	if unrank_payload_len <= 0 {
		return nil, ErrInsufficientCapacity
	}

	msg_len_header := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, msg_len_header[:8]); err != nil {
		return nil, err
	}
	binary.BigEndian.PutUint64(msg_len_header[8:], uint64(unrank_payload_len))

	encryptedHeader := make([]byte, len(msg_len_header))
	c.enc.block.Encrypt(encryptedHeader, msg_len_header)
	msg_len_header = encryptedHeader

	unrank_payload := encryptedHeader
	if len(ciphertext) <= maximumBytesToRank-16 {
		unrank_payload = append(unrank_payload, ciphertext...)
	} else {
		unrank_payload = append(unrank_payload, ciphertext[:maximumBytesToRank-16]...)
	}

	random_padding_len := maximumBytesToRank - len(unrank_payload)
	if random_padding_len > 0 {
		randomPadding := make([]byte, random_padding_len)
		if _, err := io.ReadFull(rand.Reader, randomPadding); err != nil {
			return nil, err
		}
		unrank_payload = append(unrank_payload, randomPadding...)
	}

	var unrankValue big.Int
	unrankValue.SetBytes(unrank_payload)

	formatted_covertext_header, err := c.dfa.Unrank(&unrankValue)
	if err != nil {
		return nil, err
	}

	var unformatted_covertext_body []byte
	if len(ciphertext) > maximumBytesToRank-16 {
		unformatted_covertext_body = ciphertext[maximumBytesToRank-16:]
	}
	return append([]byte(formatted_covertext_header), unformatted_covertext_body...), nil
}

// Decrypt decrypts ciphertext into plaintext.
// Returns ErrShortCiphertext if the ciphertext is too short to be decrypted.
func (c *Cipher) Decrypt(ciphertext []byte) (plaintext, remainder []byte, err error) {
	if len(ciphertext) < c.dfa.N() {
		return nil, nil, ErrShortCiphertext
	}

	maximumBytesToRank := c.Capacity()

	rank_payload, err := c.dfa.Rank(string(ciphertext[:c.dfa.N()]))
	if err != nil {
		return nil, nil, err
	}
	X := rank_payload.Bytes()
	if len(X) < maximumBytesToRank {
		X = append(make([]byte, maximumBytesToRank-len(X)), X...)
	}

	msg_len_header := make([]byte, 16)
	c.dec.block.Decrypt(msg_len_header, X[:16])
	msg_len := binary.BigEndian.Uint64(msg_len_header[8:16])

	retval := X[16 : 16+msg_len]
	retval = append(retval, ciphertext[c.dfa.N():]...)
	ctxt_len := c.dec.CiphertextLen(retval)
	var remaining_buffer []byte
	if len(retval) > ctxt_len {
		remaining_buffer = retval[ctxt_len:]
	}
	if len(retval) > ctxt_len {
		retval = retval[:ctxt_len]
	}

	if retval, err = c.dec.Decrypt(retval); err != nil {
		return nil, nil, err
	}
	return retval, remaining_buffer, nil
}
