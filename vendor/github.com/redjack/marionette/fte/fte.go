package fte

import (
	"crypto/aes"
	"io"
	"io/ioutil"
	"os"
)

const (
	COVERTEXT_HEADER_LEN_CIPHERTTEXT = 16
)

const (
	IV_LENGTH          = 7
	MSG_COUNTER_LENGTH = 8
	CTXT_EXPANSION     = 1 + IV_LENGTH + MSG_COUNTER_LENGTH + aes.BlockSize
)

var Verbose bool

// Cache represents a cache of Ciphers & DFAs.
type Cache struct {
	ciphers map[cacheKey]*Cipher
	dfas    map[cacheKey]*DFA
}

// NewCache returns a new instance of Cache.
func NewCache() *Cache {
	return &Cache{
		ciphers: make(map[cacheKey]*Cipher),
		dfas:    make(map[cacheKey]*DFA),
	}
}

// Close close and removes all ciphers & dfas.
func (c *Cache) Close() (err error) {
	for _, cipher := range c.ciphers {
		if e := cipher.Close(); e != nil && err == nil {
			err = e
		}
	}
	c.ciphers = nil

	for _, dfa := range c.dfas {
		if e := dfa.Close(); e != nil && err == nil {
			err = e
		}
	}
	c.dfas = nil

	return err
}

// Cipher returns a instance of Cipher associated with regex & n.
// Creates a new cipher if one doesn't already exist.
func (c *Cache) Cipher(regex string, n int) (_ *Cipher, err error) {
	cipher := c.ciphers[cacheKey{regex, n}]
	if cipher == nil {
		if cipher, err = NewCipher(regex, n); err != nil {
			return nil, err
		}
		c.ciphers[cacheKey{regex, n}] = cipher
	}
	return cipher, nil
}

// DFA returns a instance of DFA associated with regex & n.
// Creates a new DFA if one doesn't already exist.
func (c *Cache) DFA(regex string, n int) (_ *DFA, err error) {
	dfa := c.dfas[cacheKey{regex, n}]
	if dfa == nil {
		if dfa, err = NewDFA(regex, n); err != nil {
			return nil, err
		}
		c.dfas[cacheKey{regex, n}] = dfa
	}
	return dfa, nil
}

type cacheKey struct {
	regex string
	n     int
}

func stderr() io.Writer {
	if Verbose {
		return os.Stderr
	}
	return ioutil.Discard
}
