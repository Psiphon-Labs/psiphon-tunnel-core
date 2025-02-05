// Copyright 2020 Jigsaw Operations LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package shadowsocks

import (
	"crypto/rand"
	"errors"
)

// SaltGenerator generates unique salts to use in Shadowsocks connections.
type SaltGenerator interface {
	// Returns a new salt
	GetSalt(salt []byte) error
}

// randomSaltGenerator generates a new random salt.
type randomSaltGenerator struct{}

// GetSalt outputs a random salt.
func (randomSaltGenerator) GetSalt(salt []byte) error {
	_, err := rand.Read(salt)
	return err
}

// RandomSaltGenerator is a basic SaltGenerator.
var RandomSaltGenerator SaltGenerator = randomSaltGenerator{}

type prefixSaltGenerator struct {
	prefix []byte
}

func (g prefixSaltGenerator) GetSalt(salt []byte) error {
	n := copy(salt, g.prefix)
	if n != len(g.prefix) {
		return errors.New("prefix is too long")
	}
	_, err := rand.Read(salt[n:])
	return err
}

// NewPrefixSaltGenerator returns a SaltGenerator with output including
// the provided prefix, followed by random bytes. This is useful to change
// how shadowsocks traffic is classified by middleboxes.
//
// Note: Prefixes steal entropy from the initialization vector. This weakens
// security by increasing the likelihood that the same IV is used in two
// different connections (which becomes likely once 2^(N/2) connections are
// made, due to the birthday attack).  If an IV is reused, the attacker can
// not only decrypt the ciphertext of those two connections; they can also
// easily recover the shadowsocks key and decrypt all other connections to
// this server.  Use with care!
func NewPrefixSaltGenerator(prefix []byte) SaltGenerator {
	return prefixSaltGenerator{prefix}
}
