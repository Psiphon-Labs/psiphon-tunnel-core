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

package service

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"fmt"
	"io"

	ss "github.com/Jigsaw-Code/outline-sdk/transport/shadowsocks"
	"golang.org/x/crypto/hkdf"
)

// ServerSaltGenerator offers the ability to check if a salt was marked as
// server-originated.
type ServerSaltGenerator interface {
	ss.SaltGenerator
	// IsServerSalt returns true if the salt was created by this generator
	// and is marked as server-originated.
	IsServerSalt(salt []byte) bool
}

// randomServerSaltGenerator generates a new random salt.
type randomServerSaltGenerator struct{}

// GetSalt outputs a random salt.
func (randomServerSaltGenerator) GetSalt(salt []byte) error {
	_, err := rand.Read(salt)
	return err
}

func (randomServerSaltGenerator) IsServerSalt(salt []byte) bool {
	return false
}

// RandomServerSaltGenerator is a basic ServerSaltGenerator.
var RandomServerSaltGenerator ServerSaltGenerator = randomServerSaltGenerator{}

// serverSaltGenerator generates unique salts that are secretly marked.
type serverSaltGenerator struct {
	key []byte
}

// serverSaltMarkLen is the number of bytes of salt to use as a marker.
// Increasing this value reduces the false positive rate, but increases
// the likelihood of salt collisions.
const serverSaltMarkLen = 4 // Must be less than or equal to SHA1.Size()

// Constant to identify this marking scheme.
var serverSaltLabel = []byte("outline-server-salt")

// NewServerSaltGenerator returns a SaltGenerator whose output is apparently
// random, but is secretly marked as being issued by the server.
// This is useful to prevent the server from accepting its own output in a
// reflection attack.
func NewServerSaltGenerator(secret string) ServerSaltGenerator {
	// Shadowsocks already uses HKDF-SHA1 to derive the AEAD key, so we use
	// the same derivation with a different "info" to generate our HMAC key.
	keySource := hkdf.New(crypto.SHA1.New, []byte(secret), nil, serverSaltLabel)
	// The key can be any size, but matching the block size is most efficient.
	key := make([]byte, crypto.SHA1.Size())
	io.ReadFull(keySource, key)
	return serverSaltGenerator{key}
}

func (sg serverSaltGenerator) splitSalt(salt []byte) (prefix, mark []byte, err error) {
	prefixLen := len(salt) - serverSaltMarkLen
	if prefixLen < 0 {
		return nil, nil, fmt.Errorf("salt is too short: %d < %d", len(salt), serverSaltMarkLen)
	}
	return salt[:prefixLen], salt[prefixLen:], nil
}

// getTag takes in a salt prefix and returns the tag.
func (sg serverSaltGenerator) getTag(prefix []byte) []byte {
	// Use HMAC-SHA1, even though SHA1 is broken, because HMAC-SHA1 is still
	// secure, and we're already using HKDF-SHA1.
	hmac := hmac.New(crypto.SHA1.New, sg.key)
	hmac.Write(prefix) // Hash.Write never returns an error.
	return hmac.Sum(nil)
}

// GetSalt returns an apparently random salt that can be identified
// as server-originated by anyone who knows the Shadowsocks key.
func (sg serverSaltGenerator) GetSalt(salt []byte) error {
	prefix, mark, err := sg.splitSalt(salt)
	if err != nil {
		return err
	}
	if _, err := rand.Read(prefix); err != nil {
		return err
	}
	tag := sg.getTag(prefix)
	copy(mark, tag)
	return nil
}

func (sg serverSaltGenerator) IsServerSalt(salt []byte) bool {
	prefix, mark, err := sg.splitSalt(salt)
	if err != nil {
		return false
	}
	tag := sg.getTag(prefix)
	return bytes.Equal(tag[:serverSaltMarkLen], mark)
}
