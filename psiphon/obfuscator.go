/*
 * Copyright (c) 2015, Psiphon Inc.
 * All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

package psiphon

import (
	"bytes"
	"crypto/rc4"
	"crypto/sha1"
	"encoding/binary"
	"errors"
)

const (
	OBFUSCATE_SEED_LENGTH         = 16
	OBFUSCATE_KEY_LENGTH          = 16
	OBFUSCATE_HASH_ITERATIONS     = 6000
	OBFUSCATE_MAX_PADDING         = 8192
	OBFUSCATE_MAGIC_VALUE         = 0x0BF5CA7E
	OBFUSCATE_CLIENT_TO_SERVER_IV = "client_to_server"
	OBFUSCATE_SERVER_TO_CLIENT_IV = "server_to_client"
)

// Obfuscator implements the seed message, key derivation, and
// stream ciphers for:
// https://github.com/brl/obfuscated-openssh/blob/master/README.obfuscation
type Obfuscator struct {
	seedMessage          []byte
	clientToServerCipher *rc4.Cipher
	serverToClientCipher *rc4.Cipher
}

type ObfuscatorConfig struct {
	Keyword    string
	MaxPadding int
}

// NewObfuscator creates a new Obfuscator, initializes it with
// a seed message, derives client and server keys, and creates
// RC4 stream ciphers to obfuscate data.
func NewObfuscator(config *ObfuscatorConfig) (obfuscator *Obfuscator, err error) {
	seed, err := MakeSecureRandomBytes(OBFUSCATE_SEED_LENGTH)
	if err != nil {
		return nil, ContextError(err)
	}
	clientToServerKey, err := deriveKey(seed, []byte(config.Keyword), []byte(OBFUSCATE_CLIENT_TO_SERVER_IV))
	if err != nil {
		return nil, ContextError(err)
	}
	serverToClientKey, err := deriveKey(seed, []byte(config.Keyword), []byte(OBFUSCATE_SERVER_TO_CLIENT_IV))
	if err != nil {
		return nil, ContextError(err)
	}
	clientToServerCipher, err := rc4.NewCipher(clientToServerKey)
	if err != nil {
		return nil, ContextError(err)
	}
	serverToClientCipher, err := rc4.NewCipher(serverToClientKey)
	if err != nil {
		return nil, ContextError(err)
	}
	maxPadding := OBFUSCATE_MAX_PADDING
	if config.MaxPadding > 0 {
		maxPadding = config.MaxPadding
	}
	seedMessage, err := makeSeedMessage(maxPadding, seed, clientToServerCipher)
	if err != nil {
		return nil, ContextError(err)
	}
	return &Obfuscator{
		seedMessage:          seedMessage,
		clientToServerCipher: clientToServerCipher,
		serverToClientCipher: serverToClientCipher}, nil
}

// ConsumeSeedMessage returns the seed message created in NewObfuscator,
// removing the reference so that it may be garbage collected.
func (obfuscator *Obfuscator) ConsumeSeedMessage() []byte {
	seedMessage := obfuscator.seedMessage
	obfuscator.seedMessage = nil
	return seedMessage
}

// ObfuscateClientToServer applies the client RC4 stream to the bytes in buffer.
func (obfuscator *Obfuscator) ObfuscateClientToServer(buffer []byte) {
	obfuscator.clientToServerCipher.XORKeyStream(buffer, buffer)
}

// ObfuscateServerToClient applies the server RC4 stream to the bytes in buffer.
func (obfuscator *Obfuscator) ObfuscateServerToClient(buffer []byte) {
	obfuscator.serverToClientCipher.XORKeyStream(buffer, buffer)
}

func deriveKey(seed, keyword, iv []byte) ([]byte, error) {
	h := sha1.New()
	h.Write(seed)
	h.Write(keyword)
	h.Write(iv)
	digest := h.Sum(nil)
	for i := 0; i < OBFUSCATE_HASH_ITERATIONS; i++ {
		h.Reset()
		h.Write(digest)
		digest = h.Sum(nil)
	}
	if len(digest) < OBFUSCATE_KEY_LENGTH {
		return nil, ContextError(errors.New("insufficient bytes for obfuscation key"))
	}
	return digest[0:OBFUSCATE_KEY_LENGTH], nil
}

func makeSeedMessage(maxPadding int, seed []byte, clientToServerCipher *rc4.Cipher) ([]byte, error) {
	// paddingLength is integer in range [0, maxPadding]
	paddingLength, err := MakeSecureRandomInt(maxPadding + 1)
	if err != nil {
		return nil, ContextError(err)
	}
	padding, err := MakeSecureRandomBytes(paddingLength)
	if err != nil {
		return nil, ContextError(err)
	}
	buffer := new(bytes.Buffer)
	err = binary.Write(buffer, binary.BigEndian, seed)
	if err != nil {
		return nil, ContextError(err)
	}
	err = binary.Write(buffer, binary.BigEndian, uint32(OBFUSCATE_MAGIC_VALUE))
	if err != nil {
		return nil, ContextError(err)
	}
	err = binary.Write(buffer, binary.BigEndian, uint32(paddingLength))
	if err != nil {
		return nil, ContextError(err)
	}
	err = binary.Write(buffer, binary.BigEndian, padding)
	if err != nil {
		return nil, ContextError(err)
	}
	seedMessage := buffer.Bytes()
	clientToServerCipher.XORKeyStream(seedMessage[len(seed):], seedMessage[len(seed):])
	return seedMessage, nil
}
