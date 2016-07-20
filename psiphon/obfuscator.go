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
	"io"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
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

// NewClientObfuscator creates a new Obfuscator, staging a seed message to be
// sent to the server (by the caller) and initializing stream ciphers to
// obfuscate data.
func NewClientObfuscator(
	config *ObfuscatorConfig) (obfuscator *Obfuscator, err error) {

	seed, err := common.MakeSecureRandomBytes(OBFUSCATE_SEED_LENGTH)
	if err != nil {
		return nil, common.ContextError(err)
	}

	clientToServerCipher, serverToClientCipher, err := initObfuscatorCiphers(seed, config)
	if err != nil {
		return nil, common.ContextError(err)
	}

	maxPadding := OBFUSCATE_MAX_PADDING
	if config.MaxPadding > 0 {
		maxPadding = config.MaxPadding
	}

	seedMessage, err := makeSeedMessage(maxPadding, seed, clientToServerCipher)
	if err != nil {
		return nil, common.ContextError(err)
	}

	return &Obfuscator{
		seedMessage:          seedMessage,
		clientToServerCipher: clientToServerCipher,
		serverToClientCipher: serverToClientCipher}, nil
}

// NewServerObfuscator creates a new Obfuscator, reading a seed message directly
// from the clientReader and initializing stream ciphers to obfuscate data.
func NewServerObfuscator(
	clientReader io.Reader, config *ObfuscatorConfig) (obfuscator *Obfuscator, err error) {

	clientToServerCipher, serverToClientCipher, err := readSeedMessage(
		clientReader, config)
	if err != nil {
		return nil, common.ContextError(err)
	}

	return &Obfuscator{
		clientToServerCipher: clientToServerCipher,
		serverToClientCipher: serverToClientCipher}, nil
}

// SendSeedMessage returns the seed message created in NewObfuscatorClient,
// removing the reference so that it may be garbage collected.
func (obfuscator *Obfuscator) SendSeedMessage() []byte {
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

func initObfuscatorCiphers(
	seed []byte, config *ObfuscatorConfig) (*rc4.Cipher, *rc4.Cipher, error) {

	clientToServerKey, err := deriveKey(seed, []byte(config.Keyword), []byte(OBFUSCATE_CLIENT_TO_SERVER_IV))
	if err != nil {
		return nil, nil, common.ContextError(err)
	}

	serverToClientKey, err := deriveKey(seed, []byte(config.Keyword), []byte(OBFUSCATE_SERVER_TO_CLIENT_IV))
	if err != nil {
		return nil, nil, common.ContextError(err)
	}

	clientToServerCipher, err := rc4.NewCipher(clientToServerKey)
	if err != nil {
		return nil, nil, common.ContextError(err)
	}

	serverToClientCipher, err := rc4.NewCipher(serverToClientKey)
	if err != nil {
		return nil, nil, common.ContextError(err)
	}

	return clientToServerCipher, serverToClientCipher, nil
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
		return nil, common.ContextError(errors.New("insufficient bytes for obfuscation key"))
	}
	return digest[0:OBFUSCATE_KEY_LENGTH], nil
}

func makeSeedMessage(maxPadding int, seed []byte, clientToServerCipher *rc4.Cipher) ([]byte, error) {
	// paddingLength is integer in range [0, maxPadding]
	paddingLength, err := common.MakeSecureRandomInt(maxPadding + 1)
	if err != nil {
		return nil, common.ContextError(err)
	}
	padding, err := common.MakeSecureRandomBytes(paddingLength)
	if err != nil {
		return nil, common.ContextError(err)
	}
	buffer := new(bytes.Buffer)
	err = binary.Write(buffer, binary.BigEndian, seed)
	if err != nil {
		return nil, common.ContextError(err)
	}
	err = binary.Write(buffer, binary.BigEndian, uint32(OBFUSCATE_MAGIC_VALUE))
	if err != nil {
		return nil, common.ContextError(err)
	}
	err = binary.Write(buffer, binary.BigEndian, uint32(paddingLength))
	if err != nil {
		return nil, common.ContextError(err)
	}
	err = binary.Write(buffer, binary.BigEndian, padding)
	if err != nil {
		return nil, common.ContextError(err)
	}
	seedMessage := buffer.Bytes()
	clientToServerCipher.XORKeyStream(seedMessage[len(seed):], seedMessage[len(seed):])
	return seedMessage, nil
}

func readSeedMessage(
	clientReader io.Reader, config *ObfuscatorConfig) (*rc4.Cipher, *rc4.Cipher, error) {

	seed := make([]byte, OBFUSCATE_SEED_LENGTH)
	_, err := io.ReadFull(clientReader, seed)
	if err != nil {
		return nil, nil, common.ContextError(err)
	}

	clientToServerCipher, serverToClientCipher, err := initObfuscatorCiphers(seed, config)
	if err != nil {
		return nil, nil, common.ContextError(err)
	}

	fixedLengthFields := make([]byte, 8) // 4 bytes each for magic value and padding length
	_, err = io.ReadFull(clientReader, fixedLengthFields)
	if err != nil {
		return nil, nil, common.ContextError(err)
	}

	clientToServerCipher.XORKeyStream(fixedLengthFields, fixedLengthFields)

	buffer := bytes.NewReader(fixedLengthFields)

	var magicValue, paddingLength int32
	err = binary.Read(buffer, binary.BigEndian, &magicValue)
	if err != nil {
		return nil, nil, common.ContextError(err)
	}
	err = binary.Read(buffer, binary.BigEndian, &paddingLength)
	if err != nil {
		return nil, nil, common.ContextError(err)
	}

	if magicValue != OBFUSCATE_MAGIC_VALUE {
		return nil, nil, common.ContextError(errors.New("invalid magic value"))
	}

	if paddingLength < 0 || paddingLength > OBFUSCATE_MAX_PADDING {
		return nil, nil, common.ContextError(errors.New("invalid padding length"))
	}

	padding := make([]byte, paddingLength)
	_, err = io.ReadFull(clientReader, padding)
	if err != nil {
		return nil, nil, common.ContextError(err)
	}

	clientToServerCipher.XORKeyStream(padding, padding)

	return clientToServerCipher, serverToClientCipher, nil
}
