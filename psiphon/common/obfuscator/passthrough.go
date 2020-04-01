/*
 * Copyright (c) 2020, Psiphon Inc.
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

package obfuscator

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"io"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"golang.org/x/crypto/hkdf"
)

const (
	TLS_PASSTHROUGH_NONCE_SIZE   = 16
	TLS_PASSTHROUGH_KEY_SIZE     = 32
	TLS_PASSTHROUGH_MESSAGE_SIZE = 32
)

// DeriveTLSPassthroughKey derives a TLS passthrough key from a master
// obfuscated key. The resulting key can be cached and passed to
// VerifyTLSPassthroughMessage.
func DeriveTLSPassthroughKey(obfuscatedKey string) ([]byte, error) {

	secret := []byte(obfuscatedKey)

	salt := []byte("passthrough-obfuscation-key")

	key := make([]byte, TLS_PASSTHROUGH_KEY_SIZE)

	_, err := io.ReadFull(hkdf.New(sha256.New, secret, salt, nil), key)
	if err != nil {
		return nil, errors.Trace(err)
	}

	return key, nil
}

// MakeTLSPassthroughMessage generates a unique TLS passthrough message
// using the passthrough key derived from a master obfuscated key.
//
// The passthrough message demonstrates knowledge of the obfuscated key.
func MakeTLSPassthroughMessage(obfuscatedKey string) ([]byte, error) {

	passthroughKey, err := DeriveTLSPassthroughKey(obfuscatedKey)
	if err != nil {
		return nil, errors.Trace(err)
	}

	message := make([]byte, TLS_PASSTHROUGH_MESSAGE_SIZE)

	_, err = rand.Read(message[0:TLS_PASSTHROUGH_NONCE_SIZE])
	if err != nil {
		return nil, errors.Trace(err)
	}

	h := hmac.New(sha256.New, passthroughKey)
	h.Write(message[0:TLS_PASSTHROUGH_NONCE_SIZE])
	copy(message[TLS_PASSTHROUGH_NONCE_SIZE:], h.Sum(nil))

	return message, nil
}

// VerifyTLSPassthroughMessage checks that the specified passthrough message
// was generated using the passthrough key.
func VerifyTLSPassthroughMessage(passthroughKey, message []byte) bool {

	if len(message) != TLS_PASSTHROUGH_MESSAGE_SIZE {
		return false
	}

	h := hmac.New(sha256.New, passthroughKey)
	h.Write(message[0:TLS_PASSTHROUGH_NONCE_SIZE])

	return 1 == subtle.ConstantTimeCompare(
		message[TLS_PASSTHROUGH_NONCE_SIZE:],
		h.Sum(nil)[0:TLS_PASSTHROUGH_MESSAGE_SIZE-TLS_PASSTHROUGH_NONCE_SIZE])
}
