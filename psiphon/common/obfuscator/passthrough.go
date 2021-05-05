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
	"encoding/binary"
	"io"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"golang.org/x/crypto/hkdf"
)

const (
	TLS_PASSTHROUGH_NONCE_SIZE   = 16
	TLS_PASSTHROUGH_KEY_SIZE     = 32
	TLS_PASSTHROUGH_TIME_PERIOD  = 15 * time.Minute
	TLS_PASSTHROUGH_MESSAGE_SIZE = 32
)

// MakeTLSPassthroughMessage generates a unique TLS passthrough message
// using the passthrough key derived from a master obfuscated key.
//
// The passthrough message demonstrates knowledge of the obfuscated key.
// When useTimeFactor is set, the message will also reflect the current
// time period, limiting how long it remains valid.
//
// The configurable useTimeFactor enables support for legacy clients and
// servers which don't use the time factor.
func MakeTLSPassthroughMessage(
	useTimeFactor bool, obfuscatedKey string) ([]byte, error) {

	passthroughKey := derivePassthroughKey(useTimeFactor, obfuscatedKey)

	message := make([]byte, TLS_PASSTHROUGH_MESSAGE_SIZE)

	_, err := rand.Read(message[0:TLS_PASSTHROUGH_NONCE_SIZE])
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
//
// useTimeFactor must be set to the same value used in
// MakeTLSPassthroughMessage.
func VerifyTLSPassthroughMessage(
	useTimeFactor bool, obfuscatedKey string, message []byte) bool {

	// If the message is the wrong length, continue processing with a stub
	// message of the correct length. This is to avoid leaking the existence of
	// passthrough via timing differences.
	if len(message) != TLS_PASSTHROUGH_MESSAGE_SIZE {
		var stub [TLS_PASSTHROUGH_MESSAGE_SIZE]byte
		message = stub[:]
	}

	passthroughKey := derivePassthroughKey(useTimeFactor, obfuscatedKey)

	h := hmac.New(sha256.New, passthroughKey)
	h.Write(message[0:TLS_PASSTHROUGH_NONCE_SIZE])

	return 1 == subtle.ConstantTimeCompare(
		message[TLS_PASSTHROUGH_NONCE_SIZE:],
		h.Sum(nil)[0:TLS_PASSTHROUGH_MESSAGE_SIZE-TLS_PASSTHROUGH_NONCE_SIZE])
}

// timePeriodSeconds is variable, to enable overriding the value in
// TestTLSPassthrough. This value should not be overridden outside of test
// cases.
var timePeriodSeconds = int64(TLS_PASSTHROUGH_TIME_PERIOD / time.Second)

func derivePassthroughKey(
	useTimeFactor bool, obfuscatedKey string) []byte {

	secret := []byte(obfuscatedKey)

	salt := []byte("passthrough-obfuscation-key")

	if useTimeFactor {

		// Include a time factor, so messages created with this key remain valid
		// only for a limited time period. The current time is rounded, allowing the
		// client clock to be slightly ahead of or behind of the server clock.
		//
		// This time factor mechanism is used in concert with SeedHistory to detect
		// passthrough message replay. SeedHistory, a history of recent passthrough
		// messages, is used to detect duplicate passthrough messages. The time
		// factor bounds the necessary history length: passthrough messages older
		// than the time period no longer need to be retained in history.
		//
		// We _always_ derive the passthrough key for each
		// MakeTLSPassthroughMessage, even for multiple calls in the same time
		// factor period, to avoid leaking the presense of passthough via timing
		// differences at time boundaries. We assume that the server always or never
		// sets useTimeFactor.

		roundedTimePeriod := (time.Now().Unix() + (timePeriodSeconds / 2)) / timePeriodSeconds

		var timeFactor [8]byte
		binary.LittleEndian.PutUint64(timeFactor[:], uint64(roundedTimePeriod))
		salt = append(salt, timeFactor[:]...)
	}

	key := make([]byte, TLS_PASSTHROUGH_KEY_SIZE)

	_, _ = io.ReadFull(hkdf.New(sha256.New, secret, salt, nil), key)

	return key
}
