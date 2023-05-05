/*
 * Copyright (c) 2023, Psiphon Inc.
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

package inproxy

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"sync"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"github.com/panmari/cuckoofilter"
	"golang.org/x/crypto/hkdf"
)

const (
	obfuscationSessionPacketNonceSize = 12
	obfuscationAntiReplayTimePeriod   = 20 * time.Minute
	obfuscationAntiReplayHistorySize  = 10000000
)

// ObfuscationSecret is shared, semisecret value used in obfuscation layers.
type ObfuscationSecret [32]byte

// GenerateRootObfuscationSecret creates a new ObfuscationSecret using
// crypto/rand.
func GenerateRootObfuscationSecret() (ObfuscationSecret, error) {

	var secret ObfuscationSecret
	_, err := rand.Read(secret[:])
	if err != nil {
		return secret, errors.Trace(err)
	}

	return secret, nil
}

// antiReplayTimeFactorPeriodSeconds is variable, to enable overriding the value in
// tests. This value should not be overridden outside of test
// cases.
var antiReplayTimeFactorPeriodSeconds = int64(
	obfuscationAntiReplayTimePeriod / time.Second)

// deriveObfuscationSecret derives an obfuscation secret from the root secret,
// a context, and an optional time factor.
//
// With a time factor, derived secrets remain valid only for a limited time
// period. Both ends of an obfuscated communication will derive the same
// secret based on a shared root secret, a common context, and local clocks.
// The current time is rounded, allowing the one end's clock to be slightly
// ahead of or behind of the other end's clock.
//
// The time factor can be used in concert with a replay history, bounding the
// number of historical messages that need to be retained in the history.
func deriveObfuscationSecret(
	rootObfuscationSecret ObfuscationSecret,
	useTimeFactor bool,
	context string) (ObfuscationSecret, error) {

	var salt []byte

	if useTimeFactor {

		roundedTimePeriod := (time.Now().Unix() +
			(antiReplayTimeFactorPeriodSeconds / 2)) / antiReplayTimeFactorPeriodSeconds

		var timeFactor [8]byte
		binary.BigEndian.PutUint64(timeFactor[:], uint64(roundedTimePeriod))
		salt = timeFactor[:]
	}

	var key ObfuscationSecret

	_, err := io.ReadFull(
		hkdf.New(sha256.New, rootObfuscationSecret[:], salt, []byte(context)), key[:])
	if err != nil {
		return key, errors.Trace(err)
	}

	return key, nil

}

// deriveSessionPacketObfuscationSecret derives a common session obfuscation
// secret for either end of a session. Set isInitiator to true for packets
// sent or received by the initator; and false for packets sent or received
// by a responder. Set isObfuscating to true for sent packets, and false for
// received packets.
func deriveSessionPacketObfuscationSecret(
	rootObfuscationSecret ObfuscationSecret,
	isInitiator bool,
	isObfuscating bool) (ObfuscationSecret, error) {

	// Upstream is packets from the initiator to the responder; or,
	// (isInitiator && isObfuscating) || (!isInitiator && !isObfuscating)
	isUpstream := (isInitiator == isObfuscating)

	// Derive distinct keys for each flow direction, to ensure that the two
	// flows can't simply be xor'd.
	context := "in-proxy-session-packet-intiator-to-responder"
	if !isUpstream {
		context = "in-proxy-session-packet-responder-to-initiator"
	}

	// The time factor is set for upstream; the responder uses an anti-replay
	// history for packets received from initiators.
	key, err := deriveObfuscationSecret(rootObfuscationSecret, isUpstream, context)
	if err != nil {
		return key, errors.Trace(err)
	}

	return key, nil
}

// obfuscateSessionPacket wraps a session packet with an obfuscation layer
// which provides:
//
// - indistiguishability from fully random
// - random padding
// - anti-replay
//
// The full-random and padding properties make obfuscated packets appropriate
// to embed in otherwise plaintext transports, such as HTTP, without being
// trivially fingerprintable.
//
// While Noise protocol sessions messages have nonces and associated
// anti-replay for nonces, this measure doen't cover the session handshake,
// so an independent anti-replay mechanism is implemented here.
func obfuscateSessionPacket(
	rootObfuscationSecret ObfuscationSecret,
	isInitiator bool,
	packet []byte,
	paddingMin int,
	paddingMax int) ([]byte, error) {

	// For simplicity, the secret is derived here for each packet. Derived
	// keys could be cached, but we need to be updated when a time factor is
	// active. Typical in-proxy sessions will exchange only a handful of
	// packets per event: the session handshake, and an API request round
	// trip or two. We don't attempt to avoid allocations here.
	//
	// Benchmark for secret derivation:
	//
	//   BenchmarkDeriveObfuscationSecret
	//   BenchmarkDeriveObfuscationSecret-8   	 1303953	       902.7 ns/op

	key, err := deriveSessionPacketObfuscationSecret(
		rootObfuscationSecret, isInitiator, true)
	if err != nil {
		return nil, errors.Trace(err)
	}

	obfuscatedPacket := make([]byte, obfuscationSessionPacketNonceSize)

	_, err = prng.Read(obfuscatedPacket[:])
	if err != nil {
		return nil, errors.Trace(err)
	}

	var paddedPacket []byte
	paddingSize := prng.Range(paddingMin, paddingMax)
	paddedPacket = binary.AppendUvarint(paddedPacket, uint64(paddingSize))

	paddedPacket = append(paddedPacket, make([]byte, paddingSize)...)
	paddedPacket = append(paddedPacket, packet...)

	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, errors.Trace(err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.Trace(err)
	}

	obfuscatedPacket = aesgcm.Seal(
		obfuscatedPacket,
		obfuscatedPacket[:obfuscationSessionPacketNonceSize],
		paddedPacket,
		nil)

	return obfuscatedPacket, nil
}

// deobfuscateSessionPacket deobfuscates a session packet obfuscated with
// obfuscateSessionPacket and the same deobfuscateSessionPacket.
//
// Responders must supply an obfuscationReplayHistory, which checks for
// replayed session packets (within the time factor). Responders should drop
// into anti-probing response behavior when deobfuscateSessionPacket returns
// an error: the obfuscated packet may have been created by a prober without
// the correct secret; or replayed by a prober.
func deobfuscateSessionPacket(
	rootObfuscationSecret ObfuscationSecret,
	isInitiator bool,
	replayHistory *obfuscationReplayHistory,
	obfuscatedPacket []byte) ([]byte, error) {

	// A responder must provide a relay history, or it's misconfigured.
	if isInitiator == (replayHistory != nil) {
		return nil, errors.TraceNew("unexpected replay history")
	}

	// imitateDeobfuscateSessionPacketDuration is called in early failure
	// cases to imitate the elapsed time of lookups and cryptographic
	// operations that would otherwise be skipped. This is intended to
	// mitigate timing attacks by probers.
	//
	// Limitation: this doesn't result in a constant time.

	if len(obfuscatedPacket) < obfuscationSessionPacketNonceSize {
		imitateDeobfuscateSessionPacketDuration(replayHistory)
		return nil, errors.TraceNew("invalid nonce")
	}

	nonce := obfuscatedPacket[:obfuscationSessionPacketNonceSize]

	if replayHistory != nil && replayHistory.Lookup(nonce) {
		imitateDeobfuscateSessionPacketDuration(nil)
		return nil, errors.TraceNew("replayed nonce")
	}

	key, err := deriveSessionPacketObfuscationSecret(
		rootObfuscationSecret, isInitiator, false)
	if err != nil {
		return nil, errors.Trace(err)
	}

	// As an AEAD, AES-GCM authenticates that the sender used the expected
	// key, and so has the root obfuscation secret.

	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, errors.Trace(err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.Trace(err)
	}

	plaintext, err := aesgcm.Open(
		nil,
		nonce,
		obfuscatedPacket[obfuscationSessionPacketNonceSize:],
		nil)
	if err != nil {
		return nil, errors.Trace(err)
	}

	offset := 0
	paddingSize, n := binary.Uvarint(plaintext[offset:])
	if n < 1 {
		return nil, errors.TraceNew("invalid padding size")
	}
	offset += n
	if len(plaintext[offset:]) < int(paddingSize) {
		return nil, errors.TraceNew("invalid padding")
	}
	offset += int(paddingSize)

	if replayHistory != nil {

		// Now that it's validated, add this packet to the replay history. The
		// nonce is expected to be unique, so it's used as the history key.

		err = replayHistory.Insert(nonce)
		if err != nil {
			return nil, errors.Trace(err)
		}
	}

	return plaintext[offset:], nil
}

func imitateDeobfuscateSessionPacketDuration(replayHistory *obfuscationReplayHistory) {

	// Limitations: only one block is decrypted; crypto/aes or
	// crypto/cipher.GCM may not be constant time, depending on hardware
	// support; at best, this all-zeros invocation will make it as far as
	// GCM.Open, and not check padding.

	const (
		blockSize = 16
		tagSize   = 16
	)
	var secret ObfuscationSecret
	var packet [obfuscationSessionPacketNonceSize + blockSize + tagSize]byte
	if replayHistory != nil {
		_ = replayHistory.Lookup(packet[:obfuscationSessionPacketNonceSize])
	}
	_, _ = deobfuscateSessionPacket(secret, true, nil, packet[:])
}

// obfuscationReplayHistory provides a lookup for recently observed obfuscated
// session packet nonces. History is maintained for
// 2*antiReplayTimeFactorPeriodSeconds; it's assumed that older packets, if
// replayed, will fail to decrypt due to using an expired time factor.
type obfuscationReplayHistory struct {
	mutex         sync.Mutex
	filters       [2]*cuckoo.Filter
	currentFilter int
	switchTime    time.Time
}

func newObfuscationReplayHistory() *obfuscationReplayHistory {

	// Replay history is implemented using cuckoo filters, which use fixed
	// space overhead, and less space overhead than storing nonces explictly
	// under anticipated loads. With cuckoo filters, false positive lookups
	// are possible, but false negative lookups are not. So there's a small
	// chance that a non-replayed nonce will be flagged as in the history,
	// but no chance that a replayed nonce will pass as not in the history.
	//
	// From github.com/panmari/cuckoofilter:
	//   > With the 16 bit fingerprint size in this repository, you can expect r
	//   > ~= 0.0001. Other implementations use 8 bit, which correspond to a
	//   > false positive rate of r ~= 0.03. NewFilter returns a new
	//   > cuckoofilter suitable for the given number of elements. When
	//   > inserting more elements, insertion speed will drop significantly and
	//   > insertions might fail altogether. A capacity of 1000000 is a normal
	//   > default, which allocates about ~2MB on 64-bit machines.
	//
	// With obfuscationAntiReplayHistorySize set to 10M, the session_test test
	// case with 10k clients making 100 requests each all within one time
	// period consistently produces no false positives.
	//
	// To accomodate the rolling time factor window, there are two cuckoo
	// filters, the "current" filter and the "next" filter. New nonces are
	// inserted into both the current and next filter. Every
	// antiReplayTimeFactorPeriodSeconds, the next filter replaces the
	// current filter. The previous current filter is reset and becomes the
	// new next filter.

	return &obfuscationReplayHistory{
		filters: [2]*cuckoo.Filter{
			cuckoo.NewFilter(obfuscationAntiReplayHistorySize),
			cuckoo.NewFilter(obfuscationAntiReplayHistorySize),
		},
		currentFilter: 0,
		switchTime:    time.Now(),
	}
}

func (h *obfuscationReplayHistory) Insert(value []byte) error {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	h.switchFilters()

	if !h.filters[0].Insert(value) || !h.filters[1].Insert(value) {
		return errors.TraceNew("replay history insert failed")
	}

	return nil
}

func (h *obfuscationReplayHistory) Lookup(value []byte) bool {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	h.switchFilters()

	return h.filters[h.currentFilter].Lookup(value)
}

func (h *obfuscationReplayHistory) switchFilters() {

	// Assumes caller holds h.mutex lock.

	now := time.Now()
	if h.switchTime.Before(now.Add(-time.Duration(antiReplayTimeFactorPeriodSeconds) * time.Second)) {
		h.filters[h.currentFilter].Reset()
		h.currentFilter = (h.currentFilter + 1) % 2
		h.switchTime = now
	}
}
