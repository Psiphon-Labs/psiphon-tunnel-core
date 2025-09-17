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
	"encoding/base64"
	"encoding/binary"
	"io"
	"sync"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"github.com/bits-and-blooms/bloom/v3"
	"golang.org/x/crypto/hkdf"
)

const (
	obfuscationSessionPacketNonceSize = 12
	obfuscationAntiReplayTimePeriod   = 10 * time.Minute
	obfuscationAntiReplayHistorySize  = 10_000_000
)

// ObfuscationSecret is shared, semisecret value used in obfuscation layers.
type ObfuscationSecret [32]byte

// ObfuscationSecretFromString returns an ObfuscationSecret given its string encoding.
func ObfuscationSecretFromString(s string) (ObfuscationSecret, error) {
	var secret ObfuscationSecret
	return secret, errors.Trace(fromBase64String(s, secret[:]))
}

// String emits ObfuscationSecrets as base64.
func (secret ObfuscationSecret) String() string {
	return base64.RawStdEncoding.EncodeToString([]byte(secret[:]))
}

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
// and context.
func deriveObfuscationSecret(
	rootObfuscationSecret ObfuscationSecret,
	context string) (ObfuscationSecret, error) {

	var key ObfuscationSecret
	_, err := io.ReadFull(
		hkdf.New(sha256.New, rootObfuscationSecret[:], nil, []byte(context)), key[:])
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

	key, err := deriveObfuscationSecret(rootObfuscationSecret, context)
	if err != nil {
		return ObfuscationSecret{}, errors.Trace(err)
	}

	return key, nil
}

// deriveSessionPacketObfuscationSecrets derives both send and receive
// obfuscation secrets.
func deriveSessionPacketObfuscationSecrets(
	rootObfuscationSecret ObfuscationSecret,
	isInitiator bool) (ObfuscationSecret, ObfuscationSecret, error) {

	send, err := deriveSessionPacketObfuscationSecret(
		rootObfuscationSecret, isInitiator, true)
	if err != nil {
		return ObfuscationSecret{}, ObfuscationSecret{}, errors.Trace(err)
	}

	receive, err := deriveSessionPacketObfuscationSecret(
		rootObfuscationSecret, isInitiator, false)
	if err != nil {
		return ObfuscationSecret{}, ObfuscationSecret{}, errors.Trace(err)
	}

	return send, receive, nil
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
	obfuscationSecret ObfuscationSecret,
	isInitiator bool,
	packet []byte,
	paddingMin int,
	paddingMax int) ([]byte, error) {

	obfuscatedPacket := make([]byte, obfuscationSessionPacketNonceSize)

	_, err := prng.Read(obfuscatedPacket[:])
	if err != nil {
		return nil, errors.Trace(err)
	}

	// Initiators add a timestamp within the obfuscated packet. The responder
	// uses this value to discard potentially replayed packets which are
	// outside the time range of the responder's anti-replay history.

	// TODO: add a consistent (per-session), random offset to timestamps for
	// privacy?

	var timestampedPacket []byte
	if isInitiator {
		timestampedPacket = binary.AppendVarint(nil, time.Now().Unix())
	}

	paddingSize := prng.Range(paddingMin, paddingMax)
	paddedPacket := binary.AppendUvarint(timestampedPacket, uint64(paddingSize))

	paddedPacket = append(paddedPacket, make([]byte, paddingSize)...)
	paddedPacket = append(paddedPacket, packet...)

	block, err := aes.NewCipher(obfuscationSecret[:])
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

// DeobfuscationAnomoly is an error type that is returned when an anomalous
// condition is encountered while deobfuscating a session packet. This may
// include malformed packets; packets obfuscated without knowledge of the
// correct obfuscation secret; replay of valid packets; etc.
//
// On the server side, Broker.HandleSessionPacket already specifies that
// anti-probing mechanisms should be applied on any error return; the
// DeobfuscationAnomoly error type enables further error filtering before
// logging an irregular tunnel event.
type DeobfuscationAnomoly struct {
	err error
}

func NewDeobfuscationAnomoly(err error) *DeobfuscationAnomoly {
	return &DeobfuscationAnomoly{err: err}
}

func (e *DeobfuscationAnomoly) Error() string {
	return e.err.Error()
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
	obfuscationSecret ObfuscationSecret,
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
		return nil, NewDeobfuscationAnomoly(
			errors.TraceNew("invalid nonce"))
	}

	nonce := obfuscatedPacket[:obfuscationSessionPacketNonceSize]

	if replayHistory != nil && replayHistory.Lookup(nonce) {
		imitateDeobfuscateSessionPacketDuration(nil)
		return nil, NewDeobfuscationAnomoly(
			errors.TraceNew("replayed nonce"))
	}

	// As an AEAD, AES-GCM authenticates that the sender used the expected
	// key, and so has the root obfuscation secret.

	block, err := aes.NewCipher(obfuscationSecret[:])
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

	n := 0
	offset := 0
	timestamp := int64(0)
	if replayHistory != nil {
		timestamp, n = binary.Varint(plaintext[offset:])
		if timestamp == 0 && n <= 0 {
			return nil, NewDeobfuscationAnomoly(
				errors.TraceNew("invalid timestamp"))
		}
		offset += n
	}
	paddingSize, n := binary.Uvarint(plaintext[offset:])
	if n < 1 {
		return nil, NewDeobfuscationAnomoly(
			errors.TraceNew("invalid padding size"))
	}
	offset += n
	if len(plaintext[offset:]) < int(paddingSize) {
		return nil, NewDeobfuscationAnomoly(
			errors.TraceNew("invalid padding"))
	}
	offset += int(paddingSize)

	if replayHistory != nil {

		// Accept the initiator's timestamp only if it's within +/-
		// antiReplayTimeFactorPeriodSeconds/2 of the responder's clock. This
		// step discards packets that are outside the range of the replay history.

		now := time.Now().Unix()
		if timestamp+antiReplayTimeFactorPeriodSeconds/2 < now {
			return nil, NewDeobfuscationAnomoly(
				errors.TraceNew("timestamp behind"))
		}
		if timestamp-antiReplayTimeFactorPeriodSeconds/2 > now {
			return nil, NewDeobfuscationAnomoly(
				errors.TraceNew("timestamp ahead"))
		}

		// Now that it's validated, add this packet to the replay history. The
		// nonce is expected to be unique, so it's used as the history key.

		replayHistory.Insert(nonce)
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
// replayed, will fail to deobfuscate due to using an expired timestamp.
type obfuscationReplayHistory struct {
	mutex         sync.Mutex
	filters       [2]*bloom.BloomFilter
	currentFilter int
	switchTime    time.Time
}

func newObfuscationReplayHistory() *obfuscationReplayHistory {

	// Replay history is implemented using bloom filters, which use fixed
	// space overhead, and less space overhead than storing nonces explictly
	// under anticipated loads. With bloom filters, false positive lookups
	// are possible, but false negative lookups are not. So there's a small
	// chance that a non-replayed nonce will be flagged as in the history,
	// but no chance that a replayed nonce will pass as not in the history.
	//
	// With obfuscationAntiReplayHistorySize set to 10M and a false positive
	// rate of 0.001, the session_test test case with 10k clients making 100
	// requests each all within one time period consistently produces no
	// false positives.
	//
	// Memory overhead is approximately 18MB per bloom filter, so 18MB x 2.
	// From:
	//
	// m, _ := bloom.EstimateParameters(10_000_000, 0.001) --> 143775876
	// bitset.New(143775876).BinaryStorageSize() --> approx. 18MB in terms of
	// underlying bits-and-blooms/bitset.BitSet
	//
	// To accomodate the rolling time factor window, there are two rotating
	// bloom filters.

	return &obfuscationReplayHistory{
		filters: [2]*bloom.BloomFilter{
			bloom.NewWithEstimates(obfuscationAntiReplayHistorySize, 0.001),
			bloom.NewWithEstimates(obfuscationAntiReplayHistorySize, 0.001),
		},
		currentFilter: 0,
		switchTime:    time.Now(),
	}
}

func (h *obfuscationReplayHistory) Insert(value []byte) {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	h.switchFilters()

	h.filters[h.currentFilter].Add(value)
}

func (h *obfuscationReplayHistory) Lookup(value []byte) bool {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	h.switchFilters()

	return h.filters[0].Test(value) ||
		h.filters[1].Test(value)
}

func (h *obfuscationReplayHistory) switchFilters() {

	// Assumes caller holds h.mutex lock.

	now := time.Now()
	if h.switchTime.Before(now.Add(-time.Duration(antiReplayTimeFactorPeriodSeconds) * time.Second)) {
		h.currentFilter = (h.currentFilter + 1) % 2
		h.filters[h.currentFilter].ClearAll()
		h.switchTime = now
	}
}
