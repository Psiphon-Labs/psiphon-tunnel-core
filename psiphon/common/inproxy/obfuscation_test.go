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
	"bytes"
	"testing"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
)

func FuzzSessionPacketDeobfuscation(f *testing.F) {

	packet := prng.Padding(100, 1000)
	minPadding := 1
	maxPadding := 1000

	rootSecret, err := GenerateRootObfuscationSecret()
	if err != nil {
		f.Fatalf(errors.Trace(err).Error())
	}

	n := 10

	originals := make([][]byte, n)

	for i := 0; i < n; i++ {

		obfuscatedPacket, err := obfuscateSessionPacket(
			rootSecret, true, packet, minPadding, maxPadding)
		if err != nil {
			f.Fatalf(errors.Trace(err).Error())
		}

		originals[i] = obfuscatedPacket

		f.Add(obfuscatedPacket)
	}

	f.Fuzz(func(t *testing.T, obfuscatedPacket []byte) {

		// Make a new history each time to bypass the replay check and focus
		// on fuzzing the parsing code.

		_, err := deobfuscateSessionPacket(
			rootSecret,
			false,
			newObfuscationReplayHistory(),
			obfuscatedPacket)

		// Only the original, valid messages should successfully deobfuscate.

		inOriginals := false
		for i := 0; i < n; i++ {
			if bytes.Equal(originals[i], obfuscatedPacket) {
				inOriginals = true
				break
			}
		}

		if (err == nil) != inOriginals {
			f.Errorf("unexpected deobfuscation result")
		}
	})
}

func TestSessionPacketObfuscation(t *testing.T) {
	err := runTestSessionPacketObfuscation()
	if err != nil {
		t.Errorf(errors.Trace(err).Error())
	}
}

func runTestSessionPacketObfuscation() error {

	// Use a replay time period factor more suitable for test runs.

	originalAntiReplayTimeFactorPeriodSeconds := antiReplayTimeFactorPeriodSeconds
	antiReplayTimeFactorPeriodSeconds = 2
	defer func() {
		antiReplayTimeFactorPeriodSeconds = originalAntiReplayTimeFactorPeriodSeconds
	}()

	rootSecret, err := GenerateRootObfuscationSecret()
	if err != nil {
		return errors.Trace(err)
	}

	initiatorSendSecret, initiatorReceiveSecret, err :=
		deriveSessionPacketObfuscationSecrets(rootSecret, true)
	if err != nil {
		return errors.Trace(err)
	}

	responderSendSecret, responderReceiveSecret, err :=
		deriveSessionPacketObfuscationSecrets(rootSecret, false)
	if err != nil {
		return errors.Trace(err)
	}

	replayHistory := newObfuscationReplayHistory()

	// Test: obfuscate/deobfuscate initiator -> responder

	packet := prng.Bytes(1000)
	minPadding := 1
	maxPadding := 1000

	obfuscatedPacket1, err := obfuscateSessionPacket(
		initiatorSendSecret, true, packet, minPadding, maxPadding)
	if err != nil {
		return errors.Trace(err)
	}

	packet1, err := deobfuscateSessionPacket(
		responderReceiveSecret, false, replayHistory, obfuscatedPacket1)
	if err != nil {
		return errors.Trace(err)
	}

	if !bytes.Equal(packet1, packet) {
		return errors.TraceNew("unexpected deobfuscated packet")
	}

	// Test: replay packet

	_, err = deobfuscateSessionPacket(
		responderReceiveSecret, false, replayHistory, obfuscatedPacket1)
	if err == nil {
		return errors.TraceNew("unexpected replay success")
	}

	// Test: replay packet after time factor period

	time.Sleep(time.Duration(antiReplayTimeFactorPeriodSeconds) * time.Second)

	_, err = deobfuscateSessionPacket(
		responderReceiveSecret, false, replayHistory, obfuscatedPacket1)
	if err == nil {
		return errors.TraceNew("unexpected replay success")
	}

	// Test: different packet sizes (due to padding)

	n := 10
	for i := 0; i < n; i++ {
		obfuscatedPacket2, err := obfuscateSessionPacket(
			initiatorSendSecret, true, packet, minPadding, maxPadding)
		if err != nil {
			return errors.Trace(err)
		}
		if len(obfuscatedPacket1) != len(obfuscatedPacket2) {
			break
		}
		if i == n-1 {
			return errors.TraceNew("unexpected same size")
		}
	}

	// Test: obfuscate/deobfuscate responder -> initiator

	obfuscatedPacket2, err := obfuscateSessionPacket(
		responderSendSecret, false, packet, minPadding, maxPadding)
	if err != nil {
		return errors.Trace(err)
	}

	packet2, err := deobfuscateSessionPacket(
		initiatorReceiveSecret, true, nil, obfuscatedPacket2)
	if err != nil {
		return errors.Trace(err)
	}

	if !bytes.Equal(packet2, packet) {
		return errors.TraceNew("unexpected deobfuscated packet")
	}

	// Test: initiator -> initiator

	obfuscatedPacket1, err = obfuscateSessionPacket(
		initiatorSendSecret, true, packet, minPadding, maxPadding)
	if err != nil {
		return errors.Trace(err)
	}

	_, err = deobfuscateSessionPacket(
		initiatorReceiveSecret, true, nil, obfuscatedPacket1)
	if err == nil {
		return errors.TraceNew("unexpected initiator -> initiator success")
	}

	// Test: responder -> responder

	obfuscatedPacket2, err = obfuscateSessionPacket(
		responderSendSecret, false, packet, minPadding, maxPadding)
	if err != nil {
		return errors.Trace(err)
	}

	_, err = deobfuscateSessionPacket(
		responderReceiveSecret, false, newObfuscationReplayHistory(), obfuscatedPacket2)
	if err == nil {
		return errors.TraceNew("unexpected responder -> responder success")
	}

	// Test: distinct keys derived for each direction

	isInitiator := true
	secret1, err := deriveSessionPacketObfuscationSecret(
		rootSecret, isInitiator, true)
	if err != nil {
		return errors.Trace(err)
	}

	isInitiator = false
	secret2, err := deriveSessionPacketObfuscationSecret(
		rootSecret, isInitiator, true)
	if err != nil {
		return errors.Trace(err)
	}

	err = testMostlyDifferent(secret1[:], secret2[:])
	if err != nil {
		return errors.Trace(err)
	}

	// Test: for identical packet with same padding and derived key, most
	// bytes different (due to nonce)

	padding := 100

	obfuscatedPacket1, err = obfuscateSessionPacket(
		initiatorSendSecret, true, packet, padding, padding)
	if err != nil {
		return errors.Trace(err)
	}

	obfuscatedPacket2, err = obfuscateSessionPacket(
		initiatorSendSecret, true, packet, padding, padding)
	if err != nil {
		return errors.Trace(err)
	}

	err = testMostlyDifferent(obfuscatedPacket1, obfuscatedPacket2)
	if err != nil {
		return errors.Trace(err)
	}

	// Test: uniformly random

	for _, isInitiator := range []bool{true, false} {

		err = testEntropy(func() ([]byte, error) {
			secret := initiatorSendSecret
			if !isInitiator {
				secret = responderSendSecret
			}
			obfuscatedPacket, err := obfuscateSessionPacket(
				secret, isInitiator, packet, padding, padding)
			if err != nil {
				return nil, errors.Trace(err)
			}
			return obfuscatedPacket, nil
		})
		if err != nil {
			return errors.Trace(err)
		}
	}

	// Test: wrong obfuscation secret

	wrongRootSecret, err := GenerateRootObfuscationSecret()
	if err != nil {
		return errors.Trace(err)
	}

	wrongInitiatorSendSecret, _, err :=
		deriveSessionPacketObfuscationSecrets(wrongRootSecret, true)
	if err != nil {
		return errors.Trace(err)
	}

	obfuscatedPacket1, err = obfuscateSessionPacket(
		wrongInitiatorSendSecret, true, packet, minPadding, maxPadding)
	if err != nil {
		return errors.Trace(err)
	}

	_, err = deobfuscateSessionPacket(
		responderReceiveSecret, false, newObfuscationReplayHistory(), obfuscatedPacket1)
	if err == nil {
		return errors.TraceNew("unexpected wrong secret success")
	}

	// Test: truncated obfuscated packet

	obfuscatedPacket1, err = obfuscateSessionPacket(
		initiatorSendSecret, true, packet, minPadding, maxPadding)
	if err != nil {
		return errors.Trace(err)
	}

	obfuscatedPacket1 = obfuscatedPacket1[:len(obfuscatedPacket1)-1]

	_, err = deobfuscateSessionPacket(
		responderReceiveSecret, false, newObfuscationReplayHistory(), obfuscatedPacket1)
	if err == nil {
		return errors.TraceNew("unexpected truncated packet success")
	}

	// Test: flip byte

	obfuscatedPacket1, err = obfuscateSessionPacket(
		initiatorSendSecret, true, packet, minPadding, maxPadding)
	if err != nil {
		return errors.Trace(err)
	}

	obfuscatedPacket1[len(obfuscatedPacket1)-1] ^= 1

	_, err = deobfuscateSessionPacket(
		responderReceiveSecret, false, newObfuscationReplayHistory(), obfuscatedPacket1)
	if err == nil {
		return errors.TraceNew("unexpected modified packet success")
	}

	return nil
}

func TestObfuscationReplayHistory(t *testing.T) {
	err := runTestObfuscationReplayHistory()
	if err != nil {
		t.Errorf(errors.Trace(err).Error())
	}
}

func runTestObfuscationReplayHistory() error {

	replayHistory := newObfuscationReplayHistory()

	size := obfuscationSessionPacketNonceSize

	count := int(obfuscationAntiReplayHistorySize / 100)

	// Test: values found as expected; no false positives

	for i := 0; i < count; i++ {

		value := prng.Bytes(size)

		if replayHistory.Lookup(value) {
			return errors.Tracef("value found on iteration %d", i)
		}

		err := replayHistory.Insert(value)
		if err != nil {
			return errors.Trace(err)
		}

		if !replayHistory.Lookup(value) {
			return errors.Tracef("value not found on iteration %d", i)
		}
	}

	return nil
}

func testMostlyDifferent(a, b []byte) error {

	if len(a) != len(b) {
		return errors.TraceNew("unexpected different size")
	}

	equalBytes := 0
	for i := 0; i < len(a); i++ {
		if a[i] == b[i] {
			equalBytes += 1
		}
	}

	// TODO: use a stricter threshold?
	if equalBytes > len(a)/10 {
		return errors.Tracef("unexpected similar bytes: %d/%d", equalBytes, len(a))
	}

	return nil
}

func testEntropy(f func() ([]byte, error)) error {

	bitCount := make(map[int]int)

	n := 10000

	for i := 0; i < n; i++ {

		value, err := f()
		if err != nil {
			return errors.Trace(err)
		}

		for j := 0; j < len(value); j++ {
			for k := 0; k < 8; k++ {
				bit := (uint8(value[j]) >> k) & 0x1
				bitCount[(j*8)+k] += int(bit)
			}
		}

	}

	// TODO: use a stricter threshold?
	for index, count := range bitCount {
		if count < n/3 || count > 2*n/3 {
			return errors.Tracef("unexpected entropy at %d: %v", index, bitCount)
		}
	}

	return nil
}
