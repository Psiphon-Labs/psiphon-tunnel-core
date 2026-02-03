/*
 * Copyright (c) 2026, Psiphon Inc.
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

package push

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
)

func TestPush(t *testing.T) {

	err := runTestPush()
	if err != nil {
		t.Fatal(err.Error())
	}
}

func runTestPush() error {

	obfuscationKey, publicKey, privateKey, err := GenerateKeys()
	if err != nil {
		return errors.Trace(err)
	}

	minPadding := 0
	maxPadding := 65535

	_, incorrectPublicKey, incorrectPrivateKey, err := GenerateKeys()
	if err != nil {
		return errors.Trace(err)
	}

	var serverEntries []*PrioritizedServerEntry

	for i := 0; i < 128; i++ {

		serverEntry := &protocol.ServerEntry{
			Tag:                  prng.Base64String(32),
			IpAddress:            fmt.Sprintf("192.0.2.%d", i),
			SshUsername:          prng.HexString(8),
			SshPassword:          prng.HexString(32),
			SshHostKey:           prng.Base64String(280),
			SshObfuscatedPort:    prng.Range(1, 65535),
			SshObfuscatedKey:     prng.HexString(32),
			Capabilities:         []string{"OSSH"},
			Region:               prng.HexString(1),
			ProviderID:           strings.ToUpper(prng.HexString(8)),
			ConfigurationVersion: 0,
			Signature:            prng.Base64String(80),
		}

		serverEntryFields, err := serverEntry.GetServerEntryFields()
		if err != nil {
			return errors.Trace(err)
		}

		packed, err := protocol.EncodePackedServerEntryFields(serverEntryFields)
		if err != nil {
			return errors.Trace(err)
		}

		serverEntries = append(serverEntries, &PrioritizedServerEntry{
			ServerEntryFields: packed,
			Source:            fmt.Sprintf("source-%d", i),
			PrioritizeDial:    i < 32 || i >= 96,
		})
	}

	// Test: successful import

	pushServerEntries := [][]*PrioritizedServerEntry{
		serverEntries[0:32], serverEntries[32:64],
		serverEntries[64:96], serverEntries[96:128],
	}

	payloads, err := MakePushPayloads(
		obfuscationKey,
		minPadding,
		maxPadding,
		publicKey,
		privateKey,
		1*time.Hour,
		pushServerEntries)
	if err != nil {
		return errors.Trace(err)
	}

	if len(payloads) != len(pushServerEntries) {
		return errors.TraceNew("unexpected payload count")
	}

	expectPrioritizeDial := true

	importer := func(
		packedServerEntryFields protocol.PackedServerEntryFields,
		source string,
		prioritizeDial bool) error {

		serverEntryFields, err := protocol.DecodePackedServerEntryFields(packedServerEntryFields)
		if err != nil {
			return errors.Trace(err)
		}
		if !strings.HasPrefix(serverEntryFields["ipAddress"].(string), "192.0.2") {
			return errors.TraceNew("unexpected server entry IP address")
		}
		if prioritizeDial != expectPrioritizeDial {
			return errors.TraceNew("unexpected prioritize dial")
		}
		return nil
	}

	for i, payload := range payloads {

		expectPrioritizeDial = i == 0 || i == 3

		n, err := ImportPushPayload(
			obfuscationKey,
			publicKey,
			payload,
			importer)
		if err != nil {
			return errors.Trace(err)
		}

		if n != 32 {
			return errors.TraceNew("unexpected import count")
		}
	}

	// Test: expired

	payloads, err = MakePushPayloads(
		obfuscationKey,
		minPadding,
		maxPadding,
		publicKey,
		privateKey,
		1*time.Microsecond,
		pushServerEntries)
	if err != nil {
		return errors.Trace(err)
	}

	time.Sleep(10 * time.Millisecond)

	_, err = ImportPushPayload(
		obfuscationKey,
		publicKey,
		payloads[0],
		importer)
	if err == nil {
		return errors.TraceNew("unexpected success")
	}

	// Test: invalid signature

	payloads, err = MakePushPayloads(
		obfuscationKey,
		minPadding,
		maxPadding,
		publicKey,
		incorrectPrivateKey,
		1*time.Hour,
		pushServerEntries)
	if err != nil {
		return errors.Trace(err)
	}

	_, err = ImportPushPayload(
		obfuscationKey,
		publicKey,
		payloads[0],
		importer)
	if err == nil {
		return errors.TraceNew("unexpected success")
	}

	// Test: wrong signature key

	payloads, err = MakePushPayloads(
		obfuscationKey,
		minPadding,
		maxPadding,
		publicKey,
		privateKey,
		1*time.Hour,
		pushServerEntries)
	if err != nil {
		return errors.Trace(err)
	}

	_, err = ImportPushPayload(
		obfuscationKey,
		incorrectPublicKey,
		payloads[0],
		importer)
	if err == nil {
		return errors.TraceNew("unexpected success")
	}

	// Test: mutate obfuscation layer

	payloads, err = MakePushPayloads(
		obfuscationKey,
		minPadding,
		maxPadding,
		publicKey,
		privateKey,
		1*time.Hour,
		pushServerEntries)
	if err != nil {
		return errors.Trace(err)
	}

	payloads[0][0] = ^payloads[0][0]

	_, err = ImportPushPayload(
		obfuscationKey,
		publicKey,
		payloads[0],
		importer)
	if err == nil {
		return errors.TraceNew("unexpected success")
	}

	return nil
}
