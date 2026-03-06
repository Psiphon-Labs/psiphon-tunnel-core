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
	"encoding/base64"
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

func TestMakePushPayloads_FFD_RespectsMaxSize(t *testing.T) {

	obfuscationKey, publicKey, privateKey, err := GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}

	entries, err := makeTestPrioritizedServerEntries(40, func(i int) int {
		return (i % 7) * 32
	})
	if err != nil {
		t.Fatal(err)
	}

	maxSinglePayloadSize := 0
	for _, entry := range entries {
		result, err := MakePushPayloads(
			obfuscationKey,
			0,
			0,
			publicKey,
			privateKey,
			1*time.Hour,
			[]*PrioritizedServerEntry{entry},
			0)
		if err != nil {
			t.Fatal(err)
		}
		if len(result.Payloads) != 1 {
			t.Fatalf("unexpected single-entry payload count: %d", len(result.Payloads))
		}
		if len(result.Payloads[0]) > maxSinglePayloadSize {
			maxSinglePayloadSize = len(result.Payloads[0])
		}
	}

	maxPayloadSizeBytes := maxSinglePayloadSize * 4

	result, err := MakePushPayloads(
		obfuscationKey,
		0,
		0,
		publicKey,
		privateKey,
		1*time.Hour,
		entries,
		maxPayloadSizeBytes)
	if err != nil {
		t.Fatal(err)
	}

	if len(result.SkippedIndexes) != 0 {
		t.Fatalf("unexpected skipped entries: %d", len(result.SkippedIndexes))
	}

	if len(result.Payloads) <= 1 {
		t.Fatalf("expected multiple payloads, got %d", len(result.Payloads))
	}

	for i, payload := range result.Payloads {
		if len(payload) > maxPayloadSizeBytes {
			t.Fatalf("payload %d exceeded max size: %d > %d", i, len(payload), maxPayloadSizeBytes)
		}
	}

	importedSources, err := importPayloadsAndCountSources(
		obfuscationKey,
		publicKey,
		result.Payloads)
	if err != nil {
		t.Fatal(err)
	}

	if len(importedSources) != len(entries) {
		t.Fatalf("unexpected unique import count: %d", len(importedSources))
	}
	for source, count := range importedSources {
		if count != 1 {
			t.Fatalf("source %s imported %d times", source, count)
		}
	}
}

func TestMakePushPayloads_FFD_SkipsOversizeEntry(t *testing.T) {

	obfuscationKey, publicKey, privateKey, err := GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}

	entries, err := makeTestPrioritizedServerEntries(12, func(_ int) int {
		return 0
	})
	if err != nil {
		t.Fatal(err)
	}

	oversizeEntry, err := makeTestPrioritizedServerEntry(1000000, 300000)
	if err != nil {
		t.Fatal(err)
	}
	oversizeIndex := len(entries)
	entries = append(entries, oversizeEntry)

	maxPayloadSizeBytes := 4096
	result, err := MakePushPayloads(
		obfuscationKey,
		0,
		0,
		publicKey,
		privateKey,
		1*time.Hour,
		entries,
		maxPayloadSizeBytes)
	if err != nil {
		t.Fatal(err)
	}

	if len(result.SkippedIndexes) != 1 {
		t.Fatalf("unexpected skipped index count: %d", len(result.SkippedIndexes))
	}
	if result.SkippedIndexes[0] != oversizeIndex {
		t.Fatalf("unexpected skipped index: %d", result.SkippedIndexes[0])
	}

	for i, payload := range result.Payloads {
		if len(payload) > maxPayloadSizeBytes {
			t.Fatalf("payload %d exceeded max size: %d > %d", i, len(payload), maxPayloadSizeBytes)
		}
	}

	importedSources, err := importPayloadsAndCountSources(
		obfuscationKey,
		publicKey,
		result.Payloads)
	if err != nil {
		t.Fatal(err)
	}

	if len(importedSources) != len(entries)-1 {
		t.Fatalf("unexpected import count: %d", len(importedSources))
	}
	if _, ok := importedSources[oversizeEntry.Source]; ok {
		t.Fatalf("oversize entry was imported")
	}
}

func TestMakePushPayloads_FFD_StrictCapWithPadding(t *testing.T) {

	obfuscationKey, publicKey, privateKey, err := GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}

	entries, err := makeTestPrioritizedServerEntries(30, func(i int) int {
		return (i % 5) * 16
	})
	if err != nil {
		t.Fatal(err)
	}

	minPadding := 1024
	maxPadding := 1024
	maxSinglePayloadSize := 0
	for _, entry := range entries {
		result, err := MakePushPayloads(
			obfuscationKey,
			minPadding,
			maxPadding,
			publicKey,
			privateKey,
			1*time.Hour,
			[]*PrioritizedServerEntry{entry},
			0)
		if err != nil {
			t.Fatal(err)
		}
		if len(result.Payloads[0]) > maxSinglePayloadSize {
			maxSinglePayloadSize = len(result.Payloads[0])
		}
	}

	maxPayloadSizeBytes := maxSinglePayloadSize * 3
	result, err := MakePushPayloads(
		obfuscationKey,
		minPadding,
		maxPadding,
		publicKey,
		privateKey,
		1*time.Hour,
		entries,
		maxPayloadSizeBytes)
	if err != nil {
		t.Fatal(err)
	}

	if len(result.SkippedIndexes) != 0 {
		t.Fatalf("unexpected skipped entries: %d", len(result.SkippedIndexes))
	}

	for i, payload := range result.Payloads {
		if len(payload) > maxPayloadSizeBytes {
			t.Fatalf("payload %d exceeded max size: %d > %d", i, len(payload), maxPayloadSizeBytes)
		}
	}
}

func TestMakePushPayloads_MetadataIntegrity(t *testing.T) {

	obfuscationKey, publicKey, privateKey, err := GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}

	entries, err := makeTestPrioritizedServerEntries(16, func(_ int) int {
		return 0
	})
	if err != nil {
		t.Fatal(err)
	}

	oversizeEntry, err := makeTestPrioritizedServerEntry(2000000, 300000)
	if err != nil {
		t.Fatal(err)
	}
	entries = append(entries, oversizeEntry)

	result, err := MakePushPayloads(
		obfuscationKey,
		0,
		0,
		publicKey,
		privateKey,
		1*time.Hour,
		entries,
		4096)
	if err != nil {
		t.Fatal(err)
	}

	if len(result.Payloads) != len(result.PayloadEntryCounts) {
		t.Fatalf("payload/entry-count mismatch: %d vs %d", len(result.Payloads), len(result.PayloadEntryCounts))
	}

	totalPayloadEntries := 0
	for _, payloadEntryCount := range result.PayloadEntryCounts {
		totalPayloadEntries += payloadEntryCount
	}

	if totalPayloadEntries+len(result.SkippedIndexes) != len(entries) {
		t.Fatalf("metadata does not account for all entries")
	}

	seenSkippedIndexes := make(map[int]bool)
	for _, skippedIndex := range result.SkippedIndexes {
		if skippedIndex < 0 || skippedIndex >= len(entries) {
			t.Fatalf("invalid skipped index: %d", skippedIndex)
		}
		if seenSkippedIndexes[skippedIndex] {
			t.Fatalf("duplicate skipped index: %d", skippedIndex)
		}
		seenSkippedIndexes[skippedIndex] = true
	}
}

func TestMakePushPayloads_SizeDeltaBounds(t *testing.T) {

	obfuscationKey, publicKey, privateKey, err := GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}

	obfuscationKeyBytes, err := base64.StdEncoding.DecodeString(obfuscationKey)
	if err != nil {
		t.Fatal(err)
	}
	publicKeyBytes, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	privateKeyBytes, err := base64.StdEncoding.DecodeString(privateKey)
	if err != nil {
		t.Fatal(err)
	}

	encoder, err := newPayloadEncoder(
		obfuscationKeyBytes,
		publicKeyBytes,
		privateKeyBytes)
	if err != nil {
		t.Fatal(err)
	}

	entries, err := makeTestPrioritizedServerEntries(12, func(i int) int {
		return (i % 4) * 128
	})
	if err != nil {
		t.Fatal(err)
	}

	expires := time.Now().Add(1 * time.Hour).UTC()

	for entryIndex, entry := range entries {
		lowerBoundDelta, err := estimatePrioritizedServerEntrySizeLowerBound(entry)
		if err != nil {
			t.Fatal(err)
		}
		upperBoundDelta, err := encoder.measureObfuscatedPayloadSize(
			[]*PrioritizedServerEntry{entry}, expires, 0)
		if err != nil {
			t.Fatal(err)
		}

		for _, paddingSize := range []int{0, 1024} {
			for baseSize := 0; baseSize < 4; baseSize++ {
				baseEntries := make([]*PrioritizedServerEntry, 0, baseSize)
				for i := 0; i < baseSize; i++ {
					baseEntries = append(baseEntries, entries[(entryIndex+i+1)%len(entries)])
				}

				basePayloadSize, err := encoder.measureObfuscatedPayloadSize(
					baseEntries, expires, paddingSize)
				if err != nil {
					t.Fatal(err)
				}

				candidateEntries := append(append(
					[]*PrioritizedServerEntry(nil), baseEntries...), entry)
				candidatePayloadSize, err := encoder.measureObfuscatedPayloadSize(
					candidateEntries, expires, paddingSize)
				if err != nil {
					t.Fatal(err)
				}

				actualDelta := candidatePayloadSize - basePayloadSize
				if actualDelta < lowerBoundDelta {
					t.Fatalf(
						"actual delta below lower bound: actual=%d lower=%d",
						actualDelta,
						lowerBoundDelta)
				}
				if actualDelta > upperBoundDelta {
					t.Fatalf(
						"actual delta above upper bound: actual=%d upper=%d padding=%d",
						actualDelta,
						upperBoundDelta,
						paddingSize)
				}
			}
		}
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

	serverEntries, err := makeTestPrioritizedServerEntries(128, func(_ int) int {
		return 0
	})
	if err != nil {
		return errors.Trace(err)
	}

	expectPrioritizeDial := make(map[string]bool)
	for _, serverEntry := range serverEntries {
		expectPrioritizeDial[serverEntry.Source] = serverEntry.PrioritizeDial
	}

	// Test: successful import

	result, err := MakePushPayloads(
		obfuscationKey,
		minPadding,
		maxPadding,
		publicKey,
		privateKey,
		1*time.Hour,
		serverEntries,
		0)
	if err != nil {
		return errors.Trace(err)
	}

	if len(result.Payloads) != 1 {
		return errors.TraceNew("unexpected payload count")
	}
	if len(result.PayloadEntryCounts) != 1 || result.PayloadEntryCounts[0] != len(serverEntries) {
		return errors.TraceNew("unexpected payload entry counts")
	}

	seenSources := make(map[string]int)
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
		expect, ok := expectPrioritizeDial[source]
		if !ok {
			return errors.TraceNew("unexpected source")
		}
		if prioritizeDial != expect {
			return errors.TraceNew("unexpected prioritize dial")
		}
		seenSources[source] += 1
		return nil
	}

	totalImported := 0
	for _, payload := range result.Payloads {
		n, err := ImportPushPayload(
			obfuscationKey,
			publicKey,
			payload,
			importer)
		if err != nil {
			return errors.Trace(err)
		}
		totalImported += n
	}

	if totalImported != len(serverEntries) {
		return errors.TraceNew("unexpected import count")
	}
	for source, count := range seenSources {
		if count != 1 {
			return errors.Tracef("source imported unexpected number of times: %s=%d", source, count)
		}
	}

	// Test: expired

	result, err = MakePushPayloads(
		obfuscationKey,
		minPadding,
		maxPadding,
		publicKey,
		privateKey,
		1*time.Microsecond,
		serverEntries,
		0)
	if err != nil {
		return errors.Trace(err)
	}

	time.Sleep(10 * time.Millisecond)

	_, err = ImportPushPayload(
		obfuscationKey,
		publicKey,
		result.Payloads[0],
		importer)
	if err == nil {
		return errors.TraceNew("unexpected success")
	}

	// Test: invalid signature

	result, err = MakePushPayloads(
		obfuscationKey,
		minPadding,
		maxPadding,
		publicKey,
		incorrectPrivateKey,
		1*time.Hour,
		serverEntries,
		0)
	if err != nil {
		return errors.Trace(err)
	}

	_, err = ImportPushPayload(
		obfuscationKey,
		publicKey,
		result.Payloads[0],
		importer)
	if err == nil {
		return errors.TraceNew("unexpected success")
	}

	// Test: wrong signature key

	result, err = MakePushPayloads(
		obfuscationKey,
		minPadding,
		maxPadding,
		publicKey,
		privateKey,
		1*time.Hour,
		serverEntries,
		0)
	if err != nil {
		return errors.Trace(err)
	}

	_, err = ImportPushPayload(
		obfuscationKey,
		incorrectPublicKey,
		result.Payloads[0],
		importer)
	if err == nil {
		return errors.TraceNew("unexpected success")
	}

	// Test: mutate obfuscation layer

	result, err = MakePushPayloads(
		obfuscationKey,
		minPadding,
		maxPadding,
		publicKey,
		privateKey,
		1*time.Hour,
		serverEntries,
		0)
	if err != nil {
		return errors.Trace(err)
	}

	result.Payloads[0][0] = ^result.Payloads[0][0]

	_, err = ImportPushPayload(
		obfuscationKey,
		publicKey,
		result.Payloads[0],
		importer)
	if err == nil {
		return errors.TraceNew("unexpected success")
	}

	return nil
}

func makeTestPrioritizedServerEntries(
	count int,
	sourceExtraBytes func(index int) int) ([]*PrioritizedServerEntry, error) {

	serverEntries := make([]*PrioritizedServerEntry, 0, count)
	for i := range count {
		entry, err := makeTestPrioritizedServerEntry(i, sourceExtraBytes(i))
		if err != nil {
			return nil, errors.Trace(err)
		}
		serverEntries = append(serverEntries, entry)
	}

	return serverEntries, nil
}

func makeTestPrioritizedServerEntry(
	index int,
	sourceExtraBytes int) (*PrioritizedServerEntry, error) {

	serverEntry := &protocol.ServerEntry{
		Tag:                  prng.Base64String(32),
		IpAddress:            fmt.Sprintf("192.0.2.%d", index%255),
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
		return nil, errors.Trace(err)
	}

	packed, err := protocol.EncodePackedServerEntryFields(serverEntryFields)
	if err != nil {
		return nil, errors.Trace(err)
	}

	source := fmt.Sprintf("source-%d", index)
	if sourceExtraBytes > 0 {
		source = source + strings.Repeat("s", sourceExtraBytes)
	}

	return &PrioritizedServerEntry{
		ServerEntryFields: packed,
		Source:            source,
		PrioritizeDial:    index < 32 || index >= 96,
	}, nil
}

func importPayloadsAndCountSources(
	obfuscationKey string,
	signaturePublicKey string,
	payloads [][]byte) (map[string]int, error) {

	sourceCounts := make(map[string]int)
	importer := func(
		packedServerEntryFields protocol.PackedServerEntryFields,
		source string,
		_ bool) error {

		_, err := protocol.DecodePackedServerEntryFields(packedServerEntryFields)
		if err != nil {
			return errors.Trace(err)
		}
		sourceCounts[source] += 1
		return nil
	}

	for _, payload := range payloads {
		_, err := ImportPushPayload(
			obfuscationKey,
			signaturePublicKey,
			payload,
			importer)
		if err != nil {
			return nil, errors.Trace(err)
		}
	}

	return sourceCounts, nil
}

// BenchmarkMakePushPayloads-16    	   19814	     59170 ns/op	   70691 B/op	     248 allocs/op
// BenchmarkMakePushPayloads-16    	    1027	   1226358 ns/op	  374154 B/op	    2311 allocs/op
// BenchmarkMakePushPayloads-16    	    1328	    766850 ns/op	  176738 B/op	    1154 allocs/op
func BenchmarkMakePushPayloads(b *testing.B) {

	obfuscationKey, publicKey, privateKey, err := GenerateKeys()
	if err != nil {
		b.Fatal(err)
	}

	// Create 10 server entries with sizes ranging from ~700 to ~2500 bytes.
	// Base entry is ~500-700 bytes, so add 0-2000 extra bytes to source field.
	entries, err := makeTestPrioritizedServerEntries(10, func(i int) int {
		// Vary size from 0 to 2000 bytes across the 10 entries
		return i * 200
	})
	if err != nil {
		b.Fatal(err)
	}

	maxPayloadSizeBytes := 4096

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := MakePushPayloads(
			obfuscationKey,
			0,
			0,
			publicKey,
			privateKey,
			1*time.Hour,
			entries,
			maxPayloadSizeBytes)
		if err != nil {
			b.Fatal(err)
		}
	}
}
