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
	"bytes"
	"fmt"
	"reflect"
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

	serverEntries, err := makeTestPrioritizedServerEntries(
		128,
		func(_ int) int { return 0 })
	if err != nil {
		return errors.Trace(err)
	}

	expectPrioritizeDialReasons := make(map[string]string)
	expectPrioritizeTunnelProtocols := make(map[string]string)
	for _, serverEntry := range serverEntries {
		if serverEntry.PrioritizeDial != (serverEntry.PrioritizeReason != "") {
			return errors.TraceNew("unexpected test data")
		}
		if serverEntry.PrioritizeDial != (serverEntry.PrioritizeTunnelProtocol != "") {
			return errors.TraceNew("unexpected test data")
		}
		expectPrioritizeDialReasons[serverEntry.Source] = serverEntry.PrioritizeReason
		expectPrioritizeTunnelProtocols[serverEntry.Source] = serverEntry.PrioritizeTunnelProtocol
	}

	maker, err := NewPushPayloadMaker(obfuscationKey, publicKey, privateKey)
	if err != nil {
		return errors.Trace(err)
	}

	incorrectMaker, err := NewPushPayloadMaker(obfuscationKey, publicKey, incorrectPrivateKey)
	if err != nil {
		return errors.Trace(err)
	}

	// Test: successful import

	result, err := maker.MakePushPayloads(
		minPadding, maxPadding, 1*time.Hour, serverEntries, PinnedEntries{}, 0)
	if err != nil {
		return errors.Trace(err)
	}

	if len(result.Payloads) != 1 {
		return errors.TraceNew("unexpected payload count")
	}
	if len(result.PayloadRegularEntryIndexes) != 1 || len(result.PayloadRegularEntryIndexes[0]) != len(serverEntries) {
		return errors.TraceNew("unexpected payload regular entry indexes")
	}

	seenSources := make(map[string]int)
	importer := func(
		packedServerEntryFields protocol.PackedServerEntryFields,
		source string,
		prioritizeDial bool,
		prioritizeReason string,
		prioritizeTunnelProtocol string) error {

		serverEntryFields, err := protocol.DecodePackedServerEntryFields(packedServerEntryFields)
		if err != nil {
			return errors.Trace(err)
		}
		if !strings.HasPrefix(serverEntryFields["ipAddress"].(string), "192.0.2") {
			return errors.TraceNew("unexpected server entry IP address")
		}
		expectReason, ok := expectPrioritizeDialReasons[source]
		if !ok {
			return errors.TraceNew("unexpected source")
		}
		if prioritizeDial != (expectReason != "") {
			return errors.TraceNew("unexpected prioritize dial")
		}
		if prioritizeReason != expectReason {
			return errors.TraceNew("unexpected prioritize reason")
		}
		expectProtocol, ok := expectPrioritizeTunnelProtocols[source]
		if !ok {
			return errors.TraceNew("unexpected source")
		}
		if prioritizeTunnelProtocol != expectProtocol {
			return errors.TraceNew("unexpected prioritize tunnel protocol")
		}
		seenSources[source] += 1
		return nil
	}

	totalImported := 0
	for _, payload := range result.Payloads {
		n, _, err := ImportPushPayload(
			obfuscationKey,
			publicKey,
			payload,
			importer,
			nil)
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

	_, _, err = ImportPushPayload(
		obfuscationKey,
		publicKey,
		result.Payloads[0],
		nil,
		nil)
	if err == nil {
		return errors.TraceNew("unexpected success with missing server entry importer")
	}

	// Test: light proxy is placed only in the first payload

	lightProxyEntry := &LightProxyEntry{
		ProxyEntry:        []byte("encoded-signed-light-proxy-entry-1"),
		ProxyEntryTracker: 0x0102030405060708,
	}

	result, err = maker.MakePushPayloads(
		0, 0, 1*time.Hour, serverEntries[:16],
		PinnedEntries{LightProxyEntries: []*LightProxyEntry{lightProxyEntry}}, 2048)
	if err != nil {
		return errors.Trace(err)
	}
	if len(result.Payloads) <= 1 {
		return errors.TraceNew("expected multiple light proxy payloads")
	}

	for payloadIndex, payload := range result.Payloads {
		var importedLightProxyEntry *LightProxyEntry
		_, _, err := ImportPushPayload(
			obfuscationKey,
			publicKey,
			payload,
			func(
				packedServerEntryFields protocol.PackedServerEntryFields,
				source string,
				prioritizeDial bool,
				prioritizeReason string,
				prioritizeTunnelProtocol string) error {

				return importer(
					packedServerEntryFields,
					source,
					prioritizeDial,
					prioritizeReason,
					prioritizeTunnelProtocol)
			},
			func(proxyEntry []byte, proxyEntryTracker int64) error {
				if importedLightProxyEntry != nil {
					return errors.TraceNew(
						"light proxy importer invoked more than once for a single payload")
				}
				importedLightProxyEntry = &LightProxyEntry{
					ProxyEntry:        proxyEntry,
					ProxyEntryTracker: proxyEntryTracker,
				}
				return nil
			})
		if err != nil {
			return errors.Trace(err)
		}
		expectLightProxy := payloadIndex == 0
		if expectLightProxy {
			if importedLightProxyEntry == nil {
				return errors.Tracef(
					"expected light proxy entry in payload %d", payloadIndex)
			}
			if !bytes.Equal(
				importedLightProxyEntry.ProxyEntry,
				lightProxyEntry.ProxyEntry) ||
				importedLightProxyEntry.ProxyEntryTracker !=
					lightProxyEntry.ProxyEntryTracker {

				return errors.TraceNew("unexpected light proxy entry")
			}
		} else if importedLightProxyEntry != nil {
			return errors.Tracef(
				"unexpected light proxy entry in payload %d", payloadIndex)
		}
	}

	// Test: light proxy only payload (no regular entries)

	result, err = maker.MakePushPayloads(
		0, 0, 1*time.Hour, nil,
		PinnedEntries{LightProxyEntries: []*LightProxyEntry{lightProxyEntry}}, 0)
	if err != nil {
		return errors.Trace(err)
	}
	if len(result.Payloads) != 1 {
		return errors.TraceNew("unexpected light-only payload count")
	}

	nServer, nLightProxy, err := ImportPushPayload(
		obfuscationKey,
		publicKey,
		result.Payloads[0],
		importer,
		func(proxyEntry []byte, proxyEntryTracker int64) error {
			if !bytes.Equal(proxyEntry, lightProxyEntry.ProxyEntry) ||
				proxyEntryTracker != lightProxyEntry.ProxyEntryTracker {

				return errors.TraceNew("unexpected light-only proxy entry")
			}
			return nil
		})
	if err != nil {
		return errors.Trace(err)
	}
	if nServer != 0 || nLightProxy != 1 {
		return errors.TraceNew("unexpected light-only import count")
	}

	_, _, err = ImportPushPayload(
		obfuscationKey,
		publicKey,
		result.Payloads[0],
		importer,
		nil)
	if err == nil {
		return errors.TraceNew("unexpected success with missing light proxy entry importer")
	}

	// Test: multiple light proxy entries are imported from a light-only payload.

	lightProxyEntry2 := &LightProxyEntry{
		ProxyEntry:        []byte("encoded-signed-light-proxy-entry-2"),
		ProxyEntryTracker: 0x1112131415161718,
	}
	result, err = maker.MakePushPayloads(
		0, 0, 1*time.Hour, nil,
		PinnedEntries{LightProxyEntries: []*LightProxyEntry{lightProxyEntry, lightProxyEntry2}}, 0)
	if err != nil {
		return errors.Trace(err)
	}
	if len(result.Payloads) != 1 {
		return errors.TraceNew("unexpected multi-light-only payload count")
	}

	var importedLightProxyEntries []*LightProxyEntry
	nServer, nLightProxy, err = ImportPushPayload(
		obfuscationKey,
		publicKey,
		result.Payloads[0],
		importer,
		func(proxyEntry []byte, proxyEntryTracker int64) error {
			importedLightProxyEntries = append(importedLightProxyEntries, &LightProxyEntry{
				ProxyEntry:        proxyEntry,
				ProxyEntryTracker: proxyEntryTracker,
			})
			return nil
		})
	if err != nil {
		return errors.Trace(err)
	}
	if nServer != 0 || nLightProxy != 2 {
		return errors.TraceNew("unexpected multi-light-only import count")
	}
	if len(importedLightProxyEntries) != 2 ||
		!bytes.Equal(importedLightProxyEntries[0].ProxyEntry, lightProxyEntry.ProxyEntry) ||
		importedLightProxyEntries[0].ProxyEntryTracker != lightProxyEntry.ProxyEntryTracker ||
		!bytes.Equal(importedLightProxyEntries[1].ProxyEntry, lightProxyEntry2.ProxyEntry) ||
		importedLightProxyEntries[1].ProxyEntryTracker != lightProxyEntry2.ProxyEntryTracker {

		return errors.TraceNew("unexpected multi-light-only proxy entries")
	}

	// Test: a pinned server entry is prioritized into the first payload

	pinnedServerEntry := serverEntries[0]
	pinned := PinnedEntries{
		PrioritizedServerEntries: []*PrioritizedServerEntry{pinnedServerEntry},
	}
	regularEntries := serverEntries[1:16]
	result, err = maker.MakePushPayloads(
		0, 0, 1*time.Hour, regularEntries, pinned, 2048)
	if err != nil {
		return errors.Trace(err)
	}

	for payloadIndex, payload := range result.Payloads {
		seenPinned := false
		_, _, err := ImportPushPayload(
			obfuscationKey,
			publicKey,
			payload,
			func(
				packedServerEntryFields protocol.PackedServerEntryFields,
				source string,
				_ bool,
				_ string,
				_ string) error {

				if source == pinnedServerEntry.Source {
					seenPinned = true
				}
				_, decodeErr := protocol.DecodePackedServerEntryFields(packedServerEntryFields)
				return decodeErr
			},
			nil)
		if err != nil {
			return errors.Trace(err)
		}
		if payloadIndex == 0 && !seenPinned {
			return errors.Tracef(
				"expected pinned server entry in payload 0 (source %s)",
				pinnedServerEntry.Source)
		}
		if payloadIndex != 0 && seenPinned {
			return errors.Tracef(
				"unexpected pinned server entry in payload %d (source %s)",
				payloadIndex, pinnedServerEntry.Source)
		}
	}

	// Test: an oversized pinned LightProxyEntry is dropped (rather than
	// erroring); the request still succeeds with the LightProxyEntry
	// reported as dropped.

	oversizeLightProxyEntry := &LightProxyEntry{
		ProxyEntry:        bytes.Repeat([]byte("x"), 4096),
		ProxyEntryTracker: 1,
	}
	result, err = maker.MakePushPayloads(
		0, 0, 1*time.Hour, nil,
		PinnedEntries{LightProxyEntries: []*LightProxyEntry{oversizeLightProxyEntry}},
		2048)
	if err != nil {
		return errors.Trace(err)
	}
	if !reflect.DeepEqual(result.SkippedPinnedLightProxyEntryIndexes, []int{0}) {
		return errors.Tracef(
			"unexpected skipped pinned light proxy indexes: %v",
			result.SkippedPinnedLightProxyEntryIndexes)
	}
	if len(result.Payloads) != 0 {
		return errors.TraceNew("expected no payloads when pinned content is fully dropped and no regular entries provided")
	}

	// Test: expired

	result, err = maker.MakePushPayloads(
		minPadding, maxPadding, 1*time.Microsecond, serverEntries, PinnedEntries{}, 0)
	if err != nil {
		return errors.Trace(err)
	}

	time.Sleep(10 * time.Millisecond)

	_, _, err = ImportPushPayload(
		obfuscationKey,
		publicKey,
		result.Payloads[0],
		importer,
		nil)
	if err == nil {
		return errors.TraceNew("unexpected success")
	}

	// Test: invalid signature

	result, err = incorrectMaker.MakePushPayloads(
		minPadding, maxPadding, 1*time.Hour, serverEntries, PinnedEntries{}, 0)
	if err != nil {
		return errors.Trace(err)
	}

	_, _, err = ImportPushPayload(
		obfuscationKey,
		publicKey,
		result.Payloads[0],
		importer,
		nil)
	if err == nil {
		return errors.TraceNew("unexpected success")
	}

	// Test: wrong signature key

	result, err = maker.MakePushPayloads(
		minPadding, maxPadding, 1*time.Hour, serverEntries, PinnedEntries{}, 0)
	if err != nil {
		return errors.Trace(err)
	}

	_, _, err = ImportPushPayload(
		obfuscationKey,
		incorrectPublicKey,
		result.Payloads[0],
		importer,
		nil)
	if err == nil {
		return errors.TraceNew("unexpected success")
	}

	// Test: mutate obfuscation layer

	result, err = maker.MakePushPayloads(
		minPadding, maxPadding, 1*time.Hour, serverEntries, PinnedEntries{}, 0)
	if err != nil {
		return errors.Trace(err)
	}

	result.Payloads[0][0] = ^result.Payloads[0][0]

	_, _, err = ImportPushPayload(
		obfuscationKey,
		publicKey,
		result.Payloads[0],
		importer,
		nil)
	if err == nil {
		return errors.TraceNew("unexpected success")
	}

	return nil
}

func TestMakePushPayloads_RF2_RespectsMaxSize(t *testing.T) {

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

	maker, err := NewPushPayloadMaker(obfuscationKey, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}

	maxSinglePayloadSize := 0
	for _, entry := range entries {
		result, err := maker.MakePushPayloads(
			0, 0, 1*time.Hour,
			[]*PrioritizedServerEntry{entry}, PinnedEntries{}, 0)
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

	result, err := maker.MakePushPayloads(
		0, 0, 1*time.Hour,
		entries, PinnedEntries{}, maxPayloadSizeBytes)
	if err != nil {
		t.Fatal(err)
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

func TestMakePushPayloads_RF2_SkipsOversizeEntry(t *testing.T) {

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
	entries = append(entries, oversizeEntry)

	maker, err := NewPushPayloadMaker(obfuscationKey, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}

	maxPayloadSizeBytes := 4096
	result, err := maker.MakePushPayloads(
		0, 0, 1*time.Hour, entries, PinnedEntries{}, maxPayloadSizeBytes)
	if err != nil {
		t.Fatal(err)
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

func TestMakePushPayloads_RF2_StrictCapWithPadding(t *testing.T) {

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

	maker, err := NewPushPayloadMaker(obfuscationKey, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}

	minPadding := 1024
	maxPadding := 1024
	maxSinglePayloadSize := 0
	for _, entry := range entries {
		result, err := maker.MakePushPayloads(
			minPadding, maxPadding, 1*time.Hour,
			[]*PrioritizedServerEntry{entry}, PinnedEntries{}, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(result.Payloads[0]) > maxSinglePayloadSize {
			maxSinglePayloadSize = len(result.Payloads[0])
		}
	}

	maxPayloadSizeBytes := maxSinglePayloadSize * 3
	result, err := maker.MakePushPayloads(
		minPadding, maxPadding, 1*time.Hour,
		entries, PinnedEntries{}, maxPayloadSizeBytes)
	if err != nil {
		t.Fatal(err)
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

	maker, err := NewPushPayloadMaker(obfuscationKey, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}

	result, err := maker.MakePushPayloads(
		0, 0, 1*time.Hour, entries, PinnedEntries{}, 4096)
	if err != nil {
		t.Fatal(err)
	}

	if len(result.Payloads) != len(result.PayloadRegularEntryIndexes) {
		t.Fatalf("payload/regular-index mismatch: %d vs %d", len(result.Payloads), len(result.PayloadRegularEntryIndexes))
	}
	if len(result.Payloads) != len(result.PayloadPinnedEntryIndexes) {
		t.Fatalf("payload/pinned-index mismatch: %d vs %d", len(result.Payloads), len(result.PayloadPinnedEntryIndexes))
	}
	if len(result.Payloads) != len(result.PayloadPinnedLightProxyEntryIndexes) {
		t.Fatalf("payload/light-proxy-index mismatch: %d vs %d", len(result.Payloads), len(result.PayloadPinnedLightProxyEntryIndexes))
	}

	seenRegularIndexes := make(map[int]bool)
	for _, payloadIndexes := range result.PayloadRegularEntryIndexes {
		for _, payloadIndex := range payloadIndexes {
			if payloadIndex < 0 || payloadIndex >= len(entries) {
				t.Fatalf("invalid regular index: %d", payloadIndex)
			}
			if seenRegularIndexes[payloadIndex] {
				t.Fatalf("duplicate regular index: %d", payloadIndex)
			}
			seenRegularIndexes[payloadIndex] = true
		}
	}
	if len(seenRegularIndexes) != len(entries)-1 {
		t.Fatalf("metadata accounts for %d regular entries, want %d", len(seenRegularIndexes), len(entries)-1)
	}
}

func TestMakePushPayloads_MetadataTracksAllServerEntries(t *testing.T) {

	obfuscationKey, publicKey, privateKey, err := GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}

	maker, err := NewPushPayloadMaker(obfuscationKey, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}

	pinnedEntry1, err := makeTestPrioritizedServerEntry(900, 0)
	if err != nil {
		t.Fatal(err)
	}
	pinnedEntry2, err := makeTestPrioritizedServerEntry(901, 0)
	if err != nil {
		t.Fatal(err)
	}
	pinnedEntries := []*PrioritizedServerEntry{pinnedEntry1, pinnedEntry2}
	regularEntries, err := makeTestPrioritizedServerEntries(3, func(_ int) int { return 0 })
	if err != nil {
		t.Fatal(err)
	}

	result, err := maker.MakePushPayloads(
		0, 0, 1*time.Hour,
		regularEntries,
		PinnedEntries{PrioritizedServerEntries: pinnedEntries},
		65535)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Payloads) != 1 {
		t.Fatalf("expected one payload, got %d", len(result.Payloads))
	}
	if !reflect.DeepEqual(result.PayloadPinnedEntryIndexes, [][]int{{0, 1}}) {
		t.Fatalf("PayloadPinnedEntryIndexes=%v, want [[0 1]]", result.PayloadPinnedEntryIndexes)
	}
	if !reflect.DeepEqual(result.PayloadRegularEntryIndexes, [][]int{{0, 1, 2}}) {
		t.Fatalf("PayloadRegularEntryIndexes=%v, want [[0 1 2]]", result.PayloadRegularEntryIndexes)
	}

	var sources []string
	_, _, err = ImportPushPayload(
		obfuscationKey, publicKey, result.Payloads[0],
		func(_ protocol.PackedServerEntryFields, source string, _ bool, _, _ string) error {
			sources = append(sources, source)
			return nil
		},
		nil)
	if err != nil {
		t.Fatal(err)
	}
	expectedSources := []string{
		pinnedEntries[0].Source,
		pinnedEntries[1].Source,
		regularEntries[0].Source,
		regularEntries[1].Source,
		regularEntries[2].Source,
	}
	if !reflect.DeepEqual(sources, expectedSources) {
		t.Fatalf("decoded sources=%v, want %v", sources, expectedSources)
	}
}

func TestMakePushPayloads_PinnedAndRegularCoexistInPayload0(t *testing.T) {

	obfuscationKey, publicKey, privateKey, err := GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}

	maker, err := NewPushPayloadMaker(obfuscationKey, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}

	entries, err := makeTestPrioritizedServerEntries(8, func(_ int) int { return 0 })
	if err != nil {
		t.Fatal(err)
	}

	pinnedEntry, err := makeTestPrioritizedServerEntry(900, 0)
	if err != nil {
		t.Fatal(err)
	}

	result, err := maker.MakePushPayloads(
		0, 0, 1*time.Hour,
		entries,
		PinnedEntries{PrioritizedServerEntries: []*PrioritizedServerEntry{pinnedEntry}},
		8192)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Payloads) == 0 {
		t.Fatal("expected at least one payload")
	}

	// Decode payload 0 and verify it contains the pinned entry plus at
	// least one regular entry (they coexist).
	seenPinned := false
	regularCount := 0
	_, _, err = ImportPushPayload(
		obfuscationKey, publicKey, result.Payloads[0],
		func(_ protocol.PackedServerEntryFields, source string, _ bool, _, _ string) error {
			if source == pinnedEntry.Source {
				seenPinned = true
			} else {
				regularCount++
			}
			return nil
		},
		nil)
	if err != nil {
		t.Fatal(err)
	}
	if !seenPinned {
		t.Fatal("expected pinned entry in payload 0")
	}
	if regularCount == 0 {
		t.Fatal("expected regular entries to coexist with pinned entries in payload 0")
	}
}

// TestMakePushPayloads_PinnedLightProxyAndServerEntries_AllFit verifies the
// common-case happy path: a pinned LightProxyEntry plus pinned server
// entries plus regular entries all coexist correctly when the budget
// permits, with the LightProxy in payload 0 and pinned server entries in
// the earliest payloads.
func TestMakePushPayloads_PinnedLightProxyAndServerEntries_AllFit(t *testing.T) {

	obfuscationKey, publicKey, privateKey, err := GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}
	maker, err := NewPushPayloadMaker(obfuscationKey, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}

	lightProxyEntry := &LightProxyEntry{
		ProxyEntry:        []byte("pinned-light-proxy"),
		ProxyEntryTracker: 0xC0FFEE,
	}
	pinnedServerEntry1, err := makeTestPrioritizedServerEntry(500, 0)
	if err != nil {
		t.Fatal(err)
	}
	pinnedServerEntry2, err := makeTestPrioritizedServerEntry(501, 0)
	if err != nil {
		t.Fatal(err)
	}
	regularEntries, err := makeTestPrioritizedServerEntries(8, func(_ int) int { return 0 })
	if err != nil {
		t.Fatal(err)
	}

	pinned := PinnedEntries{
		LightProxyEntries: []*LightProxyEntry{lightProxyEntry},
		PrioritizedServerEntries: []*PrioritizedServerEntry{
			pinnedServerEntry1, pinnedServerEntry2,
		},
	}

	result, err := maker.MakePushPayloads(
		0, 0, 1*time.Hour, regularEntries, pinned, 8192)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.SkippedPinnedLightProxyEntryIndexes) != 0 {
		t.Errorf(
			"expected no skipped pinned light proxy indexes, got %v",
			result.SkippedPinnedLightProxyEntryIndexes)
	}
	if len(result.SkippedPinnedIndexes) != 0 {
		t.Errorf("expected no skipped pinned indexes, got %v", result.SkippedPinnedIndexes)
	}
	seenPinnedPayloads := 0
	for _, indexes := range result.PayloadPinnedEntryIndexes {
		if len(indexes) > 0 {
			seenPinnedPayloads++
		}
	}
	if seenPinnedPayloads != 1 {
		t.Errorf("expected 1 payload with pinned server entries, got %d", seenPinnedPayloads)
	}

	pinnedServerEntrySources := map[string]struct{}{
		pinnedServerEntry1.Source: {},
		pinnedServerEntry2.Source: {},
	}
	for payloadIndex, payload := range result.Payloads {
		seenPinnedSources := 0
		seenLightProxy := 0
		_, _, err := ImportPushPayload(
			obfuscationKey, publicKey, payload,
			func(_ protocol.PackedServerEntryFields, source string, _ bool, _, _ string) error {
				if _, ok := pinnedServerEntrySources[source]; ok {
					seenPinnedSources++
				}
				return nil
			},
			func(_ []byte, _ int64) error {
				seenLightProxy++
				return nil
			})
		if err != nil {
			t.Fatal(err)
		}
		if payloadIndex == 0 {
			if seenLightProxy != 1 {
				t.Errorf("payload 0: light proxy count=%d, want 1", seenLightProxy)
			}
			if seenPinnedSources != 2 {
				t.Errorf("payload 0: pinned server entries seen=%d, want 2", seenPinnedSources)
			}
		} else {
			if seenLightProxy != 0 {
				t.Errorf("payload %d: light proxy leaked, count=%d", payloadIndex, seenLightProxy)
			}
			if seenPinnedSources != 0 {
				t.Errorf("payload %d: pinned server entries leaked, count=%d", payloadIndex, seenPinnedSources)
			}
		}
	}
}

// TestMakePushPayloads_PinnedServerEntries_SpillIntoEarlyPayloads verifies
// that pinned server entries are prioritized before regular entries but may
// spill beyond payload 0 when the first payload has no room for all of them.
func TestMakePushPayloads_PinnedServerEntries_SpillIntoEarlyPayloads(t *testing.T) {

	obfuscationKey, publicKey, privateKey, err := GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}
	maker, err := NewPushPayloadMaker(obfuscationKey, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}

	// Build a single pinned server entry and reference it three times. Same
	// pointer means identical encoded size, making the budget math
	// deterministic while still counting three pinned slots.
	pinnedEntryProto, err := makeTestPrioritizedServerEntry(700, 0)
	if err != nil {
		t.Fatal(err)
	}
	pinnedEntries := []*PrioritizedServerEntry{
		pinnedEntryProto, pinnedEntryProto, pinnedEntryProto,
	}

	lightProxyEntry := &LightProxyEntry{
		ProxyEntry:        []byte("partial-fit-light-proxy"),
		ProxyEntryTracker: 0xDEAD,
	}

	// Measure a single-entry payload containing the LightProxyEntry plus one
	// copy of the pinned server entry. The max payload size is the measurement
	// plus a small slack (timestamps use RFC 3339 nano, which varies a few
	// bytes between calls based on fractional-second trailing zeros). The slack
	// is much smaller than one entry, so the first payload can hold only one
	// pinned server entry; the remaining pinned entries should spill into
	// subsequent payloads instead of being dropped.
	measureResult, err := maker.MakePushPayloads(
		0, 0, 1*time.Hour, nil,
		PinnedEntries{
			LightProxyEntries:        []*LightProxyEntry{lightProxyEntry},
			PrioritizedServerEntries: []*PrioritizedServerEntry{pinnedEntryProto},
		},
		0)
	if err != nil {
		t.Fatal(err)
	}
	if len(measureResult.Payloads) != 1 {
		t.Fatalf("measurement: expected 1 payload, got %d", len(measureResult.Payloads))
	}
	const timestampSlack = 32
	maxPayloadSizeBytes := len(measureResult.Payloads[0]) + timestampSlack

	result, err := maker.MakePushPayloads(
		0, 0, 1*time.Hour, nil,
		PinnedEntries{
			LightProxyEntries:        []*LightProxyEntry{lightProxyEntry},
			PrioritizedServerEntries: pinnedEntries,
		},
		maxPayloadSizeBytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.SkippedPinnedLightProxyEntryIndexes) != 0 {
		t.Errorf(
			"expected no skipped pinned light proxy indexes, got %v",
			result.SkippedPinnedLightProxyEntryIndexes)
	}
	if len(result.SkippedPinnedIndexes) != 0 {
		t.Fatalf("expected no skipped pinned indexes, got %v", result.SkippedPinnedIndexes)
	}
	if len(result.Payloads) < 2 {
		t.Fatalf("expected pinned entries to spill into multiple payloads, got %d", len(result.Payloads))
	}

	seenLightProxyTotal := 0
	seenPinnedServerEntryTotal := 0
	seenPinnedPayloads := 0
	pinnedSources := make(map[string]struct{}, len(pinnedEntries))
	for _, e := range pinnedEntries {
		pinnedSources[e.Source] = struct{}{}
	}
	for payloadIndex, payload := range result.Payloads {
		seenLightProxy := 0
		seenPinnedServerEntry := 0
		_, _, err = ImportPushPayload(
			obfuscationKey, publicKey, payload,
			func(_ protocol.PackedServerEntryFields, source string, _ bool, _, _ string) error {
				if _, ok := pinnedSources[source]; ok {
					seenPinnedServerEntry++
				}
				return nil
			},
			func(_ []byte, _ int64) error {
				seenLightProxy++
				return nil
			})
		if err != nil {
			t.Fatal(err)
		}

		if payloadIndex == 0 {
			if seenLightProxy != 1 {
				t.Errorf("payload 0: light proxy count=%d, want 1", seenLightProxy)
			}
		} else if seenLightProxy != 0 {
			t.Errorf("payload %d: light proxy leaked, count=%d", payloadIndex, seenLightProxy)
		}

		if seenPinnedServerEntry > 0 {
			seenPinnedPayloads++
		}
		seenLightProxyTotal += seenLightProxy
		seenPinnedServerEntryTotal += seenPinnedServerEntry
	}
	if seenLightProxyTotal != 1 {
		t.Errorf("light proxy total=%d, want 1", seenLightProxyTotal)
	}
	if seenPinnedServerEntryTotal != len(pinnedEntries) {
		t.Errorf("pinned server entries=%d, want %d", seenPinnedServerEntryTotal, len(pinnedEntries))
	}
	if seenPinnedPayloads < 2 {
		t.Errorf("expected pinned server entries across multiple payloads, got %d", seenPinnedPayloads)
	}
	metadataPinnedPayloads := 0
	for _, indexes := range result.PayloadPinnedEntryIndexes {
		if len(indexes) > 0 {
			metadataPinnedPayloads++
		}
	}
	if metadataPinnedPayloads != seenPinnedPayloads {
		t.Errorf("metadata pinned payloads=%d, want %d", metadataPinnedPayloads, seenPinnedPayloads)
	}

	// Verify max payload size respected.
	for i, p := range result.Payloads {
		if len(p) > maxPayloadSizeBytes {
			t.Errorf("payload %d exceeds max: %d > %d", i, len(p), maxPayloadSizeBytes)
		}
	}
}

func TestMakePushPayloads_PinnedLightProxyAndServerEntries_PackingOrder(t *testing.T) {

	obfuscationKey, publicKey, privateKey, err := GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}
	maker, err := NewPushPayloadMaker(obfuscationKey, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}

	lightProxyEntry := makeTestLightProxyEntryWithEncodedSize(t, 1000)
	pinnedEntries := []*PrioritizedServerEntry{
		makeTestPrioritizedServerEntryWithEncodedSize(t, 0, 1200),
		makeTestPrioritizedServerEntryWithEncodedSize(t, 1, 800),
		makeTestPrioritizedServerEntryWithEncodedSize(t, 2, 300),
		makeTestPrioritizedServerEntryWithEncodedSize(t, 3, 200),
		makeTestPrioritizedServerEntryWithEncodedSize(t, 4, 100),
	}

	regularEntries := make([]*PrioritizedServerEntry, 0, 16)
	for i := range 16 {
		regularEntries = append(
			regularEntries,
			makeTestPrioritizedServerEntryWithEncodedSize(t, 100+i, 400))
	}

	lightProxyEncodedSize, err := encodedLightProxyEntrySize(lightProxyEntry)
	if err != nil {
		t.Fatal(err)
	}
	maxPayloadSizeBytes, err := maker.EstimateObfuscatedPayloadSize(
		2,
		800+200,
		1,
		lightProxyEncodedSize,
		0)
	if err != nil {
		t.Fatal(err)
	}

	result, err := maker.MakePushPayloads(
		0, 0, 1*time.Hour, regularEntries,
		PinnedEntries{
			LightProxyEntries:        []*LightProxyEntry{lightProxyEntry},
			PrioritizedServerEntries: pinnedEntries,
		},
		maxPayloadSizeBytes)
	if err != nil {
		t.Fatal(err)
	}

	if len(result.SkippedPinnedLightProxyEntryIndexes) != 0 {
		t.Fatalf(
			"expected no skipped pinned light proxy indexes, got %v",
			result.SkippedPinnedLightProxyEntryIndexes)
	}
	if len(result.SkippedPinnedIndexes) != 0 {
		t.Fatalf("expected no skipped pinned indexes, got %v", result.SkippedPinnedIndexes)
	}
	if len(result.Payloads) < 2 {
		t.Fatalf("expected at least 2 payloads, got %d", len(result.Payloads))
	}

	pinnedPayloadCount := 0
	for _, pinnedIndexes := range result.PayloadPinnedEntryIndexes {
		if len(pinnedIndexes) > 0 {
			pinnedPayloadCount++
		}
	}

	seenPinnedIndexes := make(map[int]struct{})
	for payloadIndex, pinnedIndexes := range result.PayloadPinnedEntryIndexes {
		if payloadIndex < pinnedPayloadCount {
			if len(pinnedIndexes) == 0 {
				t.Fatalf("payload %d: expected pinned server entries", payloadIndex)
			}
		} else if len(pinnedIndexes) != 0 {
			t.Fatalf(
				"payload %d pinned indexes=%v, want none after pinned payloads",
				payloadIndex,
				pinnedIndexes)
		}

		for _, pinnedIndex := range pinnedIndexes {
			seenPinnedIndexes[pinnedIndex] = struct{}{}
		}
	}
	if len(seenPinnedIndexes) != len(pinnedEntries) {
		t.Fatalf(
			"seen pinned indexes=%v, want %d pinned entries",
			seenPinnedIndexes,
			len(pinnedEntries))
	}
	for i := range pinnedEntries {
		if _, ok := seenPinnedIndexes[i]; !ok {
			t.Fatalf("missing pinned index %d in payloads", i)
		}
	}

	seenLightProxyTotal := 0
	for payloadIndex, payload := range result.Payloads {
		seenLightProxy := 0
		_, _, err = ImportPushPayload(
			obfuscationKey, publicKey, payload,
			func(_ protocol.PackedServerEntryFields, _ string, _ bool, _, _ string) error {
				return nil
			},
			func(proxyEntry []byte, proxyEntryTracker int64) error {
				if !bytes.Equal(proxyEntry, lightProxyEntry.ProxyEntry) ||
					proxyEntryTracker != lightProxyEntry.ProxyEntryTracker {

					return errors.TraceNew("unexpected light proxy entry")
				}
				seenLightProxy++
				return nil
			})
		if err != nil {
			t.Fatal(err)
		}

		if payloadIndex == 0 {
			if seenLightProxy != 1 {
				t.Fatalf("payload 0: light proxy count=%d, want 1", seenLightProxy)
			}
		} else if seenLightProxy != 0 {
			t.Fatalf("payload %d: light proxy leaked, count=%d", payloadIndex, seenLightProxy)
		}
		seenLightProxyTotal += seenLightProxy
	}
	if seenLightProxyTotal != 1 {
		t.Fatalf("light proxy total=%d, want 1", seenLightProxyTotal)
	}
}

func TestMakePushPayloads_MultiplePinnedLightProxies_PrecedeServerEntries(t *testing.T) {

	obfuscationKey, publicKey, privateKey, err := GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}
	maker, err := NewPushPayloadMaker(obfuscationKey, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}

	lightProxyEntries := []*LightProxyEntry{
		makeTestLightProxyEntryWithEncodedSize(t, 1000),
		makeTestLightProxyEntryWithEncodedSize(t, 900),
		makeTestLightProxyEntryWithEncodedSize(t, 800),
	}
	pinnedEntries := []*PrioritizedServerEntry{
		makeTestPrioritizedServerEntryWithEncodedSize(t, 0, 700),
		makeTestPrioritizedServerEntryWithEncodedSize(t, 1, 600),
	}
	regularEntries := []*PrioritizedServerEntry{
		makeTestPrioritizedServerEntryWithEncodedSize(t, 100, 500),
		makeTestPrioritizedServerEntryWithEncodedSize(t, 101, 500),
	}

	maxPayloadSizeBytes, err := maker.EstimateObfuscatedPayloadSize(
		0,
		0,
		1,
		1000,
		0)
	if err != nil {
		t.Fatal(err)
	}

	result, err := maker.MakePushPayloads(
		0, 0, 1*time.Hour, regularEntries,
		PinnedEntries{
			LightProxyEntries:        lightProxyEntries,
			PrioritizedServerEntries: pinnedEntries,
		},
		maxPayloadSizeBytes)
	if err != nil {
		t.Fatal(err)
	}

	if len(result.SkippedPinnedLightProxyEntryIndexes) != 0 {
		t.Fatalf(
			"expected no skipped pinned light proxy indexes, got %v",
			result.SkippedPinnedLightProxyEntryIndexes)
	}
	if len(result.Payloads) < len(lightProxyEntries) {
		t.Fatalf(
			"expected at least %d payloads, got %d",
			len(lightProxyEntries), len(result.Payloads))
	}

	seenLightProxyIndexes := make(map[int]struct{})
	seenLightProxyPayloadPrefix := true
	for payloadIndex, lightProxyIndexes := range result.PayloadPinnedLightProxyEntryIndexes {
		if len(lightProxyIndexes) == 0 {
			seenLightProxyPayloadPrefix = false
		} else if !seenLightProxyPayloadPrefix {
			t.Fatalf(
				"payload %d light proxy indexes=%v after non-light-proxy payload",
				payloadIndex,
				lightProxyIndexes)
		}

		for _, lightProxyIndex := range lightProxyIndexes {
			seenLightProxyIndexes[lightProxyIndex] = struct{}{}
		}
	}
	if len(seenLightProxyIndexes) != len(lightProxyEntries) {
		t.Fatalf(
			"seen light proxy indexes=%v, want %d entries",
			seenLightProxyIndexes,
			len(lightProxyEntries))
	}
	for i := range lightProxyEntries {
		if _, ok := seenLightProxyIndexes[i]; !ok {
			t.Fatalf("missing light proxy index %d in payloads", i)
		}
	}

	seenLightProxyTotal := 0
	for payloadIndex, payload := range result.Payloads {
		seenLightProxy := 0
		_, _, err = ImportPushPayload(
			obfuscationKey, publicKey, payload,
			func(_ protocol.PackedServerEntryFields, _ string, _ bool, _, _ string) error {
				return nil
			},
			func(_ []byte, _ int64) error {
				seenLightProxy++
				return nil
			})
		if err != nil {
			t.Fatal(err)
		}

		if len(result.PayloadPinnedLightProxyEntryIndexes[payloadIndex]) != seenLightProxy {
			t.Fatalf(
				"payload %d: imported light proxies=%d, metadata=%v",
				payloadIndex,
				seenLightProxy,
				result.PayloadPinnedLightProxyEntryIndexes[payloadIndex])
		}
		seenLightProxyTotal += seenLightProxy
	}
	if seenLightProxyTotal != len(lightProxyEntries) {
		t.Fatalf(
			"light proxy total=%d, want %d",
			seenLightProxyTotal,
			len(lightProxyEntries))
	}
}

// TestMakePushPayloads_PinnedLightProxySkipped_ServerEntriesStillFit
// verifies that an oversized LightProxyEntry gets dropped but the request
// still succeeds and pinned server entries are prioritized into payloads.
func TestMakePushPayloads_PinnedLightProxySkipped_ServerEntriesStillFit(t *testing.T) {

	obfuscationKey, publicKey, privateKey, err := GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}
	maker, err := NewPushPayloadMaker(obfuscationKey, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}

	// LightProxyEntry with a 4 KiB ProxyEntry won't fit in a 2 KiB payload.
	oversizedLightProxy := &LightProxyEntry{
		ProxyEntry:        bytes.Repeat([]byte("L"), 4096),
		ProxyEntryTracker: 0xBADBEEF,
	}
	pinnedServerEntry1, err := makeTestPrioritizedServerEntry(800, 0)
	if err != nil {
		t.Fatal(err)
	}
	pinnedServerEntry2, err := makeTestPrioritizedServerEntry(801, 0)
	if err != nil {
		t.Fatal(err)
	}

	result, err := maker.MakePushPayloads(
		0, 0, 1*time.Hour, nil,
		PinnedEntries{
			LightProxyEntries: []*LightProxyEntry{oversizedLightProxy},
			PrioritizedServerEntries: []*PrioritizedServerEntry{
				pinnedServerEntry1, pinnedServerEntry2,
			},
		},
		2048)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(result.SkippedPinnedLightProxyEntryIndexes, []int{0}) {
		t.Errorf(
			"unexpected skipped pinned light proxy indexes: %v",
			result.SkippedPinnedLightProxyEntryIndexes)
	}
	if len(result.SkippedPinnedIndexes) != 0 {
		t.Errorf("expected no skipped pinned server entries, got %v", result.SkippedPinnedIndexes)
	}

	if len(result.Payloads) == 0 {
		t.Fatal("expected pinned server entries to produce payloads")
	}

	// Verify all pinned server entries ship and the dropped light proxy does
	// not appear in any payload.
	pinnedSources := map[string]struct{}{
		pinnedServerEntry1.Source: {},
		pinnedServerEntry2.Source: {},
	}
	seenLightProxyTotal := 0
	seenPinnedServerEntryTotal := 0
	seenPinnedPayloads := 0
	for payloadIndex, payload := range result.Payloads {
		seenLightProxy := 0
		seenPinnedServerEntry := 0
		_, _, err = ImportPushPayload(
			obfuscationKey, publicKey, payload,
			func(_ protocol.PackedServerEntryFields, source string, _ bool, _, _ string) error {
				if _, ok := pinnedSources[source]; ok {
					seenPinnedServerEntry++
				}
				return nil
			},
			func(_ []byte, _ int64) error {
				seenLightProxy++
				return nil
			})
		if err != nil {
			t.Fatal(err)
		}
		if seenLightProxy != 0 {
			t.Errorf("payload %d: light proxy leaked, count=%d", payloadIndex, seenLightProxy)
		}
		if seenPinnedServerEntry > 0 {
			seenPinnedPayloads++
		}
		seenLightProxyTotal += seenLightProxy
		seenPinnedServerEntryTotal += seenPinnedServerEntry
	}
	if seenLightProxyTotal != 0 {
		t.Errorf("light proxy leaked, total=%d", seenLightProxyTotal)
	}
	if seenPinnedServerEntryTotal != 2 {
		t.Errorf("pinned server entries=%d, want 2", seenPinnedServerEntryTotal)
	}
	metadataPinnedPayloads := 0
	for _, indexes := range result.PayloadPinnedEntryIndexes {
		if len(indexes) > 0 {
			metadataPinnedPayloads++
		}
	}
	if metadataPinnedPayloads != seenPinnedPayloads {
		t.Errorf("metadata pinned payloads=%d, want %d", metadataPinnedPayloads, seenPinnedPayloads)
	}
}

// TestMakePushPayloads_PinnedServerEntries_PrecedeRegularEntries verifies
// that pinned server entries are packed into the earliest payloads before
// regular entries are considered.
func TestMakePushPayloads_PinnedServerEntries_PrecedeRegularEntries(t *testing.T) {

	obfuscationKey, publicKey, privateKey, err := GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}
	maker, err := NewPushPayloadMaker(obfuscationKey, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}

	pinnedEntries := make([]*PrioritizedServerEntry, 0, 3)
	for i := 0; i < 3; i++ {
		entry, err := makeTestPrioritizedServerEntry(900+i, 700)
		if err != nil {
			t.Fatal(err)
		}
		pinnedEntries = append(pinnedEntries, entry)
	}
	regularEntries := make([]*PrioritizedServerEntry, 0, 2)
	for i := 0; i < 2; i++ {
		entry, err := makeTestPrioritizedServerEntry(1000+i, 700)
		if err != nil {
			t.Fatal(err)
		}
		regularEntries = append(regularEntries, entry)
	}

	// Measure a single-entry payload, plus a small slack to absorb RFC 3339
	// nano timestamp encoding variation between calls. The slack is much
	// smaller than one entry, so each payload can hold exactly one server
	// entry. That makes payload ordering observable.
	measure, err := maker.MakePushPayloads(
		0, 0, 1*time.Hour, []*PrioritizedServerEntry{regularEntries[0]},
		PinnedEntries{},
		0)
	if err != nil {
		t.Fatal(err)
	}
	const timestampSlack = 32
	maxPayloadSizeBytes := len(measure.Payloads[0]) + timestampSlack

	result, err := maker.MakePushPayloads(
		0, 0, 1*time.Hour, regularEntries,
		PinnedEntries{PrioritizedServerEntries: pinnedEntries},
		maxPayloadSizeBytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.SkippedPinnedIndexes) != 0 {
		t.Fatalf("expected no skipped pinned indexes, got %v", result.SkippedPinnedIndexes)
	}
	expectedPayloads := len(pinnedEntries) + len(regularEntries)
	if len(result.Payloads) != expectedPayloads {
		t.Fatalf("expected %d payloads, got %d", expectedPayloads, len(result.Payloads))
	}
	if len(result.PayloadPinnedLightProxyEntryIndexes) != expectedPayloads ||
		len(result.PayloadPinnedEntryIndexes) != expectedPayloads ||
		len(result.PayloadRegularEntryIndexes) != expectedPayloads {

		t.Fatalf(
			"metadata lengths: light_proxy=%d pinned=%d regular=%d payloads=%d",
			len(result.PayloadPinnedLightProxyEntryIndexes),
			len(result.PayloadPinnedEntryIndexes),
			len(result.PayloadRegularEntryIndexes),
			expectedPayloads)
	}

	pinnedSources := make(map[string]struct{}, len(pinnedEntries))
	for _, entry := range pinnedEntries {
		pinnedSources[entry.Source] = struct{}{}
	}
	regularSources := make(map[string]struct{}, len(regularEntries))
	for _, entry := range regularEntries {
		regularSources[entry.Source] = struct{}{}
	}

	for payloadIndex, payload := range result.Payloads {
		pinnedCount := 0
		regularCount := 0
		_, _, err = ImportPushPayload(
			obfuscationKey, publicKey, payload,
			func(_ protocol.PackedServerEntryFields, source string, _ bool, _, _ string) error {
				if _, ok := pinnedSources[source]; ok {
					pinnedCount++
				}
				if _, ok := regularSources[source]; ok {
					regularCount++
				}
				return nil
			},
			nil)
		if err != nil {
			t.Fatal(err)
		}
		if pinnedCount+regularCount != 1 {
			t.Fatalf(
				"payload %d: pinned=%d regular=%d, want exactly one entry",
				payloadIndex, pinnedCount, regularCount)
		}

		if payloadIndex < len(pinnedEntries) {
			expectedPinnedIndexes := []int{payloadIndex}
			if !reflect.DeepEqual(result.PayloadPinnedEntryIndexes[payloadIndex], expectedPinnedIndexes) {
				t.Fatalf(
					"payload %d: PayloadPinnedEntryIndexes=%v, want %v",
					payloadIndex,
					result.PayloadPinnedEntryIndexes[payloadIndex],
					expectedPinnedIndexes)
			}
			if result.PayloadRegularEntryIndexes[payloadIndex] != nil {
				t.Fatalf(
					"payload %d: PayloadRegularEntryIndexes=%v, want nil",
					payloadIndex,
					result.PayloadRegularEntryIndexes[payloadIndex])
			}
			if pinnedCount != 1 || regularCount != 0 {
				t.Fatalf(
					"payload %d: pinned=%d regular=%d, want pinned-only",
					payloadIndex, pinnedCount, regularCount)
			}
		} else {
			expectedRegularIndexes := []int{payloadIndex - len(pinnedEntries)}
			if result.PayloadPinnedEntryIndexes[payloadIndex] != nil {
				t.Fatalf(
					"payload %d: PayloadPinnedEntryIndexes=%v, want nil",
					payloadIndex,
					result.PayloadPinnedEntryIndexes[payloadIndex])
			}
			if !reflect.DeepEqual(result.PayloadRegularEntryIndexes[payloadIndex], expectedRegularIndexes) {
				t.Fatalf(
					"payload %d: PayloadRegularEntryIndexes=%v, want %v",
					payloadIndex,
					result.PayloadRegularEntryIndexes[payloadIndex],
					expectedRegularIndexes)
			}
			if pinnedCount != 0 || regularCount != 1 {
				t.Fatalf(
					"payload %d: pinned=%d regular=%d, want regular-only",
					payloadIndex, pinnedCount, regularCount)
			}
		}
	}
}

func TestComputeObfuscatedPayloadSize_MatchesMeasured(t *testing.T) {

	obfuscationKey, publicKey, _, err := GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}

	_, _, privateKey, err := GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}

	maker, err := NewPushPayloadMaker(obfuscationKey, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}

	bufs := &payloadBuffers{}

	expires := time.Now().Add(1 * time.Hour).UTC()
	expiresEncoded, err := protocol.CBOREncoding.Marshal(expires)
	if err != nil {
		t.Fatal(err)
	}
	expiresEncodedSize := len(expiresEncoded)

	allEntries, err := makeTestPrioritizedServerEntries(20, func(i int) int {
		return i * 50
	})
	if err != nil {
		t.Fatal(err)
	}

	// Light proxy variants exercised below: nil (no light proxy field on
	// the payload) plus a small and a larger entry to cover the
	// computeObfuscatedPayloadSize branch that adds light-proxy bytes.
	lightProxyVariants := []*LightProxyEntry{
		nil,
		{ProxyEntry: []byte("small-light-proxy"), ProxyEntryTracker: 1},
		{ProxyEntry: bytes.Repeat([]byte("L"), 1024), ProxyEntryTracker: 2},
	}

	for _, paddingSize := range []int{0, 1024, 65535} {
		for _, lightProxyEntry := range lightProxyVariants {
			lightProxyEntryEncodedSize, err := encodedLightProxyEntrySize(lightProxyEntry)
			if err != nil {
				t.Fatal(err)
			}
			nLightProxyEntries := 0
			if lightProxyEntry != nil {
				nLightProxyEntries = 1
			}

			for numEntries := 0; numEntries <= len(allEntries); numEntries++ {
				entries := allEntries[:numEntries]

				measured, err := maker.measureObfuscatedPayloadSize(
					bufs, entries, lightProxyEntry, expires, paddingSize)
				if err != nil {
					t.Fatal(err)
				}

				entrySizeSum := 0
				for _, entry := range entries {
					encodedEntry, err := protocol.CBOREncoding.Marshal(entry)
					if err != nil {
						t.Fatal(err)
					}
					entrySizeSum += len(encodedEntry)
				}

				computed := maker.computeObfuscatedPayloadSize(
					expiresEncodedSize,
					numEntries,
					entrySizeSum,
					nLightProxyEntries,
					lightProxyEntryEncodedSize,
					paddingSize)

				if computed != measured {
					t.Fatalf(
						"mismatch: numEntries=%d paddingSize=%d lightProxyEncoded=%d computed=%d measured=%d",
						numEntries, paddingSize, lightProxyEntryEncodedSize, computed, measured)
				}
			}
		}
	}
}

func TestEstimateObfuscatedPayloadSize(t *testing.T) {

	obfuscationKey, publicKey, privateKey, err := GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}

	maker, err := NewPushPayloadMaker(obfuscationKey, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}

	// Empty-payload overhead grows with padding and is always positive.
	var prev int
	for i, paddingSize := range []int{0, 256, 4096} {
		size, err := maker.EstimateObfuscatedPayloadSize(0, 0, 0, 0, paddingSize)
		if err != nil {
			t.Fatal(err)
		}
		if size <= 0 {
			t.Fatalf("expected positive size for paddingSize=%d, got %d", paddingSize, size)
		}
		if i > 0 && size <= prev {
			t.Fatalf("expected size to grow with padding: paddingSize=%d size=%d prev=%d", paddingSize, size, prev)
		}
		prev = size
	}

	// Invalid padding returns an error.
	if _, err := maker.EstimateObfuscatedPayloadSize(0, 0, 0, 0, -1); err == nil {
		t.Fatal("expected error for negative padding")
	}
	if _, err := maker.EstimateObfuscatedPayloadSize(0, 0, 0, 0, maxPaddingLimit+1); err == nil {
		t.Fatal("expected error for oversize padding")
	}

	// Inconsistent light proxy count vs. size sum returns an error.
	if _, err := maker.EstimateObfuscatedPayloadSize(0, 0, 1, 0, 0); err == nil {
		t.Fatal("expected error for light proxy count without size sum")
	}
	if _, err := maker.EstimateObfuscatedPayloadSize(0, 0, 0, 100, 0); err == nil {
		t.Fatal("expected error for light proxy size sum without count")
	}
	if _, err := maker.EstimateObfuscatedPayloadSize(0, 0, -1, 0, 0); err == nil {
		t.Fatal("expected error for negative light proxy count")
	}
	if _, err := maker.EstimateObfuscatedPayloadSize(0, 0, 0, -1, 0); err == nil {
		t.Fatal("expected error for negative light proxy size sum")
	}

	// The estimate must be within a few bytes of the size MakePushPayloads
	// actually produces for an equivalent input. This locks the
	// expires-size estimate quality to the real packer.
	entries, err := makeTestPrioritizedServerEntries(3, func(_ int) int { return 64 })
	if err != nil {
		t.Fatal(err)
	}
	result, err := maker.MakePushPayloads(
		0, 0, 1*time.Hour, entries, PinnedEntries{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Payloads) != 1 {
		t.Fatalf("expected 1 payload, got %d", len(result.Payloads))
	}
	sumEntrySizes := 0
	for _, entry := range entries {
		encodedEntry, err := protocol.CBOREncoding.Marshal(entry)
		if err != nil {
			t.Fatal(err)
		}
		sumEntrySizes += len(encodedEntry)
	}
	estimated, err := maker.EstimateObfuscatedPayloadSize(
		len(entries), sumEntrySizes, 0, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	actual := len(result.Payloads[0])
	// EstimateObfuscatedPayloadSize is an upper bound: it must never
	// understate the real payload size, and the overstatement should be
	// bounded by the expires-size headroom (a few bytes for RFC 3339 nano
	// variance plus the safety margin in expiresEncodedSizeUpperBound).
	if estimated < actual {
		t.Fatalf(
			"estimate is not an upper bound: estimated=%d actual=%d",
			estimated, actual)
	}
	const allowedOverstate = expiresEncodedSizeUpperBound
	if estimated-actual > allowedOverstate {
		t.Fatalf(
			"estimate overstates actual by too much: estimated=%d actual=%d diff=%d",
			estimated, actual, estimated-actual)
	}
}

// measureObfuscatedPayloadSize computes the obfuscated payload size by
// performing real CBOR marshaling. This is the reference implementation used
// to validate the arithmetic computation in computeObfuscatedPayloadSize.
// lightProxyEntry may be nil.
func (m *PushPayloadMaker) measureObfuscatedPayloadSize(
	bufs *payloadBuffers,
	prioritizedServerEntries []*PrioritizedServerEntry,
	lightProxyEntry *LightProxyEntry,
	expires time.Time,
	paddingSize int) (int, error) {

	payload := Payload{
		Expires:                  expires,
		PrioritizedServerEntries: prioritizedServerEntries,
	}
	if lightProxyEntry != nil {
		payload.LightProxyEntries = []*LightProxyEntry{lightProxyEntry}
	}

	cborPayload, err := protocol.CBOREncoding.Marshal(&payload)
	if err != nil {
		return 0, errors.Trace(err)
	}

	signedPayload := SignedPayload{
		Signature: make([]byte, signatureSize),
		Payload:   cborPayload,
	}

	if paddingSize < 0 || paddingSize > maxPaddingLimit {
		return 0, errors.TraceNew("invalid padding size")
	}
	if paddingSize > 0 {
		if bufs.padding == nil {
			bufs.padding = make([]byte, maxPaddingLimit)
		}
		signedPayload.Padding = bufs.padding[:paddingSize]
	}

	cborSignedPayload, err := protocol.CBOREncoding.Marshal(&signedPayload)
	if err != nil {
		return 0, errors.Trace(err)
	}

	return m.aead.NonceSize() + len(cborSignedPayload) + m.aead.Overhead(), nil
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

	prioritizedServerEntry := &PrioritizedServerEntry{
		ServerEntryFields: packed,
		Source:            source,
		PrioritizeDial:    index < 32 || index >= 96,
	}

	if prioritizedServerEntry.PrioritizeDial {
		prioritizedServerEntry.PrioritizeReason =
			fmt.Sprintf("prioritize-reason-%d", index)
		prioritizedServerEntry.PrioritizeTunnelProtocol =
			protocol.TUNNEL_PROTOCOL_OBFUSCATED_SSH
	}

	return prioritizedServerEntry, nil
}

func makeTestLightProxyEntryWithEncodedSize(
	t *testing.T,
	encodedSize int) *LightProxyEntry {

	t.Helper()

	for proxyEntrySize := range encodedSize {
		entry := &LightProxyEntry{
			ProxyEntry:        bytes.Repeat([]byte("L"), proxyEntrySize),
			ProxyEntryTracker: 0x0102030405060708,
		}

		encodedEntry, err := protocol.CBOREncoding.Marshal(entry)
		if err != nil {
			t.Fatal(err)
		}
		if len(encodedEntry) == encodedSize {
			return entry
		}
	}

	t.Fatalf("unable to make light proxy entry with encoded size %d", encodedSize)
	return nil
}

func makeTestPrioritizedServerEntryWithEncodedSize(
	t *testing.T,
	index int,
	encodedSize int) *PrioritizedServerEntry {

	t.Helper()

	sourcePrefix := fmt.Sprintf("source-%d-", index)
	for sourceExtraBytes := range encodedSize {
		entry := &PrioritizedServerEntry{
			Source: sourcePrefix + strings.Repeat("s", sourceExtraBytes),
		}

		encodedEntry, err := protocol.CBOREncoding.Marshal(entry)
		if err != nil {
			t.Fatal(err)
		}
		if len(encodedEntry) == encodedSize {
			return entry
		}
	}

	t.Fatalf("unable to make server entry with encoded size %d", encodedSize)
	return nil
}

func importPayloadsAndCountSources(
	obfuscationKey string,
	signaturePublicKey string,
	payloads [][]byte) (map[string]int, error) {

	sourceCounts := make(map[string]int)
	importer := func(
		packedServerEntryFields protocol.PackedServerEntryFields,
		source string,
		_ bool,
		_ string,
		_ string) error {

		_, err := protocol.DecodePackedServerEntryFields(packedServerEntryFields)
		if err != nil {
			return errors.Trace(err)
		}
		sourceCounts[source] += 1
		return nil
	}

	for _, payload := range payloads {
		_, _, err := ImportPushPayload(
			obfuscationKey,
			signaturePublicKey,
			payload,
			importer,
			nil)
		if err != nil {
			return nil, errors.Trace(err)
		}
	}

	return sourceCounts, nil
}

// BenchmarkMakePushPayloads_RF2_AverageBucketUtilization-16    	    8608	    138130 ns/op	         0.9204 avg_utilization	         4.000 payloads/op	   75750 B/op	     554 allocs/op
func BenchmarkMakePushPayloads_RF2_AverageBucketUtilization(b *testing.B) {

	obfuscationKey, publicKey, privateKey, err := GenerateKeys()
	if err != nil {
		b.Fatal(err)
	}

	// Create 10 server entries with sizes ranging from ~700 to ~2500 bytes.
	// Base entry is ~500-700 bytes, so add 0-2000 extra bytes to source field.
	entries, err := makeTestPrioritizedServerEntries(10, func(i int) int {
		// Vary size from 0 to 2000 bytes across the 10 entries.
		return i * 200
	})
	if err != nil {
		b.Fatal(err)
	}

	maxPayloadSizeBytes := 4096

	maker, err := NewPushPayloadMaker(obfuscationKey, publicKey, privateKey)
	if err != nil {
		b.Fatal(err)
	}

	totalUtilization := 0.0
	totalPayloadCount := 0.0

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result, err := maker.MakePushPayloads(
			0, 0, 1*time.Hour, entries, PinnedEntries{}, maxPayloadSizeBytes)
		if err != nil {
			b.Fatal(err)
		}

		if len(result.Payloads) == 0 {
			b.Fatal("no payloads generated")
		}

		totalPayloadBytes := 0
		for payloadIndex, payload := range result.Payloads {
			if len(payload) > maxPayloadSizeBytes {
				b.Fatalf("payload %d exceeded max size: %d > %d", payloadIndex, len(payload), maxPayloadSizeBytes)
			}
			totalPayloadBytes += len(payload)
		}

		averageBucketUtilization := float64(totalPayloadBytes) /
			float64(len(result.Payloads)*maxPayloadSizeBytes)
		totalUtilization += averageBucketUtilization
		totalPayloadCount += float64(len(result.Payloads))
	}
	b.StopTimer()

	b.ReportMetric(totalUtilization/float64(b.N), "avg_utilization")
	b.ReportMetric(totalPayloadCount/float64(b.N), "payloads/op")
}

// BenchmarkMakePushPayloads-16    	    8889	    139301 ns/op	   75742 B/op	     554 allocs/op
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

	maker, err := NewPushPayloadMaker(obfuscationKey, publicKey, privateKey)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := maker.MakePushPayloads(
			0, 0, 1*time.Hour, entries, PinnedEntries{}, maxPayloadSizeBytes)
		if err != nil {
			b.Fatal(err)
		}
	}
}
