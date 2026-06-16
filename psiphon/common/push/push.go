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

// Package push implements server entry push payloads, which support pushing
// server entries to clients through external distribution channels. Push
// payloads use the compact packed CBOR server entry representation.
//
// Each server entry has an optional prioritize dial flag which is equivalent
// to dsl.VersionedServerEntryTag.PrioritizedDial.
//
// Payloads include an expiry date to ensure freshness and mitigate replay
// attacks. The entire payload is digitally signed, and an obfuscation layer
// is added on top.
package push

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"sort"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	"github.com/fxamacker/cbor/v2"
)

const (
	obfuscationKeySize           = 32
	signaturePublicKeyDigestSize = 8
	maxPaddingLimit              = 65535
	signatureSize                = signaturePublicKeyDigestSize + ed25519.SignatureSize

	// expiresEncodedSizeUpperBound is a conservative upper bound on the
	// CBOR-encoded size of a payload expiry timestamp. The encoding is
	// CBOR tag 0 (1 byte) + text string header (<= 2 bytes) + RFC 3339 nano
	// UTC text (<= 30 chars, e.g. "2026-05-14T15:53:34.999999999Z"),
	// totaling at most 33 bytes plus a small safety margin.
	expiresEncodedSizeUpperBound = 40
)

// Payload is a push payload, consisting of a list of server entries and
// optional light proxy entries. To ensure stale server entries and stale dial
// prioritizations are not imported, the payload has an expiry timestamp.
type Payload struct {
	Expires                  time.Time                 `cbor:"1,keyasint,omitempty"`
	PrioritizedServerEntries []*PrioritizedServerEntry `cbor:"2,keyasint,omitempty"`
	LightProxyEntries        []*LightProxyEntry        `cbor:"3,keyasint,omitempty"`
}

// SignedPayload is Payload with a digital signature.
type SignedPayload struct {
	Signature []byte `cbor:"1,keyasint,omitempty"`
	Payload   []byte `cbor:"2,keyasint,omitempty"`
	Padding   []byte `cbor:"3,keyasint,omitempty"`
}

// PrioritizedServerEntry is a server entry paired with a server entry source
// description and a dial prioritization indication. PrioritizeDial is
// equivalent to DSL prioritized dials.
type PrioritizedServerEntry struct {
	ServerEntryFields        protocol.PackedServerEntryFields `cbor:"1,keyasint,omitempty"`
	Source                   string                           `cbor:"2,keyasint,omitempty"`
	PrioritizeDial           bool                             `cbor:"3,keyasint,omitempty"`
	PrioritizeReason         string                           `cbor:"4,keyasint,omitempty"`
	PrioritizeTunnelProtocol string                           `cbor:"5,keyasint,omitempty"`
}

// LightProxyEntry is a light proxy entry paired with its tracker value.
// ProxyEntry is an opaque encoded light.SignedProxyEntry.
type LightProxyEntry struct {
	ProxyEntry        []byte `cbor:"1,keyasint,omitempty"`
	ProxyEntryTracker int64  `cbor:"2,keyasint,omitempty"`
}

// PinnedEntries groups entries that should be prioritized ahead of regular
// entries. Pinned light proxy entries are packed before pinned server entries,
// and pinned server entries are packed before prioritizedServerEntries, so the
// first generated payloads receive them first.
//
// The zero value indicates "no pinned entries": MakePushPayloads behaves
// as if only prioritizedServerEntries were provided.
type PinnedEntries struct {
	// PrioritizedServerEntries are prioritized into the first generated
	// payloads before regular entries are packed.
	PrioritizedServerEntries []*PrioritizedServerEntry
	// LightProxyEntries are prioritized into the first generated payloads
	// before pinned server entries are packed.
	LightProxyEntries []*LightProxyEntry
}

// IsEmpty reports whether PinnedEntries contains no entries.
func (p PinnedEntries) IsEmpty() bool {
	return len(p.PrioritizedServerEntries) == 0 && len(p.LightProxyEntries) == 0
}

// ServerEntryImporter is a callback that is invoked for each server entry in
// an imported push payload.
type ServerEntryImporter func(
	packedServerEntryFields protocol.PackedServerEntryFields,
	source string,
	prioritizeDial bool,
	prioritizeReason string,
	prioritizeTunnelProtocol string) error

// LightProxyEntryImporter is a callback that is invoked for each light proxy
// entry in an imported push payload.
type LightProxyEntryImporter func(
	proxyEntry []byte,
	proxyEntryTracker int64) error

// GenerateKeys generates a new obfuscation key and signature key pair for
// push payloads.
func GenerateKeys() (
	payloadObfuscationKey string,
	payloadSignaturePublicKey string,
	payloadSignaturePrivateKey string,
	err error) {

	obfuscationKey := make([]byte, obfuscationKeySize)
	_, err = rand.Read(obfuscationKey)
	if err != nil {
		return "", "", "", errors.Trace(err)
	}

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", "", errors.Trace(err)
	}

	return base64.StdEncoding.EncodeToString(obfuscationKey),
		base64.StdEncoding.EncodeToString(publicKey),
		base64.StdEncoding.EncodeToString(privateKey),
		nil
}

// ImportPushPayload imports the input push payload. The ServerEntryImporter
// callback is invoked for each imported server entry and its associated
// source and prioritize data. The lightProxyEntryImporter callback is invoked
// for each light proxy entry.
//
// If the payload contains server entries, serverEntryImporter must be non-nil.
// If the payload contains light proxy entries, lightProxyEntryImporter must be
// non-nil.
//
// Returns the number of imported server entries and the number of imported
// light proxy entries.
func ImportPushPayload(
	payloadObfuscationKey string,
	payloadSignaturePublicKey string,
	obfuscatedPayload []byte,
	serverEntryImporter ServerEntryImporter,
	lightProxyEntryImporter LightProxyEntryImporter) (int, int, error) {

	obfuscationKey, err := base64.StdEncoding.DecodeString(
		payloadObfuscationKey)
	if err == nil && len(obfuscationKey) != obfuscationKeySize {
		err = errors.TraceNew("unexpected obfuscation key size")
	}
	if err != nil {
		return 0, 0, errors.Trace(err)
	}

	publicKey, err := base64.StdEncoding.DecodeString(
		payloadSignaturePublicKey)
	if err == nil && len(publicKey) != ed25519.PublicKeySize {
		err = errors.TraceNew("unexpected signature public key size")
	}
	if err != nil {
		return 0, 0, errors.Trace(err)
	}

	blockCipher, err := aes.NewCipher(obfuscationKey)
	if err != nil {
		return 0, 0, errors.Trace(err)
	}

	aead, err := cipher.NewGCM(blockCipher)
	if err != nil {
		return 0, 0, errors.Trace(err)
	}

	if len(obfuscatedPayload) < aead.NonceSize() {
		return 0, 0, errors.TraceNew("missing nonce")
	}

	cborSignedPayload, err := aead.Open(
		nil,
		obfuscatedPayload[:aead.NonceSize()],
		obfuscatedPayload[aead.NonceSize():],
		nil)
	if err != nil {
		return 0, 0, errors.Trace(err)
	}

	var signedPayload SignedPayload
	err = cbor.Unmarshal(cborSignedPayload, &signedPayload)
	if err != nil {
		return 0, 0, errors.Trace(err)
	}

	if len(signedPayload.Signature) !=
		signaturePublicKeyDigestSize+ed25519.SignatureSize {

		return 0, 0, errors.TraceNew("invalid signature size")
	}

	publicKeyDigest := sha256.Sum256(publicKey)
	expectedPublicKeyID := publicKeyDigest[:signaturePublicKeyDigestSize]

	if !bytes.Equal(
		expectedPublicKeyID,
		signedPayload.Signature[:signaturePublicKeyDigestSize]) {

		return 0, 0, errors.TraceNew("unexpected signature public key ID")
	}

	if !ed25519.Verify(
		publicKey,
		signedPayload.Payload,
		signedPayload.Signature[signaturePublicKeyDigestSize:]) {

		return 0, 0, errors.TraceNew("invalid signature")
	}

	var payload Payload
	err = cbor.Unmarshal(signedPayload.Payload, &payload)
	if err != nil {
		return 0, 0, errors.Trace(err)
	}

	if payload.Expires.Before(time.Now().UTC()) {
		return 0, 0, errors.TraceNew("payload expired")
	}

	importedServerEntries := 0
	importedLightProxyEntries := 0
	if len(payload.PrioritizedServerEntries) > 0 && serverEntryImporter == nil {
		return importedServerEntries, importedLightProxyEntries,
			errors.TraceNew("missing server entry importer")
	}
	for _, prioritizedServerEntry := range payload.PrioritizedServerEntries {
		if prioritizedServerEntry == nil {
			return importedServerEntries, importedLightProxyEntries,
				errors.TraceNew("missing server entry")
		}

		err := serverEntryImporter(
			prioritizedServerEntry.ServerEntryFields,
			prioritizedServerEntry.Source,
			prioritizedServerEntry.PrioritizeDial,
			prioritizedServerEntry.PrioritizeReason,
			prioritizedServerEntry.PrioritizeTunnelProtocol)
		if err != nil {
			return importedServerEntries, importedLightProxyEntries,
				errors.Trace(err)
		}
		importedServerEntries += 1
	}

	if len(payload.LightProxyEntries) > 0 {
		if lightProxyEntryImporter == nil {
			return importedServerEntries, importedLightProxyEntries,
				errors.TraceNew("missing light proxy entry importer")
		}

		for _, lightProxyEntry := range payload.LightProxyEntries {
			if lightProxyEntry == nil {
				return importedServerEntries, importedLightProxyEntries,
					errors.TraceNew("missing light proxy entry")
			}

			err := lightProxyEntryImporter(
				lightProxyEntry.ProxyEntry,
				lightProxyEntry.ProxyEntryTracker)
			if err != nil {
				return importedServerEntries, importedLightProxyEntries,
					errors.Trace(err)
			}
			importedLightProxyEntries += 1
		}
	}

	return importedServerEntries, importedLightProxyEntries, nil
}

// MakePushPayloadsResult is the output from MakePushPayloads.
//
// Pinned entries are tracked separately from regular entries in the index
// metadata below. Callers can combine the per-payload index metadata with any
// response cap they apply after this call to determine which pinned entries
// actually shipped.
type MakePushPayloadsResult struct {
	// Payloads contains generated obfuscated push payloads. When pinned server
	// entries are provided, they are prioritized into the earliest payloads.
	Payloads [][]byte
	// PayloadPinnedLightProxyEntryIndexes contains original input indexes of
	// pinned light proxy entries (from pinned.LightProxyEntries) packed into
	// each payload, aligned by index with Payloads.
	PayloadPinnedLightProxyEntryIndexes [][]int
	// PayloadRegularEntryIndexes contains original input indexes of regular entries
	// (from MakePushPayloads's prioritizedServerEntries argument) packed into
	// each payload, aligned by index with Payloads.
	PayloadRegularEntryIndexes [][]int
	// PayloadPinnedEntryIndexes contains original input indexes of pinned entries
	// (from pinned.PrioritizedServerEntries) packed into each payload, aligned by
	// index with Payloads.
	PayloadPinnedEntryIndexes [][]int
	// SkippedPinnedIndexes contains input indexes of pinned
	// PrioritizedServerEntries that could not fit into any payload when
	// max payload size is enforced. Sorted ascending. Indexes reference the
	// input pinned.PrioritizedServerEntries.
	SkippedPinnedIndexes []int
	// SkippedPinnedLightProxyEntryIndexes contains input indexes of pinned
	// LightProxyEntries that could not fit into any payload when max payload
	// size is enforced. Sorted ascending.
	SkippedPinnedLightProxyEntryIndexes []int
}

type payloadBuffers struct {
	nonce       []byte
	signature   []byte
	obfuscation []byte
	padding     []byte
}

type sortablePrioritizedServerEntry struct {
	entry         *PrioritizedServerEntry
	originalIndex int
	encodedSize   int
}

type sortableLightProxyEntry struct {
	entry         *LightProxyEntry
	originalIndex int
	encodedSize   int
}

// PushPayloadMaker caches expensive initialization (base64 decoding, AES-GCM
// cipher creation, SHA256 hashing) so that multiple MakePayloads calls can
// reuse the same state.
//
// PushPayloadMaker is safe for concurrent use. Each MakePayloads call
// allocates its own mutable buffers via a fresh payloadBuffers.
type PushPayloadMaker struct {
	aead        cipher.AEAD
	privateKey  ed25519.PrivateKey
	publicKeyID []byte
}

// NewPushPayloadMaker creates a PushPayloadMaker by performing the expensive
// one-time initialization: base64 decoding all keys, validating sizes, and
// creating the AES-GCM cipher.
func NewPushPayloadMaker(
	payloadObfuscationKey string,
	payloadSignaturePublicKey string,
	payloadSignaturePrivateKey string,
) (*PushPayloadMaker, error) {

	obfuscationKey, err := base64.StdEncoding.DecodeString(
		payloadObfuscationKey)
	if err == nil && len(obfuscationKey) != obfuscationKeySize {
		err = errors.TraceNew("unexpected obfuscation key size")
	}
	if err != nil {
		return nil, errors.Trace(err)
	}

	publicKey, err := base64.StdEncoding.DecodeString(
		payloadSignaturePublicKey)
	if err == nil && len(publicKey) != ed25519.PublicKeySize {
		err = errors.TraceNew("unexpected signature public key size")
	}
	if err != nil {
		return nil, errors.Trace(err)
	}

	privateKey, err := base64.StdEncoding.DecodeString(
		payloadSignaturePrivateKey)
	if err == nil && len(privateKey) != ed25519.PrivateKeySize {
		err = errors.TraceNew("unexpected signature private key size")
	}
	if err != nil {
		return nil, errors.Trace(err)
	}

	blockCipher, err := aes.NewCipher(obfuscationKey)
	if err != nil {
		return nil, errors.Trace(err)
	}

	aead, err := cipher.NewGCM(blockCipher)
	if err != nil {
		return nil, errors.Trace(err)
	}

	publicKeyDigest := sha256.Sum256(publicKey)

	return &PushPayloadMaker{
		aead:        aead,
		privateKey:  privateKey,
		publicKeyID: publicKeyDigest[:signaturePublicKeyDigestSize],
	}, nil
}

// MakePushPayloads generates obfuscated push payloads from prioritized server
// entries and optional pinned entries, reusing the cached key material and
// cipher from the maker.
//
// When pinned is non-empty, its LightProxyEntries are considered first and
// packed into the earliest payloads. Entries that cannot fit by themselves
// under maxPayloadSizeBytes are dropped and reported in the result. Pinned
// PrioritizedServerEntries are then packed before regular
// prioritizedServerEntries so they get first claim on the earliest payloads
// that can fit them. Within a payload, pinned server entries are encoded
// before regular server entries.
//
// When maxPayloadSizeBytes <= 0, all entries (pinned + regular) are encoded
// into a single payload.
//
// When maxPayloadSizeBytes > 0, entries are packed into multiple payloads
// using an RF(2) (random-fit with 2 candidates) strategy after sorting pinned
// entries, then regular entries, by decreasing encoded size. Entries that
// cannot fit by themselves under maxPayloadSizeBytes are skipped and reported
// in the returned result metadata.
func (m *PushPayloadMaker) MakePushPayloads(
	minPadding int,
	maxPadding int,
	TTL time.Duration,
	prioritizedServerEntries []*PrioritizedServerEntry,
	pinned PinnedEntries,
	maxPayloadSizeBytes int,
) (MakePushPayloadsResult, error) {

	result := MakePushPayloadsResult{}

	if len(prioritizedServerEntries) == 0 && pinned.IsEmpty() {
		return result, nil
	}

	if minPadding > maxPadding || maxPadding > maxPaddingLimit {
		return result, errors.TraceNew("invalid min/max padding")
	}

	bufs := &payloadBuffers{
		nonce: make([]byte, m.aead.NonceSize()),
	}

	expires := time.Now().Add(TTL).UTC()

	// maxPayloadSizeBytes <= 0 means no payload size cap is enforced.
	if maxPayloadSizeBytes <= 0 {
		entryIndexes := make([]int, len(prioritizedServerEntries))
		for i := range prioritizedServerEntries {
			entryIndexes[i] = i
		}
		pinnedEntryIndexes := make([]int, len(pinned.PrioritizedServerEntries))
		for i := range pinned.PrioritizedServerEntries {
			pinnedEntryIndexes[i] = i
		}
		pinnedLightProxyEntryIndexes := make([]int, len(pinned.LightProxyEntries))
		for i, entry := range pinned.LightProxyEntries {
			if entry == nil {
				return result, errors.TraceNew("missing light proxy entry")
			}
			pinnedLightProxyEntryIndexes[i] = i
		}
		result.PayloadPinnedLightProxyEntryIndexes = append(
			result.PayloadPinnedLightProxyEntryIndexes, pinnedLightProxyEntryIndexes)
		result.PayloadRegularEntryIndexes = append(
			result.PayloadRegularEntryIndexes, entryIndexes)
		result.PayloadPinnedEntryIndexes = append(
			result.PayloadPinnedEntryIndexes, pinnedEntryIndexes)

		paddingSize := prng.Range(minPadding, maxPadding)
		payload, err := m.buildObfuscatedPayload(
			bufs, pinned, prioritizedServerEntries, expires, paddingSize)
		if err != nil {
			return result, errors.Trace(err)
		}
		result.Payloads = append(result.Payloads, payload)
		return result, nil
	}

	expiresEncoded, err := protocol.CBOREncoding.Marshal(expires)
	if err != nil {
		return result, errors.Trace(err)
	}
	expiresEncodedSize := len(expiresEncoded)

	// Pre-compute pinned sizes once for the priority packing pass when a max
	// payload size is enforced.
	pinnedServerEntries := make(
		[]sortablePrioritizedServerEntry, 0, len(pinned.PrioritizedServerEntries))
	for i, entry := range pinned.PrioritizedServerEntries {
		encodedEntry, err := protocol.CBOREncoding.Marshal(entry)
		if err != nil {
			return result, errors.Trace(err)
		}
		encodedSize := len(encodedEntry)

		pinnedServerEntries = append(pinnedServerEntries, sortablePrioritizedServerEntry{
			entry:         entry,
			originalIndex: i,
			encodedSize:   encodedSize,
		})
	}

	sort.Slice(pinnedServerEntries, func(i, j int) bool {
		if pinnedServerEntries[i].encodedSize == pinnedServerEntries[j].encodedSize {
			return pinnedServerEntries[i].originalIndex < pinnedServerEntries[j].originalIndex
		}
		return pinnedServerEntries[i].encodedSize > pinnedServerEntries[j].encodedSize
	})

	// Pre-compute light proxy sizes once for the priority packing pass when a
	// max payload size is enforced.
	pinnedLightProxyEntries := make(
		[]sortableLightProxyEntry, 0, len(pinned.LightProxyEntries))
	for i, entry := range pinned.LightProxyEntries {
		if entry == nil {
			return result, errors.TraceNew("missing light proxy entry")
		}

		encodedEntry, err := protocol.CBOREncoding.Marshal(entry)
		if err != nil {
			return result, errors.Trace(err)
		}
		encodedSize := len(encodedEntry)

		pinnedLightProxyEntries = append(pinnedLightProxyEntries, sortableLightProxyEntry{
			entry:         entry,
			originalIndex: i,
			encodedSize:   encodedSize,
		})
	}

	sort.Slice(pinnedLightProxyEntries, func(i, j int) bool {
		if pinnedLightProxyEntries[i].encodedSize == pinnedLightProxyEntries[j].encodedSize {
			return pinnedLightProxyEntries[i].originalIndex < pinnedLightProxyEntries[j].originalIndex
		}
		return pinnedLightProxyEntries[i].encodedSize > pinnedLightProxyEntries[j].encodedSize
	})

	// Compute encoded sizes for each (regular) PrioritizedServerEntry.
	serverEntries := make(
		[]sortablePrioritizedServerEntry, 0, len(prioritizedServerEntries))
	for i, entry := range prioritizedServerEntries {
		encodedEntry, err := protocol.CBOREncoding.Marshal(entry)
		if err != nil {
			return result, errors.Trace(err)
		}

		encodedSize := len(encodedEntry)

		serverEntries = append(serverEntries, sortablePrioritizedServerEntry{
			entry:         entry,
			originalIndex: i,
			encodedSize:   encodedSize,
		})
	}

	// Sort server entries by decreasing size, this significantly
	// increases packing quality but doesn't bias the bins themselves.
	sort.Slice(serverEntries, func(i, j int) bool {
		if serverEntries[i].encodedSize == serverEntries[j].encodedSize {
			return serverEntries[i].originalIndex < serverEntries[j].originalIndex
		}
		return serverEntries[i].encodedSize > serverEntries[j].encodedSize
	})

	// Worst-case each pinned light proxy and server entry gets its own bin.
	type payloadBin struct {
		lightProxyEntries      []*LightProxyEntry
		pinnedServerEntries    []*PrioritizedServerEntry
		serverEntries          []*PrioritizedServerEntry
		lightProxyEntryIndexes []int
		pinnedEntryIndexes     []int
		entryIndexes           []int
		paddingSize            int
		// sumLightProxyEntrySize is the total encoded size of light proxy
		// entries in this bin.
		sumLightProxyEntrySize int
		// sumPinnedServerEntrySize is the total encoded size of pinned
		// server entries in this bin.
		sumPinnedServerEntrySize int
		// sumServerEntrySize is the total encoded size of regular server
		// entries in this bin, used to compute the obfuscated payload size.
		sumServerEntrySize int
	}
	bins := make(
		[]payloadBin, 0,
		len(pinnedLightProxyEntries)+len(pinnedServerEntries)+len(serverEntries))

	// computeBinPayloadSize returns the total obfuscated payload size for the
	// given bin under consideration.
	computeBinPayloadSize := func(
		binIndex int,
		extraServerEntries int,
		extraServerEntrySizeSum int,
		extraLightProxyEntries int,
		extraLightProxyEntrySizeSum int,
		paddingSize int,
	) int {
		nServer := len(bins[binIndex].pinnedServerEntries) +
			len(bins[binIndex].serverEntries) + extraServerEntries
		sumServer := bins[binIndex].sumPinnedServerEntrySize +
			bins[binIndex].sumServerEntrySize + extraServerEntrySizeSum
		nLightProxy := len(bins[binIndex].lightProxyEntries) + extraLightProxyEntries
		sumLightProxy := bins[binIndex].sumLightProxyEntrySize + extraLightProxyEntrySizeSum
		return m.computeObfuscatedPayloadSize(
			expiresEncodedSize, nServer, sumServer, nLightProxy, sumLightProxy, paddingSize)
	}

	binOrder := make(
		[]int, 0,
		len(pinnedLightProxyEntries)+len(pinnedServerEntries)+len(serverEntries))

	type candidate struct {
		binIndex int
		size     int
	}

	placeLightProxyEntry := func(
		sortedLightProxyEntry sortableLightProxyEntry) {

		// RF(2): randomly sample bins, collect the first 2 that fit,
		// and pick the tightest (least remaining space).

		binOrder = binOrder[:0]
		for i := range bins {
			binOrder = append(binOrder, i)
		}
		prng.Shuffle(len(binOrder), func(i, j int) {
			binOrder[i], binOrder[j] = binOrder[j], binOrder[i]
		})

		var candidates [2]candidate
		numCandidates := 0

		for _, bi := range binOrder {
			if numCandidates >= 2 {
				break
			}

			size := computeBinPayloadSize(
				bi, 0, 0, 1, sortedLightProxyEntry.encodedSize, bins[bi].paddingSize)
			if size <= maxPayloadSizeBytes {
				candidates[numCandidates] = candidate{
					binIndex: bi,
					size:     size,
				}
				numCandidates++
			}
		}

		if numCandidates > 0 {
			// Pick tightest fit (highest size).
			best := 0
			if numCandidates == 2 &&
				candidates[1].size > candidates[0].size {
				best = 1
			}
			bi := candidates[best].binIndex
			bins[bi].lightProxyEntries = append(
				bins[bi].lightProxyEntries, sortedLightProxyEntry.entry)
			bins[bi].lightProxyEntryIndexes = append(
				bins[bi].lightProxyEntryIndexes, sortedLightProxyEntry.originalIndex)
			bins[bi].sumLightProxyEntrySize += sortedLightProxyEntry.encodedSize
			return
		}

		paddingSize := minPadding
		size := m.computeObfuscatedPayloadSize(
			expiresEncodedSize,
			0,
			0,
			1,
			sortedLightProxyEntry.encodedSize,
			paddingSize)
		if size > maxPayloadSizeBytes {
			result.SkippedPinnedLightProxyEntryIndexes = append(
				result.SkippedPinnedLightProxyEntryIndexes,
				sortedLightProxyEntry.originalIndex)
			return
		}

		bins = append(bins, payloadBin{
			lightProxyEntries:      []*LightProxyEntry{sortedLightProxyEntry.entry},
			lightProxyEntryIndexes: []int{sortedLightProxyEntry.originalIndex},
			paddingSize:            paddingSize,
			sumLightProxyEntrySize: sortedLightProxyEntry.encodedSize,
		})
	}

	placeServerEntry := func(
		sortedServerEntry sortablePrioritizedServerEntry,
		isPinned bool) {

		// RF(2): randomly sample bins, collect the first 2 that fit,
		// and pick the tightest (least remaining space).

		// Grow and reset binOrder to [0..len(bins)).
		binOrder = binOrder[:0]
		for i := range bins {
			binOrder = append(binOrder, i)
		}
		prng.Shuffle(len(binOrder), func(i, j int) {
			binOrder[i], binOrder[j] = binOrder[j], binOrder[i]
		})

		var candidates [2]candidate
		numCandidates := 0

		for _, bi := range binOrder {
			if numCandidates >= 2 {
				break
			}

			// Arithmetically compute the size of the obfuscated payload
			// without the expensive marshalling and encryption.
			size := computeBinPayloadSize(
				bi, 1, sortedServerEntry.encodedSize, 0, 0, bins[bi].paddingSize)
			if size <= maxPayloadSizeBytes {
				candidates[numCandidates] = candidate{
					binIndex: bi,
					size:     size,
				}
				numCandidates++
			}
		}

		if numCandidates > 0 {
			// Pick tightest fit (highest size).
			best := 0
			if numCandidates == 2 &&
				candidates[1].size > candidates[0].size {
				best = 1
			}
			bi := candidates[best].binIndex
			if isPinned {
				bins[bi].pinnedServerEntries = append(
					bins[bi].pinnedServerEntries, sortedServerEntry.entry)
				bins[bi].pinnedEntryIndexes = append(
					bins[bi].pinnedEntryIndexes, sortedServerEntry.originalIndex)
				bins[bi].sumPinnedServerEntrySize += sortedServerEntry.encodedSize
			} else {
				bins[bi].serverEntries = append(bins[bi].serverEntries, sortedServerEntry.entry)
				bins[bi].entryIndexes = append(bins[bi].entryIndexes, sortedServerEntry.originalIndex)
				bins[bi].sumServerEntrySize += sortedServerEntry.encodedSize
			}
			return
		}

		// Server entry did not fit into existing bins,
		// create a new bin with minPadding. Random padding is
		// applied after packing to avoid wasting bin capacity.
		paddingSize := minPadding
		size := m.computeObfuscatedPayloadSize(
			expiresEncodedSize,
			1,
			sortedServerEntry.encodedSize,
			0,
			0,
			paddingSize)
		if size > maxPayloadSizeBytes {
			if isPinned {
				result.SkippedPinnedIndexes = append(
					result.SkippedPinnedIndexes, sortedServerEntry.originalIndex)
			}
			return
		}

		bin := payloadBin{
			paddingSize: paddingSize,
		}
		if isPinned {
			bin.pinnedServerEntries = []*PrioritizedServerEntry{sortedServerEntry.entry}
			bin.pinnedEntryIndexes = []int{sortedServerEntry.originalIndex}
			bin.sumPinnedServerEntrySize = sortedServerEntry.encodedSize
		} else {
			bin.serverEntries = []*PrioritizedServerEntry{sortedServerEntry.entry}
			bin.entryIndexes = []int{sortedServerEntry.originalIndex}
			bin.sumServerEntrySize = sortedServerEntry.encodedSize
		}
		bins = append(bins, bin)
	}

	for _, sortedPinnedLightProxyEntry := range pinnedLightProxyEntries {
		placeLightProxyEntry(sortedPinnedLightProxyEntry)
	}
	if len(result.SkippedPinnedLightProxyEntryIndexes) > 0 {
		sort.Ints(result.SkippedPinnedLightProxyEntryIndexes)
	}

	for _, sortedPinnedServerEntry := range pinnedServerEntries {
		placeServerEntry(sortedPinnedServerEntry, true)
	}
	if len(result.SkippedPinnedIndexes) > 0 {
		sort.Ints(result.SkippedPinnedIndexes)
	}

	for _, sortedServerEntry := range serverEntries {
		placeServerEntry(sortedServerEntry, false)
	}

	// Apply random padding to each bin, respecting maxPayloadSizeBytes.
	noPadding := minPadding == 0 && maxPadding == 0
	if !noPadding {
		for i := range bins {
			randomPadding := prng.Range(minPadding, maxPadding)
			if randomPadding <= bins[i].paddingSize {
				continue
			}
			size := computeBinPayloadSize(i, 0, 0, 0, 0, randomPadding)
			if size <= maxPayloadSizeBytes {
				bins[i].paddingSize = randomPadding
			} else {
				// Reduce padding to fit within maxPayloadSizeBytes.
				excess := size - maxPayloadSizeBytes
				reduced := randomPadding - excess
				if reduced > bins[i].paddingSize {
					bins[i].paddingSize = reduced
				}
			}
		}
	}

	result.Payloads = make([][]byte, 0, len(bins))
	result.PayloadPinnedLightProxyEntryIndexes = make([][]int, 0, len(bins))
	result.PayloadRegularEntryIndexes = make([][]int, 0, len(bins))
	result.PayloadPinnedEntryIndexes = make([][]int, 0, len(bins))

	for _, bin := range bins {
		var binPinned PinnedEntries
		if len(bin.lightProxyEntries) > 0 {
			binPinned.LightProxyEntries = bin.lightProxyEntries
		}
		if len(bin.pinnedServerEntries) > 0 {
			binPinned.PrioritizedServerEntries = bin.pinnedServerEntries
		}
		payload, err := m.buildObfuscatedPayload(
			bufs, binPinned, bin.serverEntries, expires, bin.paddingSize)
		if err != nil {
			return result, errors.Trace(err)
		}
		// Apply a hard correctness check.
		if len(payload) > maxPayloadSizeBytes {
			return result, errors.TraceNew(
				"internal error: payload size exceeds max")
		}
		result.Payloads = append(result.Payloads, payload)
		result.PayloadPinnedLightProxyEntryIndexes = append(
			result.PayloadPinnedLightProxyEntryIndexes, bin.lightProxyEntryIndexes)
		result.PayloadRegularEntryIndexes = append(
			result.PayloadRegularEntryIndexes, bin.entryIndexes)
		result.PayloadPinnedEntryIndexes = append(
			result.PayloadPinnedEntryIndexes, bin.pinnedEntryIndexes)
	}

	return result, nil
}

// EstimateObfuscatedPayloadSize returns an upper-bound estimate of the
// obfuscated payload size MakePushPayloads would produce for an equivalent
// input, overshooting by at most a handful of bytes due to a conservative
// expiry timestamp encoding (see expiresEncodedSizeUpperBound).
//
// It is a pure arithmetic helper for byte-budget calculations; pass 0 for
// any component that is not present. numLightProxyEntries is the number of
// light proxy entries and lightProxyEntrySizeSum is the sum of their
// CBOR-encoded sizes. Returns an error only when paddingSize is out of
// range or when numLightProxyEntries / lightProxyEntrySizeSum are
// inconsistent (one is zero while the other is not).
func (m *PushPayloadMaker) EstimateObfuscatedPayloadSize(
	numServerEntries int,
	serverEntrySizeSum int,
	numLightProxyEntries int,
	lightProxyEntrySizeSum int,
	paddingSize int,
) (int, error) {
	if paddingSize < 0 || paddingSize > maxPaddingLimit {
		return 0, errors.TraceNew("invalid padding size")
	}
	if numLightProxyEntries < 0 || lightProxyEntrySizeSum < 0 {
		return 0, errors.TraceNew("invalid light proxy entry count or size sum")
	}
	if (numLightProxyEntries == 0) != (lightProxyEntrySizeSum == 0) {
		return 0, errors.TraceNew(
			"inconsistent light proxy entry count and size sum")
	}
	return m.computeObfuscatedPayloadSize(
		expiresEncodedSizeUpperBound,
		numServerEntries,
		serverEntrySizeSum,
		numLightProxyEntries,
		lightProxyEntrySizeSum,
		paddingSize), nil
}

// buildObfuscatedPayload builds a single obfuscated payload that contains the
// pinned entries (if any) followed by the regular server entries.
func (m *PushPayloadMaker) buildObfuscatedPayload(
	bufs *payloadBuffers,
	pinned PinnedEntries,
	regularServerEntries []*PrioritizedServerEntry,
	expires time.Time,
	paddingSize int) ([]byte, error) {

	var combinedServerEntries []*PrioritizedServerEntry
	if len(pinned.PrioritizedServerEntries) == 0 {
		combinedServerEntries = regularServerEntries
	} else if len(regularServerEntries) == 0 {
		combinedServerEntries = pinned.PrioritizedServerEntries
	} else {
		combinedServerEntries = make(
			[]*PrioritizedServerEntry,
			0,
			len(pinned.PrioritizedServerEntries)+len(regularServerEntries))
		combinedServerEntries = append(
			combinedServerEntries, pinned.PrioritizedServerEntries...)
		combinedServerEntries = append(
			combinedServerEntries, regularServerEntries...)
	}

	obfuscatedPayload, err := m.makeObfuscatedPayload(
		bufs, combinedServerEntries, pinned.LightProxyEntries, expires, paddingSize)
	if err != nil {
		return nil, errors.Trace(err)
	}

	return append([]byte(nil), obfuscatedPayload...), nil
}

// cborHeaderSize returns the size of a CBOR definite-length header for the
// given count or length value.
func cborHeaderSize(n int) int {
	switch {
	case n <= 23:
		return 1
	case n <= 255:
		return 2
	case n <= 65535:
		return 3
	default:
		return 5
	}
}

// encodedLightProxyEntrySize returns the CBOR-encoded size of the given light
// proxy entry, or 0 when entry is nil.
func encodedLightProxyEntrySize(entry *LightProxyEntry) (int, error) {
	if entry == nil {
		return 0, nil
	}
	encodedEntry, err := protocol.CBOREncoding.Marshal(entry)
	if err != nil {
		return 0, errors.Trace(err)
	}
	return len(encodedEntry), nil
}

// computeObfuscatedPayloadSize computes the exact obfuscated payload size
// arithmetically from pre-computed component sizes, avoiding CBOR marshaling.
//
// lightProxyEntrySizeSum is the sum of CBOR-encoded LightProxyEntry sizes.
//
// The obfuscated payload structure is:
//
//	nonce || AES-GCM(CBOR(SignedPayload{ Signature, CBOR(Payload), Padding })) || tag
func (m *PushPayloadMaker) computeObfuscatedPayloadSize(
	expiresEncodedSize int,
	numServerEntries int,
	serverEntrySizeSum int,
	numLightProxyEntries int,
	lightProxyEntrySizeSum int,
	paddingSize int) int {

	// Payload = map { 1: expires, 2: array(server entries),
	// 3: array(light proxy entries) }
	// With omitempty, entry fields are omitted when their values are
	// empty/nil.
	payloadFields := 1 // Expires
	payloadBody := 1 + expiresEncodedSize
	if numServerEntries > 0 {
		payloadFields++
		payloadBody += 1 + cborHeaderSize(numServerEntries) + serverEntrySizeSum
	}
	if numLightProxyEntries > 0 {
		payloadFields++
		payloadBody += 1 + cborHeaderSize(numLightProxyEntries) + lightProxyEntrySizeSum
	}
	payloadSize := cborHeaderSize(payloadFields) + payloadBody

	// SignedPayload = map { 1: bstr(signature), 2: bstr(payload), [3: bstr(padding)] }
	sigLen := signatureSize
	spFields := 2
	spBody := 1 + cborHeaderSize(sigLen) + sigLen +
		1 + cborHeaderSize(payloadSize) + payloadSize
	if paddingSize > 0 {
		spFields++
		spBody += 1 + cborHeaderSize(paddingSize) + paddingSize
	}
	signedPayloadSize := cborHeaderSize(spFields) + spBody

	return m.aead.NonceSize() + signedPayloadSize + m.aead.Overhead()
}

func (m *PushPayloadMaker) makeObfuscatedPayload(
	bufs *payloadBuffers,
	prioritizedServerEntries []*PrioritizedServerEntry,
	lightProxyEntries []*LightProxyEntry,
	expires time.Time,
	paddingSize int) ([]byte, error) {

	payload := Payload{
		Expires:                  expires,
		PrioritizedServerEntries: prioritizedServerEntries,
		LightProxyEntries:        lightProxyEntries,
	}

	cborPayload, err := protocol.CBOREncoding.Marshal(&payload)
	if err != nil {
		return nil, errors.Trace(err)
	}

	signature := ed25519.Sign(m.privateKey, cborPayload)

	bufs.signature = bufs.signature[:0]
	bufs.signature = append(bufs.signature, m.publicKeyID...)
	bufs.signature = append(bufs.signature, signature...)

	signedPayload := SignedPayload{
		Signature: bufs.signature,
		Payload:   cborPayload,
	}

	if paddingSize < 0 || paddingSize > maxPaddingLimit {
		return nil, errors.TraceNew("invalid padding size")
	}
	if paddingSize > 0 {
		if bufs.padding == nil {
			bufs.padding = make([]byte, maxPaddingLimit)
		}
		signedPayload.Padding = bufs.padding[:paddingSize]
	}

	cborSignedPayload, err := protocol.CBOREncoding.Marshal(&signedPayload)
	if err != nil {
		return nil, errors.Trace(err)
	}

	// The faster common/prng is appropriate for obfuscation.
	prng.Read(bufs.nonce[:])

	bufs.obfuscation = bufs.obfuscation[:0]
	bufs.obfuscation = append(bufs.obfuscation, bufs.nonce...)
	bufs.obfuscation = m.aead.Seal(
		bufs.obfuscation,
		bufs.nonce[:],
		cborSignedPayload,
		nil)

	return bufs.obfuscation, nil
}
