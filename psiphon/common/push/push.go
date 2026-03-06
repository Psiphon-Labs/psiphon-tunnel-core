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
	// Each server entry can increase up to two CBOR length headers:
	// - Payload.PrioritizedServerEntries array length
	// - SignedPayload.Payload byte-string length
	// Each header can grow by up to 8 bytes, so 16 is a safe global bound.
	serverEntryCBORSizeOverhead = 16
)

// Payload is a push payload, consisting of a list of server entries. To
// ensure stale server entries and stale dial prioritizations are not
// imported, the list has an expiry timestamp.
type Payload struct {
	Expires                  time.Time                 `cbor:"1,keyasint,omitempty"`
	PrioritizedServerEntries []*PrioritizedServerEntry `cbor:"2,keyasint,omitempty"`
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
	ServerEntryFields protocol.PackedServerEntryFields `cbor:"1,keyasint,omitempty"`
	Source            string                           `cbor:"2,keyasint,omitempty"`
	PrioritizeDial    bool                             `cbor:"3,keyasint,omitempty"`
}

// MakePushPayloadsResult is the output from MakePushPayloads.
type MakePushPayloadsResult struct {
	// Payloads contains generated obfuscated push payloads.
	Payloads [][]byte
	// PayloadEntryCounts contains the number of entries in each payload, aligned
	// by index with Payloads.
	PayloadEntryCounts []int
	// SkippedIndexes contains original input indexes for entries that could not
	// fit into a payload when max payload size is enforced.
	SkippedIndexes []int
}

type payloadEncoder struct {
	aead              cipher.AEAD
	privateKey        ed25519.PrivateKey
	publicKeyID       []byte
	nonceBuffer       []byte
	signatureBuffer   []byte
	obfuscationBuffer []byte
	paddingBuffer     []byte
}

type sortablePrioritizedServerEntry struct {
	entry               *PrioritizedServerEntry
	originalIndex       int
	sortWeight          int
	sizeDeltaLowerBound int
	sizeDeltaUpperBound int
}

type payloadBin struct {
	entries        []*PrioritizedServerEntry
	paddingSize    int
	sizeLowerBound int
	sizeUpperBound int
}

// ServerEntryImporter is a callback that is invoked for each server entry in
// an imported push payload.
type ServerEntryImporter func(
	packedServerEntryFields protocol.PackedServerEntryFields,
	source string,
	prioritizeDial bool) error

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
// source and prioritizeDial data.
func ImportPushPayload(
	payloadObfuscationKey string,
	payloadSignaturePublicKey string,
	obfuscatedPayload []byte,
	serverEntryImporter ServerEntryImporter) (int, error) {

	obfuscationKey, err := base64.StdEncoding.DecodeString(
		payloadObfuscationKey)
	if err == nil && len(obfuscationKey) != obfuscationKeySize {
		err = errors.TraceNew("unexpected obfuscation key size")
	}
	if err != nil {
		return 0, errors.Trace(err)
	}

	publicKey, err := base64.StdEncoding.DecodeString(
		payloadSignaturePublicKey)
	if err == nil && len(publicKey) != ed25519.PublicKeySize {
		err = errors.TraceNew("unexpected signature public key size")
	}
	if err != nil {
		return 0, errors.Trace(err)
	}

	blockCipher, err := aes.NewCipher(obfuscationKey)
	if err != nil {
		return 0, errors.Trace(err)
	}

	aead, err := cipher.NewGCM(blockCipher)
	if err != nil {
		return 0, errors.Trace(err)
	}

	if len(obfuscatedPayload) < aead.NonceSize() {
		return 0, errors.TraceNew("missing nonce")
	}

	cborSignedPayload, err := aead.Open(
		nil,
		obfuscatedPayload[:aead.NonceSize()],
		obfuscatedPayload[aead.NonceSize():],
		nil)
	if err != nil {
		return 0, errors.Trace(err)
	}

	var signedPayload SignedPayload
	err = cbor.Unmarshal(cborSignedPayload, &signedPayload)
	if err != nil {
		return 0, errors.Trace(err)
	}

	if len(signedPayload.Signature) !=
		signaturePublicKeyDigestSize+ed25519.SignatureSize {

		return 0, errors.TraceNew("invalid signature size")
	}

	publicKeyDigest := sha256.Sum256(publicKey)
	expectedPublicKeyID := publicKeyDigest[:signaturePublicKeyDigestSize]

	if !bytes.Equal(
		expectedPublicKeyID,
		signedPayload.Signature[:signaturePublicKeyDigestSize]) {

		return 0, errors.TraceNew("unexpected signature public key ID")
	}

	if !ed25519.Verify(
		publicKey,
		signedPayload.Payload,
		signedPayload.Signature[signaturePublicKeyDigestSize:]) {

		return 0, errors.TraceNew("invalid signature")
	}

	var payload Payload
	err = cbor.Unmarshal(signedPayload.Payload, &payload)
	if err != nil {
		return 0, errors.Trace(err)
	}

	if payload.Expires.Before(time.Now().UTC()) {
		return 0, errors.TraceNew("payload expired")
	}

	imported := 0
	for _, prioritizedServerEntry := range payload.PrioritizedServerEntries {
		err := serverEntryImporter(
			prioritizedServerEntry.ServerEntryFields,
			prioritizedServerEntry.Source,
			prioritizedServerEntry.PrioritizeDial)
		if err != nil {
			return imported, errors.Trace(err)
		}
		imported += 1
	}

	return imported, nil
}

// MakePushPayloads generates obfuscated push payloads from prioritized server
// entries.
//
// When maxPayloadSizeBytes <= 0, all entries are encoded into a single payload.
//
// When maxPayloadSizeBytes > 0, entries are packed into multiple payloads using
// a FFD (first-fit decreasing) strategy based on estimated encoded entry sizes
// with exact payload-size checks as fallback. Entries that cannot fit by
// themselves under maxPayloadSizeBytes are skipped and reported in the returned
// result metadata.
func MakePushPayloads(
	payloadObfuscationKey string,
	minPadding int,
	maxPadding int,
	payloadSignaturePublicKey string,
	payloadSignaturePrivateKey string,
	TTL time.Duration,
	prioritizedServerEntries []*PrioritizedServerEntry,
	maxPayloadSizeBytes int) (MakePushPayloadsResult, error) {

	result := MakePushPayloadsResult{}

	obfuscationKey, err := base64.StdEncoding.DecodeString(
		payloadObfuscationKey)
	if err == nil && len(obfuscationKey) != obfuscationKeySize {
		err = errors.TraceNew("unexpected obfuscation key size")
	}
	if err != nil {
		return result, errors.Trace(err)
	}

	publicKey, err := base64.StdEncoding.DecodeString(
		payloadSignaturePublicKey)
	if err == nil && len(publicKey) != ed25519.PublicKeySize {
		err = errors.TraceNew("unexpected signature public key size")
	}
	if err != nil {
		return result, errors.Trace(err)
	}

	privateKey, err := base64.StdEncoding.DecodeString(
		payloadSignaturePrivateKey)
	if err == nil && len(privateKey) != ed25519.PrivateKeySize {
		err = errors.TraceNew("unexpected signature private key size")
	}
	if err != nil {
		return result, errors.Trace(err)
	}

	if minPadding > maxPadding || maxPadding > maxPaddingLimit {
		return result, errors.TraceNew("invalid min/max padding")
	}

	encoder, err := newPayloadEncoder(obfuscationKey, publicKey, privateKey)
	if err != nil {
		return result, errors.Trace(err)
	}

	expires := time.Now().Add(TTL).UTC()

	// maxPayloadSizeBytes <= 0 means no payload size cap is enforced.
	if maxPayloadSizeBytes <= 0 {
		paddingSize := prng.Range(minPadding, maxPadding)
		payload, err := encoder.buildObfuscatedPayload(
			prioritizedServerEntries, expires, paddingSize)
		if err != nil {
			return result, errors.Trace(err)
		}
		result.Payloads = append(result.Payloads, payload)
		result.PayloadEntryCounts = append(
			result.PayloadEntryCounts, len(prioritizedServerEntries))
		return result, nil
	}

	if len(prioritizedServerEntries) == 0 {
		return result, nil
	}

	// Estimate size bounds for each PrioritizedServerEntry.
	entries := make(
		[]sortablePrioritizedServerEntry, 0, len(prioritizedServerEntries))
	for i, entry := range prioritizedServerEntries {
		entrySizeLowerBound, err := estimatePrioritizedServerEntrySizeLowerBound(entry)
		if err != nil {
			return result, errors.Trace(err)
		}
		entrySizeUpperBound := estimatePrioritizedServerEntrySizeUpperBound(
			entrySizeLowerBound)

		// Sort by estimated marginal size.
		sortWeight := entrySizeLowerBound

		entries = append(entries, sortablePrioritizedServerEntry{
			entry:               entry,
			originalIndex:       i,
			sortWeight:          sortWeight,
			sizeDeltaLowerBound: entrySizeLowerBound,
			sizeDeltaUpperBound: entrySizeUpperBound,
		})
	}

	// Sort by decreasing size
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].sortWeight == entries[j].sortWeight {
			return entries[i].originalIndex < entries[j].originalIndex
		}
		return entries[i].sortWeight > entries[j].sortWeight
	})

	// Worst-case each PrioritizedServerEntry gets it's own bin.
	bins := make([]payloadBin, 0, len(entries))

	for _, sortableEntry := range entries {

		// Try to fit server entry into the first bin that has space.
		// Note that there are no bins on the first loop.
		placed := false
		for i := range bins {
			candidateSizeLowerBound :=
				bins[i].sizeLowerBound + sortableEntry.sizeDeltaLowerBound
			if candidateSizeLowerBound > maxPayloadSizeBytes {
				// Fast path: guaranteed not to fit, skip this bin.
				continue
			}

			candidateSizeUpperBound :=
				bins[i].sizeUpperBound + sortableEntry.sizeDeltaUpperBound
			if candidateSizeUpperBound <= maxPayloadSizeBytes {
				// Fast path: upper bound fits, so exact size must fit as well.
				bins[i].entries = append(bins[i].entries, sortableEntry.entry)
				bins[i].sizeLowerBound = candidateSizeLowerBound
				bins[i].sizeUpperBound = candidateSizeUpperBound
				placed = true
				break
			}

			// Ambiguous case: do exact measurement
			candidateEntries := append(
				append([]*PrioritizedServerEntry(nil), bins[i].entries...),
				sortableEntry.entry)
			size, err := encoder.measureObfuscatedPayloadSize(
				candidateEntries, expires, bins[i].paddingSize)
			if err != nil {
				return result, errors.Trace(err)
			}
			if size <= maxPayloadSizeBytes {
				bins[i].entries = append(bins[i].entries, sortableEntry.entry)
				bins[i].sizeLowerBound = size
				bins[i].sizeUpperBound = size
				placed = true
				break
			}
		}

		if placed {
			continue
		}

		// Server entry did not fit into existing bins,
		// create a new bin with a random padding.
		paddingSize := prng.Range(minPadding, maxPadding)
		size, err := encoder.measureObfuscatedPayloadSize(
			[]*PrioritizedServerEntry{sortableEntry.entry}, expires, paddingSize)
		if err != nil {
			return result, errors.Trace(err)
		}
		if size > maxPayloadSizeBytes {
			result.SkippedIndexes = append(
				result.SkippedIndexes, sortableEntry.originalIndex)
			continue
		}

		bins = append(bins, payloadBin{
			entries:        []*PrioritizedServerEntry{sortableEntry.entry},
			paddingSize:    paddingSize,
			sizeLowerBound: size,
			sizeUpperBound: size,
		})
	}

	result.Payloads = make([][]byte, 0, len(bins))
	result.PayloadEntryCounts = make([]int, 0, len(bins))

	for _, bin := range bins {
		payload, err := encoder.buildObfuscatedPayload(
			bin.entries, expires, bin.paddingSize)
		if err != nil {
			return result, errors.Trace(err)
		}
		// Apply a hard correctness check.
		if len(payload) > maxPayloadSizeBytes {
			return result, errors.TraceNew(
				"internal error: payload size exceeds max")
		}
		result.Payloads = append(result.Payloads, payload)
		result.PayloadEntryCounts = append(
			result.PayloadEntryCounts, len(bin.entries))
	}

	return result, nil
}

func newPayloadEncoder(
	obfuscationKey []byte,
	publicKey []byte,
	privateKey []byte) (*payloadEncoder, error) {

	blockCipher, err := aes.NewCipher(obfuscationKey)
	if err != nil {
		return nil, errors.Trace(err)
	}

	aead, err := cipher.NewGCM(blockCipher)
	if err != nil {
		return nil, errors.Trace(err)
	}

	publicKeyDigest := sha256.Sum256(publicKey)

	return &payloadEncoder{
		aead:        aead,
		privateKey:  privateKey,
		publicKeyID: publicKeyDigest[:signaturePublicKeyDigestSize],
		nonceBuffer: make([]byte, aead.NonceSize()),
	}, nil
}

func (encoder *payloadEncoder) buildObfuscatedPayload(
	prioritizedServerEntries []*PrioritizedServerEntry,
	expires time.Time,
	paddingSize int) ([]byte, error) {

	obfuscatedPayload, err := encoder.makeObfuscatedPayload(
		prioritizedServerEntries, expires, paddingSize)
	if err != nil {
		return nil, errors.Trace(err)
	}

	return append([]byte(nil), obfuscatedPayload...), nil
}

func (encoder *payloadEncoder) measureObfuscatedPayloadSize(
	prioritizedServerEntries []*PrioritizedServerEntry,
	expires time.Time,
	paddingSize int) (int, error) {

	obfuscatedPayload, err := encoder.makeObfuscatedPayload(
		prioritizedServerEntries, expires, paddingSize)
	if err != nil {
		return 0, errors.Trace(err)
	}

	return len(obfuscatedPayload), nil
}

func estimatePrioritizedServerEntrySizeLowerBound(
	prioritizedServerEntry *PrioritizedServerEntry) (int, error) {

	// In the final payload, each entry appears as a CBOR array element; at
	// minimum, this contributes exactly its own CBOR element length.
	encodedEntry, err := protocol.CBOREncoding.Marshal(prioritizedServerEntry)
	if err != nil {
		return 0, errors.Trace(err)
	}

	return len(encodedEntry), nil
}

func estimatePrioritizedServerEntrySizeUpperBound(lowerBound int) int {
	return lowerBound + serverEntryCBORSizeOverhead
}

func (encoder *payloadEncoder) makeObfuscatedPayload(
	prioritizedServerEntries []*PrioritizedServerEntry,
	expires time.Time,
	paddingSize int) ([]byte, error) {

	payload := Payload{
		Expires:                  expires,
		PrioritizedServerEntries: prioritizedServerEntries,
	}

	cborPayload, err := protocol.CBOREncoding.Marshal(&payload)
	if err != nil {
		return nil, errors.Trace(err)
	}

	signature := ed25519.Sign(encoder.privateKey, cborPayload)

	encoder.signatureBuffer = encoder.signatureBuffer[:0]
	encoder.signatureBuffer = append(
		encoder.signatureBuffer, encoder.publicKeyID...)
	encoder.signatureBuffer = append(encoder.signatureBuffer, signature...)

	signedPayload := SignedPayload{
		Signature: encoder.signatureBuffer,
		Payload:   cborPayload,
	}

	if paddingSize < 0 || paddingSize > maxPaddingLimit {
		return nil, errors.TraceNew("invalid padding size")
	}
	if paddingSize > 0 {
		if encoder.paddingBuffer == nil {
			encoder.paddingBuffer = make([]byte, maxPaddingLimit)
		}
		signedPayload.Padding = encoder.paddingBuffer[:paddingSize]
	}

	cborSignedPayload, err := protocol.CBOREncoding.Marshal(&signedPayload)
	if err != nil {
		return nil, errors.Trace(err)
	}

	// The faster common/prng is appropriate for obfuscation.
	prng.Read(encoder.nonceBuffer[:])

	encoder.obfuscationBuffer = encoder.obfuscationBuffer[:0]
	encoder.obfuscationBuffer = append(
		encoder.obfuscationBuffer, encoder.nonceBuffer...)
	encoder.obfuscationBuffer = encoder.aead.Seal(
		encoder.obfuscationBuffer,
		encoder.nonceBuffer[:],
		cborSignedPayload,
		nil)

	return encoder.obfuscationBuffer, nil
}
