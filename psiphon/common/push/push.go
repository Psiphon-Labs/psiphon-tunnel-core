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
	PrioritizeReason  string                           `cbor:"4,keyasint,omitempty"`
}

// ServerEntryImporter is a callback that is invoked for each server entry in
// an imported push payload.
type ServerEntryImporter func(
	packedServerEntryFields protocol.PackedServerEntryFields,
	source string,
	prioritizeDial bool,
	prioritizeReason string) error

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
			prioritizedServerEntry.PrioritizeDial,
			prioritizedServerEntry.PrioritizeReason)
		if err != nil {
			return imported, errors.Trace(err)
		}
		imported += 1
	}

	return imported, nil
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
// entries, reusing the cached key material and cipher from the maker.
//
// When maxPayloadSizeBytes <= 0, all entries are encoded into a single payload.
//
// When maxPayloadSizeBytes > 0, entries are packed into multiple payloads using
// an RF(2) (random-fit with 2 candidates) strategy. Entries that cannot
// fit by themselves under maxPayloadSizeBytes are skipped and reported in the
// returned result metadata.
func (m *PushPayloadMaker) MakePushPayloads(
	minPadding int,
	maxPadding int,
	TTL time.Duration,
	prioritizedServerEntries []*PrioritizedServerEntry,
	maxPayloadSizeBytes int) (MakePushPayloadsResult, error) {

	result := MakePushPayloadsResult{}

	if len(prioritizedServerEntries) == 0 {
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
		paddingSize := prng.Range(minPadding, maxPadding)
		payload, err := m.buildObfuscatedPayload(
			bufs, prioritizedServerEntries, expires, paddingSize)
		if err != nil {
			return result, errors.Trace(err)
		}
		result.Payloads = append(result.Payloads, payload)
		result.PayloadEntryCounts = append(
			result.PayloadEntryCounts, len(prioritizedServerEntries))
		return result, nil
	}

	// Pre-compute the CBOR-encoded size of the expires timestamp.
	expiresEncoded, err := protocol.CBOREncoding.Marshal(expires)
	if err != nil {
		return result, errors.Trace(err)
	}
	expiresEncodedSize := len(expiresEncoded)

	// Compute encoded sizes for each PrioritizedServerEntry.
	serverEntries := make(
		[]sortablePrioritizedServerEntry, 0, len(prioritizedServerEntries))
	for i, entry := range prioritizedServerEntries {
		encodedEntry, err := protocol.CBOREncoding.Marshal(entry)
		if err != nil {
			return result, errors.Trace(err)
		}

		serverEntries = append(serverEntries, sortablePrioritizedServerEntry{
			entry:         entry,
			originalIndex: i,
			encodedSize:   len(encodedEntry),
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

	// Worst-case each PrioritizedServerEntry gets its own bin.
	type payloadBin struct {
		serverEntries []*PrioritizedServerEntry
		paddingSize   int
		// sumServerEntrySize is the total encoded size of all server
		// entries in this bin, used to compute the obfuscated payload size.
		sumServerEntrySize int
	}
	bins := make([]payloadBin, 0, len(serverEntries))

	binOrder := make([]int, 0, len(serverEntries))

	type candidate struct {
		binIndex int
		size     int
	}

	for _, sortedServerEntry := range serverEntries {

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

			// Arithmetically compute the size of the obfuscated payload size
			// without the expensive marshalling and encryption.
			size := m.computeObfuscatedPayloadSize(
				expiresEncodedSize,
				len(bins[bi].serverEntries)+1,
				bins[bi].sumServerEntrySize+sortedServerEntry.encodedSize,
				bins[bi].paddingSize)
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
			bins[bi].serverEntries = append(bins[bi].serverEntries, sortedServerEntry.entry)
			bins[bi].sumServerEntrySize += sortedServerEntry.encodedSize
			continue
		}

		// Server entry did not fit into existing bins,
		// create a new bin with minPadding. Random padding is
		// applied after packing to avoid wasting bin capacity.
		paddingSize := minPadding
		size := m.computeObfuscatedPayloadSize(
			expiresEncodedSize, 1, sortedServerEntry.encodedSize, paddingSize)
		if size > maxPayloadSizeBytes {
			result.SkippedIndexes = append(
				result.SkippedIndexes, sortedServerEntry.originalIndex)
			continue
		}

		bins = append(bins, payloadBin{
			serverEntries:      []*PrioritizedServerEntry{sortedServerEntry.entry},
			paddingSize:        paddingSize,
			sumServerEntrySize: sortedServerEntry.encodedSize,
		})
	}

	// Apply random padding to each bin, respecting maxPayloadSizeBytes.
	noPadding := minPadding == 0 && maxPadding == 0
	if !noPadding {
		for i := range bins {
			randomPadding := prng.Range(minPadding, maxPadding)
			if randomPadding <= bins[i].paddingSize {
				continue
			}
			size := m.computeObfuscatedPayloadSize(
				expiresEncodedSize, len(bins[i].serverEntries), bins[i].sumServerEntrySize, randomPadding)
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
	result.PayloadEntryCounts = make([]int, 0, len(bins))

	for _, bin := range bins {
		payload, err := m.buildObfuscatedPayload(
			bufs, bin.serverEntries, expires, bin.paddingSize)
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
			result.PayloadEntryCounts, len(bin.serverEntries))
	}

	return result, nil
}

func (m *PushPayloadMaker) buildObfuscatedPayload(
	bufs *payloadBuffers,
	prioritizedServerEntries []*PrioritizedServerEntry,
	expires time.Time,
	paddingSize int) ([]byte, error) {

	obfuscatedPayload, err := m.makeObfuscatedPayload(
		bufs, prioritizedServerEntries, expires, paddingSize)
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

// computeObfuscatedPayloadSize computes the exact obfuscated payload size
// arithmetically from pre-computed component sizes, avoiding CBOR marshaling.
//
// The obfuscated payload structure is:
//
//	nonce || AES-GCM(CBOR(SignedPayload{ Signature, CBOR(Payload), Padding })) || tag
func (m *PushPayloadMaker) computeObfuscatedPayloadSize(
	expiresEncodedSize int,
	numEntries int,
	entrySizeSum int,
	paddingSize int) int {

	// Payload = map { 1: expires, 2: array(entries) }
	// With omitempty, the entries field is omitted when numEntries == 0.
	payloadFields := 1 // Expires
	payloadBody := 1 + expiresEncodedSize
	if numEntries > 0 {
		payloadFields++
		payloadBody += 1 + cborHeaderSize(numEntries) + entrySizeSum
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
