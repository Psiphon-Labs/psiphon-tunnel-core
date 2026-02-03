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
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	"github.com/fxamacker/cbor/v2"
)

const (
	obfuscationKeySize           = 32
	signaturePublicKeyDigestSize = 8
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

// MakePushPayloads generates batches of push payloads.
func MakePushPayloads(
	payloadObfuscationKey string,
	minPadding int,
	maxPadding int,
	payloadSignaturePublicKey string,
	payloadSignaturePrivateKey string,
	TTL time.Duration,
	prioritizedServerEntries [][]*PrioritizedServerEntry) ([][]byte, error) {

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

	expires := time.Now().Add(TTL).UTC()

	maxPaddingLimit := 65535
	if minPadding > maxPadding || maxPadding > 65535 {
		return nil, errors.TraceNew("invalid min/max padding")
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
	publicKeyID := publicKeyDigest[:signaturePublicKeyDigestSize]

	// Reuse buffers to reduce some allocations.
	var signatureBuffer []byte
	var obfuscationBuffer []byte
	nonceBuffer := make([]byte, aead.NonceSize())
	var paddingBuffer []byte

	obfuscatedPayloads := [][]byte{}

	for _, p := range prioritizedServerEntries {

		payload := Payload{
			Expires:                  expires,
			PrioritizedServerEntries: p,
		}

		cborPayload, err := protocol.CBOREncoding.Marshal(&payload)
		if err != nil {
			return nil, errors.Trace(err)
		}

		signature := ed25519.Sign(privateKey, cborPayload)

		signatureBuffer = signatureBuffer[:0]
		signatureBuffer = append(signatureBuffer, publicKeyID...)
		signatureBuffer = append(signatureBuffer, signature...)

		signedPayload := SignedPayload{
			Signature: signatureBuffer,
			Payload:   cborPayload,
		}

		// Padding is an optional part of the obfuscation layer.
		if maxPadding > 0 {
			paddingSize := prng.Range(minPadding, maxPadding)
			if paddingBuffer == nil {
				paddingBuffer = make([]byte, maxPaddingLimit)
			}
			if paddingSize > 0 {
				signedPayload.Padding = paddingBuffer[0:paddingSize]
			}
		}

		cborSignedPayload, err := protocol.CBOREncoding.
			Marshal(&signedPayload)
		if err != nil {
			return nil, errors.Trace(err)
		}

		// The faster common/prng is appropriate for obfuscation.
		prng.Read(nonceBuffer[:])

		obfuscationBuffer = obfuscationBuffer[:0]
		obfuscationBuffer = append(obfuscationBuffer, nonceBuffer...)
		obfuscationBuffer = aead.Seal(
			obfuscationBuffer, nonceBuffer[:], cborSignedPayload, nil)

		obfuscatedPayloads = append(
			obfuscatedPayloads, append([]byte(nil), obfuscationBuffer...))
	}

	return obfuscatedPayloads, nil
}
