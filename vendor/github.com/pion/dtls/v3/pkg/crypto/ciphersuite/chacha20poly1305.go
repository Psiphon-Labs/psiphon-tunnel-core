// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package ciphersuite

import (
	"crypto/cipher"
	"encoding/binary"
	"fmt"

	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/recordlayer"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	chachaTagLength   = 16
	chachaNonceLength = 12
)

// ChaCha20Poly1305 Provides an API to Encrypt/Decrypt DTLS 1.2 Packets.
//
// Per RFC 7905, ChaCha20-Poly1305 nonce is formed by XOR-ing the write_IV with
// the padded 64-bit sequence number (epoch || sequence_number).
type ChaCha20Poly1305 struct {
	localCipher   cipher.AEAD
	remoteCipher  cipher.AEAD
	localWriteIV  []byte
	remoteWriteIV []byte
}

// NewChaCha20Poly1305 creates a DTLS ChaCha20-Poly1305 Cipher.
func NewChaCha20Poly1305(localKey, localWriteIV, remoteKey, remoteWriteIV []byte) (*ChaCha20Poly1305, error) {
	localChaCha20Poly1305, err := chacha20poly1305.New(localKey)
	if err != nil {
		return nil, err
	}

	remoteChaCha20Poly1305, err := chacha20poly1305.New(remoteKey)
	if err != nil {
		return nil, err
	}

	return &ChaCha20Poly1305{
		localCipher:   localChaCha20Poly1305,
		remoteCipher:  remoteChaCha20Poly1305,
		localWriteIV:  localWriteIV,
		remoteWriteIV: remoteWriteIV,
	}, nil
}

// Encrypt encrypts a DTLS RecordLayer message.
func (c *ChaCha20Poly1305) Encrypt(pkt *recordlayer.RecordLayer, raw []byte) ([]byte, error) {
	payload := raw[pkt.Header.Size():]
	raw = raw[:pkt.Header.Size()]

	var nonce [chachaNonceLength]byte
	copy(nonce[:], c.localWriteIV)

	// https://www.rfc-editor.org/rfc/rfc9325#name-nonce-reuse-in-tls-12
	seq64 := (uint64(pkt.Header.Epoch) << 48) | (pkt.Header.SequenceNumber & 0x0000ffffffffffff)

	// XOR the last 8 bytes of the nonce with the sequence number
	for i := range 8 {
		nonce[4+i] ^= byte(seq64 >> (56 - uint(i)*8)) //nolint:gosec
	}

	var additionalData []byte
	if pkt.Header.ContentType == protocol.ContentTypeConnectionID {
		additionalData = generateAEADAdditionalDataCID(&pkt.Header, len(payload))
	} else {
		additionalData = generateAEADAdditionalData(&pkt.Header, len(payload))
	}

	// NOTE: ChaCha20-Poly1305 does NOT include an explicit nonce
	// in the record (unlike GCM which includes 8 bytes)
	encrypted := c.localCipher.Seal(nil, nonce[:], payload, additionalData)

	result := make([]byte, len(raw)+len(encrypted))
	copy(result, raw)
	copy(result[len(raw):], encrypted)

	binary.BigEndian.PutUint16(result[pkt.Header.Size()-2:], uint16(len(encrypted))) //nolint:gosec

	return result, nil
}

// Decrypt decrypts a DTLS RecordLayer message.
func (c *ChaCha20Poly1305) Decrypt(header recordlayer.Header, in []byte) ([]byte, error) {
	err := header.Unmarshal(in)
	switch {
	case err != nil:
		return nil, err
	case header.ContentType == protocol.ContentTypeChangeCipherSpec:
		// Nothing to decrypt with ChangeCipherSpec
		return in, nil
	}

	var nonce [chachaNonceLength]byte
	copy(nonce[:], c.remoteWriteIV)

	// https://www.rfc-editor.org/rfc/rfc9325#name-nonce-reuse-in-tls-12
	seq64 := (uint64(header.Epoch) << 48) | (header.SequenceNumber & 0x0000ffffffffffff)

	// XOR the last 8 bytes of the nonce with the sequence number
	for i := range 8 {
		nonce[4+i] ^= byte(seq64 >> (56 - uint(i)*8)) //nolint:gosec
	}

	// NOTE: ChaCha20-Poly1305 has NO explicit nonce in the record
	ciphertext := in[header.Size():]

	var additionalData []byte
	if header.ContentType == protocol.ContentTypeConnectionID {
		additionalData = generateAEADAdditionalDataCID(&header, len(ciphertext)-chachaTagLength)
	} else {
		additionalData = generateAEADAdditionalData(&header, len(ciphertext)-chachaTagLength)
	}

	plaintext, err := c.remoteCipher.Open(nil, nonce[:], ciphertext, additionalData)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errDecryptPacket, err) //nolint:errorlint
	}

	return append(in[:header.Size()], plaintext...), nil
}
