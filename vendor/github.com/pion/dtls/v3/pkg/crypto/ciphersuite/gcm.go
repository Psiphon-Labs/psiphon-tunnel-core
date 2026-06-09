// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package ciphersuite

import (
	"crypto/aes"
	"crypto/cipher"

	"github.com/pion/dtls/v3/pkg/protocol/recordlayer"
)

const (
	gcmTagLength   = 16
	gcmNonceLength = 12
)

// GCM Provides an API to Encrypt/Decrypt DTLS 1.2 Packets.
type GCM struct {
	aead *aead
}

// NewGCM creates a DTLS GCM Cipher.
func NewGCM(localKey, localWriteIV, remoteKey, remoteWriteIV []byte) (*GCM, error) {
	localBlock, err := aes.NewCipher(localKey)
	if err != nil {
		return nil, err
	}
	localGCM, err := cipher.NewGCM(localBlock)
	if err != nil {
		return nil, err
	}

	remoteBlock, err := aes.NewCipher(remoteKey)
	if err != nil {
		return nil, err
	}
	remoteGCM, err := cipher.NewGCM(remoteBlock)
	if err != nil {
		return nil, err
	}

	return &GCM{
		aead: newAEAD(
			localGCM,
			localWriteIV,
			remoteGCM,
			remoteWriteIV,
			gcmNonceLength,
			gcmTagLength,
		),
	}, nil
}

// Encrypt encrypts a DTLS RecordLayer message.
func (g *GCM) Encrypt(pkt *recordlayer.RecordLayer, raw []byte) ([]byte, error) {
	return g.aead.encrypt(pkt, raw)
}

// Decrypt decrypts a DTLS RecordLayer message.
func (g *GCM) Decrypt(header recordlayer.Header, in []byte) ([]byte, error) {
	return g.aead.decrypt(header, in)
}
