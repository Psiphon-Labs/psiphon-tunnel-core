// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package ciphersuite

import (
	"crypto/aes"

	"github.com/pion/dtls/v3/pkg/crypto/ccm"
	"github.com/pion/dtls/v3/pkg/protocol/recordlayer"
)

// CCMTagLen is the length of Authentication Tag.
type CCMTagLen int

// CCM Enums.
const (
	CCMTagLength8  CCMTagLen = 8
	CCMTagLength   CCMTagLen = 16
	ccmNonceLength           = 12
)

// CCM Provides an API to Encrypt/Decrypt DTLS 1.2 Packets.
type CCM struct {
	aead *aead
}

// NewCCM creates a DTLS GCM Cipher.
func NewCCM(tagLen CCMTagLen, localKey, localWriteIV, remoteKey, remoteWriteIV []byte) (*CCM, error) {
	localBlock, err := aes.NewCipher(localKey)
	if err != nil {
		return nil, err
	}
	localCCM, err := ccm.NewCCM(localBlock, int(tagLen), ccmNonceLength)
	if err != nil {
		return nil, err
	}

	remoteBlock, err := aes.NewCipher(remoteKey)
	if err != nil {
		return nil, err
	}
	remoteCCM, err := ccm.NewCCM(remoteBlock, int(tagLen), ccmNonceLength)
	if err != nil {
		return nil, err
	}

	return &CCM{
		aead: newAEAD(
			localCCM,
			localWriteIV,
			remoteCCM,
			remoteWriteIV,
			ccmNonceLength,
			int(tagLen),
		),
	}, nil
}

// Encrypt encrypt a DTLS RecordLayer message.
func (c *CCM) Encrypt(pkt *recordlayer.RecordLayer, raw []byte) ([]byte, error) {
	return c.aead.encrypt(pkt, raw)
}

// Decrypt decrypts a DTLS RecordLayer message.
func (c *CCM) Decrypt(header recordlayer.Header, in []byte) ([]byte, error) {
	return c.aead.decrypt(header, in)
}
