// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package ciphersuite

import (
	"crypto/sha256"
	"fmt"
	"hash"
	"sync/atomic"

	"github.com/pion/dtls/v3/pkg/crypto/ciphersuite"
	"github.com/pion/dtls/v3/pkg/crypto/clientcertificate"
	"github.com/pion/dtls/v3/pkg/crypto/prf"
	"github.com/pion/dtls/v3/pkg/protocol/recordlayer"
)

// TLSEcdheEcdsaWithChacha20Poly1305Sha256 represents a TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 CipherSuite.
type TLSEcdheEcdsaWithChacha20Poly1305Sha256 struct {
	chacha atomic.Value // *ciphersuite.ChaCha20Poly1305
}

// CertificateType returns what type of certificate this CipherSuite exchanges.
func (c *TLSEcdheEcdsaWithChacha20Poly1305Sha256) CertificateType() clientcertificate.Type {
	return clientcertificate.ECDSASign
}

// KeyExchangeAlgorithm controls what key exchange algorithm is using during the handshake.
func (c *TLSEcdheEcdsaWithChacha20Poly1305Sha256) KeyExchangeAlgorithm() KeyExchangeAlgorithm {
	return KeyExchangeAlgorithmEcdhe
}

// ECC uses Elliptic Curve Cryptography.
func (c *TLSEcdheEcdsaWithChacha20Poly1305Sha256) ECC() bool {
	return true
}

// ID returns the ID of the CipherSuite.
func (c *TLSEcdheEcdsaWithChacha20Poly1305Sha256) ID() ID {
	return TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
}

// String returns the string representation of the cipher's ID.
func (c *TLSEcdheEcdsaWithChacha20Poly1305Sha256) String() string {
	return c.ID().String()
}

// HashFunc returns the hashing func for this CipherSuite.
func (c *TLSEcdheEcdsaWithChacha20Poly1305Sha256) HashFunc() func() hash.Hash {
	return sha256.New
}

// AuthenticationType controls what authentication method is using during the handshake.
func (c *TLSEcdheEcdsaWithChacha20Poly1305Sha256) AuthenticationType() AuthenticationType {
	return AuthenticationTypeCertificate
}

// IsInitialized returns if the CipherSuite has keying material and can
// encrypt/decrypt packets.
func (c *TLSEcdheEcdsaWithChacha20Poly1305Sha256) IsInitialized() bool {
	return c.chacha.Load() != nil
}

func (c *TLSEcdheEcdsaWithChacha20Poly1305Sha256) init(
	masterSecret, clientRandom, serverRandom []byte,
	isClient bool,
	prfMacLen, prfKeyLen, prfIvLen int,
	hashFunc func() hash.Hash,
) error {
	keys, err := prf.GenerateEncryptionKeys(
		masterSecret,
		clientRandom,
		serverRandom,
		prfMacLen,
		prfKeyLen,
		prfIvLen,
		hashFunc,
	)
	if err != nil {
		return err
	}

	var chacha *ciphersuite.ChaCha20Poly1305
	if isClient {
		chacha, err = ciphersuite.NewChaCha20Poly1305(
			keys.ClientWriteKey,
			keys.ClientWriteIV,
			keys.ServerWriteKey,
			keys.ServerWriteIV,
		)
	} else {
		chacha, err = ciphersuite.NewChaCha20Poly1305(
			keys.ServerWriteKey,
			keys.ServerWriteIV,
			keys.ClientWriteKey,
			keys.ClientWriteIV,
		)
	}
	c.chacha.Store(chacha)

	return err
}

// Init initializes the internal Cipher with keying material.
func (c *TLSEcdheEcdsaWithChacha20Poly1305Sha256) Init(
	masterSecret []byte,
	clientRandom []byte,
	serverRandom []byte,
	isClient bool,
) error {
	prfMacLen := 0
	prfKeyLen := 32
	prfIvLen := 12

	return c.init(
		masterSecret,
		clientRandom,
		serverRandom,
		isClient,
		prfMacLen,
		prfKeyLen,
		prfIvLen,
		c.HashFunc(),
	)
}

// Encrypt encrypts a single TLS RecordLayer.
func (c *TLSEcdheEcdsaWithChacha20Poly1305Sha256) Encrypt(pkt *recordlayer.RecordLayer, raw []byte) ([]byte, error) {
	cipherSuite, ok := c.chacha.Load().(*ciphersuite.ChaCha20Poly1305)
	if !ok {
		return nil, fmt.Errorf("%w, unable to encrypt", errCipherSuiteNotInit)
	}

	return cipherSuite.Encrypt(pkt, raw)
}

// Decrypt decrypts a single TLS RecordLayer.
func (c *TLSEcdheEcdsaWithChacha20Poly1305Sha256) Decrypt(h recordlayer.Header, raw []byte) ([]byte, error) {
	cipherSuite, ok := c.chacha.Load().(*ciphersuite.ChaCha20Poly1305)
	if !ok {
		return nil, fmt.Errorf("%w, unable to decrypt", errCipherSuiteNotInit)
	}

	return cipherSuite.Decrypt(h, raw)
}
