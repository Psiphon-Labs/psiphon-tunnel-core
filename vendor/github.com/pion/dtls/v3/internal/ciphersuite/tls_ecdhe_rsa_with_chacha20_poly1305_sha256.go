// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package ciphersuite

import (
	"github.com/pion/dtls/v3/pkg/crypto/clientcertificate"
)

// TLSEcdheRsaWithChacha20Poly1305Sha256 represents a TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 CipherSuite.
type TLSEcdheRsaWithChacha20Poly1305Sha256 struct {
	TLSEcdheEcdsaWithChacha20Poly1305Sha256
}

// CertificateType returns what type of certificate this CipherSuite exchanges.
func (c *TLSEcdheRsaWithChacha20Poly1305Sha256) CertificateType() clientcertificate.Type {
	return clientcertificate.RSASign
}

// ID returns the ID of the CipherSuite.
func (c *TLSEcdheRsaWithChacha20Poly1305Sha256) ID() ID {
	return TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
}

// String returns the string representation of the cipher's ID.
func (c *TLSEcdheRsaWithChacha20Poly1305Sha256) String() string {
	return c.ID().String()
}
