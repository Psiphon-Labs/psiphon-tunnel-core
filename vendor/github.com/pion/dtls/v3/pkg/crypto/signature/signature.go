// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package signature provides our implemented Signature Algorithms
package signature

import "github.com/pion/dtls/v3/pkg/crypto/hash"

// Algorithm as defined in TLS 1.2
// https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-16
type Algorithm uint16

// SignatureAlgorithm enums.
const (
	Anonymous Algorithm = 0
	RSA       Algorithm = 1
	ECDSA     Algorithm = 3
	Ed25519   Algorithm = 7

	// RSA-PSS (DTLS 1.3 only) - full SignatureScheme values
	// https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-signaturescheme
	RSA_PSS_RSAE_SHA256 Algorithm = 0x0804 // nolint: staticcheck
	RSA_PSS_RSAE_SHA384 Algorithm = 0x0805 // nolint: staticcheck
	RSA_PSS_RSAE_SHA512 Algorithm = 0x0806 // nolint: revive,staticcheck
	RSA_PSS_PSS_SHA256  Algorithm = 0x0809 // nolint: revive,staticcheck
	RSA_PSS_PSS_SHA384  Algorithm = 0x080a // nolint: revive,staticcheck
	RSA_PSS_PSS_SHA512  Algorithm = 0x080b // nolint: revive,staticcheck
)

// Algorithms returns all implemented Signature Algorithms.
func Algorithms() map[Algorithm]struct{} {
	return map[Algorithm]struct{}{
		Anonymous:           {},
		RSA:                 {},
		ECDSA:               {},
		Ed25519:             {},
		RSA_PSS_RSAE_SHA256: {},
		RSA_PSS_RSAE_SHA384: {},
		RSA_PSS_RSAE_SHA512: {},
		RSA_PSS_PSS_SHA256:  {},
		RSA_PSS_PSS_SHA384:  {},
		RSA_PSS_PSS_SHA512:  {},
	}
}

// IsPSS returns true if the algorithm is an RSA-PSS signature scheme.
// It's tempting to check for range between 0x0804 and 0x080b, but 0x0807 is Ed25519
// and 0x0808 is Ed448, which are NOT PSS, so we check specific values instead.
func (a Algorithm) IsPSS() bool {
	return a == RSA_PSS_RSAE_SHA256 ||
		a == RSA_PSS_RSAE_SHA384 ||
		a == RSA_PSS_RSAE_SHA512 ||
		a == RSA_PSS_PSS_SHA256 ||
		a == RSA_PSS_PSS_SHA384 ||
		a == RSA_PSS_PSS_SHA512
}

// IsUnsupported returns true if the algorithm is a signature scheme that is
// not supported by pion/dtls.
func (a Algorithm) IsUnsupported() bool {
	// Skip RSA_PSS_PSS schemes (0x0809-0x080b). We parse them for interoperability
	// but don't negotiate them to avoid unnecessary complexity for certificates that
	// don't exist in practice. This follows the pragmatic approach of Go's crypto/tls
	// and BoringSSL: target real-world WebPKI use cases rather than RFC completeness.
	return a == RSA_PSS_PSS_SHA256 ||
		a == RSA_PSS_PSS_SHA384 ||
		a == RSA_PSS_PSS_SHA512
}

// GetPSSHash returns the hash algorithm associated with an RSA-PSS signature scheme.
// Returns hash.None if the algorithm is not an RSA-PSS scheme.
func (a Algorithm) GetPSSHash() hash.Algorithm {
	switch a {
	case RSA_PSS_RSAE_SHA256, RSA_PSS_PSS_SHA256:
		return hash.SHA256
	case RSA_PSS_RSAE_SHA384, RSA_PSS_PSS_SHA384:
		return hash.SHA384
	case RSA_PSS_RSAE_SHA512, RSA_PSS_PSS_SHA512:
		return hash.SHA512
	default:
		return hash.None
	}
}
