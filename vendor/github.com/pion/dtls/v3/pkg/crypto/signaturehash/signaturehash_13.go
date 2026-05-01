// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package signaturehash

import (
	"github.com/pion/dtls/v3/pkg/crypto/hash"
	"github.com/pion/dtls/v3/pkg/crypto/signature"
)

// Algorithms13 returns signature algorithms compatible with DTLS 1.3. This.
// includes DTLS 1.3-specific schemes like RSA-PSS in addition to DTLS 1.2 schemes.
//
// IMPORTANT: order in this slice determines priority used by SelectSignatureScheme13.
//
// Order follows industry standard preference (ECDSA-first) as used by OpenSSL,
// BoringSSL, Firefox, Chrome, and other major TLS 1.3 implementations.
func Algorithms13() []Algorithm {
	return []Algorithm{
		// ECDSA schemes (modern, efficient - industry standard preference)
		{hash.SHA256, signature.ECDSA},
		{hash.SHA384, signature.ECDSA},
		{hash.SHA512, signature.ECDSA},

		// Ed25519
		{hash.Ed25519, signature.Ed25519},

		// RSA-PSS RSAE schemes (TLS 1.3 / DTLS 1.3 compatible with standard RSA certs)
		// Note: We only offer RSA_PSS_RSAE variants (0x0804-0x0806), not RSA_PSS_PSS
		// (0x0809-0x080b). RSA-PSS certificates with OID id-RSASSA-PSS are virtually
		// unused in the real world and are not allowed by the CA/Browser Forum Baseline
		// Requirements for WebPKI. We avoid unnecessary complexity for certificates that
		// don't exist in practice, following the pragmatic approach of Go's crypto/tls
		// and BoringSSL: target real-world WebPKI use cases rather than RFC completeness.
		// RSA_PSS_PSS schemes are parsed for wire-format compatibility but never negotiated.
		{hash.SHA256, signature.RSA_PSS_RSAE_SHA256},
		{hash.SHA384, signature.RSA_PSS_RSAE_SHA384},
		{hash.SHA512, signature.RSA_PSS_RSAE_SHA512},
		// {hash.SHA256, signature.RSA_PSS_PSS_SHA256},
		// {hash.SHA384, signature.RSA_PSS_PSS_SHA384},
		// {hash.SHA512, signature.RSA_PSS_PSS_SHA512},

		// RSA PKCS#1 v1.5 schemes (backward compatibility with DTLS 1.2)
		{hash.SHA256, signature.RSA},
		{hash.SHA384, signature.RSA},
		{hash.SHA512, signature.RSA},
	}
}
