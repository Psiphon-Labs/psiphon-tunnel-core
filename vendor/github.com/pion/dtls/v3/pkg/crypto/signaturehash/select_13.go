// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package signaturehash

import (
	"crypto"
)

// selectSignatureScheme13 returns most preferred and compatible scheme.
// It's compatible with all DTLS versions up to and including 1.3.
func selectSignatureScheme13(sigs []Algorithm, privateKey crypto.PrivateKey, is13 bool) (Algorithm, error) {
	signer, ok := privateKey.(crypto.Signer)
	if !ok {
		return Algorithm{}, errInvalidPrivateKey
	}
	for _, ss := range sigs {
		// Skip PSS schemes for DTLS 1.2 (PSS is only supported in DTLS 1.3)
		if !is13 && ss.Signature.IsPSS() {
			continue
		}
		// Skip schemes understood but not supported by pion/dtls.
		if ss.Signature.IsUnsupported() {
			continue
		}
		if ss.isCompatible(signer) {
			return ss, nil
		}
	}

	return Algorithm{}, errNoAvailableSignatureSchemes
}
