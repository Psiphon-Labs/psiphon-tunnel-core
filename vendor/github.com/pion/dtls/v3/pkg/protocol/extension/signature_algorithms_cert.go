// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package extension

import (
	"github.com/pion/dtls/v3/pkg/crypto/signaturehash"
)

// SignatureAlgorithmsCert allows a Client/Server to indicate which signature algorithms
// may be used in digital signatures for X.509 certificates.
// This is separate from signature_algorithms which applies to handshake signatures.
//
// RFC 8446 Section 4.2.3:
// "TLS 1.2 implementations SHOULD also process this extension.
// If present, the signature_algorithms_cert extension SHALL be treated as being
// equivalent to signature_algorithms for the purposes of certificate chain validation."
//
// https://tools.ietf.org/html/rfc8446#section-4.2.3
type SignatureAlgorithmsCert struct {
	SignatureHashAlgorithms []signaturehash.Algorithm
}

// TypeValue returns the extension TypeValue.
func (s SignatureAlgorithmsCert) TypeValue() TypeValue {
	return SignatureAlgorithmsCertTypeValue
}

// Marshal encodes the extension.
// This supports hybrid encoding: TLS 1.3 PSS schemes are encoded as full uint16,
// while TLS 1.2 schemes use hash (high byte) + signature (low byte) encoding.
func (s *SignatureAlgorithmsCert) Marshal() ([]byte, error) {
	return marshalGenericSignatureHashAlgorithm(s.TypeValue(), s.SignatureHashAlgorithms)
}

// Unmarshal populates the extension from encoded data.
// This supports hybrid encoding: detects TLS 1.3 PSS schemes
// and handles them as full uint16, while TLS 1.2 schemes use byte-split encoding.
func (s *SignatureAlgorithmsCert) Unmarshal(data []byte) error {
	s.SignatureHashAlgorithms = []signaturehash.Algorithm{}

	return unmarshalGenericSignatureHashAlgorithm(s.TypeValue(), data, &s.SignatureHashAlgorithms)
}
