// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package extension

import (
	"github.com/pion/dtls/v3/pkg/crypto/signaturehash"
)

// SupportedSignatureAlgorithms allows a Client/Server to
// negotiate what SignatureHash Algorithms they both support
//
// https://tools.ietf.org/html/rfc5246#section-7.4.1.4.1
type SupportedSignatureAlgorithms struct {
	SignatureHashAlgorithms []signaturehash.Algorithm
}

// TypeValue returns the extension TypeValue.
func (s SupportedSignatureAlgorithms) TypeValue() TypeValue {
	return SupportedSignatureAlgorithmsTypeValue
}

// Marshal encodes the extension.
// This supports hybrid encoding: TLS 1.3 PSS schemes are encoded as full uint16,
// while TLS 1.2 schemes use hash (high byte) + signature (low byte) encoding.
func (s *SupportedSignatureAlgorithms) Marshal() ([]byte, error) {
	return marshalGenericSignatureHashAlgorithm(s.TypeValue(), s.SignatureHashAlgorithms)
}

// Unmarshal populates the extension from encoded data.
// This supports hybrid encoding: detects TLS 1.3 PSS schemes
// and handles them as full uint16, while TLS 1.2 schemes use byte-split encoding.
func (s *SupportedSignatureAlgorithms) Unmarshal(data []byte) error {
	s.SignatureHashAlgorithms = []signaturehash.Algorithm{}

	return unmarshalGenericSignatureHashAlgorithm(s.TypeValue(), data, &s.SignatureHashAlgorithms)
}
