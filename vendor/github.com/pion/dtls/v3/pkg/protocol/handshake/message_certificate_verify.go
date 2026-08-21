// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package handshake

import (
	"crypto/tls"
	"encoding/binary"

	"github.com/pion/dtls/v3/pkg/crypto/hash"
	"github.com/pion/dtls/v3/pkg/crypto/signature"
	"github.com/pion/dtls/v3/pkg/crypto/signaturehash"
)

// MessageCertificateVerify provide explicit verification of a
// client certificate.
//
// https://tools.ietf.org/html/rfc5246#section-7.4.8
type MessageCertificateVerify struct {
	HashAlgorithm      hash.Algorithm
	SignatureAlgorithm signature.Algorithm
	Signature          []byte
}

const handshakeMessageCertificateVerifyMinLength = 4

// Type returns the Handshake Type.
func (m MessageCertificateVerify) Type() Type {
	return TypeCertificateVerify
}

// Marshal encodes the Handshake.
func (m *MessageCertificateVerify) Marshal() ([]byte, error) {
	if m.HashAlgorithm > 0xFF || m.SignatureAlgorithm > 0xFF {
		return nil, errInvalidSignHashAlgorithm
	}

	// CertificateVerify in DTLS 1.2 encodes hash/signature as 1 byte each.
	scheme := tls.SignatureScheme(uint16(m.HashAlgorithm)<<8 | uint16(m.SignatureAlgorithm))
	var alg signaturehash.Algorithm
	if err := alg.Unmarshal(scheme); err != nil {
		return nil, errInvalidSignHashAlgorithm
	}

	out := make([]byte, 1+1+2+len(m.Signature))

	out[0] = byte(m.HashAlgorithm)
	out[1] = byte(m.SignatureAlgorithm)
	binary.BigEndian.PutUint16(out[2:], uint16(len(m.Signature))) //nolint:gosec // G115
	copy(out[4:], m.Signature)

	return out, nil
}

// Unmarshal populates the message from encoded data.
func (m *MessageCertificateVerify) Unmarshal(data []byte) error {
	if len(data) < handshakeMessageCertificateVerifyMinLength {
		return errBufferTooSmall
	}

	scheme := binary.BigEndian.Uint16(data[0:2])

	var alg signaturehash.Algorithm
	err := alg.Unmarshal(tls.SignatureScheme(scheme))
	if err != nil {
		return errInvalidSignHashAlgorithm
	}

	m.HashAlgorithm = alg.Hash
	m.SignatureAlgorithm = alg.Signature

	signatureLength := int(binary.BigEndian.Uint16(data[2:]))
	if (signatureLength + 4) != len(data) {
		return errBufferTooSmall
	}

	m.Signature = append([]byte{}, data[4:]...)

	return nil
}
