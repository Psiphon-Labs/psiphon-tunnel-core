// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package extension implements the extension values in the ClientHello/ServerHello
package extension

import (
	"github.com/pion/dtls/v3/pkg/crypto/hash"
	"github.com/pion/dtls/v3/pkg/crypto/signature"
	"github.com/pion/dtls/v3/pkg/crypto/signaturehash"
	"golang.org/x/crypto/cryptobyte"
)

// marshalGenericSignatureHashAlgorithm encodes the extension.
// This supports hybrid encoding: TLS 1.3 PSS schemes are encoded as full uint16,
// while TLS 1.2 schemes use hash (high byte) + signature (low byte) encoding.
func marshalGenericSignatureHashAlgorithm(typeValue TypeValue, sigHashAlgs []signaturehash.Algorithm) ([]byte, error) {
	var builder cryptobyte.Builder
	builder.AddUint16(uint16(typeValue))
	builder.AddUint16LengthPrefixed(func(extBuilder *cryptobyte.Builder) {
		extBuilder.AddUint16LengthPrefixed(func(algBuilder *cryptobyte.Builder) {
			for _, v := range sigHashAlgs {
				// For PSS schemes, write the full uint16 SignatureScheme value
				// For other schemes, write hash (high byte) + signature (low byte) in TLS 1.2 style
				if v.Signature.IsPSS() {
					// TLS 1.3 PSS: full uint16 is the signature scheme
					algBuilder.AddUint16(uint16(v.Signature))
				} else {
					// TLS 1.2 style: hash byte + signature byte
					algBuilder.AddUint8(byte(v.Hash))
					algBuilder.AddUint8(byte(v.Signature))
				}
			}
		})
	})

	return builder.Bytes()
}

// unmarshalGenericSignatureAlgorithm populates the extension from encoded data.
// This supports hybrid encoding: detects TLS 1.3 PSS schemes
// and handles them as full uint16, while TLS 1.2 schemes use byte-split encoding.
func unmarshalGenericSignatureHashAlgorithm(typeValue TypeValue, data []byte, dst *[]signaturehash.Algorithm) error {
	val := cryptobyte.String(data)
	var extension uint16
	if !val.ReadUint16(&extension) || TypeValue(extension) != typeValue {
		return errInvalidExtensionType
	}

	var extData cryptobyte.String
	if !val.ReadUint16LengthPrefixed(&extData) {
		return errBufferTooSmall
	}

	var algData cryptobyte.String
	if !extData.ReadUint16LengthPrefixed(&algData) {
		return errLengthMismatch
	}

	for !algData.Empty() {
		var scheme uint16
		if !algData.ReadUint16(&scheme) {
			return errLengthMismatch
		}

		// Parse the signature scheme (handles both TLS 1.2 and TLS 1.3 PSS encoding)
		supportedHashAlgorithm, supportedSignatureAlgorithm := parseSignatureScheme(scheme)

		// Validate both hash and signature algorithms
		if _, ok := hash.Algorithms()[supportedHashAlgorithm]; ok {
			if _, ok := signature.Algorithms()[supportedSignatureAlgorithm]; ok {
				*dst = append(*dst, signaturehash.Algorithm{
					Hash:      supportedHashAlgorithm,
					Signature: supportedSignatureAlgorithm,
				})
			}
		}
	}

	return nil
}
