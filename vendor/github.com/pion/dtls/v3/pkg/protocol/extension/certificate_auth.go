// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package extension

import (
	"golang.org/x/crypto/cryptobyte"
)

// CertificateAuthorities implements the certificate_authorities extension in DTLS 1.3.
//
// See RFC 8446 section 4.2.4. Certificate Authorities.
//
// https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.4
type CertificateAuthorities struct {
	Authorities [][]byte
}

// TypeValue returns the extension TypeValue.
func (c CertificateAuthorities) TypeValue() TypeValue {
	return CertificateAuthoritiesTypeValue
}

// Marshal encodes the extension.
func (c *CertificateAuthorities) Marshal() ([]byte, error) {
	if len(c.Authorities) < 1 {
		return []byte{}, errInvalidCertificateAuthFormat
	}
	var out cryptobyte.Builder
	out.AddUint16(uint16(c.TypeValue()))
	out.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			for _, ca := range c.Authorities {
				if len(ca) < 1 {
					b.SetError(errInvalidCertificateAuthFormat)

					return
				}
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddBytes(ca)
				})
			}
		})
	})

	return out.Bytes()
}

// Unmarshal populates the extension from encoded data.
func (c *CertificateAuthorities) Unmarshal(data []byte) error { //nolint:cyclop
	val := cryptobyte.String(data)
	var extension uint16
	if !val.ReadUint16(&extension) || TypeValue(extension) != c.TypeValue() {
		return errInvalidExtensionType
	}

	var extData cryptobyte.String
	if !val.ReadUint16LengthPrefixed(&extData) {
		return errBufferTooSmall
	}

	var auths cryptobyte.String
	if extData.Empty() || !extData.ReadUint16LengthPrefixed(&auths) || auths.Empty() {
		return errInvalidCertificateAuthFormat
	}

	if !extData.Empty() {
		return errLengthMismatch
	}

	var cauths [][]byte
	for !auths.Empty() {
		var ca cryptobyte.String
		if !auths.ReadUint16LengthPrefixed(&ca) || len(ca) < 1 {
			return errInvalidCertificateAuthFormat
		}
		cauths = append(cauths, ca)
	}

	c.Authorities = make([][]byte, len(cauths))
	copy(c.Authorities, cauths)

	return nil
}
