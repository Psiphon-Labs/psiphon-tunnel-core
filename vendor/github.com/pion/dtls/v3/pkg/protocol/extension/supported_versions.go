// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package extension

import (
	"github.com/pion/dtls/v3/pkg/protocol"
	"golang.org/x/crypto/cryptobyte"
)

// SupportedVersions is a TLS extension used by the client to indicate
// which versions of TLS it supports and by the server to indicate which
// version it is using.
//
// https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.1
type SupportedVersions struct {
	// ClientHello's preference-ordered list.
	Versions []protocol.Version
}

func (s SupportedVersions) TypeValue() TypeValue { return SupportedVersionsTypeValue }

// Marshal encodes the extension without carrying negotiation state.
func (s *SupportedVersions) Marshal() ([]byte, error) {
	if len(s.Versions) == 0 {
		return nil, errInvalidSupportedVersionsFormat
	}

	totalBytes := len(s.Versions) * 2

	// The 2..254 bound is defined in the following:
	// https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.1
	if totalBytes < 2 || totalBytes > 254 {
		return nil, errInvalidSupportedVersionsFormat
	}

	// We're only checking for *valid* versions, not to be confused with supported versions.
	// Error on invalid versions to protect against malformed messages/DOS attacks.
	for _, v := range s.Versions {
		if !protocol.IsValidVersion(v) {
			return nil, errInvalidDTLSVersion
		}
	}

	var builder cryptobyte.Builder

	builder.AddUint16(uint16(s.TypeValue()))
	builder.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		if len(s.Versions) == 1 {
			// in the case that there's only one version, the do not add the length (uint8).
			b.AddUint8(s.Versions[0].Major)
			b.AddUint8(s.Versions[0].Minor)

			return
		}

		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
			for _, v := range s.Versions {
				b.AddUint8(v.Major)
				b.AddUint8(v.Minor)
			}
		})
	})

	return builder.Bytes()
}

// Unmarshal parses either the ClientHello list or the ServerHello/HelloRetryRequest single value.
// Any version not recognized is discarded.
func (s *SupportedVersions) Unmarshal(data []byte) error { //nolint:cyclop
	val := cryptobyte.String(data)
	var extData cryptobyte.String

	var extension uint16
	val.ReadUint16(&extension)
	if TypeValue(extension) != s.TypeValue() {
		return errInvalidExtensionType
	}

	if !val.ReadUint16LengthPrefixed(&extData) {
		return errBufferTooSmall
	}

	if extData.Empty() {
		return errInvalidSupportedVersionsFormat
	}

	// Try ClientHello list: versions<2..254> (1-byte length, then pairs)
	peek := extData
	var listLen uint8
	if peek.ReadUint8(&listLen) && int(listLen) == len(peek) && listLen >= 2 && (listLen%2) == 0 {
		s.Versions = s.Versions[:0]

		for !peek.Empty() {
			var major, minor uint8
			if !peek.ReadUint8(&major) || !peek.ReadUint8(&minor) {
				return errInvalidSupportedVersionsFormat
			}

			// We're only checking for *valid* versions, not to be confused with supported versions.
			if protocol.IsValidBytes(major, minor) {
				s.Versions = append(s.Versions, protocol.Version{Major: major, Minor: minor})
			}
		}

		if !extData.Skip(1 + int(listLen)) {
			return errInvalidSupportedVersionsFormat
		}

		return nil
	}

	// Otherwise, expect ServerHello/HelloRetryRequest selected_version, which should be exactly 2 bytes.
	if len(extData) != 2 {
		return errInvalidSupportedVersionsFormat
	}

	var major, minor uint8
	if !extData.ReadUint8(&major) || !extData.ReadUint8(&minor) {
		return errInvalidSupportedVersionsFormat
	}

	// We're only checking for *valid* versions, not to be confused with supported versions.
	if protocol.IsValidBytes(major, minor) {
		s.Versions = append(s.Versions[:0], protocol.Version{Major: major, Minor: minor})
	}

	return nil
}
