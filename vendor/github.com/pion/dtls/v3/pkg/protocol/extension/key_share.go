// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package extension

import (
	"github.com/pion/dtls/v3/pkg/crypto/elliptic"
	"golang.org/x/crypto/cryptobyte"
)

type KeyShareEntry struct {
	Group       elliptic.Curve
	KeyExchange []byte
}

// KeyShare represents the "key_share" extension. Only one of the fields can be used at a time.
// See RFC 8446 section 4.2.8.
type KeyShare struct {
	ClientShares  []KeyShareEntry // ClientHello
	ServerShare   *KeyShareEntry  // ServerHello
	SelectedGroup *elliptic.Curve // HelloRetryRequest
}

func (k KeyShare) TypeValue() TypeValue { return KeyShareTypeValue }

// Marshal encodes the extension.
func (k *KeyShare) Marshal() ([]byte, error) { //nolint:cyclop
	hasClientShares := k.ClientShares != nil // vector MAY be empty
	hasServerShare := k.ServerShare != nil
	hasHelloRetryRequest := k.SelectedGroup != nil

	// there must be exactly one context.
	if hasTooManyContexts(hasClientShares, hasServerShare, hasHelloRetryRequest) {
		return nil, errInvalidKeyShareFormat
	}

	var builder cryptobyte.Builder

	builder.AddUint16(uint16(k.TypeValue()))

	if hasClientShares {
		seenGroups := map[elliptic.Curve]struct{}{}
		for _, e := range k.ClientShares {
			if _, ok := seenGroups[e.Group]; ok {
				return nil, errDuplicateKeyShare
			}

			seenGroups[e.Group] = struct{}{}

			if l := len(e.KeyExchange); l == 0 || l > 0xffff {
				return nil, errInvalidKeyShareFormat
			}
		}
	}

	if hasServerShare {
		if l := len(k.ServerShare.KeyExchange); l == 0 || l > 0xffff {
			return nil, errInvalidKeyShareFormat
		}
	}

	builder.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		switch {
		case hasHelloRetryRequest:
			// KeyShareHelloRetryRequest { NamedGroup selected_group; }
			b.AddUint16(uint16(*k.SelectedGroup))

		case hasServerShare:
			// KeyShareServerHello { KeyShareEntry server_share; }
			addKeyShareEntry(b, *k.ServerShare)

		default:
			// KeyShareClientHello { KeyShareEntry client_shares<0..2^16-1>; }
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				for _, e := range k.ClientShares {
					addKeyShareEntry(b, e)
				}
			})
		}
	})

	return builder.Bytes()
}

// Unmarshal decodes the extension.
func (k *KeyShare) Unmarshal(data []byte) error { //nolint:cyclop
	val := cryptobyte.String(data)
	var extData cryptobyte.String

	var ext uint16
	if !val.ReadUint16(&ext) || TypeValue(ext) != k.TypeValue() {
		return errInvalidExtensionType
	}
	if !val.ReadUint16LengthPrefixed(&extData) {
		return errBufferTooSmall
	}
	if extData.Empty() {
		return errInvalidKeyShareFormat
	}

	k.ClientShares, k.ServerShare, k.SelectedGroup = nil, nil, nil

	peek := extData
	var vecLen uint16
	// ClientHello: client_shares is a uint16-length-prefixed vector.
	if peek.ReadUint16(&vecLen) && int(vecLen) == len(peek) { //nolint:nestif
		seenGroups := map[elliptic.Curve]struct{}{}
		for !peek.Empty() {
			var entry KeyShareEntry
			var groupU16 uint16
			var raw cryptobyte.String

			if !peek.ReadUint16(&groupU16) || !peek.ReadUint16LengthPrefixed(&raw) || len(raw) == 0 {
				return errInvalidKeyShareFormat
			}

			group := elliptic.Curve(groupU16)

			if _, ok := seenGroups[group]; ok {
				return errDuplicateKeyShare
			}

			seenGroups[group] = struct{}{}

			entry.Group = group
			entry.KeyExchange = append([]byte(nil), raw...)
			k.ClientShares = append(k.ClientShares, entry)
		}

		// consume vector (2 bytes length + vecLen)
		if !extData.Skip(2 + int(vecLen)) {
			return errInvalidKeyShareFormat
		}

		return nil
	}

	// HelloRetryRequest: exactly 2 bytes = selected_group
	if len(extData) == 2 {
		var groupU16 uint16
		if !extData.ReadUint16(&groupU16) {
			return errInvalidKeyShareFormat
		}

		group := elliptic.Curve(groupU16)
		if elliptic.Curves()[group] {
			k.SelectedGroup = &group
		}

		return nil
	}

	// ServerHello: exactly one KeyShareEntry and no trailing bytes
	var groupU16 uint16
	var raw cryptobyte.String

	if !extData.ReadUint16(&groupU16) || !extData.ReadUint16LengthPrefixed(&raw) || !extData.Empty() || len(raw) == 0 {
		return errInvalidKeyShareFormat
	}

	group := elliptic.Curve(groupU16)
	share := KeyShareEntry{Group: group, KeyExchange: append([]byte(nil), raw...)}
	k.ServerShare = &share

	return nil
}

func addKeyShareEntry(b *cryptobyte.Builder, e KeyShareEntry) {
	b.AddUint16(uint16(e.Group))

	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(e.KeyExchange)
	})
}

// hasTooManyContexts is used in Marshal(). It returns whether the KeyShare struct has more than exactly one context.
func hasTooManyContexts(a bool, b bool, c bool) bool {
	return (a && b) || (a && c) || (b && c)
}
