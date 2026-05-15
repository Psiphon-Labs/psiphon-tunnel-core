// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package extension

import (
	"golang.org/x/crypto/cryptobyte"
)

// PreSharedKey represents the "pre_shared_key" extension for DTLS 1.3.
// This extension is used in both ClientHello and ServerHello messages,
// but only the relevant fields should be populated for each context.
// See RFC 8446 section 4.2.11.
//
// https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.11
type PreSharedKey struct {
	// ClientHello only - offered PSK identities
	Identities []PskIdentity
	// ClientHello only - binder values associated with a PSK identity
	Binders []PskBinderEntry
	// ServerHello only - index of selected identity
	SelectedIdentity uint16
}

// PskIdentity represents the PSK identitiy in the "pre_shared_key" extension
// for DTLS 1.3.
type PskIdentity struct {
	Identity            []byte
	ObfuscatedTicketAge uint32
}

// PskBinderEntry represents the binder related to a PSK identity in the
// "pre_shared_key" extension for DTLS 1.3.
type PskBinderEntry []byte

const minPSKBinderSize = 32

// TypeValue returns the extension TypeValue.
func (p PreSharedKey) TypeValue() TypeValue {
	return PreSharedKeyValue
}

// Marshal encodes the extension.
func (p *PreSharedKey) Marshal() ([]byte, error) {
	var out cryptobyte.Builder
	out.AddUint16(uint16(p.TypeValue()))

	// ServerHello
	if len(p.Identities) == 0 || len(p.Binders) == 0 {
		out.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddUint16(p.SelectedIdentity)
		})

		return out.Bytes()
	}

	// ClientHello
	out.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			for _, pskIdentity := range p.Identities {
				if len(pskIdentity.Identity) == 0 {
					b.SetError(errPreSharedKeyFormat)
				}
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddBytes(pskIdentity.Identity)
				})
				b.AddUint32(pskIdentity.ObfuscatedTicketAge)
			}
		})
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			for _, binder := range p.Binders {
				if len(binder) < minPSKBinderSize {
					b.SetError(errPreSharedKeyFormat)
				}
				b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddBytes(binder)
				})
			}
		})
	})

	return out.Bytes()
}

// Unmarshal populates the extension from encoded data.
func (p *PreSharedKey) Unmarshal(data []byte) error { //nolint:cyclop
	val := cryptobyte.String(data)
	var extension uint16
	if !val.ReadUint16(&extension) || TypeValue(extension) != p.TypeValue() {
		return errInvalidExtensionType
	}

	var extData cryptobyte.String
	if !val.ReadUint16LengthPrefixed(&extData) {
		return errBufferTooSmall
	}

	// ServerHello
	if len(extData) == 2 {
		var selected uint16
		if !extData.ReadUint16(&selected) {
			return errPreSharedKeyFormat
		}
		p.SelectedIdentity = selected

		return nil
	}

	// ClientHello
	var identities cryptobyte.String
	if !extData.ReadUint16LengthPrefixed(&identities) || identities.Empty() {
		return errPreSharedKeyFormat
	}

	for !identities.Empty() {
		var identity cryptobyte.String
		var ticket uint32
		if !identities.ReadUint16LengthPrefixed(&identity) || !identities.ReadUint32(&ticket) || identity.Empty() {
			return errPreSharedKeyFormat
		}
		p.Identities = append(p.Identities, PskIdentity{identity, ticket})
	}

	var binders cryptobyte.String
	if !extData.ReadUint16LengthPrefixed(&binders) || binders.Empty() {
		return errPreSharedKeyFormat
	}

	for !binders.Empty() {
		var binder cryptobyte.String
		if !binders.ReadUint8LengthPrefixed(&binder) || len(binder) < minPSKBinderSize {
			return errPreSharedKeyFormat
		}
		p.Binders = append(p.Binders, PskBinderEntry(binder))
	}

	// Ensure there is one binder value per identity in list,
	// and check for trailing bytes.
	if len(p.Binders) != len(p.Identities) || !extData.Empty() {
		return errPreSharedKeyFormat
	}

	return nil
}
