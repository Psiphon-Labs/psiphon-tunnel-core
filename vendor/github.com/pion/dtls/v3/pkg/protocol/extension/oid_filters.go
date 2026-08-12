// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package extension

import "golang.org/x/crypto/cryptobyte"

// OIDFilters defines a DTLS 1.3 extension that is used to allow server to
// provide a set of OID/value pairs which it would like the client's
// certificate to match.
//
// https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.5
type OIDFilters struct {
	Filters []OIDFilter
}

type OIDFilter struct {
	OID    []byte
	Values []byte
}

// TypeValue returns the extension TypeValue.
func (o OIDFilters) TypeValue() TypeValue {
	return OIDFiltersTypeValue
}

// Marshal encodes the extension.
func (o *OIDFilters) Marshal() ([]byte, error) {
	var out cryptobyte.Builder
	out.AddUint16(uint16(o.TypeValue()))

	out.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint16LengthPrefixed(func(builder *cryptobyte.Builder) {
			seen := map[string]struct{}{}
			for _, filter := range o.Filters {
				if len(filter.OID) < 1 {
					builder.SetError(errEmptyOIDFilter)
				}
				if _, ok := seen[string(filter.OID)]; ok {
					builder.SetError(errDuplicateOID)
				}
				seen[string(filter.OID)] = struct{}{}
				builder.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddBytes(filter.OID)
				})
				builder.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					if filter.Values != nil {
						b.AddBytes(filter.Values)
					}
				})
			}
		})
	})

	return out.Bytes()
}

// Unmarshal populates the extension from encoded data.
func (o *OIDFilters) Unmarshal(data []byte) error { //nolint:cyclop
	val := cryptobyte.String(data)

	var extension uint16
	if !val.ReadUint16(&extension) || TypeValue(extension) != o.TypeValue() {
		return errInvalidExtensionType
	}

	var extData cryptobyte.String
	if !val.ReadUint16LengthPrefixed(&extData) {
		return errBufferTooSmall
	}

	var filterList cryptobyte.String
	if !extData.ReadUint16LengthPrefixed(&filterList) || !extData.Empty() {
		return errLengthMismatch
	}

	o.Filters = make([]OIDFilter, 0)

	seen := map[string]struct{}{}

	for !filterList.Empty() {
		var filter OIDFilter

		var oid cryptobyte.String
		if !filterList.ReadUint8LengthPrefixed(&oid) || oid.Empty() {
			return errOIDFiltersFormat
		}
		if _, ok := seen[string(oid)]; ok {
			return errDuplicateOID
		}
		seen[string(oid)] = struct{}{}

		filter.OID = make([]byte, len(oid))
		copy(filter.OID, oid)

		var values cryptobyte.String
		if !filterList.ReadUint16LengthPrefixed(&values) {
			return errOIDFiltersFormat
		}
		filter.Values = make([]byte, len(values))
		copy(filter.Values, values)

		o.Filters = append(o.Filters, filter)
	}

	return nil
}
