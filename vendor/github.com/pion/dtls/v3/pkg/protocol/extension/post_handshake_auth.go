// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package extension //nolint:dupl

import "encoding/binary"

const (
	postHandshakeAuthHeaderSize = 4
)

// PostHandshakeAuth defines a DTLS 1.3 extension that is used to indicate
// that a client is willing to perform post-handshake authentication.
//
// https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.6
type PostHandshakeAuth struct {
	Enabled bool
}

// TypeValue returns the extension TypeValue.
func (p PostHandshakeAuth) TypeValue() TypeValue {
	return PostHandshakeAuthTypeValue
}

// Marshal encodes the extension.
func (p *PostHandshakeAuth) Marshal() ([]byte, error) {
	if !p.Enabled {
		return []byte{}, nil
	}

	out := make([]byte, postHandshakeAuthHeaderSize)

	binary.BigEndian.PutUint16(out, uint16(p.TypeValue()))
	binary.BigEndian.PutUint16(out[2:], uint16(0))

	return out, nil
}

// Unmarshal populates the extension from encoded data.
func (p *PostHandshakeAuth) Unmarshal(data []byte) error {
	switch {
	case len(data) < postHandshakeAuthHeaderSize:
		return errBufferTooSmall
	case data[2] != 0x00 || data[3] != 0x00:
		return errLengthMismatch
	case TypeValue(binary.BigEndian.Uint16(data)) != p.TypeValue():
		return errInvalidExtensionType
	}

	p.Enabled = true

	return nil
}
