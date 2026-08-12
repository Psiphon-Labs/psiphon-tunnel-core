// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package handshake

import (
	"encoding/binary"

	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
)

/*
MessageClientHello is for when a client first connects to a server it is
required to send the client hello as its first message.  The client can also send a
client hello in response to a hello request or on its own
initiative in order to renegotiate the security parameters in an
existing connection.
*/
type MessageClientHello struct {
	Version protocol.Version
	Random  Random
	Cookie  []byte

	SessionID []byte

	CipherSuiteIDs     []uint16
	CompressionMethods []*protocol.CompressionMethod
	Extensions         []extension.Extension
}

const handshakeMessageClientHelloVariableWidthStart = 34

// Type returns the Handshake Type.
func (m MessageClientHello) Type() Type {
	return TypeClientHello
}

// Marshal encodes the Handshake.
func (m *MessageClientHello) Marshal() ([]byte, error) {
	if len(m.Cookie) > 255 {
		return nil, errCookieTooLong
	}
	if len(m.SessionID) > 255 {
		return nil, errSessionIDTooLong
	}
	if len(m.CompressionMethods) > 255 {
		return nil, errCompressionMethodsTooLong
	}

	extensions, err := extension.Marshal(m.Extensions)
	if err != nil {
		return nil, err
	}

	encodedCipherSuiteIDs := encodeCipherSuiteIDs(m.CipherSuiteIDs)
	encodedCompressionMethods := protocol.EncodeCompressionMethods(m.CompressionMethods)

	out := make(
		[]byte,
		0,
		handshakeMessageClientHelloVariableWidthStart+1+len(m.SessionID)+1+
			len(m.Cookie)+len(encodedCipherSuiteIDs)+len(encodedCompressionMethods)+len(extensions),
	)
	out = append(out, m.Version.Major, m.Version.Minor)

	rand := m.Random.MarshalFixed()
	out = append(out, rand[:]...)

	out = append(out, byte(len(m.SessionID))) //nolint:gosec // G115: session ID length is validated to be <= 255 above.
	out = append(out, m.SessionID...)

	out = append(out, byte(len(m.Cookie))) //nolint:gosec // G115: cookie length is validated to be <= 255 above.
	out = append(out, m.Cookie...)
	out = append(out, encodedCipherSuiteIDs...)
	out = append(out, encodedCompressionMethods...)

	return append(out, extensions...), nil
}

// Unmarshal populates the message from encoded data.
func (m *MessageClientHello) Unmarshal(data []byte) error { //nolint:cyclop
	if len(data) < 2+RandomLength {
		return errBufferTooSmall
	}

	m.Version.Major = data[0]
	m.Version.Minor = data[1]

	var random [RandomLength]byte
	copy(random[:], data[2:])
	m.Random.UnmarshalFixed(random)

	// rest of packet has variable width sections
	currOffset := handshakeMessageClientHelloVariableWidthStart

	currOffset++
	if len(data) <= currOffset {
		return errBufferTooSmall
	}
	n := int(data[currOffset-1])
	if len(data) <= currOffset+n {
		return errBufferTooSmall
	}
	m.SessionID = append([]byte{}, data[currOffset:currOffset+n]...)
	currOffset += len(m.SessionID)

	currOffset++
	if len(data) <= currOffset {
		return errBufferTooSmall
	}
	n = int(data[currOffset-1])
	if len(data) <= currOffset+n {
		return errBufferTooSmall
	}
	m.Cookie = append([]byte{}, data[currOffset:currOffset+n]...)
	currOffset += len(m.Cookie)

	// Cipher Suites
	if len(data) < currOffset {
		return errBufferTooSmall
	}
	cipherSuiteIDs, err := decodeCipherSuiteIDs(data[currOffset:])
	if err != nil {
		return err
	}
	m.CipherSuiteIDs = cipherSuiteIDs
	if len(data) < currOffset+2 {
		return errBufferTooSmall
	}
	currOffset += int(binary.BigEndian.Uint16(data[currOffset:])) + 2

	// Compression Methods
	if len(data) < currOffset {
		return errBufferTooSmall
	}
	compressionMethods, err := protocol.DecodeCompressionMethods(data[currOffset:])
	if err != nil {
		return err
	}
	m.CompressionMethods = compressionMethods
	if len(data) < currOffset {
		return errBufferTooSmall
	}
	currOffset += int(data[currOffset]) + 1

	// Extensions
	extensions, err := extension.Unmarshal(data[currOffset:])
	if err != nil {
		return err
	}
	m.Extensions = extensions

	return nil
}
