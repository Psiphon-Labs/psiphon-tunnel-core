// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package handshake

import (
	"github.com/pion/dtls/v3/internal/util"
)

// MessageCertificate is a DTLS Handshake Message
// it can contain either a Client or Server Certificate
//
// https://tools.ietf.org/html/rfc5246#section-7.4.2
type MessageCertificate struct {
	Certificate [][]byte
}

// Type returns the Handshake Type.
func (m MessageCertificate) Type() Type {
	return TypeCertificate
}

const (
	handshakeMessageCertificateLengthFieldSize = 3
)

// Marshal encodes the Handshake.
func (m *MessageCertificate) Marshal() ([]byte, error) {
	total := handshakeMessageCertificateLengthFieldSize

	for _, cert := range m.Certificate {
		total += handshakeMessageCertificateLengthFieldSize + len(cert)
	}

	out := make([]byte, total)

	// Total Payload Size
	//nolint:gosec // G115
	util.PutBigEndianUint24(out, uint32(total-handshakeMessageCertificateLengthFieldSize))
	offset := handshakeMessageCertificateLengthFieldSize

	for _, cert := range m.Certificate {
		// Certificate Length
		//nolint:gosec // G115
		util.PutBigEndianUint24(out[offset:], uint32(len(cert)))
		offset += handshakeMessageCertificateLengthFieldSize

		// Certificate body
		copy(out[offset:], cert)
		offset += len(cert)
	}

	return out, nil
}

// Unmarshal populates the message from encoded data.
func (m *MessageCertificate) Unmarshal(data []byte) error {
	if len(data) < handshakeMessageCertificateLengthFieldSize {
		return errBufferTooSmall
	}

	if certificateBodyLen := int(util.BigEndianUint24(
		data,
	)); certificateBodyLen+handshakeMessageCertificateLengthFieldSize != len(data) {
		return errLengthMismatch
	}

	offset := handshakeMessageCertificateLengthFieldSize
	for offset < len(data) {
		certificateLen := int(util.BigEndianUint24(data[offset:]))
		offset += handshakeMessageCertificateLengthFieldSize

		if offset+certificateLen > len(data) {
			return errLengthMismatch
		}

		m.Certificate = append(m.Certificate, append([]byte{}, data[offset:offset+certificateLen]...))
		offset += certificateLen
	}

	return nil
}
