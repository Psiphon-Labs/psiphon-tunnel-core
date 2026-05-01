// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package ice

import (
	"encoding/binary"

	"github.com/pion/stun/v3"
)

// DtlsInStunAttribute is a STUN attribute for carrying DTLS embedded in STUN.
type DtlsInStunAttribute []byte

// AddTo adds DTLS-in-STUN attribute to message.
func (d DtlsInStunAttribute) AddTo(m *stun.Message) error {
	m.Add(stun.AttrDtlsInStun, d)

	return nil
}

// GetFrom decodes DTLS-in-STUN attribute from message.
func (d *DtlsInStunAttribute) GetFrom(m *stun.Message) error {
	v, err := m.Get(stun.AttrDtlsInStun)
	if err != nil {
		return err
	}

	*d = v

	return nil
}

// DtlsInStunAckAttribute is a STUN attribute for acknowledging the receipt
// of DTLS packets (embedded in STUN or without embedding).
type DtlsInStunAckAttribute []uint32

// Acks are 32 bit values, the attribute can carry up to four of these.
const ackSizeBytes, ackSizeValues = 32, 4

// AddTo adds DTLS-in-STUN-ACK attribute to message.
func (a DtlsInStunAckAttribute) AddTo(m *stun.Message) error {
	if len(a) > ackSizeValues {
		return stun.ErrAttributeSizeInvalid
	}
	v := make([]byte, len(a)*4)
	for i, ack := range a {
		binary.BigEndian.PutUint32(v[i*4:], ack)
	}
	m.Add(stun.AttrDtlsInStunAck, v)

	return nil
}

// GetFrom decodes DTLS-in-STUN-ACK attribute from message.
func (a *DtlsInStunAckAttribute) GetFrom(m *stun.Message) error {
	v, err := m.Get(stun.AttrDtlsInStunAck)
	if err != nil {
		return err
	}
	if len(v) > ackSizeBytes || len(v)%4 != 0 {
		return stun.ErrAttributeSizeInvalid
	}
	u := make([]uint32, len(v)/4)
	for i := range u {
		u[i] = binary.BigEndian.Uint32(v[i*4 : (i+1)*4])
	}
	*a = DtlsInStunAckAttribute(u)

	return nil
}
