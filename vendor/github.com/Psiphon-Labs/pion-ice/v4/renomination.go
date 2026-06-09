// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package ice

import (
	"fmt"

	"github.com/pion/stun/v3"
)

// Default STUN Nomination attribute type for ICE renomination.
// Following the specification draft-thatcher-ice-renomination-01.
const (
	// DefaultNominationAttribute represents the default STUN Nomination attribute.
	// This is a custom attribute for ICE renomination support.
	// This value can be overridden via AgentConfig.NominationAttribute.
	DefaultNominationAttribute stun.AttrType = 0x0030 // Using a value in the reserved range
)

// NominationAttribute represents a STUN Nomination attribute.
type NominationAttribute struct {
	Value uint32
}

// GetFrom decodes a Nomination attribute from a STUN message.
func (a *NominationAttribute) GetFrom(m *stun.Message) error {
	return a.GetFromWithType(m, DefaultNominationAttribute)
}

// GetFromWithType decodes a Nomination attribute from a STUN message using a specific attribute type.
func (a *NominationAttribute) GetFromWithType(m *stun.Message, attrType stun.AttrType) error {
	v, err := m.Get(attrType)
	if err != nil {
		return err
	}
	if len(v) < 4 {
		return stun.ErrAttributeSizeInvalid
	}

	// Extract 24-bit value from the last 3 bytes
	a.Value = uint32(v[1])<<16 | uint32(v[2])<<8 | uint32(v[3])

	return nil
}

// AddTo adds a Nomination attribute to a STUN message.
func (a NominationAttribute) AddTo(m *stun.Message) error {
	return a.AddToWithType(m, DefaultNominationAttribute)
}

// AddToWithType adds a Nomination attribute to a STUN message using a specific attribute type.
func (a NominationAttribute) AddToWithType(m *stun.Message, attrType stun.AttrType) error {
	// Store as 4 bytes with first byte as 0
	v := make([]byte, 4)
	v[1] = byte(a.Value >> 16) //nolint:gosec
	v[2] = byte(a.Value >> 8)  //nolint:gosec
	v[3] = byte(a.Value)       //nolint:gosec

	m.Add(attrType, v)

	return nil
}

// String returns string representation of the nomination attribute.
func (a NominationAttribute) String() string {
	return fmt.Sprintf("NOMINATION: %d", a.Value)
}

// Nomination creates a new STUN nomination attribute.
func Nomination(value uint32) NominationAttribute {
	return NominationAttribute{Value: value}
}

// NominationSetter is a STUN setter for nomination attribute with configurable type.
type NominationSetter struct {
	Value    uint32
	AttrType stun.AttrType
}

// AddTo adds a Nomination attribute to a STUN message using the configured attribute type.
func (n NominationSetter) AddTo(m *stun.Message) error {
	attr := NominationAttribute{Value: n.Value}

	return attr.AddToWithType(m, n.AttrType)
}
