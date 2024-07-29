// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package ice

import (
	"errors"
	"testing"

	"github.com/pion/stun"
)

func TestControlled_GetFrom(t *testing.T) { //nolint:dupl
	m := new(stun.Message)
	var c AttrControlled
	if err := c.GetFrom(m); !errors.Is(err, stun.ErrAttributeNotFound) {
		t.Error("unexpected error")
	}
	if err := m.Build(stun.BindingRequest, &c); err != nil {
		t.Error(err)
	}
	m1 := new(stun.Message)
	if _, err := m1.Write(m.Raw); err != nil {
		t.Error(err)
	}
	var c1 AttrControlled
	if err := c1.GetFrom(m1); err != nil {
		t.Error(err)
	}
	if c1 != c {
		t.Error("not equal")
	}
	t.Run("IncorrectSize", func(t *testing.T) {
		m3 := new(stun.Message)
		m3.Add(stun.AttrICEControlled, make([]byte, 100))
		var c2 AttrControlled
		if err := c2.GetFrom(m3); !stun.IsAttrSizeInvalid(err) {
			t.Error("should error")
		}
	})
}

func TestControlling_GetFrom(t *testing.T) { //nolint:dupl
	m := new(stun.Message)
	var c AttrControlling
	if err := c.GetFrom(m); !errors.Is(err, stun.ErrAttributeNotFound) {
		t.Error("unexpected error")
	}
	if err := m.Build(stun.BindingRequest, &c); err != nil {
		t.Error(err)
	}
	m1 := new(stun.Message)
	if _, err := m1.Write(m.Raw); err != nil {
		t.Error(err)
	}
	var c1 AttrControlling
	if err := c1.GetFrom(m1); err != nil {
		t.Error(err)
	}
	if c1 != c {
		t.Error("not equal")
	}
	t.Run("IncorrectSize", func(t *testing.T) {
		m3 := new(stun.Message)
		m3.Add(stun.AttrICEControlling, make([]byte, 100))
		var c2 AttrControlling
		if err := c2.GetFrom(m3); !stun.IsAttrSizeInvalid(err) {
			t.Error("should error")
		}
	})
}

func TestControl_GetFrom(t *testing.T) {
	t.Run("Blank", func(t *testing.T) {
		m := new(stun.Message)
		var c AttrControl
		if err := c.GetFrom(m); !errors.Is(err, stun.ErrAttributeNotFound) {
			t.Error("unexpected error")
		}
	})
	t.Run("Controlling", func(t *testing.T) { //nolint:dupl
		m := new(stun.Message)
		var c AttrControl
		if err := c.GetFrom(m); !errors.Is(err, stun.ErrAttributeNotFound) {
			t.Error("unexpected error")
		}
		c.Role = Controlling
		c.Tiebreaker = 4321
		if err := m.Build(stun.BindingRequest, &c); err != nil {
			t.Error(err)
		}
		m1 := new(stun.Message)
		if _, err := m1.Write(m.Raw); err != nil {
			t.Error(err)
		}
		var c1 AttrControl
		if err := c1.GetFrom(m1); err != nil {
			t.Error(err)
		}
		if c1 != c {
			t.Error("not equal")
		}
		t.Run("IncorrectSize", func(t *testing.T) {
			m3 := new(stun.Message)
			m3.Add(stun.AttrICEControlling, make([]byte, 100))
			var c2 AttrControl
			if err := c2.GetFrom(m3); !stun.IsAttrSizeInvalid(err) {
				t.Error("should error")
			}
		})
	})
	t.Run("Controlled", func(t *testing.T) { //nolint:dupl
		m := new(stun.Message)
		var c AttrControl
		if err := c.GetFrom(m); !errors.Is(err, stun.ErrAttributeNotFound) {
			t.Error("unexpected error")
		}
		c.Role = Controlled
		c.Tiebreaker = 1234
		if err := m.Build(stun.BindingRequest, &c); err != nil {
			t.Error(err)
		}
		m1 := new(stun.Message)
		if _, err := m1.Write(m.Raw); err != nil {
			t.Error(err)
		}
		var c1 AttrControl
		if err := c1.GetFrom(m1); err != nil {
			t.Error(err)
		}
		if c1 != c {
			t.Error("not equal")
		}
		t.Run("IncorrectSize", func(t *testing.T) {
			m3 := new(stun.Message)
			m3.Add(stun.AttrICEControlling, make([]byte, 100))
			var c2 AttrControl
			if err := c2.GetFrom(m3); !stun.IsAttrSizeInvalid(err) {
				t.Error("should error")
			}
		})
	})
}
