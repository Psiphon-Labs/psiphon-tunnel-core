// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package ice

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTCPType(t *testing.T) {
	var tcpType TCPType

	assert.Equal(t, TCPTypeUnspecified, tcpType)
	assert.Equal(t, TCPTypeActive, NewTCPType("active"))
	assert.Equal(t, TCPTypePassive, NewTCPType("passive"))
	assert.Equal(t, TCPTypeSimultaneousOpen, NewTCPType("so"))
	assert.Equal(t, TCPTypeUnspecified, NewTCPType("something else"))

	assert.Equal(t, "", TCPTypeUnspecified.String())
	assert.Equal(t, "active", TCPTypeActive.String())
	assert.Equal(t, "passive", TCPTypePassive.String())
	assert.Equal(t, "so", TCPTypeSimultaneousOpen.String())
	assert.Equal(t, "Unknown", TCPType(-1).String())
}
