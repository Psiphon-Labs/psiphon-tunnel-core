// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !js
// +build !js

package ice

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNoBestAvailableCandidatePairAfterAgentConstruction(t *testing.T) {
	agent := setupTest(t)

	require.Nil(t, agent.getBestAvailableCandidatePair())

	tearDownTest(t, agent)
}

func setupTest(t *testing.T) *Agent {
	agent, err := NewAgent(&AgentConfig{})
	require.NoError(t, err)
	return agent
}

func tearDownTest(t *testing.T, agent *Agent) {
	require.NoError(t, agent.Close())
}
