// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !js
// +build !js

package ice

import (
	"context"
	"regexp"
	"testing"
	"time"

	"github.com/pion/transport/v2/test"
	"github.com/stretchr/testify/assert"
)

func TestMulticastDNSOnlyConnection(t *testing.T) {
	report := test.CheckRoutines(t)
	defer report()

	// Limit runtime in case of deadlocks
	lim := test.TimeOut(time.Second * 30)
	defer lim.Stop()

	cfg := &AgentConfig{
		NetworkTypes:     []NetworkType{NetworkTypeUDP4},
		CandidateTypes:   []CandidateType{CandidateTypeHost},
		MulticastDNSMode: MulticastDNSModeQueryAndGather,
	}

	aAgent, err := NewAgent(cfg)
	if err != nil {
		t.Fatal(err)
	}

	aNotifier, aConnected := onConnected()
	if err = aAgent.OnConnectionStateChange(aNotifier); err != nil {
		t.Fatal(err)
	}

	bAgent, err := NewAgent(cfg)
	if err != nil {
		t.Fatal(err)
	}

	bNotifier, bConnected := onConnected()
	if err = bAgent.OnConnectionStateChange(bNotifier); err != nil {
		t.Fatal(err)
	}

	connect(aAgent, bAgent)
	<-aConnected
	<-bConnected

	assert.NoError(t, aAgent.Close())
	assert.NoError(t, bAgent.Close())
}

func TestMulticastDNSMixedConnection(t *testing.T) {
	report := test.CheckRoutines(t)
	defer report()

	// Limit runtime in case of deadlocks
	lim := test.TimeOut(time.Second * 30)
	defer lim.Stop()

	aAgent, err := NewAgent(&AgentConfig{
		NetworkTypes:     []NetworkType{NetworkTypeUDP4},
		CandidateTypes:   []CandidateType{CandidateTypeHost},
		MulticastDNSMode: MulticastDNSModeQueryAndGather,
	})
	if err != nil {
		t.Fatal(err)
	}

	aNotifier, aConnected := onConnected()
	if err = aAgent.OnConnectionStateChange(aNotifier); err != nil {
		t.Fatal(err)
	}

	bAgent, err := NewAgent(&AgentConfig{
		NetworkTypes:     []NetworkType{NetworkTypeUDP4},
		CandidateTypes:   []CandidateType{CandidateTypeHost},
		MulticastDNSMode: MulticastDNSModeQueryOnly,
	})
	if err != nil {
		t.Fatal(err)
	}

	bNotifier, bConnected := onConnected()
	if err = bAgent.OnConnectionStateChange(bNotifier); err != nil {
		t.Fatal(err)
	}

	connect(aAgent, bAgent)
	<-aConnected
	<-bConnected

	assert.NoError(t, aAgent.Close())
	assert.NoError(t, bAgent.Close())
}

func TestMulticastDNSStaticHostName(t *testing.T) {
	report := test.CheckRoutines(t)
	defer report()

	lim := test.TimeOut(time.Second * 30)
	defer lim.Stop()

	_, err := NewAgent(&AgentConfig{
		NetworkTypes:         []NetworkType{NetworkTypeUDP4},
		CandidateTypes:       []CandidateType{CandidateTypeHost},
		MulticastDNSMode:     MulticastDNSModeQueryAndGather,
		MulticastDNSHostName: "invalidHostName",
	})
	assert.Equal(t, err, ErrInvalidMulticastDNSHostName)

	agent, err := NewAgent(&AgentConfig{
		NetworkTypes:         []NetworkType{NetworkTypeUDP4},
		CandidateTypes:       []CandidateType{CandidateTypeHost},
		MulticastDNSMode:     MulticastDNSModeQueryAndGather,
		MulticastDNSHostName: "validName.local",
	})
	assert.NoError(t, err)

	correctHostName, resolveFunc := context.WithCancel(context.Background())
	assert.NoError(t, agent.OnCandidate(func(c Candidate) {
		if c != nil && c.Address() == "validName.local" {
			resolveFunc()
		}
	}))

	assert.NoError(t, agent.GatherCandidates())
	<-correctHostName.Done()
	assert.NoError(t, agent.Close())
}

func TestGenerateMulticastDNSName(t *testing.T) {
	name, err := generateMulticastDNSName()
	if err != nil {
		t.Fatal(err)
	}
	isMDNSName := regexp.MustCompile(
		`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}.local+$`,
	).MatchString

	if !isMDNSName(name) {
		t.Fatalf("mDNS name must be UUID v4 + \".local\" suffix, got %s", name)
	}
}
