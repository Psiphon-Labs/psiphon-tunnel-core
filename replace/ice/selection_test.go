// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !js
// +build !js

package ice

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/stun"
	"github.com/pion/transport/v3/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func sendUntilDone(t *testing.T, writingConn, readingConn net.Conn, maxAttempts int) bool {
	testMessage := []byte("Hello World")
	testBuffer := make([]byte, len(testMessage))

	readDone, readDoneCancel := context.WithCancel(context.Background())
	go func() {
		_, err := readingConn.Read(testBuffer)
		if errors.Is(err, io.EOF) {
			return
		}

		require.NoError(t, err)
		require.True(t, bytes.Equal(testMessage, testBuffer))

		readDoneCancel()
	}()

	attempts := 0
	for {
		select {
		case <-time.After(5 * time.Millisecond):
			if attempts > maxAttempts {
				return false
			}

			_, err := writingConn.Write(testMessage)
			require.NoError(t, err)
			attempts++
		case <-readDone.Done():
			return true
		}
	}
}

func TestBindingRequestHandler(t *testing.T) {
	defer test.CheckRoutines(t)()
	defer test.TimeOut(time.Second * 30).Stop()

	var switchToNewCandidatePair, controlledLoggingFired atomic.Value
	oneHour := time.Hour
	keepaliveInterval := time.Millisecond * 20

	aNotifier, aConnected := onConnected()
	bNotifier, bConnected := onConnected()
	controllingAgent, err := NewAgent(&AgentConfig{
		NetworkTypes:      []NetworkType{NetworkTypeUDP4, NetworkTypeUDP6},
		MulticastDNSMode:  MulticastDNSModeDisabled,
		KeepaliveInterval: &keepaliveInterval,
		CheckInterval:     &oneHour,
		BindingRequestHandler: func(_ *stun.Message, _, _ Candidate, _ *CandidatePair) bool {
			controlledLoggingFired.Store(true)
			return false
		},
	})
	require.NoError(t, err)
	require.NoError(t, controllingAgent.OnConnectionStateChange(aNotifier))

	controlledAgent, err := NewAgent(&AgentConfig{
		NetworkTypes:      []NetworkType{NetworkTypeUDP4},
		MulticastDNSMode:  MulticastDNSModeDisabled,
		KeepaliveInterval: &keepaliveInterval,
		CheckInterval:     &oneHour,
		BindingRequestHandler: func(_ *stun.Message, _, _ Candidate, _ *CandidatePair) bool {
			// Don't switch candidate pair until we are ready
			val, ok := switchToNewCandidatePair.Load().(bool)
			return ok && val
		},
	})
	require.NoError(t, err)
	require.NoError(t, controlledAgent.OnConnectionStateChange(bNotifier))

	controlledConn, controllingConn := connect(controlledAgent, controllingAgent)
	<-aConnected
	<-bConnected

	// Assert we have connected and can send data
	require.True(t, sendUntilDone(t, controlledConn, controllingConn, 100))

	// Take the lock on the controlling Agent and unset state
	assert.NoError(t, controlledAgent.run(controlledAgent.context(), func(_ context.Context, controlledAgent *Agent) {
		for net, cs := range controlledAgent.remoteCandidates {
			for _, c := range cs {
				require.NoError(t, c.close())
			}
			delete(controlledAgent.remoteCandidates, net)
		}

		for _, c := range controlledAgent.localCandidates[NetworkTypeUDP4] {
			cast, ok := c.(*CandidateHost)
			require.True(t, ok)
			cast.remoteCandidateCaches = map[AddrPort]Candidate{}
		}

		controlledAgent.setSelectedPair(nil)
		controlledAgent.checklist = make([]*CandidatePair, 0)
	}))

	// Assert that Selected Candidate pair has only been unset on Controlled side
	candidatePair, err := controlledAgent.GetSelectedCandidatePair()
	assert.Nil(t, candidatePair)
	assert.NoError(t, err)

	candidatePair, err = controllingAgent.GetSelectedCandidatePair()
	assert.NotNil(t, candidatePair)
	assert.NoError(t, err)

	// Sending will fail, we no longer have a selected candidate pair
	require.False(t, sendUntilDone(t, controlledConn, controllingConn, 20))

	// Send STUN Binding requests until a new Selected Candidate Pair has been set by BindingRequestHandler
	switchToNewCandidatePair.Store(true)
	for {
		controllingAgent.requestConnectivityCheck()

		candidatePair, err = controlledAgent.GetSelectedCandidatePair()
		require.NoError(t, err)
		if candidatePair != nil {
			break
		}

		time.Sleep(time.Millisecond * 5)
	}

	// We have a new selected candidate pair because of BindingRequestHandler, test that it works
	require.True(t, sendUntilDone(t, controllingConn, controlledConn, 100))

	fired, ok := controlledLoggingFired.Load().(bool)
	require.True(t, ok)
	require.True(t, fired)

	closePipe(t, controllingConn, controlledConn)
}
