/*
 * Copyright (c) 2023, Psiphon Inc.
 * All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

package inproxy

import (
	"bytes"
	"context"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"github.com/flynn/noise"
	"golang.zx2c4.com/wireguard/replay"
)

func TestSessions(t *testing.T) {
	err := runTestSessions()
	if err != nil {
		t.Errorf(errors.Trace(err).Error())
	}
}

func runTestSessions() error {

	// Test: basic round trip succeeds

	responderPrivateKey, err := GenerateSessionPrivateKey()
	if err != nil {
		return errors.Trace(err)
	}

	responderPublicKey, err := responderPrivateKey.GetPublicKey()
	if err != nil {
		return errors.Trace(err)
	}

	responderRootObfuscationSecret, err := GenerateRootObfuscationSecret()
	if err != nil {
		return errors.Trace(err)
	}

	responderSessions, err := NewResponderSessions(
		responderPrivateKey, responderRootObfuscationSecret)
	if err != nil {
		return errors.Trace(err)
	}

	initiatorPrivateKey, err := GenerateSessionPrivateKey()
	if err != nil {
		return errors.Trace(err)
	}

	initiatorPublicKey, err := initiatorPrivateKey.GetPublicKey()
	if err != nil {
		return errors.Trace(err)
	}

	initiatorSessions := NewInitiatorSessions(initiatorPrivateKey)

	waitToShareSession := true

	sessionHandshakeTimeout := 100 * time.Millisecond
	requestDelay := 1 * time.Microsecond
	requestTimeout := 200 * time.Millisecond

	roundTripper := newTestSessionRoundTripper(
		responderSessions,
		&initiatorPublicKey,
		sessionHandshakeTimeout,
		requestDelay,
		requestTimeout)

	request := roundTripper.MakeRequest()

	response, err := initiatorSessions.RoundTrip(
		context.Background(),
		roundTripper,
		responderPublicKey,
		responderRootObfuscationSecret,
		waitToShareSession,
		sessionHandshakeTimeout,
		requestDelay,
		requestTimeout,
		request)
	if err != nil {
		return errors.Trace(err)
	}

	if !bytes.Equal(response, roundTripper.ExpectedResponse(request)) {
		return errors.TraceNew("unexpected response")
	}

	// Test: session expires; new one negotiated
	//
	// sessionStateResponder_XK_recv_e_es_send_e_ee case, when Nonce = 0

	responderSessions.sessions.Flush()

	request = roundTripper.MakeRequest()

	response, err = initiatorSessions.RoundTrip(
		context.Background(),
		roundTripper,
		responderPublicKey,
		responderRootObfuscationSecret,
		waitToShareSession,
		sessionHandshakeTimeout,
		requestDelay,
		requestTimeout,
		request)
	if err != nil {
		return errors.Trace(err)
	}

	if !bytes.Equal(response, roundTripper.ExpectedResponse(request)) {
		return errors.TraceNew("unexpected response")
	}

	// Test: session expires; new one negotiated
	//
	// "unexpected nonce" case, when Nonce > 0

	for i := 0; i < 10; i++ {
		_, err = initiatorSessions.RoundTrip(
			context.Background(),
			roundTripper,
			responderPublicKey,
			responderRootObfuscationSecret,
			waitToShareSession,
			sessionHandshakeTimeout,
			requestDelay,
			requestTimeout,
			roundTripper.MakeRequest())
		if err != nil {
			return errors.Trace(err)
		}
	}

	responderSessions.sessions.Flush()

	request = roundTripper.MakeRequest()

	response, err = initiatorSessions.RoundTrip(
		context.Background(),
		roundTripper,
		responderPublicKey,
		responderRootObfuscationSecret,
		waitToShareSession,
		sessionHandshakeTimeout,
		requestDelay,
		requestTimeout,
		request)
	if err != nil {
		return errors.Trace(err)
	}

	if !bytes.Equal(response, roundTripper.ExpectedResponse(request)) {
		return errors.TraceNew("unexpected response")
	}

	// Test: RoundTrips with waitToShareSession are interrupted when session
	// fails

	responderSessions.sessions.Flush()

	initiatorSessions = NewInitiatorSessions(initiatorPrivateKey)

	failingRoundTripper := newTestSessionRoundTripper(
		nil,
		&initiatorPublicKey,
		sessionHandshakeTimeout,
		requestDelay,
		requestTimeout)

	roundTripCount := 100

	results := make(chan error, roundTripCount)

	for i := 0; i < roundTripCount; i++ {
		go func() {
			time.Sleep(prng.DefaultPRNG().Period(0, 10*time.Millisecond))
			waitToShareSession := true
			_, err := initiatorSessions.RoundTrip(
				context.Background(),
				failingRoundTripper,
				responderPublicKey,
				responderRootObfuscationSecret,
				waitToShareSession,
				sessionHandshakeTimeout,
				requestDelay,
				requestTimeout,
				roundTripper.MakeRequest())
			results <- err
		}()
	}

	waitToShareSessionFailed := false
	for i := 0; i < roundTripCount; i++ {
		err := <-results
		if err == nil {
			return errors.TraceNew("unexpected success")
		}
		if strings.HasSuffix(err.Error(), "waitToShareSession failed") {
			waitToShareSessionFailed = true
		}
	}
	if !waitToShareSessionFailed {
		return errors.TraceNew("missing waitToShareSession failed error")
	}

	// Test: expected known initiator public key

	initiatorSessions = NewInitiatorSessions(initiatorPrivateKey)

	responderSessions, err = NewResponderSessionsForKnownInitiators(
		responderPrivateKey,
		responderRootObfuscationSecret,
		[]SessionPublicKey{initiatorPublicKey})
	if err != nil {
		return errors.Trace(err)
	}

	roundTripper = newTestSessionRoundTripper(
		responderSessions,
		&initiatorPublicKey,
		sessionHandshakeTimeout,
		requestDelay,
		requestTimeout)

	request = roundTripper.MakeRequest()

	response, err = initiatorSessions.RoundTrip(
		context.Background(),
		roundTripper,
		responderPublicKey,
		responderRootObfuscationSecret,
		waitToShareSession,
		sessionHandshakeTimeout,
		requestDelay,
		requestTimeout,
		request)
	if err != nil {
		return errors.Trace(err)
	}

	if !bytes.Equal(response, roundTripper.ExpectedResponse(request)) {
		return errors.TraceNew("unexpected response")
	}

	// Test: expected known initiator public key using SetKnownInitiatorPublicKeys

	initiatorSessions = NewInitiatorSessions(initiatorPrivateKey)

	responderSessions, err = NewResponderSessionsForKnownInitiators(
		responderPrivateKey,
		responderRootObfuscationSecret,
		[]SessionPublicKey{})
	if err != nil {
		return errors.Trace(err)
	}

	responderSessions.SetKnownInitiatorPublicKeys([]SessionPublicKey{initiatorPublicKey})

	roundTripper = newTestSessionRoundTripper(
		responderSessions,
		&initiatorPublicKey,
		sessionHandshakeTimeout,
		requestDelay,
		requestTimeout)

	request = roundTripper.MakeRequest()

	response, err = initiatorSessions.RoundTrip(
		context.Background(),
		roundTripper,
		responderPublicKey,
		responderRootObfuscationSecret,
		waitToShareSession,
		sessionHandshakeTimeout,
		requestDelay,
		requestTimeout,
		request)
	if err != nil {
		return errors.Trace(err)
	}

	if !bytes.Equal(response, roundTripper.ExpectedResponse(request)) {
		return errors.TraceNew("unexpected response")
	}

	// The existing session should not be dropped as the original key remains valid.
	responderSessions.SetKnownInitiatorPublicKeys([]SessionPublicKey{initiatorPublicKey})

	if responderSessions.sessions.ItemCount() != 1 {
		return errors.TraceNew("unexpected session cache state")
	}

	otherKnownInitiatorPrivateKey, err := GenerateSessionPrivateKey()
	if err != nil {
		return errors.Trace(err)
	}
	otherKnownInitiatorPublicKey, err := otherKnownInitiatorPrivateKey.GetPublicKey()
	if err != nil {
		return errors.Trace(err)
	}

	// The existing session should be dropped as the original key is not longer valid.
	responderSessions.SetKnownInitiatorPublicKeys([]SessionPublicKey{otherKnownInitiatorPublicKey})

	if responderSessions.sessions.ItemCount() != 0 {
		return errors.TraceNew("unexpected session cache state")
	}

	// Test: wrong known initiator public key

	unknownInitiatorPrivateKey, err := GenerateSessionPrivateKey()
	if err != nil {
		return errors.Trace(err)
	}

	unknownInitiatorSessions := NewInitiatorSessions(unknownInitiatorPrivateKey)

	ctx, cancelFunc := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancelFunc()

	request = roundTripper.MakeRequest()

	response, err = unknownInitiatorSessions.RoundTrip(
		ctx,
		roundTripper,
		responderPublicKey,
		responderRootObfuscationSecret,
		waitToShareSession,
		sessionHandshakeTimeout,
		requestDelay,
		requestTimeout,
		request)
	if err == nil || !strings.HasSuffix(err.Error(), "unexpected initiator public key") {
		return errors.Tracef("unexpected result: %v", err)
	}

	// Test: many concurrent sessions

	responderSessions, err = NewResponderSessions(
		responderPrivateKey, responderRootObfuscationSecret)
	if err != nil {
		return errors.Trace(err)
	}

	roundTripper = newTestSessionRoundTripper(
		responderSessions,
		nil,
		sessionHandshakeTimeout,
		requestDelay,
		requestTimeout)

	clientCount := 10000
	requestCount := 100
	concurrentRequestCount := 5

	if common.IsRaceDetectorEnabled {
		// Workaround for very high memory usage and OOM that occurs only with
		// the race detector enabled.
		clientCount = 100
	}

	resultChan := make(chan error, clientCount)

	for i := 0; i < clientCount; i++ {

		// Run clients concurrently

		go func() {

			initiatorPrivateKey, err := GenerateSessionPrivateKey()
			if err != nil {
				resultChan <- errors.Trace(err)
				return
			}

			initiatorSessions := NewInitiatorSessions(initiatorPrivateKey)

			for i := 0; i < requestCount; i += concurrentRequestCount {

				requestResultChan := make(chan error, concurrentRequestCount)

				for j := 0; j < concurrentRequestCount; j++ {

					// Run some of each client's requests concurrently, to
					// exercise waitToShareSession

					go func(waitToShareSession bool) {

						request := roundTripper.MakeRequest()

						response, err := initiatorSessions.RoundTrip(
							context.Background(),
							roundTripper,
							responderPublicKey,
							responderRootObfuscationSecret,
							waitToShareSession,
							sessionHandshakeTimeout,
							requestDelay,
							requestTimeout,
							request)
						if err != nil {
							requestResultChan <- errors.Trace(err)
							return
						}

						if !bytes.Equal(response, roundTripper.ExpectedResponse(request)) {
							requestResultChan <- errors.TraceNew("unexpected response")
							return
						}

						requestResultChan <- nil
					}(i%2 == 0)
				}

				for i := 0; i < concurrentRequestCount; i++ {
					err = <-requestResultChan
					if err != nil {
						resultChan <- errors.Trace(err)
						return
					}
				}
			}

			resultChan <- nil
		}()
	}

	for i := 0; i < clientCount; i++ {
		err = <-resultChan
		if err != nil {
			return errors.Trace(err)
		}
	}

	return nil
}

type testSessionRoundTripper struct {
	sessions                        *ResponderSessions
	expectedPeerPublicKey           *SessionPublicKey
	expectedSessionHandshakeTimeout time.Duration
	expectedRequestDelay            time.Duration
	expectedRequestTimeout          time.Duration
}

func newTestSessionRoundTripper(
	sessions *ResponderSessions,
	expectedPeerPublicKey *SessionPublicKey,
	expectedSessionHandshakeTimeout time.Duration,
	expectedRequestDelay time.Duration,
	expectedRequestTimeout time.Duration) *testSessionRoundTripper {

	return &testSessionRoundTripper{
		sessions:                        sessions,
		expectedPeerPublicKey:           expectedPeerPublicKey,
		expectedSessionHandshakeTimeout: expectedSessionHandshakeTimeout,
		expectedRequestDelay:            expectedRequestDelay,
		expectedRequestTimeout:          expectedRequestTimeout,
	}
}

func (t *testSessionRoundTripper) MakeRequest() []byte {
	return prng.Bytes(prng.Range(100, 1000))
}

func (t *testSessionRoundTripper) ExpectedResponse(requestPayload []byte) []byte {
	l := len(requestPayload)
	responsePayload := make([]byte, l)
	for i, b := range requestPayload {
		responsePayload[l-i-1] = b
	}
	return responsePayload
}

func (t *testSessionRoundTripper) RoundTrip(
	ctx context.Context,
	roundTripDelay time.Duration,
	roundTripTimeout time.Duration,
	requestPayload []byte) ([]byte, error) {

	err := ctx.Err()
	if err != nil {
		return nil, errors.Trace(err)
	}

	if t.sessions == nil {
		return nil, errors.TraceNew("closed")
	}

	if roundTripDelay > 0 {
		common.SleepWithContext(ctx, roundTripDelay)
	}

	_, requestCancelFunc := context.WithTimeout(ctx, roundTripTimeout)
	defer requestCancelFunc()

	isRequestRoundTrip := false

	unwrappedRequestHandler := func(initiatorID ID, unwrappedRequest []byte) ([]byte, error) {

		if t.expectedPeerPublicKey != nil {

			curve25519, err := (*t.expectedPeerPublicKey).ToCurve25519()
			if err != nil {
				return nil, errors.Trace(err)
			}

			if !bytes.Equal(initiatorID[:], curve25519[:]) {
				return nil, errors.TraceNew("unexpected initiator ID")
			}
		}

		isRequestRoundTrip = true

		return t.ExpectedResponse(unwrappedRequest), nil
	}

	responsePayload, err := t.sessions.HandlePacket(requestPayload, unwrappedRequestHandler)
	if err != nil {
		if responsePayload == nil {
			return nil, errors.Trace(err)
		} else {
			fmt.Printf("HandlePacket returned packet and error: %v\n", err)
			// Continue to relay packets
		}
	} else {

		// Handshake round trips and request payload round trips should have the
		// appropriate delays/timeouts.
		if isRequestRoundTrip {
			if roundTripDelay != t.expectedRequestDelay {
				return nil, errors.TraceNew("unexpected round trip delay")
			}
			if roundTripTimeout != t.expectedRequestTimeout {
				return nil, errors.TraceNew("unexpected round trip timeout")
			}
		} else {
			if roundTripDelay != time.Duration(0) {
				return nil, errors.TraceNew("unexpected round trip delay")
			}
			if roundTripTimeout != t.expectedSessionHandshakeTimeout {
				return nil, errors.TraceNew("unexpected round trip timeout")
			}
		}
	}

	return responsePayload, nil
}

func (t *testSessionRoundTripper) Close() error {
	t.sessions = nil
	return nil
}

func TestNoise(t *testing.T) {
	err := runTestNoise()
	if err != nil {
		t.Errorf(errors.Trace(err).Error())
	}
}

func runTestNoise() error {

	prologue := []byte("psiphon-inproxy-session")

	initiatorPrivateKey, err := GenerateSessionPrivateKey()
	if err != nil {
		return errors.Trace(err)
	}
	initiatorPublicKey, err := initiatorPrivateKey.GetPublicKey()
	if err != nil {
		return errors.Trace(err)
	}
	curve25519InitiatorPublicKey, err := initiatorPublicKey.ToCurve25519()
	if err != nil {
		return errors.Trace(err)
	}
	initiatorKeys := noise.DHKey{
		Public:  curve25519InitiatorPublicKey[:],
		Private: initiatorPrivateKey.ToCurve25519()[:],
	}

	responderPrivateKey, err := GenerateSessionPrivateKey()
	if err != nil {
		return errors.Trace(err)
	}
	responderPublicKey, err := responderPrivateKey.GetPublicKey()
	if err != nil {
		return errors.Trace(err)
	}
	curve25519ResponderPublicKey, err := responderPublicKey.ToCurve25519()
	if err != nil {
		return errors.Trace(err)
	}
	responderKeys := noise.DHKey{
		Public:  curve25519ResponderPublicKey[:],
		Private: responderPrivateKey.ToCurve25519()[:],
	}

	initiatorHandshake, err := noise.NewHandshakeState(
		noise.Config{
			CipherSuite:   noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2b),
			Pattern:       noise.HandshakeXK,
			Initiator:     true,
			Prologue:      prologue,
			StaticKeypair: initiatorKeys,
			PeerStatic:    responderKeys.Public,
		})
	if err != nil {
		return errors.Trace(err)
	}

	responderHandshake, err := noise.NewHandshakeState(
		noise.Config{
			CipherSuite:   noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2b),
			Pattern:       noise.HandshakeXK,
			Initiator:     false,
			Prologue:      prologue,
			StaticKeypair: responderKeys,
		})
	if err != nil {
		return errors.Trace(err)
	}

	// Noise XK: -> e, es

	var initiatorMsg []byte
	initiatorMsg, _, _, err = initiatorHandshake.WriteMessage(initiatorMsg, nil)
	if err != nil {
		return errors.Trace(err)
	}

	var receivedPayload []byte
	receivedPayload, _, _, err = responderHandshake.ReadMessage(nil, initiatorMsg)
	if err != nil {
		return errors.Trace(err)
	}
	if len(receivedPayload) > 0 {
		return errors.TraceNew("unexpected payload")
	}

	// Noise XK: <- e, ee

	var responderMsg []byte
	responderMsg, _, _, err = responderHandshake.WriteMessage(responderMsg, nil)
	if err != nil {
		return errors.Trace(err)
	}

	receivedPayload = nil
	receivedPayload, _, _, err = initiatorHandshake.ReadMessage(nil, responderMsg)
	if err != nil {
		return errors.Trace(err)
	}
	if len(receivedPayload) > 0 {
		return errors.TraceNew("unexpected payload")
	}

	// Noise XK: -> s, se + payload

	sendPayload := prng.Bytes(1000)

	var initiatorSend, initiatorReceive *noise.CipherState
	var initiatorReplay replay.Filter

	initiatorMsg = nil
	initiatorMsg, initiatorSend, initiatorReceive, err = initiatorHandshake.WriteMessage(initiatorMsg, sendPayload)
	if err != nil {
		return errors.Trace(err)
	}
	if initiatorSend == nil || initiatorReceive == nil {
		return errors.Tracef("unexpected incomplete handshake")
	}

	var responderSend, responderReceive *noise.CipherState
	var responderReplay replay.Filter

	receivedPayload = nil
	receivedPayload, responderReceive, responderSend, err = responderHandshake.ReadMessage(receivedPayload, initiatorMsg)
	if err != nil {
		return errors.Trace(err)
	}
	if responderReceive == nil || responderSend == nil {
		return errors.TraceNew("unexpected incomplete handshake")
	}
	if receivedPayload == nil {
		return errors.TraceNew("missing payload")
	}
	if bytes.Compare(sendPayload, receivedPayload) != 0 {
		return errors.TraceNew("incorrect payload")
	}

	if bytes.Compare(responderHandshake.PeerStatic(), initiatorKeys.Public) != 0 {
		return errors.TraceNew("unexpected initiator static public key")
	}

	// post-handshake initiator <- responder

	nonce := responderSend.Nonce()
	responderMsg = nil
	responderMsg, err = responderSend.Encrypt(responderMsg, nil, receivedPayload)
	if err != nil {
		return errors.Trace(err)
	}

	initiatorReceive.SetNonce(nonce)
	receivedPayload = nil
	receivedPayload, err = initiatorReceive.Decrypt(receivedPayload, nil, responderMsg)
	if err != nil {
		return errors.Trace(err)
	}
	if !initiatorReplay.ValidateCounter(nonce, math.MaxUint64) {
		return errors.TraceNew("replay detected")
	}
	if bytes.Compare(sendPayload, receivedPayload) != 0 {
		return errors.TraceNew("incorrect payload")
	}

	for i := 0; i < 100; i++ {

		// post-handshake initiator -> responder

		sendPayload = prng.Bytes(1000)

		nonce = initiatorSend.Nonce()
		initiatorMsg = nil
		initiatorMsg, err = initiatorSend.Encrypt(initiatorMsg, nil, sendPayload)
		if err != nil {
			return errors.Trace(err)
		}

		responderReceive.SetNonce(nonce)
		receivedPayload = nil
		receivedPayload, err = responderReceive.Decrypt(receivedPayload, nil, initiatorMsg)
		if err != nil {
			return errors.Trace(err)
		}
		if !responderReplay.ValidateCounter(nonce, math.MaxUint64) {
			return errors.TraceNew("replay detected")
		}
		if bytes.Compare(sendPayload, receivedPayload) != 0 {
			return errors.TraceNew("incorrect payload")
		}

		// post-handshake initiator <- responder

		nonce = responderSend.Nonce()
		responderMsg = nil
		responderMsg, err = responderSend.Encrypt(responderMsg, nil, receivedPayload)
		if err != nil {
			return errors.Trace(err)
		}

		responderReceive.SetNonce(nonce)
		receivedPayload = nil
		receivedPayload, err = initiatorReceive.Decrypt(receivedPayload, nil, responderMsg)
		if err != nil {
			return errors.Trace(err)
		}
		if !initiatorReplay.ValidateCounter(nonce, math.MaxUint64) {
			return errors.TraceNew("replay detected")
		}
		if bytes.Compare(sendPayload, receivedPayload) != 0 {
			return errors.TraceNew("incorrect payload")
		}
	}

	return nil
}
