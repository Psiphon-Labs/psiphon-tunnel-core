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
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"math"
	"sync"
	"time"

	"filippo.io/edwards25519"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	lrucache "github.com/cognusion/go-cache-lru"
	"github.com/flynn/noise"
	"github.com/marusama/semaphore"
	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/replay"
)

const (
	sessionsTTL     = 24 * time.Hour
	sessionsMaxSize = 1000000

	sessionObfuscationPaddingMinSize = 0
	sessionObfuscationPaddingMaxSize = 256

	resetSessionTokenName      = "psiphon-inproxy-session-reset-session-token"
	resetSessionTokenNonceSize = 32

	maxResponderConcurrentNewSessions = 32768
)

const (
	SessionProtocolName     = "psiphon-inproxy-session"
	SessionProtocolVersion1 = 1
)

// SessionPrologue is a Noise protocol prologue, which binds the session ID to
// the session.
type SessionPrologue struct {
	SessionProtocolName    string `cbor:"1,keyasint,omitempty"`
	SessionProtocolVersion uint32 `cbor:"2,keyasint,omitempty"`
	SessionID              ID     `cbor:"3,keyasint,omitempty"`
}

// SessionPacket is a Noise protocol message, which may be a session handshake
// message, or secured application data, a SessionRoundTrip.
type SessionPacket struct {
	SessionID         ID     `cbor:"1,keyasint,omitempty"`
	Nonce             uint64 `cbor:"2,keyasint,omitempty"`
	Payload           []byte `cbor:"3,keyasint,omitempty"`
	ResetSessionToken []byte `cbor:"4,keyasint,omitempty"`
}

// SessionRoundTrip is an application data request or response, which is
// secured by the Noise protocol session. Each request is assigned a unique
// RoundTripID, and each corresponding response has the same RoundTripID.
type SessionRoundTrip struct {
	RoundTripID ID     `cbor:"1,keyasint,omitempty"`
	Payload     []byte `cbor:"2,keyasint,omitempty"`
}

// SessionPrivateKey is a Noise protocol private key.
type SessionPrivateKey [ed25519.PrivateKeySize]byte

// GenerateSessionPrivateKey creates a new session private key using
// crypto/rand.
//
// GenerateSessionPrivateKey generates an Ed25519 private key, which is used
// directly for digital signatures and, when converted to Curve25519, as the
// Noise protocol ECDH private key.
//
// The Ed25519 representation is the canonical representation since there's a
// 1:1 conversion from Ed25519 to Curve25519, but not the other way.
//
// Digital signing use cases include signing a reset session token. In
// addition, externally, digital signing can be used in a challenge/response
// protocol that demonstrates ownership of a proxy private key corresponding
// to a claimed proxy public key.
func GenerateSessionPrivateKey() (SessionPrivateKey, error) {

	var k SessionPrivateKey

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return k, errors.Trace(err)
	}

	if len(privateKey) != len(k) {
		return k, errors.TraceNew("unexpected private key length")
	}
	copy(k[:], privateKey)

	return k, nil
}

// SessionPrivateKeyFromString returns a SessionPrivateKey given its base64
// string encoding.
func SessionPrivateKeyFromString(s string) (SessionPrivateKey, error) {
	var k SessionPrivateKey
	return k, errors.Trace(fromBase64String(s, k[:]))
}

// String emits SessionPrivateKey as base64.
func (k SessionPrivateKey) String() string {
	return base64.RawStdEncoding.EncodeToString([]byte(k[:]))
}

// IsZero indicates if the private key is zero-value.
func (k SessionPrivateKey) IsZero() bool {
	var zero SessionPrivateKey
	return bytes.Equal(k[:], zero[:])
}

// GetPublicKey returns the public key corresponding to the private key.
func (k SessionPrivateKey) GetPublicKey() (SessionPublicKey, error) {

	var sessionPublicKey SessionPublicKey

	// See ed25519.PrivateKey.Public.
	copy(sessionPublicKey[:], k[32:])

	return sessionPublicKey, nil
}

// ToCurve25519 converts the Ed25519 SessionPrivateKey to the unique
// corresponding Curve25519 private key for use in the Noise protocol.
func (k SessionPrivateKey) ToCurve25519() []byte {
	h := sha512.New()
	h.Write(ed25519.PrivateKey(k[:]).Seed())
	return h.Sum(nil)[:curve25519.ScalarSize]
}

// SessionPublicKey is a Noise protocol public key.
type SessionPublicKey [ed25519.PublicKeySize]byte

// SessionPublicKeyFromString returns a SessionPublicKey given its base64
// string encoding.
func SessionPublicKeyFromString(s string) (SessionPublicKey, error) {
	var k SessionPublicKey
	return k, errors.Trace(fromBase64String(s, k[:]))
}

// SessionPublicKeysFromStrings returns a list of SessionPublicKeys given the
// base64 string encodings.
func SessionPublicKeysFromStrings(strs []string) ([]SessionPublicKey, error) {
	keys := make([]SessionPublicKey, len(strs))
	for i, s := range strs {
		err := fromBase64String(s, keys[i][:])
		if err != nil {
			return nil, errors.Trace(err)
		}
	}
	return keys, nil
}

// String emits SessionPublicKey as base64.
func (k SessionPublicKey) String() string {
	return base64.RawStdEncoding.EncodeToString([]byte(k[:]))
}

// ToCurve25519 converts the Ed25519 SessionPublicKey to the unique
// corresponding Curve25519 public key for use in the Noise protocol.
func (k SessionPublicKey) ToCurve25519() (SessionPublicKeyCurve25519, error) {

	var c SessionPublicKeyCurve25519

	// Copyright 2019 The age Authors. All rights reserved.
	// Use of this source code is governed by a BSD-style
	// license that can be found in the LICENSE file.
	//
	// See https://blog.filippo.io/using-ed25519-keys-for-encryption and
	// https://pkg.go.dev/filippo.io/edwards25519#Point.BytesMontgomery.
	p, err := new(edwards25519.Point).SetBytes(k[:])
	if err != nil {
		return c, err
	}

	copy(c[:], p.BytesMontgomery())

	return c, nil
}

// SessionPublicKeyCurve25519 is a representation of a Curve25519 public key
// as a fixed-size array that may be used as a map key.
type SessionPublicKeyCurve25519 [curve25519.PointSize]byte

// String emits SessionPublicKeyCurve25519 as base64.
func (k SessionPublicKeyCurve25519) String() string {
	return base64.RawStdEncoding.EncodeToString([]byte(k[:]))
}

// InitiatorSessions is a set of secure Noise protocol sessions for an
// initiator. For in-proxy, clients and proxies will initiate sessions with
// one more brokers and brokers will initiate sessions with multiple Psiphon
// servers.
//
// Secure sessions provide encryption, authentication of the responder,
// identity hiding for the initiator, forward secrecy, and anti-replay for
// application data.
//
// Maintaining a set of established sessions minimizes round trips and
// overhead, as established sessions can be shared and reused for many client
// requests to one broker or many broker requests to one server.
//
// Currently, InitiatorSessions doesn't not cap the number of sessions or use
// an LRU cache since the number of peers is bounded in the in-proxy
// architecture; clients will typically use one or no more than a handful of
// brokers and brokers will exchange requests with a subset of Psiphon
// servers bounded by the in-proxy capability.
//
// InitiatorSessions are used via the RoundTrip function or InitiatorRoundTrip
// type. RoundTrip is a synchronous function which performs any necessary
// session establishment handshake along with the request/response exchange.
// InitiatorRoundTrip offers an iterator interface, with stepwise invocations
// for each step of the handshake and round trip.
//
// All round trips attempt to share and reuse any existing, established
// session to a given peer. For a given peer, the waitToShareSession option
// determines whether round trips will block and wait if a session handshake
// is already in progress, or proceed with a concurrent handshake. For
// in-proxy, clients and proxies use waitToShareSession; as broker/server
// round trips are relayed through clients, brokers do not use
// waitToShareSession so as to not rely on any single client.
//
// Round trips can be performed concurrently and requests can arrive out-of-
// order. The higher level transport for sessions is responsible for
// multiplexing round trips and maintaining the association between a request
// and it's corresponding response.
type InitiatorSessions struct {
	privateKey SessionPrivateKey

	mutex    sync.Mutex
	sessions map[SessionPublicKey]*session
}

// NewInitiatorSessions creates a new InitiatorSessions with the specified
// initator private key.
func NewInitiatorSessions(
	initiatorPrivateKey SessionPrivateKey) *InitiatorSessions {

	return &InitiatorSessions{
		privateKey: initiatorPrivateKey,
		sessions:   make(map[SessionPublicKey]*session),
	}
}

// RoundTrip sends the request to the specified responder and returns the
// response.
//
// RoundTrip will establish a session when required, or reuse an existing
// session when available.
//
// When waitToShareSession is true, RoundTrip will block until an existing,
// non-established session is available to be shared.
//
// When making initial network round trips to establish a session,
// sessionHandshakeTimeout is applied as the round trip timeout.
//
// When making the application-level request round trip, requestDelay, when >
// 0, is applied before the request network round trip begins; requestDelay
// may be used to spread out many concurrent requests, such as batch proxy
// announcements, to avoid CDN rate limits.
//
// requestTimeout is applied to the application-level request network round
// trip, and excludes any requestDelay; the distinct requestTimeout may be
// used to set a longer timeout for long-polling requests, such as proxy
// announcements.
//
// Any time spent blocking on waitToShareSession is not included in
// requestDelay or requestTimeout.
//
// RoundTrip returns immediately when ctx becomes done.
func (s *InitiatorSessions) RoundTrip(
	ctx context.Context,
	roundTripper RoundTripper,
	responderPublicKey SessionPublicKey,
	responderRootObfuscationSecret ObfuscationSecret,
	waitToShareSession bool,
	sessionHandshakeTimeout time.Duration,
	requestDelay time.Duration,
	requestTimeout time.Duration,
	request []byte) ([]byte, error) {

	rt, err := s.NewRoundTrip(
		responderPublicKey,
		responderRootObfuscationSecret,
		waitToShareSession,
		request)
	if err != nil {
		return nil, errors.Trace(err)
	}

	var in []byte
	for {
		out, isRequestPacket, err := rt.Next(ctx, in)
		if err != nil {
			return nil, errors.Trace(err)
		}
		if out == nil {
			response, err := rt.Response()
			if err != nil {
				return nil, errors.Trace(err)
			}
			return response, nil
		}

		// At this point, if sharing a session, any blocking on
		// waitToShareSession is complete, and time elapsed in that blocking
		// will not collapse delays or reduce timeouts. If not sharing, and
		// establishing a new session, Noise session handshake round trips
		// are required before the request payload round trip.
		//
		// Select the delay and timeout. For Noise session handshake round
		// trips, use sessionHandshakeTimeout, which should be appropriate
		// for a fast turn-around from the broker, and no delay. When sending
		// the application-level request packet, use requestDelay and
		// requestTimeout, which allows for applying a delay -- to spread out
		// requests -- and a potentially longer timeout appropriate for a
		// long-polling, slower turn-around from the broker.
		//
		// Delays and timeouts are passed down into the round tripper
		// provider. Having the round tripper perform the delay sleep allows
		// all delays to be interruped by any round tripper close, due to an
		// overall broker client reset. Passing the timeout seperately, as
		// opposed to adding to ctx, explicitly ensures that the timeout is
		// applied only right before the network round trip and no sooner.

		var delay, timeout time.Duration
		if isRequestPacket {
			delay = requestDelay
			timeout = requestTimeout
		} else {
			// No delay for session handshake packet round trips.
			timeout = sessionHandshakeTimeout
		}

		in, err = roundTripper.RoundTrip(ctx, delay, timeout, out)
		if err != nil {

			// There are no explicit retries here. Retrying in the case where
			// the initiator attempts to use an expired session is covered by
			// the reset session token logic in InitiatorRoundTrip. Higher
			// levels implicitly provide additional retries to cover other
			// cases; Psiphon client tunnel establishment will retry in-proxy
			// dials; the proxy will retry its announce requests if they
			// fail.

			// If this round trip owns its session and there are any
			// waitToShareSession initiators awaiting the session, signal them
			// that the session will not become ready.

			rt.TransportFailed()

			return nil, errors.Trace(err)
		}
	}
}

// NewRoundTrip creates a new InitiatorRoundTrip which will perform a
// request/response round trip with the specified responder, sending the
// input request. The InitiatorRoundTrip will establish a session when
// required, or reuse an existing session when available.
//
// When waitToShareSession is true, InitiatorRoundTrip.Next will block until
// an existing, non-established session is available to be shared.
//
// Limitation with waitToShareSession: currently, any new session must
// complete an _application-level_ round trip (e.g., ProxyAnnounce/ClientOffer
// request _and_ response) before the session becomes ready to share since
// the first application-level request is sent in the same packet as the last
// handshake message and ready-to-share is only signalled after a subsequent
// packet is received. This means that, for example, a long-polling
// ProxyAnnounce will block any additional ProxyAnnounce requests attempting
// to share the same InitiatorSessions. In practice, an initial
// ProxyAnnounce/ClientOffer request is expected to block only as long as
// there is no match, so the impact of blocking other concurrent requests is
// limited. See comment in InitiatorRoundTrip.Next for a related future
// enhancement.
//
// NewRoundTrip does not block or perform any session operations; the
// operations begin on the first InitiatorRoundTrip.Next call. The content of
// request should not be modified after calling NewRoundTrip.
func (s *InitiatorSessions) NewRoundTrip(
	responderPublicKey SessionPublicKey,
	responderRootObfuscationSecret ObfuscationSecret,
	waitToShareSession bool,
	request []byte) (*InitiatorRoundTrip, error) {

	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Generate a new round trip ID for the session round trip. The response
	// is expected to echo back the same round trip ID. This check detects
	// any potential misrouting of multiplexed round trip exchanges.

	roundTripID, err := MakeID()
	if err != nil {
		return nil, errors.Trace(err)
	}

	requestPayload, err := marshalRecord(
		SessionRoundTrip{RoundTripID: roundTripID, Payload: request},
		recordTypeSessionRoundTrip)
	if err != nil {
		return nil, errors.Trace(err)
	}

	return &InitiatorRoundTrip{
		initiatorSessions:              s,
		responderPublicKey:             responderPublicKey,
		responderRootObfuscationSecret: responderRootObfuscationSecret,
		waitToShareSession:             waitToShareSession,
		roundTripID:                    roundTripID,
		requestPayload:                 requestPayload,
	}, nil
}

// getSession looks for an existing session for the peer specified by public
// key. When none is found, newSession is called to create a new session, and
// this is stored, associated with the key. If an existing session is found,
// indicate if it is ready to be shared or not.
func (s *InitiatorSessions) getSession(
	publicKey SessionPublicKey,
	newSession func() (*session, error)) (
	retSession *session, retIsNew bool, retIsReady bool, retErr error) {

	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Note: unlike in ResponderSessions.getSession, there is no indication,
	// in profiling, of high lock contention and blocking here when holding
	// the mutex lock while calling newSession. The lock is left in place to
	// preserve the semantics of only one concurrent newSession call,
	// particularly for brokers initiating new sessions with servers.

	session, ok := s.sessions[publicKey]
	if ok {
		return session, false, session.isReadyToShare(nil), nil
	}

	session, err := newSession()
	if err != nil {
		return nil, false, false, errors.Trace(err)
	}

	s.sessions[publicKey] = session

	return session, true, session.isReadyToShare(nil), nil
}

// setSession sets the session associated with the peer's public key.
func (s *InitiatorSessions) setSession(publicKey SessionPublicKey, session *session) {

	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.sessions[publicKey] = session
}

// removeIfSession removes the session associated with the peer's public key,
// if it's the specified session.
func (s *InitiatorSessions) removeIfSession(publicKey SessionPublicKey, session *session) {

	s.mutex.Lock()
	defer s.mutex.Unlock()

	currentSession, ok := s.sessions[publicKey]
	if !ok || session != currentSession {
		return
	}

	delete(s.sessions, publicKey)
}

// InitiatorRoundTrip represents the state of a session round trip, including
// a session handshake if required. The session handshake and round trip is
// advanced by calling InitiatorRoundTrip.Next.
type InitiatorRoundTrip struct {
	initiatorSessions              *InitiatorSessions
	responderPublicKey             SessionPublicKey
	responderRootObfuscationSecret ObfuscationSecret
	waitToShareSession             bool
	roundTripID                    ID
	requestPayload                 []byte

	mutex          sync.Mutex
	sharingSession bool
	session        *session
	lastSentPacket bytes.Buffer
	response       []byte
}

// Next advances a round trip, as well as any session handshake that may be
// first required. Next takes the next packet received from the responder and
// returns the next packet to send to the responder. To begin, pass a nil
// receivedPacket. The round trip is complete when Next returns nil for the
// next packet to send; the response can be fetched from
// InitiatorRoundTrip.Response.
//
// When waitToShareSession is set, Next will block until an existing,
// non-established session is available to be shared.
//
// Multiple concurrent round trips are supported and requests from different
// round trips can arrive at the responder out-of-order. The provided
// transport is responsible for multiplexing round trips and maintaining an
// association between sent and received packets for a given round trip.
//
// Next returns immediately when ctx becomes done.
func (r *InitiatorRoundTrip) Next(
	ctx context.Context,
	receivedPacket []byte) (retSendPacket []byte, retIsRequestPacket bool, retErr error) {

	// Note: don't clear or reset a session in the event of a bad/rejected
	// packet as that would allow a malicious relay client to interrupt a
	// valid broker/server session with a malformed packet. Just drop the
	// packet and return an error.

	// beginOrShareSession returns the next packet to send.
	beginOrShareSession := func() ([]byte, bool, error) {

		// Check for an existing session, or create a new one if there's no
		// existing session.
		//
		// To ensure the concurrent waitToShareSession cases don't start
		// multiple handshakes, getSession populates the initiatorSessions
		// session map with a new, unestablished session.

		newSession := func() (*session, error) {

			sendObfuscationSecret, receiveObfuscationSecret, err :=
				deriveSessionPacketObfuscationSecrets(r.responderRootObfuscationSecret, false)
			if err != nil {
				return nil, errors.Trace(err)
			}

			session, err := newSession(
				true, // isInitiator
				r.initiatorSessions.privateKey,
				sendObfuscationSecret,
				receiveObfuscationSecret,
				nil, // No obfuscation replay history
				&r.responderPublicKey,
				r.requestPayload,
				nil,
				nil)
			if err != nil {
				return nil, errors.Trace(err)
			}
			return session, nil
		}

		session, isNew, isReady, err := r.initiatorSessions.getSession(
			r.responderPublicKey, newSession)
		if err != nil {
			return nil, false, errors.Trace(err)
		}

		if isNew {

			// When isNew is true, this InitiatorRoundTrip owns the session
			// and will perform the handshake.

			r.session = session
			r.sharingSession = false

		} else {

			if isReady {

				// When isReady is true, this shared session is fully
				// established and ready for immediate use.

				r.session = session
				r.sharingSession = true

			} else {

				// The existing session is not yet ready for use.

				if r.waitToShareSession {

					// Wait for the owning InitiatorRoundTrip to complete the
					// session handshake and then share the session.

					// Limitation with waitToShareSession: isReadyToShare
					// becomes true only once the session completes
					// an _application-level_ round trip
					// (e.g., ProxyAnnounce/ClientOffer request _and_
					// response) since the first application-level request is
					// bundled with the last handshake message and
					// ready-to-share is true only after a subsequent packet
					// is received, guaranteeing that the handshake is completed.
					//
					// Future enhancement: for shared sessions, don't bundle
					// the request payload with the handshake. This implies
					// one extra round trip for the initial requester, but
					// allows all sharers to proceed at once.

					signal := make(chan struct{})
					if !session.isReadyToShare(signal) {
						select {
						case <-signal:
							if !session.isReadyToShare(nil) {

								// The session failed to become ready to share due to a transport
								// failure during the handshake. Fail this round trip. Don't
								// create a new, unshared session since waitToShareSession was
								// specified. It's expected that there will be retries by the
								// RoundTrip caller.

								return nil, false, errors.TraceNew("waitToShareSession failed")
							}
							// else, use the session
						case <-ctx.Done():
							return nil, false, errors.Trace(ctx.Err())
						}
					}
					r.session = session
					r.sharingSession = true

				} else {

					// Don't wait: create a new, unshared session.

					r.session, err = newSession()
					if err != nil {
						return nil, false, errors.Trace(err)
					}
					r.sharingSession = false
				}
			}
		}

		if r.sharingSession {

			// The shared session was either ready for immediate use, or we
			// waited. Send the round trip request payload.

			sendPacket, err := r.session.sendPacket(r.requestPayload)
			if err != nil {
				return nil, false, errors.Trace(err)
			}

			return sendPacket, true, nil
		}

		// Begin the handshake for a new session.

		_, sendPacket, _, err := r.session.nextHandshakePacket(nil)
		if err != nil {
			return nil, false, errors.Trace(err)
		}

		return sendPacket, false, nil

	}

	// Return immediately if the context is already done.
	if ctx != nil {
		err := ctx.Err()
		if err != nil {
			return nil, false, errors.Trace(err)
		}
	}

	r.mutex.Lock()
	defer r.mutex.Unlock()

	// Store the output send packet, which is used to verify that any
	// subsequent ResetSessionToken isn't replayed.
	defer func() {
		if retSendPacket != nil {
			r.lastSentPacket.Reset()
			r.lastSentPacket.Write(retSendPacket)
		}
	}()

	if r.session == nil {

		// If the session is nil, this is the first call to Next, and no
		// packet from the peer is expected.

		if receivedPacket != nil {
			return nil, false, errors.TraceNew("unexpected received packet")
		}

		sendPacket, isRequestPacket, err := beginOrShareSession()

		if err != nil {
			return nil, false, errors.Trace(err)
		}
		return sendPacket, isRequestPacket, nil

	}

	// Not the first Next call, so a packet from the peer is expected.

	if receivedPacket == nil {
		return nil, false, errors.TraceNew("missing received packet")
	}

	if r.sharingSession || r.session.isEstablished() {

		// When sharing an established and ready session, or once an owned
		// session is established, the next packet is post-handshake and
		// should be the round trip request response.

		// Pre-unwrap here to check for a ResetSessionToken packet.

		sessionPacket, err := unwrapSessionPacket(
			r.session.receiveObfuscationSecret, true, nil, receivedPacket)
		if err != nil {
			return nil, false, errors.Trace(err)
		}

		// Reset the session when the packet is a valid ResetSessionToken. The
		// responder sends a ResetSessionToken when this initiator attempts
		// to use an expired session. A ResetSessionToken is valid when it's
		// signed by the responder's public key and is bound to the last
		// packet sent from this initiator (which protects against replay).

		if sessionPacket.ResetSessionToken != nil &&
			isValidResetSessionToken(
				r.responderPublicKey,
				r.lastSentPacket.Bytes(),
				sessionPacket.ResetSessionToken) {

			// removeIfSession won't clobber any other, concurrently
			// established session for the same responder.
			r.initiatorSessions.removeIfSession(r.responderPublicKey, r.session)
			r.session = nil

			sendPacket, isRequestPacket, err := beginOrShareSession()
			if err != nil {
				return nil, false, errors.Trace(err)
			}
			return sendPacket, isRequestPacket, nil
		}

		responsePayload, err := r.session.receiveUnmarshaledPacket(sessionPacket)
		if err != nil {
			return nil, false, errors.Trace(err)
		}

		var sessionRoundTrip SessionRoundTrip
		err = unmarshalRecord(recordTypeSessionRoundTrip, responsePayload, &sessionRoundTrip)
		if err != nil {
			return nil, false, errors.Trace(err)
		}

		// Check that the response RoundTripID matches the request RoundTripID.

		if sessionRoundTrip.RoundTripID != r.roundTripID {
			return nil, false, errors.TraceNew("unexpected round trip ID")
		}

		// Store the response so it can be retrieved later.

		r.response = sessionRoundTrip.Payload
		return nil, false, nil
	}

	// Continue the handshake. Since the first payload is sent to the
	// responder along with the initiator's last handshake message, there's
	// no sendPacket call in the owned session case. The last
	// nextHandshakePacket will bundle it. Also, the payload output of
	// nextHandshakePacket is ignored, as only a responder will receive a
	// payload in a handshake message.

	isEstablished, sendPacket, _, err := r.session.nextHandshakePacket(receivedPacket)
	if err != nil {
		return nil, false, errors.Trace(err)
	}

	if isEstablished {

		// Retain the most recently established session as the cached session
		// for reuse. This should be a no-op in the isNew case and only have
		// an effect for !inNew and !waitToShareSession. Modifying the
		// initiatorSessions map entry should not impact any concurrent
		// handshakes, as each InitiatorRoundTrip maintains its own reference
		// to its session.

		r.initiatorSessions.setSession(r.responderPublicKey, r.session)
	}

	return sendPacket, isEstablished, nil
}

// TransportFailed marks any owned, not yet ready-to-share session as failed
// and signals any other initiators waiting to share the session.
//
// TransportFailed should be called when using waitToShareSession and when
// there is a transport level failure to relay a session packet.
func (r *InitiatorRoundTrip) TransportFailed() {

	r.mutex.Lock()
	defer r.mutex.Unlock()

	if !r.sharingSession && !r.session.isReadyToShare(nil) {
		r.session.transportFailed()
		r.initiatorSessions.removeIfSession(r.responderPublicKey, r.session)
	}
}

// Response returns the round trip response. Call Response after Next returns
// nil for the next packet to send, indicating that the round trip is
// complete.
func (r *InitiatorRoundTrip) Response() ([]byte, error) {

	r.mutex.Lock()
	defer r.mutex.Unlock()

	if r.response == nil {
		return nil, errors.TraceNew("no response")
	}

	return r.response, nil
}

// ResponderSessions is a set of secure Noise protocol sessions for a
// responder. For in-proxy, brokers respond to clients and proxies and
// servers respond to brokers.
//
// Secure sessions provide encryption, authentication of the responder,
// identity hiding for the initiator, forward secrecy, and anti-replay for
// application data.
//
// ResponderSessions maintains a cache of established sessions to minimizes
// round trips and overhead as initiators are expected to make multiple round
// trips. The cache has a TTL and maximum size with LRU to cap overall memory
// usage. A broker may receive requests from millions of clients and proxies
// and so only more recent sessions will be retained. Servers will receive
// requests from only a handful of brokers, and so the TTL is not applied.
//
// Multiple, concurrent sessions for a single initiator public key are
// supported.
type ResponderSessions struct {
	privateKey                  SessionPrivateKey
	sendObfuscationSecret       ObfuscationSecret
	receiveObfuscationSecret    ObfuscationSecret
	applyTTL                    bool
	obfuscationReplayHistory    *obfuscationReplayHistory
	expectedInitiatorPublicKeys *sessionPublicKeyLookup

	mutex    sync.RWMutex
	sessions *lrucache.Cache

	concurrentNewSessions semaphore.Semaphore
}

// NewResponderSessions creates a new ResponderSessions which allows any
// initiators to establish a session. A TTL is applied to cached sessions.
func NewResponderSessions(
	responderPrivateKey SessionPrivateKey,
	responderRootObfuscationSecret ObfuscationSecret) (*ResponderSessions, error) {

	sendObfuscationSecret, receiveObfuscationSecret, err :=
		deriveSessionPacketObfuscationSecrets(responderRootObfuscationSecret, true)
	if err != nil {
		return nil, errors.Trace(err)
	}

	return &ResponderSessions{
		privateKey:               responderPrivateKey,
		sendObfuscationSecret:    sendObfuscationSecret,
		receiveObfuscationSecret: receiveObfuscationSecret,
		applyTTL:                 true,
		obfuscationReplayHistory: newObfuscationReplayHistory(),
		sessions:                 lrucache.NewWithLRU(sessionsTTL, 1*time.Minute, sessionsMaxSize),
		concurrentNewSessions:    semaphore.New(maxResponderConcurrentNewSessions),
	}, nil
}

// NewResponderSessionsForKnownInitiators creates a new ResponderSessions
// which allows only allow-listed initiators to establish a session. No TTL
// is applied to cached sessions.
//
// The NewResponderSessionsForKnownInitiators configuration is for Psiphon
// servers responding to brokers. Only a handful of brokers are expected to
// be deployed. A relatively small allow list of expected broker public keys
// is easy to manage, deploy, and update. No TTL is applied to keep the
// sessions established as much as possible and avoid extra client-relayed
// round trips for BrokerServerRequests.
func NewResponderSessionsForKnownInitiators(
	responderPrivateKey SessionPrivateKey,
	responderRootObfuscationKey ObfuscationSecret,
	initiatorPublicKeys []SessionPublicKey) (*ResponderSessions, error) {

	s, err := NewResponderSessions(responderPrivateKey, responderRootObfuscationKey)
	if err != nil {
		return nil, errors.Trace(err)
	}

	s.applyTTL = false

	s.expectedInitiatorPublicKeys, err = newSessionPublicKeyLookup(initiatorPublicKeys)
	if err != nil {
		return nil, errors.Trace(err)
	}

	return s, nil
}

// SetKnownInitiatorPublicKeys updates the set of initiator public keys which
// are allowed to establish sessions with the responder. Any existing
// sessions with keys not in the new list are deleted. Existing sessions with
// keys which remain in the list are retained.
func (s *ResponderSessions) SetKnownInitiatorPublicKeys(
	initiatorPublicKeys []SessionPublicKey) error {

	s.mutex.Lock()
	defer s.mutex.Unlock()

	changed, err := s.expectedInitiatorPublicKeys.set(initiatorPublicKeys)
	if err != nil {
		return errors.Trace(err)
	}

	if !changed {
		// With an identical public key set there are no sessions to be reset
		return nil
	}

	// Delete sessions for removed keys; retain established sessions for
	// still-valid keys.
	//
	// Limitations:
	// - Doesn't interrupt a concurrent request in progress which has already
	//   called getSession
	// - lrucache doesn't have iterator; Items creates a full copy of the
	//   cache state

	for sessionIDStr, entry := range s.sessions.Items() {

		// Each session.hasUnexpectedInitiatorPublicKey indirectly references
		// s.expectedInitiatorPublicKeys, which was updated above with the
		// new set of valid public keys.
		if entry.Object.(*session).hasUnexpectedInitiatorPublicKey() {
			s.sessions.Delete(sessionIDStr)
		}
	}

	return nil
}

// GetEstablishedKnownInitiatorIDs returns a list of known initiator IDs, the
// Curve21559 equivalents of known initiator public keys, with currently
// established sessions.
//
// The return value is a map that may be used for lookups, supporting the
// ProxyQualityReporter use case of sending server proxy quality requests
// only to brokers that are expected to already trust the server's session
// public key.
//
// GetEstablishedKnownInitiatorIDs requires KnownInitiators mode, and is
// intended for use with only a small number of known initiators.
func (s *ResponderSessions) GetEstablishedKnownInitiatorIDs() map[ID]struct{} {

	s.mutex.Lock()
	defer s.mutex.Unlock()

	initiatorIDs := make(map[ID]struct{})

	if s.expectedInitiatorPublicKeys == nil {
		// Exit immediately when not in known initiator mode. Don't
		// accidentally iterator over potentially millions of sessions.
		return initiatorIDs
	}

	for _, entry := range s.sessions.Items() {
		session := entry.Object.(*session)
		initiatorID, err := session.getPeerID()
		if err != nil {
			// When getPeerID fails, the session is not yet established.
			continue
		}
		initiatorIDs[initiatorID] = struct{}{}
	}

	return initiatorIDs
}

// RequestHandler is an application-level handler that receives the decrypted
// request payload and returns a response payload to be encrypted and sent to
// the initiator. The initiatorID is the authenticated identifier of the
// initiator: client, proxy, or broker.
//
// In cases where a request is a one-way message, with no response, such as a
// BrokerServerReport, RequestHandler should return a nil packet.
type RequestHandler func(initiatorID ID, request []byte) ([]byte, error)

// HandlePacket takes a session packet, as received at the transport level,
// and handles session handshake and request decryption. While a session
// handshakes, HandlePacket returns the next handshake message to be relayed
// back to the initiator over the transport.
//
// Once a session is fully established and a request is decrypted, the inner
// request payload is passed to the RequestHandler for application-level
// processing. The response received from the RequestHandler will be
// encrypted with the session and returned from HandlePacket as the next
// packet to send back over the transport. If there is no response to
// be returned, HandlePacket returns a nil packet.
//
// The session packet contains a session ID that is used to route packets from
// many initiators to the correct session state.
//
// Above the Noise protocol security layer, session packets have an
// obfuscation layer. If a packet doesn't authenticate with the expected
// obfuscation secret, or if a packet is replayed, HandlePacket returns an
// error. The obfuscation anti-replay layer covers replays of Noise handshake
// messages which aren't covered by the Noise nonce anti-replay. When
// HandlePacket returns an error, the caller should invoke anti-probing
// behavior, such as returning a generic 404 error from an HTTP server for
// HTTPS transports.
//
// There is one expected error case with legitimate initiators: when an
// initiator reuses a session that is expired or no longer in the responder
// cache. In this case HandlePacket will return a reset session token in
// outPacket along with an error, and the caller should log the error and
// also send the packet to the initiator.
//
// The HandlePacket caller should implement initiator rate limiting in its
// transport level.
func (s *ResponderSessions) HandlePacket(
	inPacket []byte,
	requestHandler RequestHandler) (retOutPacket []byte, retErr error) {

	// Concurrency: no locks are held for this function, only in specific
	// helper functions.

	// unwrapSessionPacket deobfuscates the session packet, and unmarshals a
	// SessionPacket. The SessionPacket.SessionID is used to route the
	// session packet to an existing session or to create a new one. The
	// SessionPacket.Payload is a Noise handshake message or an encrypted
	// request and that will be handled below.

	sessionPacket, err := unwrapSessionPacket(
		s.receiveObfuscationSecret, false, s.obfuscationReplayHistory, inPacket)
	if err != nil {
		return nil, errors.Trace(err)
	}

	sessionID := sessionPacket.SessionID

	// Check for an existing session with this session ID, or create a new one
	// if not found. If the session _was_ in the cache but is now expired, a
	// new session is created, but subsequent Noise operations will fail.

	session, err := s.getSession(sessionID)
	if err != nil {
		return nil, errors.Trace(err)
	}

	retainSession := false

	defer func() {
		if retErr != nil && !retainSession {

			// If an error is returned, the session has failed, so don't
			// retain it in the cache as it could be more recently used than
			// an older but still valid session.
			//
			// TODO: should we retain the session if it has completed the
			// handshake? As with initiator error signals, and depending on
			// the transport security level, a SessionPacket with a
			// legitimate session ID but corrupt Noise payload could be
			// forged, terminating a legitimate session.

			s.removeSession(sessionID)
		}
	}()

	var requestPayload []byte

	if session.isEstablished() {

		// When the session is already established, decrypt the packet to get
		// the request.

		payload, err := session.receiveUnmarshaledPacket(sessionPacket)
		if err != nil {
			return nil, errors.Trace(err)
		}
		requestPayload = payload

	} else {

		// When the session is not established, the packet is the next
		// handshake message. The initiator appends the request payload to
		// the end of its last XK handshake message, and in that case payload
		// will contain the request.

		isEstablished, outPacket, payload, err :=
			session.nextUnmarshaledHandshakePacket(sessionPacket)
		if err != nil {

			if _, ok := err.(potentialExpiredSessionError); !ok {
				return nil, errors.Trace(err)
			}

			// The initiator may be trying to use a previously valid session
			// which is now expired or flushed, due to a full cache or a
			// server reboot. Craft and send a secure reset session token,
			// signed with the responder public key (the Ed25519
			// representation), bound to the packet just received from the
			// initiator (to defend against replay).

			outPacket, wrapErr := wrapSessionPacket(
				s.sendObfuscationSecret,
				false,
				&SessionPacket{
					SessionID:         sessionPacket.SessionID,
					ResetSessionToken: makeResetSessionToken(s.privateKey, inPacket),
				})
			if wrapErr != nil {
				return nil, errors.Trace(wrapErr)
			}

			return outPacket, errors.Trace(err)
		}

		if outPacket != nil {

			// The handshake is not complete until outPacket is nil; send the
			// next handshake packet.

			if payload != nil {

				// A payload is not expected unless the handshake is complete.
				return nil, errors.TraceNew("unexpected handshake payload")
			}

			// The session TTL is not extended here. Initiators, including
			// clients and proxies, are given sessionsTTL to complete the
			// entire handshake.

			return outPacket, nil
		}

		if !isEstablished || payload == nil {

			// When outPacket is nil, the handshake should be complete --
			// isEstablished -- and, by convention, the first request payload
			// should be available.

			return nil, errors.TraceNew("unexpected established state")
		}

		requestPayload = payload
	}

	// Extend the session TTL.
	s.touchSession(sessionID, session)

	initiatorID, err := session.getPeerID()
	if err != nil {
		return nil, errors.Trace(err)
	}

	var sessionRoundTrip SessionRoundTrip
	err = unmarshalRecord(recordTypeSessionRoundTrip, requestPayload, &sessionRoundTrip)
	if err != nil {
		return nil, errors.Trace(err)
	}

	request := sessionRoundTrip.Payload

	response, err := requestHandler(initiatorID, request)
	if err != nil {

		// Don't delete the session if the application-level request handler
		// returns an error, as there is no problem with the Noise session.
		// Non-failure application-level errors can include cases like a
		// fronting CDN aborting a request due to timeout misalignment.
		retainSession = true

		return nil, errors.Trace(err)
	}

	if response == nil {
		// There is no response.
		return nil, nil
	}

	// The response is assigned the same RoundTripID as the request.
	sessionRoundTrip = SessionRoundTrip{
		RoundTripID: sessionRoundTrip.RoundTripID,
		Payload:     response,
	}

	responsePayload, err := marshalRecord(
		sessionRoundTrip, recordTypeSessionRoundTrip)
	if err != nil {
		return nil, errors.Trace(err)
	}

	responsePacket, err := session.sendPacket(responsePayload)
	if err != nil {
		return nil, errors.Trace(err)
	}

	return responsePacket, nil
}

// touchSession sets a cached session for the specified session ID; if the
// session is already in the cache, its TTL is extended. The LRU session
// cache entry may be discarded once the cache is full.
func (s *ResponderSessions) touchSession(sessionID ID, session *session) {

	s.mutex.Lock()
	defer s.mutex.Unlock()

	if session.hasUnexpectedInitiatorPublicKey() {

		// In this case, SetKnownInitiatorPublicKeys was called concurrent to
		// HandlePacket, after HandlePacket's getSession, and now the known
		// initiator public key for this session is no longer valid; don't
		// cache or extend the session, as that could revert a session flush
		// performed in SetKnownInitiatorPublicKeys.
		//
		// Limitation: this won't interrupt a handshake in progress, which may
		// complete, but then ultimately fail.
		return
	}

	TTL := lrucache.DefaultExpiration
	if !s.applyTTL {
		TTL = lrucache.NoExpiration
	}
	s.sessions.Set(string(sessionID[:]), session, TTL)
}

// getSession returns an existing session for the specified session ID, or
// creates a new session, and places it in the cache, if not found.
func (s *ResponderSessions) getSession(sessionID ID) (*session, error) {

	// Concurrency: profiling indicates that holding the mutex lock here when
	// calling newSession leads to high contention and blocking. Instead,
	// release the lock after checking for an existing session, and then
	// recheck -- using lrucache.Add, which fails if an entry exists -- when
	// inserting.
	//
	// A read-only lock is obtained on the initial check, allowing for
	// concurrent checks; however, note that lrucache has its own RWMutex and
	// obtains a write lock in Get when LRU ejection may need to be performed.
	//
	// A semaphore is used to enforce a sanity check maximum number of
	// concurrent newSession calls.
	//
	// TODO: add a timeout or stop signal to Acquire?

	strSessionID := string(sessionID[:])

	s.mutex.RLock()
	entry, ok := s.sessions.Get(strSessionID)
	s.mutex.RUnlock()

	if ok {
		return entry.(*session), nil
	}

	err := s.concurrentNewSessions.Acquire(context.Background(), 1)
	if err != nil {
		return nil, errors.Trace(err)
	}
	session, err := newSession(
		false, // !isInitiator
		s.privateKey,
		s.sendObfuscationSecret,
		s.receiveObfuscationSecret,
		s.obfuscationReplayHistory,
		nil,
		nil,
		&sessionID,
		s.expectedInitiatorPublicKeys)
	s.concurrentNewSessions.Release(1)

	if err != nil {
		return nil, errors.Trace(err)
	}

	TTL := lrucache.DefaultExpiration
	if !s.applyTTL {
		TTL = lrucache.NoExpiration
	}

	s.mutex.Lock()
	err = s.sessions.Add(
		strSessionID, session, TTL)
	s.mutex.Unlock()

	if err != nil {
		return nil, errors.Trace(err)
	}

	return session, nil
}

// removeSession removes any existing session for the specified session ID.
func (s *ResponderSessions) removeSession(sessionID ID) {

	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.sessions.Delete(string(sessionID[:]))
}

// makeResetSessionToken creates a secure reset session token.
//
// This token is used for a responder to signal to an initiator that a session
// has expired, or is no longer valid and that a new session should be
// established. Securing this signal is particularly important for the
// broker/server sessions relayed by untrusted clients, as it prevents a
// malicious client from injecting invalid reset tokens and
// interrupting/degrading session performance.
//
// A reset token is signed by the responder's Ed25519 public key. The signature covers:
//   - The last packet received from the initiator, mitigating replay attacks
//   - A context name, resetSessionTokenName, and nonce which mitigates against
//     directly signing arbitrary data in the untrusted last packet received
//     from the initiator
//
// Reset session tokens are not part of the Noise protocol, but are sent as
// session packets.
func makeResetSessionToken(
	privateKey SessionPrivateKey,
	receivedPacket []byte) []byte {

	var token bytes.Buffer
	token.Write(prng.Bytes(resetSessionTokenNonceSize))

	h := sha256.New()
	h.Write([]byte(resetSessionTokenName))
	h.Write(token.Bytes()[:resetSessionTokenNonceSize])
	h.Write(receivedPacket)

	token.Write(ed25519.Sign(privateKey[:], h.Sum(nil)))

	return token.Bytes()
}

// isValidResetSessionToken checks if a reset session token is valid, given
// the specified responder public key and last packet sent to the responder.
func isValidResetSessionToken(
	publicKey SessionPublicKey,
	lastSentPacket []byte,
	token []byte) bool {

	if len(token) <= resetSessionTokenNonceSize {
		return false
	}

	h := sha256.New()
	h.Write([]byte(resetSessionTokenName))
	h.Write(token[:resetSessionTokenNonceSize])
	h.Write(lastSentPacket)

	return ed25519.Verify(publicKey[:], h.Sum(nil), token[resetSessionTokenNonceSize:])
}

// sessionPublicKeyLookup implements set membership lookup for session public
// keys, and is used to lookup expected public keys for optional responder
// access control. The sessionPublicKeyLookup is initialized with a list of
// Ed25519 session public keys, the canonical representation, while the
// lookup is done with Curve25519 public keys, the representation that is
// received via the Noise protocol.
type sessionPublicKeyLookup struct {
	mutex     sync.Mutex
	lookupMap map[SessionPublicKeyCurve25519]struct{}
}

func newSessionPublicKeyLookup(publicKeys []SessionPublicKey) (*sessionPublicKeyLookup, error) {
	s := &sessionPublicKeyLookup{
		lookupMap: make(map[SessionPublicKeyCurve25519]struct{}),
	}
	_, err := s.set(publicKeys)
	if err != nil {
		return nil, errors.Trace(err)
	}
	return s, nil
}

// set modifies the lookup set of session public keys and returns true if the
// set has changed.
func (s *sessionPublicKeyLookup) set(publicKeys []SessionPublicKey) (bool, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Convert the Ed25519 public key to its Curve25519 representation, which
	// is what's looked up. SessionPublicKeyCurve25519 is a fixed-size array
	// which can be used as a map key.
	var curve25519PublicKeys []SessionPublicKeyCurve25519
	for _, publicKey := range publicKeys {
		k, err := publicKey.ToCurve25519()
		if err != nil {
			return false, errors.Trace(err)
		}
		curve25519PublicKeys = append(curve25519PublicKeys, k)
	}

	// Check if the set of public keys has changed. This check and return
	// value is used by ResponderSessions.SetKnownInitiatorPublicKeys to skip
	// checking for sessions to be revoked in the case of an overall tactics
	// reload in which configured expected public keys did not change.
	if len(curve25519PublicKeys) == len(s.lookupMap) {
		allFound := true
		for _, k := range curve25519PublicKeys {
			if _, ok := s.lookupMap[k]; !ok {
				allFound = false
				break
			}
		}
		if allFound {
			return false, nil
		}
	}

	lookupMap := make(map[SessionPublicKeyCurve25519]struct{})
	for _, k := range curve25519PublicKeys {

		lookupMap[k] = struct{}{}
	}

	s.lookupMap = lookupMap

	return true, nil
}

func (s *sessionPublicKeyLookup) lookup(k SessionPublicKeyCurve25519) bool {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	_, ok := s.lookupMap[k]
	return ok
}

type sessionState int

const (

	/*

	   XK:
	     <- s
	     ...
	     -> e, es
	     <- e, ee
	     -> s, se [+ first payload]

	*/

	sessionStateInitiator_XK_send_e_es = iota
	sessionStateInitiator_XK_recv_e_ee_send_s_se_payload
	sessionStateInitiator_XK_established
	sessionStateInitiator_failed

	sessionStateResponder_XK_recv_e_es_send_e_ee
	sessionStateResponder_XK_recv_s_se_payload
	sessionStateResponder_XK_established
)

// session represents a Noise protocol session, including its initial
// handshake state.
//
// The XK pattern is used:
//   - Initiators may have short-lived static keys (clients), or long-lived
//     static keys (proxies and brokers). The initiator key is securely
//     transmitted to the responder while hiding its value.
//   - The responder static key is always known (K) and exchanged out of
//     band.
//   - Provides forward secrecy.
//   - The round trip request can be appended to the initiators final
//     handshake message, eliminating an extra round trip.
//
// For in-proxy, any client or proxy can connect to a broker. Only allowed
// brokers can connect to a server.
//
// To limit access to allowed brokers, expectedInitiatorPublicKeys is an allow
// list of broker public keys. XK is still used for this case, instead of
// KK:
//   - With KK, the broker identity would have to be known before the Noise
//     handshake begins
//   - With XK, the broker proves possession of a private key corresponding to
//     a broker public key on the allow list.
//   - While KK will abort sooner than XK when an invalid broker key is used,
//     completing the handshake and decrypting the first payload does not
//     leak any information.
//
// The is no "close" operation for sessions. Responders will maintain a cache
// of established sessions and discard the state for expired sessions or in
// an LRU fashion. Initiators will reuse sessions until they are rejected by
// a responder.
//
// There is no state for the obfuscation layer; each packet is obfuscated
// independently since session packets may arrive at a peer out-of-order.
//
// There are independent replay defenses at both the obfuscation layer
// (to mitigate active probing replays) and at the Noise protocol layer
// (to defend against replay of Noise protocol packets). The obfuscation
// anti-replay covers all obfuscated packet nonce values, and the Noise
// anti-replay filter covers post-handshake packet message sequence number
// nonces. The Noise layer anti-replay filter uses a sliding window of size
// ~8000, allowing for approximately that degree of out-of-order packets as
// could happen with concurrent requests in a shared session.
//
// Future enhancement: use a single anti-replay mechanism for both use cases?
type session struct {
	isInitiator                 bool
	sessionID                   ID
	sendObfuscationSecret       ObfuscationSecret
	receiveObfuscationSecret    ObfuscationSecret
	replayHistory               *obfuscationReplayHistory
	expectedInitiatorPublicKeys *sessionPublicKeyLookup

	mutex               sync.Mutex
	state               sessionState
	signalAwaitingReady []chan struct{}
	handshake           *noise.HandshakeState
	firstPayload        []byte
	peerPublicKey       []byte
	send                *noise.CipherState
	receive             *noise.CipherState
	nonceReplay         replay.Filter
}

func newSession(
	isInitiator bool,
	privateKey SessionPrivateKey,
	sendObfuscationSecret ObfuscationSecret,
	receiveObfuscationSecret ObfuscationSecret,
	replayHistory *obfuscationReplayHistory,

	// Initiator
	expectedResponderPublicKey *SessionPublicKey,
	firstPayload []byte,

	// Responder
	peerSessionID *ID,
	expectedInitiatorPublicKeys *sessionPublicKeyLookup) (*session, error) {

	if isInitiator {
		if peerSessionID != nil ||
			expectedResponderPublicKey == nil ||
			expectedInitiatorPublicKeys != nil ||
			firstPayload == nil {
			return nil, errors.TraceNew("unexpected initiator parameters")
		}
	} else {
		if peerSessionID == nil ||
			expectedResponderPublicKey != nil ||
			firstPayload != nil {
			return nil, errors.TraceNew("unexpected responder parameters")
		}
	}

	sessionID := peerSessionID
	if sessionID == nil {
		ID, err := MakeID()
		if err != nil {
			return nil, errors.Trace(err)
		}
		sessionID = &ID
	}

	// The prologue binds the session ID and other meta data to the session.

	prologue, err := protocol.CBOREncoding.Marshal(SessionPrologue{
		SessionProtocolName:    SessionProtocolName,
		SessionProtocolVersion: SessionProtocolVersion1,
		SessionID:              *sessionID,
	})
	if err != nil {
		return nil, errors.Trace(err)
	}

	publicKey, err := privateKey.GetPublicKey()
	if err != nil {
		return nil, errors.Trace(err)
	}

	privateKeyCurve25519 := privateKey.ToCurve25519()
	publicKeyCurve25519, err := publicKey.ToCurve25519()
	if err != nil {
		return nil, errors.Trace(err)
	}

	// SessionProtocolVersion1 implies this ciphersuite

	config := noise.Config{
		CipherSuite: noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2b),
		Pattern:     noise.HandshakeXK,
		Initiator:   isInitiator,
		Prologue:    prologue,
		StaticKeypair: noise.DHKey{
			Public:  publicKeyCurve25519[:],
			Private: privateKeyCurve25519},
	}

	if expectedResponderPublicKey != nil {
		k, err := (*expectedResponderPublicKey).ToCurve25519()
		if err != nil {
			return nil, errors.Trace(err)
		}
		config.PeerStatic = k[:]
	}

	handshake, err := noise.NewHandshakeState(config)
	if err != nil {
		return nil, errors.Trace(err)
	}

	var state sessionState
	if isInitiator {
		state = sessionStateInitiator_XK_send_e_es
	} else {
		state = sessionStateResponder_XK_recv_e_es_send_e_ee
	}

	return &session{
		isInitiator:                 isInitiator,
		sessionID:                   *sessionID,
		sendObfuscationSecret:       sendObfuscationSecret,
		receiveObfuscationSecret:    receiveObfuscationSecret,
		replayHistory:               replayHistory,
		expectedInitiatorPublicKeys: expectedInitiatorPublicKeys,
		state:                       state,
		signalAwaitingReady:         make([]chan struct{}, 0), // must be non-nil
		handshake:                   handshake,
		firstPayload:                firstPayload,
	}, nil
}

// isEstablished indicates that the session handshake is complete.
//
// A session may not be ready to share when isEstablished is true.
func (s *session) isEstablished() bool {

	s.mutex.Lock()
	defer s.mutex.Unlock()

	return s.handshake == nil
}

// isReadyToShare indicates that the session handshake is complete _and_ that
// the peer is known to have received and processed the final handshake
// message.
//
// When isReadyToShare is true, multiple round trips can use a session
// concurrently. Requests from different round trips can arrive at the peer
// out-of-order.
//
// Session sharing is performed by initiators, and in the XK handshake the
// last step is the initiator sends a final message to the responder. While
// the initiator session becomes "established" after that last message is
// output, we need to delay other round trips from sharing the session and
// sending session-encrypted packets to the responder before the responder
// actually receives that final handshake message.
//
// isReadyToShare becomes true once the round trip performing the handshake
// receives its round trip response, which demonstrates that the responder
// received the final message.
//
// When a signal channel is specified, it is registered and signaled once the
// session becomes ready to share _or_ the session fails to become ready due
// to a transport failure. When signaled, the caller must call isReadyToShare
// once again to distinguish between these two outcomes.
func (s *session) isReadyToShare(signal chan struct{}) bool {

	s.mutex.Lock()
	defer s.mutex.Unlock()

	if !s.isInitiator || s.state == sessionStateInitiator_failed {
		// Signal immediately if transportFailed was already called.
		if signal != nil {
			close(signal)
		}
		return false
	}

	if s.handshake == nil && s.signalAwaitingReady == nil {
		return true
	}

	if signal != nil {
		s.signalAwaitingReady = append(
			s.signalAwaitingReady, signal)
	}

	return false
}

// transportFailed marks the session as failed and signals any initiators
// waiting to share the session.
//
// transportFailed is ignored if the session is already ready to share, as any
// transport failures past that point affect only one application-level round
// trip and not the session.
func (s *session) transportFailed() {

	s.mutex.Lock()
	defer s.mutex.Unlock()

	if !s.isInitiator {
		return
	}

	// Already ready to share, so ignore the transport failure.
	if s.handshake == nil && s.signalAwaitingReady == nil {
		return
	}

	if s.state == sessionStateInitiator_failed {
		return
	}

	// In the sessionStateInitiator_failed state, nextHandshakePacket will
	// always fail.
	s.state = sessionStateInitiator_failed

	for _, signal := range s.signalAwaitingReady {
		close(signal)
	}
	s.signalAwaitingReady = nil
}

// getPeerID returns the peer's public key, in the form of an ID. A given peer
// identifier can only be provided by the peer with the corresponding private
// key.
func (s *session) getPeerID() (ID, error) {

	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.handshake != nil {
		return ID{}, errors.TraceNew("not established")
	}

	return ID(s.peerPublicKey), nil
}

// hasUnexpectedInitiatorPublicKey indicates whether the session is
// established (and so has obtained a peer public key),
// expectedInitiatorPublicKeys is configured, and the session initiator's
// public key is not in/no longer in expectedInitiatorPublicKeys.
func (s *session) hasUnexpectedInitiatorPublicKey() bool {

	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.expectedInitiatorPublicKeys == nil {
		// Not expecting specific initiator public keys
		return false
	}

	if s.handshake != nil {
		// Peer public key not known yet
		return false
	}

	var k SessionPublicKeyCurve25519
	copy(k[:], s.peerPublicKey)

	return !s.expectedInitiatorPublicKeys.lookup(k)
}

// sendPacket prepares a session packet to be sent to the peer, containing the
// specified round trip payload. The packet is secured by the established
// session.
func (s *session) sendPacket(payload []byte) ([]byte, error) {

	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.handshake != nil {
		return nil, errors.TraceNew("not established")
	}

	if s.send == nil {
		return nil, errors.Trace(s.unexpectedStateError())
	}

	nonce := s.send.Nonce()

	// Unlike tunnels, for example, sessions are not for bulk data transfer
	// and we don't aim for zero allocation or extensive buffer reuse.

	encryptedPayload, err := s.send.Encrypt(nil, nil, payload)
	if err != nil {
		return nil, errors.Trace(err)
	}

	sessionPacket, err := s.wrapPacket(
		&SessionPacket{
			SessionID: s.sessionID,
			Nonce:     nonce,
			Payload:   encryptedPayload,
		})
	if err != nil {
		return nil, errors.Trace(err)
	}

	return sessionPacket, nil

}

// receivePacket opens a session packet received from the peer, using the
// established session, and returns the round trip payload.
//
// As responders need to inspect the packet and use its session ID to route
// packets to the correct session, responders will call
// receiveUnmarshaledPacket instead.
func (s *session) receivePacket(packet []byte) ([]byte, error) {

	sessionPacket, err := s.unwrapPacket(packet)
	if err != nil {
		return nil, errors.Trace(err)
	}

	payload, err := s.receiveUnmarshaledPacket(sessionPacket)
	if err != nil {
		return nil, errors.Trace(err)
	}

	return payload, nil
}

func (s *session) receiveUnmarshaledPacket(
	sessionPacket *SessionPacket) ([]byte, error) {

	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.receive == nil {
		return nil, errors.Trace(s.unexpectedStateError())
	}

	if sessionPacket.SessionID != s.sessionID {
		return nil, errors.Tracef("unexpected sessionID")
	}

	s.receive.SetNonce(sessionPacket.Nonce)

	payload, err := s.receive.Decrypt(nil, nil, sessionPacket.Payload)
	if err != nil {
		return nil, errors.Trace(err)
	}

	if !s.nonceReplay.ValidateCounter(sessionPacket.Nonce, math.MaxUint64) {
		return nil, errors.TraceNew("replay detected")
	}

	// The session is ready to share once it's received a post-handshake
	// response from the peer.

	s.readyToShare()

	return payload, nil
}

// nextHandshakePacket advances the session handshake. nextHandshakePacket
// takes the next handshake packet received from the peer and returns the
// next handshake packet to send to the peer. Start by passing nil for
// inPacket. The handshake is complete when outPacket is nil.
//
// XK bundles the first initiator request payload along with a handshake
// message, and nextHandshakePacket output that payload to the responder when
// the handshake is complete.
//
// Once the handshake is complete, further round trips are exchanged using
// sendPacket and receivePacket.
//
// As responders need to inspect the packet and use its session ID to route
// packets to the correct session, responders will call
// nextUnmarshaledHandshakePacket instead.
func (s *session) nextHandshakePacket(inPacket []byte) (
	isEstablished bool, outPacket []byte, payload []byte, err error) {

	var sessionPacket *SessionPacket
	if inPacket != nil {
		sessionPacket, err = s.unwrapPacket(inPacket)
		if err != nil {
			return false, nil, nil, errors.Trace(err)
		}
	}

	isEstablished, outPacket, payload, err =
		s.nextUnmarshaledHandshakePacket(sessionPacket)
	if err != nil {
		return false, nil, nil, errors.Trace(err)
	}

	return isEstablished, outPacket, payload, nil
}

// potentialExpiredSessionError is packet error that indicates a potential
// expired session condition which should be handled with a reset session
// token. This includes the responder expecting a handshake packet for a new
// session, but receiving a non-handshake packet.
// Non-potentialExpiredSessionError errors include
// "unexpected initiator public key".
type potentialExpiredSessionError struct {
	error
}

func (s *session) nextUnmarshaledHandshakePacket(sessionPacket *SessionPacket) (
	isEstablished bool, outPacket []byte, payload []byte, err error) {

	s.mutex.Lock()
	defer s.mutex.Unlock()

	var in []byte
	if sessionPacket != nil {
		if sessionPacket.SessionID != s.sessionID {
			return false, nil, nil, errors.Tracef("unexpected sessionID")
		}
		if sessionPacket.Nonce != 0 {

			// A handshake message was expected, but this packet contains a
			// post-handshake nonce, Flag this as a potential expired session
			// case. See comment below for limitation.
			return false, nil, nil,
				potentialExpiredSessionError{errors.TraceNew("unexpected nonce")}
		}
		in = sessionPacket.Payload
	}

	// Handle handshake state transitions.

	switch s.state {

	// Initiator

	case sessionStateInitiator_XK_send_e_es:
		out, _, _, err := s.handshake.WriteMessage(nil, nil)
		if err != nil {
			return false, nil, nil, errors.Trace(err)
		}
		outPacket, err := s.wrapPacket(
			&SessionPacket{SessionID: s.sessionID, Payload: out})
		if err != nil {
			return false, nil, nil, errors.Trace(err)
		}
		s.state = sessionStateInitiator_XK_recv_e_ee_send_s_se_payload
		return false, outPacket, nil, nil

	case sessionStateInitiator_XK_recv_e_ee_send_s_se_payload:
		_, _, _, err := s.handshake.ReadMessage(nil, in)
		if err != nil {
			return false, nil, nil, errors.Trace(err)
		}
		out, send, receive, err := s.handshake.WriteMessage(nil, s.firstPayload)
		if err != nil {
			return false, nil, nil, errors.Trace(err)
		}
		outPacket, err := s.wrapPacket(
			&SessionPacket{SessionID: s.sessionID, Payload: out})
		if err != nil {
			return false, nil, nil, errors.Trace(err)
		}
		s.state = sessionStateInitiator_XK_established
		s.established(send, receive)
		return true, outPacket, nil, nil

	// Responder

	case sessionStateResponder_XK_recv_e_es_send_e_ee:
		_, _, _, err := s.handshake.ReadMessage(nil, in)
		if err != nil {

			// A handshake message was expected, but and invalid message type
			// was received. Flag this as a potential expired session case, a
			// candidate for a reset session token. Limitation: there's no
			// check that the invalid message was, in fact, a valid message
			// for an expired session; this may not be possible given the
			// established-session Noise protocol message is encrypted/random.
			return false, nil, nil, potentialExpiredSessionError{errors.Trace(err)}
		}
		out, _, _, err := s.handshake.WriteMessage(nil, nil)
		if err != nil {
			return false, nil, nil, errors.Trace(err)
		}
		outPacket, err := s.wrapPacket(
			&SessionPacket{SessionID: s.sessionID, Payload: out})
		if err != nil {
			return false, nil, nil, errors.Trace(err)
		}
		s.state = sessionStateResponder_XK_recv_s_se_payload
		return false, outPacket, nil, nil

	case sessionStateResponder_XK_recv_s_se_payload:
		firstPayload, receive, send, err := s.handshake.ReadMessage(nil, in)
		if err != nil {
			return false, nil, nil, errors.Trace(err)
		}

		// Check if the initiator's public key in on the allow list.
		//
		// Limitation: unlike with the KK pattern, the handshake completes and
		// the initial payload is decrypted even when the initiator public
		// key is not on the allow list.

		err = s.checkExpectedInitiatorPublicKeys(s.handshake.PeerStatic())
		if err != nil {
			return false, nil, nil, errors.Trace(err)
		}
		s.state = sessionStateResponder_XK_established
		s.established(send, receive)
		return true, nil, firstPayload, nil
	}

	return false, nil, nil, errors.Trace(s.unexpectedStateError())
}

func (s *session) checkExpectedInitiatorPublicKeys(peerPublicKey []byte) error {

	if s.expectedInitiatorPublicKeys == nil {
		return nil
	}

	var k SessionPublicKeyCurve25519
	copy(k[:], peerPublicKey)

	ok := s.expectedInitiatorPublicKeys.lookup(k)

	if !ok {
		return errors.TraceNew("unexpected initiator public key")
	}

	return nil
}

// Set the session as established.
func (s *session) established(
	send *noise.CipherState,
	receive *noise.CipherState) {

	// Assumes s.mutex lock is held.

	s.peerPublicKey = s.handshake.PeerStatic()
	s.handshake = nil
	s.firstPayload = nil
	s.send = send
	s.receive = receive
}

// Set the session as ready to share.
func (s *session) readyToShare() {

	// Assumes s.mutex lock is held.

	if !s.isInitiator {
		return
	}

	if s.signalAwaitingReady == nil {
		return
	}

	for _, signal := range s.signalAwaitingReady {
		close(signal)
	}
	s.signalAwaitingReady = nil
}

// Marshal and obfuscate a SessionPacket.
func (s *session) wrapPacket(sessionPacket *SessionPacket) ([]byte, error) {

	// No lock. References only static session fields.

	obfuscatedPacket, err := wrapSessionPacket(
		s.sendObfuscationSecret,
		s.isInitiator,
		sessionPacket)
	if err != nil {
		return nil, errors.Trace(err)
	}

	return obfuscatedPacket, nil

}

// Marshal and obfuscated a SessionPacket. wrapSessionPacket is used by
// responders to wrap reset session token packets.
func wrapSessionPacket(
	sendObfuscationSecret ObfuscationSecret,
	isInitiator bool,
	sessionPacket *SessionPacket) ([]byte, error) {

	marshaledPacket, err := marshalRecord(
		sessionPacket, recordTypeSessionPacket)
	if err != nil {
		return nil, errors.Trace(err)
	}

	obfuscatedPacket, err := obfuscateSessionPacket(
		sendObfuscationSecret,
		isInitiator,
		marshaledPacket,
		sessionObfuscationPaddingMinSize,
		sessionObfuscationPaddingMaxSize)
	if err != nil {
		return nil, errors.Trace(err)
	}

	return obfuscatedPacket, nil
}

// Deobfuscate and unmarshal a SessionPacket.
func (s *session) unwrapPacket(obfuscatedPacket []byte) (*SessionPacket, error) {

	// No lock. References only static session fields.

	sessionPacket, err := unwrapSessionPacket(
		s.receiveObfuscationSecret,
		s.isInitiator,
		s.replayHistory,
		obfuscatedPacket)
	if err != nil {
		return nil, errors.Trace(err)
	}

	return sessionPacket, nil

}

// Deobfuscate and unmarshal SessionPacket. unwrapSessionPacket is used by
// responders, which must peak at the SessionPacket and get the session ID to
// route packets to the correct session.
func unwrapSessionPacket(
	receiveObfuscationSecret ObfuscationSecret,
	isInitiator bool,
	replayHistory *obfuscationReplayHistory,
	obfuscatedPacket []byte) (*SessionPacket, error) {

	packet, err := deobfuscateSessionPacket(
		receiveObfuscationSecret,
		isInitiator,
		replayHistory,
		obfuscatedPacket)
	if err != nil {
		return nil, errors.Trace(err)
	}

	var sessionPacket *SessionPacket
	err = unmarshalRecord(recordTypeSessionPacket, packet, &sessionPacket)
	if err != nil {
		return nil, errors.Trace(err)
	}

	return sessionPacket, nil
}

// Create an error that includes the current handshake state.
func (s *session) unexpectedStateError() error {

	s.mutex.Lock()
	defer s.mutex.Unlock()

	return errors.Tracef("unexpected state: %v", s.state)
}
