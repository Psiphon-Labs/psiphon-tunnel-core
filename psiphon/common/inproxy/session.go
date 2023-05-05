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
	"crypto/rand"
	"math"
	"sync"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	lrucache "github.com/cognusion/go-cache-lru"
	"github.com/flynn/noise"
	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/replay"
)

const (
	sessionsTTL     = 5 * time.Minute
	sessionsMaxSize = 100000

	sessionObfuscationPaddingMinSize = 0
	sessionObfuscationPaddingMaxSize = 256
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
	SessionID ID     `cbor:"1,keyasint,omitempty"`
	Nonce     uint64 `cbor:"2,keyasint,omitempty"`
	Payload   []byte `cbor:"3,keyasint,omitempty"`
}

// SessionRoundTrip is an application data request or response, which is
// secured by the Noise protocol session. Each request is assigned a unique
// RoundTripID, and each corresponding response has the same RoundTripID.
type SessionRoundTrip struct {
	RoundTripID ID     `cbor:"1,keyasint,omitempty"`
	Payload     []byte `cbor:"2,keyasint,omitempty"`
}

// SessionPrivateKey is a Noise protocol private key.
type SessionPrivateKey [32]byte

// SessionPublicKey is a Noise protocol private key.
type SessionPublicKey [32]byte

// IsZero indicates if the private key is zero-value.
func (k SessionPrivateKey) IsZero() bool {
	var zero SessionPrivateKey
	return bytes.Equal(k[:], zero[:])
}

// GenerateSessionPrivateKey creates a new Noise protocol session private key
// using crypto/rand.
func GenerateSessionPrivateKey() (SessionPrivateKey, error) {

	var privateKey SessionPrivateKey

	keyPair, err := noise.DH25519.GenerateKeypair(rand.Reader)
	if err != nil {
		return privateKey, errors.Trace(err)
	}

	if len(keyPair.Private) != len(privateKey) {
		return privateKey, errors.TraceNew("unexpected private key length")
	}
	copy(privateKey[:], keyPair.Private)

	return privateKey, nil
}

// GetSessionPublicKey returns the public key corresponding to the private
// key.
func GetSessionPublicKey(privateKey SessionPrivateKey) (SessionPublicKey, error) {

	var sessionPublicKey SessionPublicKey

	publicKey, err := curve25519.X25519(privateKey[:], curve25519.Basepoint)
	if err != nil {
		return sessionPublicKey, errors.Trace(err)
	}

	if len(publicKey) != len(sessionPublicKey) {
		return sessionPublicKey, errors.TraceNew("unexpected public key length")
	}
	copy(sessionPublicKey[:], publicKey)

	return sessionPublicKey, nil
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
	sessions sessionLookup
}

// NewInitiatorSessions creates a new InitiatorSessions with the specified
// initator private key.
func NewInitiatorSessions(
	initiatorPrivateKey SessionPrivateKey) *InitiatorSessions {

	return &InitiatorSessions{
		privateKey: initiatorPrivateKey,
		sessions:   make(sessionLookup),
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
// RoundTrip returns immediately when ctx becomes done.
func (s *InitiatorSessions) RoundTrip(
	ctx context.Context,
	roundTripper RoundTripper,
	responderPublicKey SessionPublicKey,
	responderRootObfuscationSecret ObfuscationSecret,
	waitToShareSession bool,
	request []byte) ([]byte, error) {

	rt, err := s.NewRoundTrip(
		responderPublicKey,
		responderRootObfuscationSecret,
		waitToShareSession,
		request)
	if err != nil {
		return nil, errors.Trace(err)
	}

	didResetSession := false

	var in []byte
	for {
		out, err := rt.Next(ctx, in)
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
		in, err = roundTripper.RoundTrip(ctx, out)
		if err != nil {

			// Perform at most one session reset, to accomodate the expected
			// case where the initator reuses an established session that is
			// expired for the responder.
			//
			// Higher levels implicitly provide additional retries to cover
			// other cases; Psiphon client tunnel establishment will retry
			// in-proxy dials; the proxy will retry its announce request if
			// it fails -- after an appropriate delay.

			if didResetSession == false {
				// TODO: log reset
				rt.ResetSession()
				didResetSession = true
			} else {
				return nil, errors.Trace(err)
			}
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
	retSession *session, retisNew bool, retIsReady bool, retErr error) {

	s.mutex.Lock()
	defer s.mutex.Unlock()

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

	mutex           sync.Mutex
	sharingSession  bool
	didResetSession bool
	session         *session
	response        []byte
}

// ResetSession clears the InitiatorRoundTrip session. Call ResetSession when
// the responder indicates an error in response to session packet. Errors are
// sent at the transport level. An error is expected when the initator reuses
// an established session that is expired for the responder. After calling
// ResetSession, the following Next call will being establishing a new
// session. The expected session expiry scenario should occur at most once
// per round trip.
//
// Limitation: since session errors/failures are handled at the transport
// level, they may be forged, depending on the security provided by the
// transport layer. For client and proxy sessions with a broker, if domain
// fronting is used then security depends on the HTTPS layer and CDNs can
// forge a session error. For broker sessions with Psiphon servers, the
// relaying client could forge a server error -- but that would deny service
// to the client when the BrokerServerRequest fails.
//
// ResetSession is ignored if response already received or if ResetSession
// already called before.
//
// Higher levels implicitly provide additional round trip retries to cover
// other cases; Psiphon client tunnel establishment will retry in-proxy
// dials; the proxy will retry its announce request if it fails -- after an
// appropriate delay.
func (r *InitiatorRoundTrip) ResetSession() {

	r.mutex.Lock()
	defer r.mutex.Unlock()

	if r.didResetSession || r.response != nil {
		return
	}

	if r.session != nil {

		r.initiatorSessions.removeIfSession(r.responderPublicKey, r.session)
		r.didResetSession = true
		r.session = nil
	}
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
	receivedPacket []byte) (retSendPacket []byte, retErr error) {

	r.mutex.Lock()
	defer r.mutex.Unlock()

	if ctx != nil {
		err := ctx.Err()
		if err != nil {
			return nil, errors.Trace(err)
		}
	}

	if r.session == nil {

		// If the session is nil, this is the first call to Next, and no
		// packet from the peer is expected.

		if receivedPacket != nil {
			return nil, errors.TraceNew("unexpected received packet")
		}

		newSession := func() (*session, error) {
			session, err := newSession(
				true, // isInitiator
				r.initiatorSessions.privateKey,
				r.responderRootObfuscationSecret,
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

		// Check for an existing session, or create a new one if there's no
		// existing session.
		//
		// To ensure the concurrent waitToShareSession cases don't start
		// multiple handshakes, getSession populates the initiatorSessions
		// session map with a new, unestablished session.

		session, isNew, isReady, err := r.initiatorSessions.getSession(
			r.responderPublicKey, newSession)
		if err != nil {
			return nil, errors.Trace(err)
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

					signal := make(chan struct{})
					if !session.isReadyToShare(signal) {
						select {
						case <-signal:
						case <-ctx.Done():
							return nil, errors.Trace(ctx.Err())
						}
					}
					r.session = session
					r.sharingSession = true

				} else {

					// Don't wait: create a new, unshared session.

					r.session, err = newSession()
					if err != nil {
						return nil, errors.Trace(err)
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
				return nil, errors.Trace(err)
			}
			return sendPacket, nil
		}

		// Begin the handshake for a new session.

		_, sendPacket, _, err := r.session.nextHandshakePacket(nil)
		if err != nil {
			return nil, errors.Trace(err)
		}
		return sendPacket, nil

	}

	// Not the first Next call, so a packet from the peer is expected.

	if receivedPacket == nil {
		return nil, errors.TraceNew("missing received packet")
	}

	if r.sharingSession || r.session.isEstablished() {

		// When sharing an established and ready session, or once an owned
		// session is eastablished, the next packet is post-handshake and
		// should be the round trip request response.

		responsePayload, err := r.session.receivePacket(receivedPacket)
		if err != nil {
			return nil, errors.Trace(err)
		}

		var sessionRoundTrip SessionRoundTrip
		err = unmarshalRecord(recordTypeSessionRoundTrip, responsePayload, &sessionRoundTrip)
		if err != nil {
			return nil, errors.Trace(err)
		}

		// Check that the response RoundTripID matches the request RoundTripID.

		if sessionRoundTrip.RoundTripID != r.roundTripID {
			return nil, errors.TraceNew("unexpected round trip ID")
		}

		// Store the response so it can be retrieved later.

		r.response = sessionRoundTrip.Payload
		return nil, nil
	}

	// Continue the handshake. Since the first payload is sent to the
	// responder along with the initiator's last handshake message, there's
	// no sendPacket call in the owned session case. The last
	// nextHandshakePacket will bundle it. Also, the payload output of
	// nextHandshakePacket is ignored, as only a responder will receive a
	// payload in a handshake message.

	isEstablished, sendPacket, _, err := r.session.nextHandshakePacket(receivedPacket)
	if err != nil {
		return nil, errors.Trace(err)
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

	return sendPacket, nil
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

// ResponderSessions is a set of secure Noise protocol sessions for an
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
	rootObfuscationSecret       ObfuscationSecret
	applyTTL                    bool
	obfuscationReplayHistory    *obfuscationReplayHistory
	expectedInitiatorPublicKeys sessionPublicKeyLookup

	mutex    sync.Mutex
	sessions *lrucache.Cache
}

// NewResponderSessions creates a new ResponderSessions which allows any
// initiators to establish a session. A TTL is applied to cached sessions.
func NewResponderSessions(
	responderPrivateKey SessionPrivateKey,
	responderRootObfuscationSecret ObfuscationSecret) (*ResponderSessions, error) {

	return &ResponderSessions{
		privateKey:               responderPrivateKey,
		rootObfuscationSecret:    responderRootObfuscationSecret,
		applyTTL:                 true,
		obfuscationReplayHistory: newObfuscationReplayHistory(),
		sessions:                 lrucache.NewWithLRU(sessionsTTL, 1*time.Minute, sessionsMaxSize),
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

	expectedPublicKeys := make(sessionPublicKeyLookup)
	for _, publicKey := range initiatorPublicKeys {
		expectedPublicKeys[publicKey] = struct{}{}
	}

	s.expectedInitiatorPublicKeys = expectedPublicKeys

	return s, nil
}

// RequestHandler is an application-level handler that receives the decrypted
// request payload and returns a response payload to be encrypted and sent to
// the initiator. The initiatorID is the authenticated identifier of the
// initiator: client, proxy, or broker.
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
// packet to send back over the transport.
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
// cache. In this case the error response should be the same; the initiator
// knows to attempt one session re-establishment in this case.
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
		s.rootObfuscationSecret, false, s.obfuscationReplayHistory, inPacket)
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

	defer func() {
		if retErr != nil {

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
			return nil, errors.Trace(err)
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
		return nil, errors.Trace(err)
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

	TTL := lrucache.DefaultExpiration
	if !s.applyTTL {
		TTL = lrucache.NoExpiration
	}
	s.sessions.Set(string(sessionID[:]), session, TTL)
}

// getSession returns an existing session for the specified session ID, or
// creates a new session, and places it in the cache, if not found.
func (s *ResponderSessions) getSession(sessionID ID) (*session, error) {

	s.mutex.Lock()
	defer s.mutex.Unlock()

	strSessionID := string(sessionID[:])

	entry, ok := s.sessions.Get(strSessionID)
	if ok {
		return entry.(*session), nil
	}

	session, err := newSession(
		false, // !isInitiator
		s.privateKey,
		s.rootObfuscationSecret,
		s.obfuscationReplayHistory,
		nil,
		nil,
		&sessionID,
		s.expectedInitiatorPublicKeys)
	if err != nil {
		return nil, errors.Trace(err)
	}

	s.sessions.Set(
		strSessionID, session, lrucache.DefaultExpiration)

	return session, nil
}

// removeSession removes any existing session for the specified session ID.
func (s *ResponderSessions) removeSession(sessionID ID) {

	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.sessions.Delete(string(sessionID[:]))
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

	sessionStateResponder_XK_recv_e_es_send_e_ee
	sessionStateResponder_XK_recv_s_se_payload
	sessionStateResponder_XK_established
)

type sessionPublicKeyLookup map[SessionPublicKey]struct{}

type sessionLookup map[SessionPublicKey]*session

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
type session struct {
	isInitiator                 bool
	sessionID                   ID
	rootObfuscationSecret       ObfuscationSecret
	replayHistory               *obfuscationReplayHistory
	expectedInitiatorPublicKeys sessionPublicKeyLookup

	mutex               sync.Mutex
	state               sessionState
	signalOnEstablished []chan struct{}
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
	rootObfuscationSecret ObfuscationSecret,
	replayHistory *obfuscationReplayHistory,

	// Initiator
	expectedResponderPublicKey *SessionPublicKey,
	firstPayload []byte,

	// Responder
	peerSessionID *ID,
	expectedInitiatorPublicKeys sessionPublicKeyLookup) (*session, error) {

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

	prologue, err := cborEncoding.Marshal(SessionPrologue{
		SessionProtocolName:    SessionProtocolName,
		SessionProtocolVersion: SessionProtocolVersion1,
		SessionID:              *sessionID,
	})
	if err != nil {
		return nil, errors.Trace(err)
	}

	publicKey, err := GetSessionPublicKey(privateKey)
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
			Public:  publicKey[:],
			Private: privateKey[:]},
	}

	if expectedResponderPublicKey != nil {
		config.PeerStatic = (*expectedResponderPublicKey)[:]
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
		rootObfuscationSecret:       rootObfuscationSecret,
		replayHistory:               replayHistory,
		expectedInitiatorPublicKeys: expectedInitiatorPublicKeys,
		state:                       state,
		signalOnEstablished:         make([]chan struct{}, 0), // must be non-nil
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
func (s *session) isReadyToShare(signal chan struct{}) bool {

	s.mutex.Lock()
	defer s.mutex.Unlock()

	if !s.isInitiator {
		return false
	}

	if s.handshake == nil && s.signalOnEstablished == nil {
		return true
	}

	if signal != nil {
		s.signalOnEstablished = append(
			s.signalOnEstablished, signal)
	}

	return false
}

// getPeerID returns the peer's public key, in the form of an ID. A given peer
// identifier can only be provided by the peer with the corresponding private
// key.
func (s *session) getPeerID() (ID, error) {

	s.mutex.Lock()
	defer s.mutex.Unlock()

	var peerID ID

	if s.handshake != nil {
		return peerID, errors.TraceNew("not established")
	}

	if len(s.peerPublicKey) != len(peerID) {
		return peerID, errors.TraceNew("invalid peer public key")
	}

	copy(peerID[:], s.peerPublicKey)

	return peerID, nil
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
			return false, nil, nil, errors.TraceNew("unexpected nonce")
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
			return false, nil, nil, errors.Trace(err)
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

	var publicKey SessionPublicKey
	copy(publicKey[:], peerPublicKey)

	_, ok := s.expectedInitiatorPublicKeys[publicKey]

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

	if s.signalOnEstablished == nil {
		return
	}

	for _, signal := range s.signalOnEstablished {
		close(signal)
	}
	s.signalOnEstablished = nil
}

// Marshal and obfuscate a SessionPacket.
func (s *session) wrapPacket(sessionPacket *SessionPacket) ([]byte, error) {

	// No lock. References only static session fields.

	marshaledPacket, err := marshalRecord(
		sessionPacket, recordTypeSessionPacket)
	if err != nil {
		return nil, errors.Trace(err)
	}

	obfuscatedPacket, err := obfuscateSessionPacket(
		s.rootObfuscationSecret,
		s.isInitiator,
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
		s.rootObfuscationSecret,
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
	rootObfuscationSecret ObfuscationSecret,
	isInitiator bool,
	replayHistory *obfuscationReplayHistory,
	obfuscatedPacket []byte) (*SessionPacket, error) {

	packet, err := deobfuscateSessionPacket(
		rootObfuscationSecret,
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
