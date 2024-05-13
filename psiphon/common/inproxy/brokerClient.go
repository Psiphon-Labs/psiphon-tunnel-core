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
	"context"
	std_errors "errors"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
)

// Timeouts should be aligned with Broker timeouts.

const (
	proxyAnnounceRequestTimeout       = 2 * time.Minute
	proxyAnswerRequestTimeout         = 10 * time.Second
	clientOfferRequestTimeout         = 10 * time.Second
	clientRelayedPacketRequestTimeout = 10 * time.Second
)

// BrokerClient is used to make requests to a broker.
//
// Each BrokerClient maintains a secure broker session. A BrokerClient and its
// session may be used for multiple concurrent requests. Session key material
// is provided by BrokerDialCoordinator and must remain static for the
// lifetime of the BrokerClient.
//
// Round trips between the BrokerClient and broker are provided by
// BrokerClientRoundTripper from BrokerDialCoordinator. The RoundTripper must
// maintain the association between a request payload and the corresponding
// response payload. The canonical RoundTripper is an HTTP client, with
// HTTP/2 or HTTP/3 used to multiplex concurrent requests.
//
// When the BrokerDialCoordinator BrokerClientRoundTripperSucceeded call back
// is invoked, the RoundTripper provider may mark the RoundTripper dial
// properties for replay.
//
// When the BrokerDialCoordinator BrokerClientRoundTripperFailed call back is
// invoked, the RoundTripper provider should clear any replay state and also
// create a new RoundTripper to be returned from BrokerClientRoundTripper.
//
// BrokerClient does not have a Close operation. The user should close the
// provided RoundTripper as appropriate.
//
// The secure session layer includes obfuscation that provides random padding
// and uniformly random payload content. The RoundTripper is expected to add
// its own obfuscation layer; for example, domain fronting.
type BrokerClient struct {
	coordinator BrokerDialCoordinator
	sessions    *InitiatorSessions
}

// NewBrokerClient initializes a new BrokerClient with the provided
// BrokerDialCoordinator.
func NewBrokerClient(coordinator BrokerDialCoordinator) (*BrokerClient, error) {

	// A client is expected to use an ephemeral key, and can return a
	// zero-value private key. Each proxy should use a peristent key, as the
	// corresponding public key is the proxy ID, which is used to credit the
	// proxy for its service.

	privateKey := coordinator.BrokerClientPrivateKey()
	if privateKey.IsZero() {
		var err error
		privateKey, err = GenerateSessionPrivateKey()
		if err != nil {
			return nil, errors.Trace(err)
		}
	}

	return &BrokerClient{
		coordinator: coordinator,
		sessions:    NewInitiatorSessions(privateKey),
	}, nil
}

// GetBrokerDialCoordinator returns the BrokerDialCoordinator associated with
// the BrokerClient.
func (b *BrokerClient) GetBrokerDialCoordinator() BrokerDialCoordinator {
	return b.coordinator
}

// ProxyAnnounce sends a ProxyAnnounce request and returns the response.
func (b *BrokerClient) ProxyAnnounce(
	ctx context.Context,
	request *ProxyAnnounceRequest) (*ProxyAnnounceResponse, error) {

	requestPayload, err := MarshalProxyAnnounceRequest(request)
	if err != nil {
		return nil, errors.Trace(err)
	}

	requestCtx, requestCancelFunc := context.WithTimeout(
		ctx, common.ValueOrDefault(
			b.coordinator.AnnounceRequestTimeout(),
			proxyAnnounceRequestTimeout))
	defer requestCancelFunc()

	responsePayload, err := b.roundTrip(requestCtx, requestPayload)
	if err != nil {
		return nil, errors.Trace(err)
	}

	response, err := UnmarshalProxyAnnounceResponse(responsePayload)
	if err != nil {
		return nil, errors.Trace(err)
	}

	return response, nil
}

// ClientOffer sends a ClientOffer request and returns the response.
func (b *BrokerClient) ClientOffer(
	ctx context.Context,
	request *ClientOfferRequest) (*ClientOfferResponse, error) {

	requestPayload, err := MarshalClientOfferRequest(request)
	if err != nil {
		return nil, errors.Trace(err)
	}

	requestCtx, requestCancelFunc := context.WithTimeout(
		ctx, common.ValueOrDefault(
			b.coordinator.OfferRequestTimeout(),
			clientOfferRequestTimeout))
	defer requestCancelFunc()

	responsePayload, err := b.roundTrip(requestCtx, requestPayload)
	if err != nil {
		return nil, errors.Trace(err)
	}

	response, err := UnmarshalClientOfferResponse(responsePayload)
	if err != nil {
		return nil, errors.Trace(err)
	}

	return response, nil
}

// ProxyAnswer sends a ProxyAnswer request and returns the response.
func (b *BrokerClient) ProxyAnswer(
	ctx context.Context,
	request *ProxyAnswerRequest) (*ProxyAnswerResponse, error) {

	requestPayload, err := MarshalProxyAnswerRequest(request)
	if err != nil {
		return nil, errors.Trace(err)
	}

	requestCtx, requestCancelFunc := context.WithTimeout(
		ctx, common.ValueOrDefault(
			b.coordinator.AnswerRequestTimeout(),
			proxyAnswerRequestTimeout))
	defer requestCancelFunc()

	responsePayload, err := b.roundTrip(requestCtx, requestPayload)
	if err != nil {
		return nil, errors.Trace(err)
	}

	response, err := UnmarshalProxyAnswerResponse(responsePayload)
	if err != nil {
		return nil, errors.Trace(err)
	}

	return response, nil
}

// ClientRelayedPacket sends a ClientRelayedPacket request and returns the
// response.
func (b *BrokerClient) ClientRelayedPacket(
	ctx context.Context,
	request *ClientRelayedPacketRequest) (*ClientRelayedPacketResponse, error) {

	requestPayload, err := MarshalClientRelayedPacketRequest(request)
	if err != nil {
		return nil, errors.Trace(err)
	}

	requestCtx, requestCancelFunc := context.WithTimeout(
		ctx, common.ValueOrDefault(
			b.coordinator.RelayedPacketRequestTimeout(),
			clientRelayedPacketRequestTimeout))
	defer requestCancelFunc()

	responsePayload, err := b.roundTrip(requestCtx, requestPayload)
	if err != nil {
		return nil, errors.Trace(err)
	}

	response, err := UnmarshalClientRelayedPacketResponse(responsePayload)
	if err != nil {
		return nil, errors.Trace(err)
	}

	return response, nil
}

func (b *BrokerClient) roundTrip(
	ctx context.Context,
	request []byte) ([]byte, error) {

	// The round tripper may need to establish a transport-level connection;
	// or this may already be established.

	roundTripper, err := b.coordinator.BrokerClientRoundTripper()
	if err != nil {
		return nil, errors.Trace(err)
	}

	// InitiatorSessions.RoundTrip may make serveral round trips with
	// roundTripper in order to complete a session establishment handshake.
	//
	// When there's an active session, only a single round trip is required,
	// to exchange the application-level request and response.
	//
	// When a concurrent BrokerClient request is currently performing a
	// session handshake, InitiatorSessions.RoundTrip will await completion
	// of that handshake before sending the application-layer request.
	//
	// Note the waitToShareSession limitation, documented in
	// InitiatorSessions.RoundTrip: a new session must complete a full,
	// application-level round trip (e.g., ProxyAnnounce/ClientOffer), not
	// just the session handshake, before a session becomes ready to share.
	//
	// Retries are built in to InitiatorSessions.RoundTrip: if there's an
	// existing session and it's expired, there will be additional round
	// trips to establish a fresh session.
	//
	// While the round tripper is responsible for maintaining the
	// request/response association, the application-level request and
	// response are tagged with a RoundTripID which is checked to ensure the
	// association is maintained.

	waitToShareSession := true

	response, err := b.sessions.RoundTrip(
		ctx,
		roundTripper,
		b.coordinator.BrokerPublicKey(),
		b.coordinator.BrokerRootObfuscationSecret(),
		waitToShareSession,
		request)
	if err != nil {

		var failedError *RoundTripperFailedError
		failed := std_errors.As(err, &failedError)

		if failed {
			// The BrokerDialCoordinator provider should close the existing
			// BrokerClientRoundTripper and create a new RoundTripper to return
			// in the next BrokerClientRoundTripper call.
			//
			// The session will be closed, if necessary, by InitiatorSessions.
			// It's possible that the session remains valid and only the
			// RoundTripper transport layer needs to be reset.
			b.coordinator.BrokerClientRoundTripperFailed(roundTripper)
		}

		return nil, errors.Trace(err)
	}

	b.coordinator.BrokerClientRoundTripperSucceeded(roundTripper)

	return response, nil
}
