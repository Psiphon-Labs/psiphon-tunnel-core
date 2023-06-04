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
	"encoding/base64"
	"encoding/json"
	"net"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	"github.com/buraksezer/consistent"
	"github.com/cespare/xxhash"
	lrucache "github.com/cognusion/go-cache-lru"
)

const (

	// BrokerReadTimeout is the read timeout, the duration before a request is
	// fully read, that should be applied by the provided broker transport.
	// For example, when the provided transport is net/http, set
	// http.Server.ReadTimeout to at least BrokerReadTimeout.
	BrokerReadTimeout = 5 * time.Second

	// BrokerWriteTimeout is the write timeout, the duration before a response
	// is fully written, that should be applied by the provided broker
	// transport. This timeout accomodates the long polling performed by the
	// proxy announce request. Both the immediate transport provider and any
	// front (e.g., a CDN) must be configured to use this timeout.
	BrokerWriteTimeout = (brokerProxyAnnounceTimeout + 5*time.Second)

	// BrokerIdleTimeout is the idle timeout, the duration before an idle
	// persistent connection is closed, that should be applied by the
	// provided broker transport.
	BrokerIdleTimeout = 2 * time.Minute

	// BrokerMaxRequestBodySize is the maximum request size, that should be
	// enforced by the provided broker transport.
	BrokerMaxRequestBodySize = 65536

	brokerProxyAnnounceTimeout         = 2 * time.Minute
	brokerClientOfferTimeout           = 10 * time.Second
	brokerPendingServerRequestsTTL     = 60 * time.Second
	brokerPendingServerRequestsMaxSize = 100000
	brokerMetricName                   = "in-proxy-broker"
)

// LookupGeoIP is a callback for providing GeoIP lookup service.
type LookupGeoIP func(IP string) common.GeoIPData

// Broker is the in-proxy broker component, which matches clients and proxies
// and provides WebRTC signaling functionalty.
//
// Both clients and proxies send requests to the broker to obtain matches and
// exchange WebRTC SDPs. Broker does not implement a transport or obfuscation
// layer; instead that is provided by the HandleSessionPacket caller. A
// typical implementation would provide a domain fronted web server which
// runs a Broker and calls Broker.HandleSessionPacket to handle web requests
// encapsulating secure session packets.
type Broker struct {
	config                *BrokerConfig
	initiatorSessions     *InitiatorSessions
	responderSessions     *ResponderSessions
	matcher               *Matcher
	pendingServerRequests *lrucache.Cache
	commonCompartments    *consistent.Consistent
}

// BrokerConfig specifies the configuration for a Broker.
type BrokerConfig struct {

	// Logger is used to log events.
	Logger common.Logger

	// CommonCompartmentIDs is a list of common compartment IDs to apply to
	// proxies that announce without personal compartment ID. Common
	// compartment IDs are managed by Psiphon and distributed to clients via
	// tactics or embedded in OSLs. Clients must supply a valid compartment
	// ID to match with a proxy.
	CommonCompartmentIDs []ID

	// AllowProxy is a callback which can indicate whether a proxy with the
	// given GeoIP data is allowed to match with common compartment ID
	// clients. Proxies with personal compartment IDs are always allowed.
	AllowProxy func(common.GeoIPData) bool

	// AllowClient is a callback which can indicate whether a client with the
	// given GeoIP data is allowed to match with common compartment ID
	// proxies. Clients are always allowed to match based on personal
	// compartment ID.
	AllowClient func(common.GeoIPData) bool

	// AllowDomainDestination is a callback which can indicate whether a
	// client with the given GeoIP data is allowed to specify a proxied
	// destination with a domain name. When false, only IP address
	// destinations are allowed.
	//
	// While tactics may may be set to instruct clients to use only direct
	// server tunnel protocols, with IP address destinations, this callback
	// adds server-side enforcement.
	AllowDomainDestination func(common.GeoIPData) bool

	// LookupGeoIP provides GeoIP lookup service.
	LookupGeoIP LookupGeoIP

	// APIParameterValidator is a callback that validates base API metrics.
	APIParameterValidator common.APIParameterValidator

	// APIParameterValidator is a callback that formats base API metrics.
	APIParameterLogFieldFormatter common.APIParameterLogFieldFormatter

	// TransportSecret is a value that must be supplied by the provided
	// transport. In the case of domain fronting, this is used to validate
	// that the peer is a trusted CDN, and so it's relayed client IP
	// (e.g, X-Forwarded-For header) is legitimate.
	TransportSecret TransportSecret

	// PrivateKey is the broker's secure session long term private key.
	PrivateKey SessionPrivateKey

	// ObfuscationRootSecret broker's secure session long term obfuscation key.
	ObfuscationRootSecret ObfuscationSecret

	// ServerEntrySignaturePublicKey is the key used to verify Psiphon server
	// entry signatures.
	ServerEntrySignaturePublicKey string

	// IsValidServerEntryTag is a callback which checks if the specified
	// server entry tag is on the list of valid and active Psiphon server
	// entry tags.
	IsValidServerEntryTag func(serverEntryTag string) bool

	// These timeout parameters may be used to override defaults.
	ProxyAnnounceTimeout     time.Duration
	ClientOfferTimeout       time.Duration
	PendingServerRequestsTTL time.Duration
}

// NewBroker initializes a new Broker.
func NewBroker(config *BrokerConfig) (*Broker, error) {

	// At least one common compatment ID is required. At a minimum, one ID
	// will be used and distributed to clients via tactics, limiting matching
	// to those clients targeted to receive that tactic parameters.

	if len(config.CommonCompartmentIDs) == 0 {
		return nil, errors.TraceNew("missing common compartment IDs")
	}

	// initiatorSessions are secure sessions initiated by the broker and used
	// to send BrokerServerRequests to servers. The servers will be
	// configured to establish sessions only with brokers with specified
	// public keys.

	initiatorSessions := NewInitiatorSessions(config.PrivateKey)

	// responderSessions are secure sessions initiated by clients and proxies
	// and used to send requests to the broker. Clients and proxies are
	// configured to establish sessions only with specified broker public keys.

	responderSessions, err := NewResponderSessions(config.PrivateKey, config.ObfuscationRootSecret)
	if err != nil {
		return nil, errors.Trace(err)
	}

	b := &Broker{
		config:            config,
		initiatorSessions: initiatorSessions,
		responderSessions: responderSessions,
		matcher: NewMatcher(&MatcherConfig{
			Logger: config.Logger,
		}),
	}

	b.pendingServerRequests = lrucache.NewWithLRU(
		common.ValueOrDefault(config.PendingServerRequestsTTL, brokerPendingServerRequestsTTL),
		1*time.Minute,
		brokerPendingServerRequestsMaxSize)
	b.pendingServerRequests.OnEvicted(b.evictedPendingServerRequest)

	b.initializeCommonCompartmentIDHashing()

	return b, nil
}

func (b *Broker) Start() error {
	return errors.Trace(b.matcher.Start())
}

func (b *Broker) Stop() {
	b.matcher.Stop()
}

// HandleSessionPacket handles a session packet from a client or proxy and
// provides a response packet. The packet is part of a secure session and may
// be a session handshake message, or a session-wrapped request payload.
// Request payloads are routed to API request endpoints.
//
// The caller is expected to provide a transport obfuscation layer, such as
// domain fronted HTTPs. The session has an obfuscation layer that ensures
// that packets are fully random, randomly padded, and cannot be replayed.
// This makes session packets suitable to embed as plaintext in some
// transports.
//
// The caller is responsible for rate limiting and enforcing timeouts and
// maximum payload size checks.
//
// Secure sessions support multiplexing concurrent requests, as long as the
// provided transport, for example HTTP/2, supports this as well.
//
// The input ctx should be canceled if the client/proxy disconnects from the
// transport while HandleSessionPacket is running, since long-polling proxy
// announcement requests will otherwise remain blocked until eventual
// timeout; net/http does this.
//
// When HandleSessionPacket returns an error, the transport provider should
// apply anti-probing mechanisms, since the client/proxy may be a prober or
// scanner. When a client/proxy tries to use an existing session that has
// expired on the broker, this results in an error. This failure must be
// relayed to the client/proxy, which will then start establishing a new
// session. No specifics about the expiry error case need to be or should be
// transmitted by the transport. For example, with an HTTP-type transport, a
// generic 404 error should suffice both as an anti-probing response and as a
// signal that a session is expired. Furthermore, HTTP-type transports may
// keep underlying network connections open in both the anti-probing and
// expired session cases, which facilitates a fast re-establishment by
// legitimate clients/proxies.
func (b *Broker) HandleSessionPacket(
	ctx context.Context,
	transportSecret TransportSecret,
	brokerClientIP string,
	geoIPData common.GeoIPData,
	inPacket []byte) ([]byte, error) {

	// Check that the transport peer has supplied the expected transport secret.
	// In the case of CDN domain fronting, the trusted CDN is configured to
	// add an HTTP header containing the secret. The original client IP and
	// derived GeoIP information is only trusted when the correct transport
	// secret is supplied. The security of the secret depends on the
	// transport; for example, HTTPS between the CDN and the broker; the
	// transport secret cannot be injected into a secure session.

	if !b.config.TransportSecret.Equal(transportSecret) {
		return nil, errors.TraceNew("invalid transport secret")
	}

	// handleUnwrappedRequest handles requests after session unwrapping.
	// responderSessions.HandlePacket handles both session establishment and
	// request unwrapping, and invokes handleUnwrappedRequest once a session
	// is established and a valid request unwrapped.

	handleUnwrappedRequest := func(initiatorID ID, unwrappedRequestPayload []byte) ([]byte, error) {

		recordType, err := peekRecordPreambleType(unwrappedRequestPayload)

		var responsePayload []byte

		switch recordType {
		case recordTypeAPIProxyAnnounceRequest:
			responsePayload, err = b.handleProxyAnnounce(ctx, geoIPData, initiatorID, unwrappedRequestPayload)
			if err != nil {
				return nil, errors.Trace(err)
			}
		case recordTypeAPIProxyAnswerRequest:
			responsePayload, err = b.handleProxyAnswer(ctx, brokerClientIP, geoIPData, initiatorID, unwrappedRequestPayload)
			if err != nil {
				return nil, errors.Trace(err)
			}
		case recordTypeAPIClientOfferRequest:
			responsePayload, err = b.handleClientOffer(ctx, brokerClientIP, geoIPData, initiatorID, unwrappedRequestPayload)
			if err != nil {
				return nil, errors.Trace(err)
			}
		case recordTypeAPIClientRelayedPacketRequest:
			responsePayload, err = b.handleClientRelayedPacket(ctx, geoIPData, initiatorID, unwrappedRequestPayload)
			if err != nil {
				return nil, errors.Trace(err)
			}
		default:
			return nil, errors.Tracef("unexpected API record type %v", recordType)
		}

		return responsePayload, nil

	}

	outPacket, err := b.responderSessions.HandlePacket(
		inPacket, handleUnwrappedRequest)
	if err != nil {

		// An error here could be due to invalid session traffic or an expired
		// session, which is expected. For anti-probing purposes, the
		// transport response should be the same in either case.

		return nil, errors.Trace(err)
	}

	return outPacket, nil
}

// handleProxyAnnounce receives a proxy announcement, awaits a matching
// client, and returns the client offer in the response. handleProxyAnnounce
// has a long timeout so this request can idle until a matching client
// arrives.
func (b *Broker) handleProxyAnnounce(
	ctx context.Context,
	geoIPData common.GeoIPData,
	initiatorID ID,
	requestPayload []byte) (retResponse []byte, retErr error) {

	startTime := time.Now()

	var logFields common.LogFields
	var clientOffer *MatchOffer

	// As a future enhancement, a broker could initiate its own test
	// connection to the proxy to verify its effectiveness, including
	// simulating a symmetric NAT client.

	// Each announcement represents availability for a single client matching.
	// Proxies with multiple client availability will send multiple requests.
	//
	// The announcement request and response could be extended to allow the
	// proxy to specify availability for multiple clients in the request, and
	// multiple client offers returned in the response.
	//
	// If, as we expect, proxies run on home ISPs have limited upstream
	// bandwidth, they will support only a couple of concurrent clients, and
	// the simple single-client-announcment model may be sufficient. Also, if
	// the transport is HTTP/2, multiple requests can be multiplexed over a
	// single connection (and session) in any case.

	// The proxy ID is an implicit parameter: it's the proxy's session public
	// key. As part of the session handshake, the proxy has proven that it
	// has the corresponding private key. Proxy IDs are logged to attribute
	// traffic to a specific proxy.

	proxyID := initiatorID

	// Generate a connection ID. This ID is used to associate proxy
	// announcments, client offers, and proxy answers, as well as associating
	// Psiphon tunnels with in-proxy pairings.
	connectionID, err := MakeID()
	if err != nil {
		return nil, errors.Trace(err)
	}

	// Always log the outcome.
	defer func() {
		if logFields == nil {
			logFields = make(common.LogFields)
		}
		logFields["broker_event"] = "proxy-announce"
		logFields["proxy_id"] = proxyID
		logFields["elapsed_time"] = time.Since(startTime) / time.Millisecond
		logFields["connection_id"] = connectionID
		if clientOffer != nil {
			// Log the target Psiphon server ID (diagnostic ID). The presence
			// of this field indicates that a match was made.
			logFields["destination_server_id"] = clientOffer.DestinationServerID
		}
		if retErr != nil {
			logFields["error"] = retErr.Error()
		}
		b.config.Logger.LogMetric(brokerMetricName, logFields)
	}()

	announceRequest, err := UnmarshalProxyAnnounceRequest(requestPayload)
	if err != nil {
		return nil, errors.Trace(err)
	}

	logFields, err = announceRequest.ValidateAndGetLogFields(
		b.config.APIParameterValidator,
		b.config.APIParameterLogFieldFormatter,
		geoIPData)
	if err != nil {
		return nil, errors.Trace(err)
	}

	// AllowProxy may be used to disallow proxies from certain geolocations,
	// such as censored locations, from announcing. Proxies with personal
	// compartment IDs are always allowed, as they will be used only by
	// clients specifically configured to use them.

	if len(announceRequest.PersonalCompartmentIDs) == 0 &&
		!b.config.AllowProxy(geoIPData) {

		return nil, errors.TraceNew("proxy disallowed")
	}

	// Assign this proxy to a common compartment ID, unless it has specified a
	// dedicated, personal compartment ID. Assignment uses consistent hashing
	// keyed with the proxy ID, in an effort to keep proxies consistently
	// assigned to the same compartment.

	var commonCompartmentIDs []ID
	if len(announceRequest.PersonalCompartmentIDs) == 0 {
		compartmentID, err := b.selectCommonCompartmentID(proxyID)
		if err != nil {
			return nil, errors.Trace(err)
		}
		commonCompartmentIDs = []ID{compartmentID}
	}

	// Await client offer.

	accounceCtx, cancelFunc := context.WithTimeout(
		ctx, common.ValueOrDefault(b.config.ProxyAnnounceTimeout, brokerProxyAnnounceTimeout))
	defer cancelFunc()

	clientOffer, err = b.matcher.Announce(
		accounceCtx,
		&MatchAnnouncement{
			Properties: MatchProperties{
				CommonCompartmentIDs:   commonCompartmentIDs,
				PersonalCompartmentIDs: announceRequest.PersonalCompartmentIDs,
				GeoIPData:              geoIPData,
				NetworkType:            announceRequest.Metrics.BaseMetrics.GetNetworkType(),
				NATType:                announceRequest.Metrics.NATType,
				PortMappingTypes:       announceRequest.Metrics.PortMappingTypes,
			},
			ProxyID:              initiatorID,
			ConnectionID:         connectionID,
			ProxyProtocolVersion: announceRequest.Metrics.ProxyProtocolVersion,
		})
	if err != nil {
		return nil, errors.Trace(err)
	}

	// Respond with the client offer. The proxy will follow up with an answer
	// request, which is relayed to the client, and then the WebRTC dial begins.

	// Limitation: as part of the client's tunnel establishment horse race, a
	// client may abort an in-proxy dial at any point. If the overall dial is
	// past the SDP exchange and aborted during the WebRTC connection
	// establishment, the client may leave the proxy's Proxy.proxyOneClient
	// dangling until timeout. Consider adding a signal from the client to
	// the proxy, relayed by the broker, that a dial is aborted.

	responsePayload, err := MarshalProxyAnnounceResponse(
		&ProxyAnnounceResponse{
			ConnectionID:                connectionID,
			ClientProxyProtocolVersion:  clientOffer.ClientProxyProtocolVersion,
			ClientOfferSDP:              clientOffer.ClientOfferSDP,
			ClientRootObfuscationSecret: clientOffer.ClientRootObfuscationSecret,
			DoDTLSRandomization:         clientOffer.DoDTLSRandomization,
			TrafficShapingParameters:    clientOffer.TrafficShapingParameters,
			NetworkProtocol:             clientOffer.NetworkProtocol,
			DestinationAddress:          clientOffer.DestinationAddress,
		})
	if err != nil {
		return nil, errors.Trace(err)
	}

	return responsePayload, nil
}

// handleClientOffer receives a client offer, awaits a matching client, and
// returns the proxy answer. handleClientOffer has a shorter timeout than
// handleProxyAnnounce since the client has supplied an SDP with STUN hole
// punches which will expire; and, in general, the client is trying to
// connect immediately and is also trying other candidates.
func (b *Broker) handleClientOffer(
	ctx context.Context,
	clientIP string,
	geoIPData common.GeoIPData,
	initiatorID ID,
	requestPayload []byte) (retResponse []byte, retErr error) {

	// As a future enhancement, consider having proxies send offer SDPs with
	// announcements and clients long poll to await a match and then provide
	// an answer. This order of operations would make sense if client demand
	// is high and proxy supply is lower.
	//
	// Also see comment in Proxy.proxyOneClient for other alternative
	// approaches.

	// The client's session public key is ephemeral and is not logged.

	startTime := time.Now()

	var logFields common.LogFields
	var serverParams *serverParams
	var clientMatchOffer *MatchOffer
	var proxyMatchAnnouncement *MatchAnnouncement
	var proxyAnswer *MatchAnswer

	// Always log the outcome.
	defer func() {
		if logFields == nil {
			logFields = make(common.LogFields)
		}
		logFields["broker_event"] = "client-offer"
		if serverParams != nil {
			logFields["destination_server_id"] = serverParams.serverID
		}
		logFields["elapsed_time"] = time.Since(startTime) / time.Millisecond
		if proxyAnswer != nil {

			// The presence of these fields indicate that a match was made,
			// the proxy delivered and answer, and the client was still
			// waiting for it.

			logFields["connection_id"] = proxyAnswer.ConnectionID
			logFields["client_nat_type"] = clientMatchOffer.Properties.NATType
			logFields["client_port_mapping_types"] = clientMatchOffer.Properties.PortMappingTypes
			logFields["proxy_nat_type"] = proxyMatchAnnouncement.Properties.NATType
			logFields["proxy_port_mapping_types"] = proxyMatchAnnouncement.Properties.PortMappingTypes
			logFields["preferred_nat_match"] =
				clientMatchOffer.Properties.IsPreferredNATMatch(&proxyMatchAnnouncement.Properties)

			// TODO: also log proxy ice_candidate_types and has_IPv6; for the
			// client, these values are added by ValidateAndGetLogFields.
		}
		if retErr != nil {
			logFields["error"] = retErr.Error()
		}

		b.config.Logger.LogMetric(brokerMetricName, logFields)
	}()

	offerRequest, err := UnmarshalClientOfferRequest(requestPayload)
	if err != nil {
		return nil, errors.Trace(err)
	}

	logFields, err = offerRequest.ValidateAndGetLogFields(
		b.config.LookupGeoIP,
		b.config.APIParameterValidator,
		b.config.APIParameterLogFieldFormatter,
		geoIPData)
	if err != nil {
		return nil, errors.Trace(err)
	}

	// AllowClient may be used to disallow clients from certain geolocations
	// from offering. Clients are always allowed to match proxies with shared
	// personal compartment IDs.

	commonCompartmentIDs := offerRequest.CommonCompartmentIDs

	if !b.config.AllowClient(geoIPData) {

		if len(offerRequest.PersonalCompartmentIDs) == 0 {
			return nil, errors.TraceNew("client disallowed")
		}

		// Only match personal compartment IDs.
		commonCompartmentIDs = nil
	}

	// Validate that the proxy destination specified by the client is a valid
	// dial address for a signed Psiphon server entry. This ensures a client
	// can't misuse a proxy to connect to arbitrary destinations.

	serverParams, err = b.validateDestination(
		geoIPData,
		offerRequest.DestinationServerEntryJSON,
		offerRequest.NetworkProtocol,
		offerRequest.DestinationAddress)
	if err != nil {
		return nil, errors.Trace(err)
	}

	// Enqueue the client offer and await a proxy matching and subsequent
	// proxy answer.

	offerCtx, cancelFunc := context.WithTimeout(
		ctx, common.ValueOrDefault(b.config.ClientOfferTimeout, brokerClientOfferTimeout))
	defer cancelFunc()

	clientMatchOffer = &MatchOffer{
		Properties: MatchProperties{
			CommonCompartmentIDs:   commonCompartmentIDs,
			PersonalCompartmentIDs: offerRequest.PersonalCompartmentIDs,
			GeoIPData:              geoIPData,
			NetworkType:            offerRequest.Metrics.BaseMetrics.GetNetworkType(),
			NATType:                offerRequest.Metrics.NATType,
			PortMappingTypes:       offerRequest.Metrics.PortMappingTypes,
		},
		ClientProxyProtocolVersion:  offerRequest.Metrics.ProxyProtocolVersion,
		ClientOfferSDP:              offerRequest.ClientOfferSDP,
		ClientRootObfuscationSecret: offerRequest.ClientRootObfuscationSecret,
		DoDTLSRandomization:         offerRequest.DoDTLSRandomization,
		TrafficShapingParameters:    offerRequest.TrafficShapingParameters,
		NetworkProtocol:             offerRequest.NetworkProtocol,
		DestinationAddress:          offerRequest.DestinationAddress,
		DestinationServerID:         serverParams.serverID,
	}

	proxyAnswer, proxyMatchAnnouncement, err = b.matcher.Offer(
		offerCtx, clientMatchOffer)
	if err != nil {
		return nil, errors.Trace(err)
	}

	// Log the type of compartment matching that occurred. As
	// PersonalCompartmentIDs are user-generated and shared, actual matching
	// values are not logged as they may link users.

	// TODO: log matching common compartment IDs?

	matchedCommonCompartments := HaveCommonIDs(
		proxyMatchAnnouncement.Properties.CommonCompartmentIDs,
		clientMatchOffer.Properties.CommonCompartmentIDs)

	matchedPersonalCompartments := HaveCommonIDs(
		proxyMatchAnnouncement.Properties.PersonalCompartmentIDs,
		clientMatchOffer.Properties.PersonalCompartmentIDs)

	// Initiate a BrokerServerRequest, which reports important information
	// about the connection, including the original client IP, plus other
	// values to be logged with server_tunne, to the server. The request is
	// sent through a secure session established between the broker and the
	// server.
	//
	// The broker may already have an established session with the server. In
	// this case, only one relay round trip between the client and server
	// will be necessary; the first round trip will be embedded in the
	// Psiphon handshake.

	relayPacket, err := b.initiateRelayedServerRequest(
		serverParams,
		proxyAnswer.ConnectionID,
		&BrokerServerRequest{
			ProxyID:                     proxyAnswer.ProxyID,
			ConnectionID:                proxyAnswer.ConnectionID,
			MatchedCommonCompartments:   matchedCommonCompartments,
			MatchedPersonalCompartments: matchedPersonalCompartments,
			ProxyNATType:                proxyMatchAnnouncement.Properties.NATType,
			ProxyPortMappingTypes:       proxyMatchAnnouncement.Properties.PortMappingTypes,
			ClientNATType:               clientMatchOffer.Properties.NATType,
			ClientPortMappingTypes:      clientMatchOffer.Properties.PortMappingTypes,
			ClientIP:                    clientIP,
			ProxyIP:                     proxyAnswer.ProxyIP,
		})
	if err != nil {
		return nil, errors.Trace(err)
	}

	// Respond with the proxy answer and initial broker/server session packet.

	responsePayload, err := MarshalClientOfferResponse(
		&ClientOfferResponse{
			ConnectionID:                 proxyAnswer.ConnectionID,
			SelectedProxyProtocolVersion: proxyAnswer.SelectedProxyProtocolVersion,
			ProxyAnswerSDP:               proxyAnswer.ProxyAnswerSDP,
			RelayPacketToServer:          relayPacket,
		})
	if err != nil {
		return nil, errors.Trace(err)
	}

	return responsePayload, nil
}

// handleProxyAnswer receives a proxy answer and delivers it to the waiting
// client.
func (b *Broker) handleProxyAnswer(
	ctx context.Context,
	proxyIP string,
	geoIPData common.GeoIPData,
	initiatorID ID,
	requestPayload []byte) (retResponse []byte, retErr error) {

	startTime := time.Now()

	var logFields common.LogFields
	var proxyAnswer *MatchAnswer
	var answerError string

	// The proxy ID is an implicit parameter: it's the proxy's session public
	// key.
	proxyID := initiatorID

	// Always log the outcome.
	defer func() {
		if logFields == nil {
			logFields = make(common.LogFields)
		}
		logFields["broker_event"] = "proxy-answer"
		logFields["proxy_id"] = proxyID
		logFields["elapsed_time"] = time.Since(startTime) / time.Millisecond
		if proxyAnswer != nil {
			logFields["connection_id"] = proxyAnswer.ConnectionID
		}
		if answerError != "" {
			// This is a proxy-reported error that occurred while creating the answer.
			logFields["answer_error"] = answerError
		}
		if retErr != nil {
			logFields["error"] = retErr.Error()
		}
		b.config.Logger.LogMetric(brokerMetricName, logFields)
	}()

	answerRequest, err := UnmarshalProxyAnswerRequest(requestPayload)
	if err != nil {
		return nil, errors.Trace(err)
	}

	logFields, err = answerRequest.ValidateAndGetLogFields(
		b.config.LookupGeoIP,
		b.config.APIParameterValidator,
		b.config.APIParameterLogFieldFormatter,
		geoIPData)
	if err != nil {
		return nil, errors.Trace(err)
	}

	if answerRequest.AnswerError != "" {

		// The proxy failed to create an answer.

		answerError = answerRequest.AnswerError

		b.matcher.AnswerError(initiatorID, answerRequest.ConnectionID)

	} else {

		// Deliver the answer to the client.

		proxyAnswer = &MatchAnswer{
			ProxyIP:                      proxyIP,
			ProxyID:                      initiatorID,
			ConnectionID:                 answerRequest.ConnectionID,
			SelectedProxyProtocolVersion: answerRequest.SelectedProxyProtocolVersion,
			ProxyAnswerSDP:               answerRequest.ProxyAnswerSDP,
		}

		err = b.matcher.Answer(proxyAnswer)
		if err != nil {
			return nil, errors.Trace(err)
		}
	}

	// There is no data in this response, it's simply an acknowledgement that
	// the answer was received. Upon receiving the response, the proxy should
	// begin the WebRTC dial operation.

	responsePayload, err := MarshalProxyAnswerResponse(
		&ProxyAnswerResponse{})
	if err != nil {
		return nil, errors.Trace(err)
	}

	return responsePayload, nil
}

// handleClientRelayedPacket facilitates broker/server sessions. The initial
// packet from the broker is sent to the client in the ClientOfferResponse.
// The client sends that to the server in the Psiphon handshake and receives
// a server packet in the handshake response. That server packet is then
// delivered to the broker in a ClientRelayedPacketRequest. If the session
// was already established, the relay ends here. If the session needs to be
// [re-]negotiated, there are additional ClientRelayedPacket round trips
// until the session is established and the BrokerServerRequest is securely
// exchanged between the broker and server.
func (b *Broker) handleClientRelayedPacket(
	ctx context.Context,
	geoIPData common.GeoIPData,
	initiatorID ID,
	requestPayload []byte) (retResponse []byte, retErr error) {

	startTime := time.Now()

	var logFields common.LogFields
	var relayedPacketRequest *ClientRelayedPacketRequest
	var serverResponse *BrokerServerResponse
	var serverID string

	// Always log the outcome.
	defer func() {
		if logFields == nil {
			logFields = make(common.LogFields)
		}
		logFields["broker_event"] = "client-relayed-packet"
		logFields["elapsed_time"] = time.Since(startTime) / time.Millisecond
		if relayedPacketRequest != nil {
			logFields["connection_id"] = relayedPacketRequest.ConnectionID
		}
		if serverResponse != nil {
			logFields["server_response"] = true
		}
		if serverID != "" {
			logFields["server_id"] = serverID
		}
		if retErr != nil {
			logFields["error"] = retErr.Error()
		}
		b.config.Logger.LogMetric(brokerMetricName, logFields)
	}()

	relayedPacketRequest, err := UnmarshalClientRelayedPacketRequest(requestPayload)
	if err != nil {
		return nil, errors.Trace(err)
	}

	logFields, err = relayedPacketRequest.ValidateAndGetLogFields(
		b.config.APIParameterValidator,
		b.config.APIParameterLogFieldFormatter,
		geoIPData)
	if err != nil {
		return nil, errors.Trace(err)
	}

	// The relay state is associated with the connection ID.

	strConnectionID := string(relayedPacketRequest.ConnectionID[:])

	entry, ok := b.pendingServerRequests.Get(strConnectionID)
	if !ok {
		// The relay state is not found; it may have been evicted from the
		// cache. The client will receive a generic error in this case and
		// should stop relaying. Assuming the server is configured to require
		// a BrokerServerRequest, the tunnel will be terminated, so the
		// client should also abandon the dial.
		return nil, errors.TraceNew("no pending request")
	}
	pendingServerRequest := entry.(*pendingServerRequest)

	serverID = pendingServerRequest.serverID

	// When the broker tries to use an existing session that is expired on the
	// server, the server will indicate that the session is invalid. The
	// broker resets the session and starts to establish a new session.
	// There's only one reset and re-establish attempt.
	//
	// The non-waiting session establishment mode is used for broker/server
	// sessions: if multiple clients concurrently try to relay new sessions,
	// all establishments will happen in parallel without forcing any clients
	// to wait for one client to lead the establishment. The last established
	// session will be retained for reuse.
	//
	// The client can forge the SessionInvalid flag, but has no incentive to
	// do so.

	if relayedPacketRequest.SessionInvalid &&
		atomic.CompareAndSwapInt32(&pendingServerRequest.resetSession, 0, 1) {

		pendingServerRequest.roundTrip.ResetSession()
	}

	// Next is given a nil ctx since we're not waiting for any other client to
	// establish the session.
	out, err := pendingServerRequest.roundTrip.Next(
		nil, relayedPacketRequest.PacketFromServer)
	if err != nil {
		return nil, errors.Trace(err)
	}

	// When out is nil, the exchange is over and the BrokerServer response
	// from the server should be available.
	if out == nil {

		// Removed the cached state. Setting the deleted flag skips a cache
		// eviction log.

		atomic.StoreInt32(&pendingServerRequest.deleted, 1)
		b.pendingServerRequests.Delete(strConnectionID)

		// Get the response cached in the session round tripper.

		serverResponsePayload, err := pendingServerRequest.roundTrip.Response()
		if err != nil {
			return nil, errors.Trace(err)
		}

		serverResponse, err = UnmarshalBrokerServerResponse(serverResponsePayload)
		if err != nil {
			return nil, errors.Trace(err)
		}

		// If ErrorMessage is set, the server has rejected the connection.

		if serverResponse.ErrorMessage != "" {
			return nil, errors.Tracef("server error: %s", serverResponse.ErrorMessage)
		}

		// Check that the server has acknowledged the expected connection ID.

		if relayedPacketRequest.ConnectionID != serverResponse.ConnectionID {
			return nil, errors.Tracef(
				"expected connection ID: %v, got: %v",
				relayedPacketRequest.ConnectionID,
				serverResponse.ConnectionID)
		}
	}

	// Return the next broker packet for the client to relay to the server.
	// When it receives a nil PacketToServer, the client will stop relaying.

	responsePayload, err := MarshalClientRelayedPacketResponse(
		&ClientRelayedPacketResponse{
			PacketToServer: out,
		})
	if err != nil {
		return nil, errors.Trace(err)
	}

	return responsePayload, nil
}

type pendingServerRequest struct {
	serverID      string
	serverRequest *BrokerServerRequest
	roundTrip     *InitiatorRoundTrip
	resetSession  int32
	deleted       int32
}

func (b *Broker) initiateRelayedServerRequest(
	serverParams *serverParams,
	connectionID ID,
	serverRequest *BrokerServerRequest) ([]byte, error) {

	requestPayload, err := MarshalBrokerServerRequest(serverRequest)
	if err != nil {
		return nil, errors.Trace(err)
	}

	// Force a new, concurrent session establishment with the server even if
	// another handshake is already in progess, relayed by some other client.
	// This ensures clients don't block waiting for other client relays
	// through other tunnels. The last established session will be retained
	// for reuse.

	waitToShareSession := false

	roundTrip, err := b.initiatorSessions.NewRoundTrip(
		serverParams.sessionPublicKey,
		serverParams.sessionRootObfuscationSecret,
		waitToShareSession,
		requestPayload)
	if err != nil {
		return nil, errors.Trace(err)
	}

	relayPacket, err := roundTrip.Next(nil, nil)
	if err != nil {
		return nil, errors.Trace(err)
	}

	strConnectionID := string(connectionID[:])

	b.pendingServerRequests.Set(
		strConnectionID,
		&pendingServerRequest{
			serverID:      serverParams.serverID,
			serverRequest: serverRequest,
			roundTrip:     roundTrip,
		},
		lrucache.DefaultExpiration)

	return relayPacket, nil
}

func (b *Broker) evictedPendingServerRequest(
	connectionID string, entry interface{}) {

	pendingServerRequest := entry.(*pendingServerRequest)

	// Don't log when the entry was removed by handleClientRelayedPacket due
	// to completion (this OnEvicted callback gets called in that case).
	if atomic.LoadInt32(&pendingServerRequest.deleted) == 1 {
		return
	}

	b.config.Logger.WithTraceFields(common.LogFields{
		"server_id":     pendingServerRequest.serverID,
		"connection_id": connectionID,
	}).Info("pending server request timed out")

	// TODO: consider adding a signal from the broker to the proxy to
	// terminate this proxied connection when the BrokerServerResponse does
	// not arrive in time.
}

type serverParams struct {
	serverID                     string
	sessionPublicKey             SessionPublicKey
	sessionRootObfuscationSecret ObfuscationSecret
}

// validateDestination checks that the client's specified proxy dial
// destination is valid destination address for a tunnel protocol in the
// specified signed abd valid Psiphon server entry.
func (b *Broker) validateDestination(
	geoIPData common.GeoIPData,
	destinationServerEntryJSON []byte,
	networkProtocol NetworkProtocol,
	destinationAddress string) (*serverParams, error) {

	var serverEntryFields protocol.ServerEntryFields

	err := json.Unmarshal(destinationServerEntryJSON, &serverEntryFields)
	if err != nil {
		return nil, errors.Trace(err)
	}

	// Strip any unsigned fields, which could be forged by the client. In
	// particular, this includes the server entry tag, which, in some cases,
	// is locally populated by a client for its own reference.

	serverEntryFields.RemoveUnsignedFields()

	// Check that the server entry is signed by Psiphon. Otherwise a client
	// could manufacture a server entry corresponding to an arbitrary dial
	// destination.

	err = serverEntryFields.VerifySignature(
		b.config.ServerEntrySignaturePublicKey)
	if err != nil {
		return nil, errors.Trace(err)
	}

	// The server entry tag must be set and signed by Psiphon, as local,
	// client derived tags are unsigned and untrusted.

	serverEntryTag := serverEntryFields.GetTag()

	if serverEntryTag == "" {
		return nil, errors.TraceNew("missing server entry tag")
	}

	// Check that the server entry tag is on a list of active and valid
	// Psiphon server entry tags. This ensures that an obsolete entry for a
	// pruned server cannot by misused by a client to proxy to what's no
	// longer a Psiphon server.

	if !b.config.IsValidServerEntryTag(serverEntryTag) {
		return nil, errors.TraceNew("invalid server entry tag")
	}

	serverID := serverEntryFields.GetDiagnosticID()

	serverEntry, err := serverEntryFields.GetServerEntry()
	if err != nil {
		return nil, errors.Trace(err)
	}

	// The server entry must include the in-proxy capability. This capability
	// is set for only a subset of all Psiphon servers, to limited the number
	// of servers a proxy can observe and enumerate. Well-behaved clients
	// will not send any server entries lacking this capability, but here the
	// broker enforces it.

	if !serverEntry.SupportsInProxy() {
		return nil, errors.TraceNew("missing inproxy capability")
	}

	// Validate the dial host (IP or domain) and port matches a tunnel
	// protocol offered by the server entry.

	destHost, destPort, err := net.SplitHostPort(destinationAddress)
	if err != nil {
		return nil, errors.Trace(err)
	}

	destPortNum, err := strconv.Atoi(destPort)
	if err != nil {
		return nil, errors.Trace(err)
	}

	// For domain fronted cases, since we can't verify the Host header, access
	// is strictly to limited to targeted clients. Clients should use tactics
	// to avoid disallowed domain dial address cases, but here the broker
	// enforces it.
	//
	// TODO: this issue could be further mitigated by signaling the proxy to
	// terminate client connections that fail to deliver a timely
	// BrokerServerResponse from the expected Psiphon server. See the comment
	// in evictedPendingServerRequest.

	isDomain := net.ParseIP(destHost) == nil
	if isDomain && !b.config.AllowDomainDestination(geoIPData) {
		return nil, errors.TraceNew("domain destination disallowed")
	}

	if !serverEntry.IsValidDialAddress(networkProtocol.String(), destHost, destPortNum) {
		return nil, errors.TraceNew("invalid destination address")
	}

	// Extract and return the key material to be used for the secure session
	// and BrokerServer exchange between the broker and the Psiphon server
	// corresponding to this server entry.

	params := &serverParams{
		serverID: serverID,
	}

	sessionPublicKey, err := base64.StdEncoding.DecodeString(
		serverEntry.InProxySessionPublicKey)
	if err != nil {
		return nil, errors.Trace(err)
	}
	if len(sessionPublicKey) != len(params.sessionPublicKey) {
		return nil, errors.TraceNew("invalid session public key length")
	}

	sessionRootObfuscationSecret, err := base64.StdEncoding.DecodeString(
		serverEntry.InProxySessionRootObfuscationSecret)
	if err != nil {
		return nil, errors.Trace(err)
	}
	if len(sessionRootObfuscationSecret) != len(params.sessionRootObfuscationSecret) {
		return nil, errors.TraceNew("invalid session root obfuscation secret length")
	}

	copy(params.sessionPublicKey[:], sessionPublicKey)
	copy(params.sessionRootObfuscationSecret[:], sessionRootObfuscationSecret)

	return params, nil
}

func (b *Broker) initializeCommonCompartmentIDHashing() {

	// Proxies without personal compartment IDs are randomly assigned to the
	// set of common, Psiphon-specified, compartment IDs. These common
	// compartment IDs are then distributed to targeted clients through
	// tactics or embedded in OSLs, to limit access to proxies.
	//
	// Use consistent hashing in an effort to keep a consistent assignment of
	// proxies (as specified by proxy ID, which covers all announcements for
	// a single proxy). This is more of a concern for long-lived, permanent
	// proxies that are not behind any NAT.
	//
	// Even with consistent hashing, a subset of proxies will still change
	// assignment when CommonCompartmentIDs changes.

	consistentMembers := make([]consistent.Member, len(b.config.CommonCompartmentIDs))
	for i, compartmentID := range b.config.CommonCompartmentIDs {
		consistentMembers[i] = consistentMember(compartmentID.String())
	}

	b.commonCompartments = consistent.New(
		consistentMembers,
		consistent.Config{
			PartitionCount:    consistent.DefaultPartitionCount,
			ReplicationFactor: consistent.DefaultReplicationFactor,
			Load:              consistent.DefaultLoad,
			Hasher:            xxhasher{},
		})
}

// xxhasher wraps github.com/cespare/xxhash.Sum64 in the interface expected by
// github.com/buraksezer/consistent. xxhash is a high quality hash function
// used in github.com/buraksezer/consistent examples.
type xxhasher struct{}

func (h xxhasher) Sum64(data []byte) uint64 {
	return xxhash.Sum64(data)
}

// consistentMember wraps the string type with the interface expected by
// github.com/buraksezer/consistent.
type consistentMember string

func (m consistentMember) String() string {
	return string(m)
}

func (b *Broker) selectCommonCompartmentID(proxyID ID) (ID, error) {

	compartmentID, err := IDFromString(
		b.commonCompartments.LocateKey(proxyID[:]).String())
	if err != nil {
		return compartmentID, errors.Trace(err)
	}

	return compartmentID, nil
}
