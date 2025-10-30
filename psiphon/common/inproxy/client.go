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
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
)

const (
	clientOfferRetryDelay  = 1 * time.Second
	clientOfferRetryJitter = 0.3
)

// ClientConn is a network connection to an in-proxy, which is relayed to a
// Psiphon server destination. Psiphon clients use a ClientConn in place of a
// physical TCP or UDP socket connection, passing the ClientConn into tunnel
// protocol dials. ClientConn implements both net.Conn and net.PacketConn,
// with net.PacketConn's ReadFrom/WriteTo behaving as if connected to the
// initial dial address.
type ClientConn struct {
	config       *ClientConfig
	webRTCConn   *webRTCConn
	connectionID ID
	remoteAddr   net.Addr
	metrics      common.LogFields

	relayMutex         sync.Mutex
	initialRelayPacket []byte
}

// ClientConfig specifies the configuration for a ClientConn dial.
type ClientConfig struct {

	// Logger is used to log events.
	Logger common.Logger

	// EnableWebRTCDebugLogging indicates whether to emit WebRTC debug logs.
	EnableWebRTCDebugLogging bool

	// BaseAPIParameters should be populated with Psiphon handshake metrics
	// parameters. These will be sent to and logger by the broker.
	BaseAPIParameters common.APIParameters

	// BrokerClient is the BrokerClient to use for broker API calls. The
	// BrokerClient may be shared with other client dials, allowing for
	// connection and session reuse.
	BrokerClient *BrokerClient

	// WebRTCDialCoordinator specifies specific WebRTC dial strategies and
	// settings; WebRTCDialCoordinator also facilities dial replay by
	// receiving callbacks when individual dial steps succeed or fail.
	WebRTCDialCoordinator WebRTCDialCoordinator

	// ReliableTransport specifies whether to use reliable delivery with the
	// underlying WebRTC DataChannel that relays the ClientConn traffic. When
	// using a ClientConn to proxy traffic that expects reliable delivery, as
	// if the physical network protocol were TCP, specify true. When using a
	// ClientConn to proxy traffic that expects unreliable delivery, such as
	// QUIC protocols expecting the physical network protocol UDP, specify
	// false.
	ReliableTransport bool

	// DialNetworkProtocol specifies whether the in-proxy will relay TCP or UDP
	// traffic.
	DialNetworkProtocol NetworkProtocol

	// DialAddress is the host:port destination network address the in-proxy
	// will relay traffic to.
	DialAddress string

	// RemoteAddrOverride, when specified, is the address to be returned by
	// ClientConn.RemoteAddr. When not specified, ClientConn.RemoteAddr
	// returns a zero-value address.
	RemoteAddrOverride string

	// PackedDestinationServerEntry is a signed Psiphon server entry
	// corresponding to the destination dial address. This signed server
	// entry is sent to the broker, which will use it to validate that the
	// server is a valid in-proxy destination.
	//
	// The expected format is CBOR-encoded protoco.PackedServerEntryFields,
	// with the caller invoking  ServerEntryFields.RemoveUnsignedFields to
	// prune local, unnsigned fields before sending.
	PackedDestinationServerEntry []byte

	// MustUpgrade is a callback that is invoked when a MustUpgrade flag is
	// received from the broker. When MustUpgrade is received, the client
	// should be stopped and the user should be prompted to upgrade before
	// restarting the client.
	//
	// In Psiphon, MustUpgrade may be ignored when not running in
	// in-proxy-only personal pairing mode, as other tunnel protocols remain
	// available.
	MustUpgrade func()
}

// DialClient establishes an in-proxy connection for relaying traffic to the
// specified destination. DialClient first contacts the broker and initiates
// an in-proxy pairing. config.BrokerClient may be shared by multiple dials,
// and may have a preexisting connection and session with the broker.
func DialClient(
	ctx context.Context,
	config *ClientConfig) (retConn *ClientConn, retErr error) {

	startTime := time.Now()
	metrics := common.LogFields{}

	// Configure the value returned by ClientConn.RemoteAddr. If no
	// config.RemoteAddrOverride is specified, RemoteAddr will return a
	// zero-value, non-nil net.Addr. The underlying webRTCConn.RemoteAddr
	// returns only nil.

	var remoteAddr net.Addr
	var addrPort netip.AddrPort
	if config.RemoteAddrOverride != "" {

		// ParseAddrPort does not perform any domain resolution. The addr
		// portion must be an IP address.
		var err error
		addrPort, err = netip.ParseAddrPort(config.RemoteAddrOverride)
		if err != nil {
			return nil, errors.Trace(err)
		}
	}

	switch config.DialNetworkProtocol {
	case NetworkProtocolTCP:
		remoteAddr = net.TCPAddrFromAddrPort(addrPort)
	case NetworkProtocolUDP:
		remoteAddr = net.UDPAddrFromAddrPort(addrPort)
	default:
		return nil, errors.TraceNew("unexpected DialNetworkProtocol")
	}

	// Reset and configure port mapper component, as required. See
	// initPortMapper comment.
	initPortMapper(config.WebRTCDialCoordinator)

	// Future improvements:
	//
	// - The broker connection and session, when not already established,
	//   could be established concurrent with the WebRTC offer setup
	//   (STUN/ICE gathering).
	//
	// - The STUN state used for NAT discovery could be reused for the WebRTC
	//   dial.
	//
	// - A subsequent WebRTC offer setup could be run concurrent with the
	//   client offer request, in case that request or WebRTC connections
	//   fails, so that the offer is immediately ready for a retry.

	if config.WebRTCDialCoordinator.DiscoverNAT() {

		// NAT discovery, using the RFC5780 algorithms is optional and
		// conditional on the DiscoverNAT flag. Discovery is performed
		// synchronously, so that NAT topology metrics can be reported to the
		// broker in the ClientOffer request. For clients, NAT discovery is
		// intended to be performed at a low sampling rate, since the RFC5780
		// traffic may be unusual (differs from standard STUN requests for
		// ICE), the port mapping probe traffic may be unusual, and since
		// this step delays the dial. Clients should to cache their NAT
		// discovery outcomes, associated with the current network by network
		// ID, so metrics can be reported even without a discovery step; this
		// is facilitated by WebRTCDialCoordinator.
		//
		// NAT topology metrics are used by the broker to optimize client and
		// in-proxy matching.

		NATDiscover(
			ctx,
			&NATDiscoverConfig{
				Logger:                config.Logger,
				WebRTCDialCoordinator: config.WebRTCDialCoordinator,
			})

		duration := time.Since(startTime)
		metrics["inproxy_dial_nat_discovery_duration"] = fmt.Sprintf("%d", duration/time.Millisecond)
		config.Logger.WithTraceFields(
			common.LogFields{"duration": duration.String()}).Info("NAT discovery complete")
		startTime = time.Now()
	}

	var result *clientWebRTCDialResult
	var lastErr error

	for attempt := 0; ; attempt += 1 {

		previousAttemptsDuration := time.Since(startTime)

		// Repeatedly try to establish in-proxy/WebRTC connection until the
		// dial context is canceled or times out.
		//
		// If a broker request fails, the WebRTCDialCoordinator
		// BrokerClientRoundTripperFailed callback will be invoked, so the
		// Psiphon client will have an opportunity to select new broker
		// connection parameters before a retry. Similarly, when STUN servers
		// fail, WebRTCDialCoordinator STUNServerAddressFailed will be
		// invoked, giving the Psiphon client an opportunity to select new
		// STUN server parameter -- although, in this failure case, the
		// WebRTC connection attempt can succeed with other ICE candidates or
		// no ICE candidates.

		err := ctx.Err()
		if err != nil {
			if lastErr != nil {
				err = fmt.Errorf(
					"%w, attempts: %d, lastErr: %w", err, attempt, lastErr)
			}
			return nil, errors.Trace(err)
		}

		var retry bool
		result, retry, err = dialClientWebRTCConn(ctx, config)
		if err == nil {

			if attempt > 0 {
				// Record the time elapsed in previous attempts.
				metrics["inproxy_dial_failed_attempts_duration"] =
					fmt.Sprintf("%d", previousAttemptsDuration/time.Millisecond)
				config.Logger.WithTraceFields(
					common.LogFields{
						"duration": previousAttemptsDuration.String()}).Info("previous failed attempts")
			}

			break
		}

		lastErr = err

		if retry {
			config.Logger.WithTraceFields(common.LogFields{"error": err}).Warning("dial failed")

			// This delay is intended avoid overloading the broker with
			// repeated requests. A jitter is applied to mitigate a traffic
			// fingerprint.

			brokerCoordinator := config.BrokerClient.GetBrokerDialCoordinator()
			common.SleepWithJitter(
				ctx,
				common.ValueOrDefault(brokerCoordinator.OfferRetryDelay(), clientOfferRetryDelay),
				common.ValueOrDefault(brokerCoordinator.OfferRetryJitter(), clientOfferRetryJitter))

			continue
		}

		return nil, errors.Trace(err)
	}

	metrics.Add(result.metrics)

	return &ClientConn{
		config:             config,
		webRTCConn:         result.conn,
		connectionID:       result.connectionID,
		remoteAddr:         remoteAddr,
		metrics:            metrics,
		initialRelayPacket: result.relayPacket,
	}, nil
}

// GetConnectionID returns the in-proxy connection ID, which the client should
// include with its Psiphon handshake parameters.
func (conn *ClientConn) GetConnectionID() ID {
	return conn.connectionID
}

// InitialRelayPacket returns the initial packet in the broker->server
// messaging session. The client must relay these packets to facilitate this
// message exchange. Session security ensures clients cannot decrypt, modify,
// or replay these session packets. The Psiphon client will sent the initial
// packet as a parameter in the Psiphon server handshake request.
func (conn *ClientConn) InitialRelayPacket() []byte {
	conn.relayMutex.Lock()
	defer conn.relayMutex.Unlock()

	relayPacket := conn.initialRelayPacket
	conn.initialRelayPacket = nil
	return relayPacket
}

// RelayPacket takes any server->broker messaging session packets the client
// receives and relays them back to the broker. RelayPacket returns the next
// broker->server packet, if any, or nil when the message exchange is
// complete. Psiphon clients receive a server->broker packet in the Psiphon
// server handshake response and exchange additional packets in a
// post-handshake Psiphon server request.
//
// If RelayPacket fails, the client should close the ClientConn and redial.
func (conn *ClientConn) RelayPacket(
	ctx context.Context, in []byte) ([]byte, error) {

	// Future improvement: the client relaying these packets back to the
	// broker is potentially an inter-flow fingerprint, alternating between
	// the WebRTC flow and the client's broker connection. It may be possible
	// to avoid this by having the client connect to the broker via the
	// tunnel, resuming its broker session and relaying any further packets.

	// Limitation: here, this mutex only ensures that this ClientConn doesn't
	// make concurrent ClientRelayedPacket requests. The client must still
	// ensure that the packets are delivered in the correct relay sequence.
	conn.relayMutex.Lock()
	defer conn.relayMutex.Unlock()

	// ClientRelayedPacket applies
	// BrokerDialCoordinator.RelayedPacketRequestTimeout as the request
	// timeout.
	relayResponse, err := conn.config.BrokerClient.ClientRelayedPacket(
		ctx,
		&ClientRelayedPacketRequest{
			ConnectionID:     conn.connectionID,
			PacketFromServer: in,
		})
	if err != nil {
		return nil, errors.Trace(err)
	}

	return relayResponse.PacketToServer, nil
}

type clientWebRTCDialResult struct {
	conn         *webRTCConn
	connectionID ID
	relayPacket  []byte
	metrics      common.LogFields
}

func dialClientWebRTCConn(
	ctx context.Context,
	config *ClientConfig) (retResult *clientWebRTCDialResult, retRetry bool, retErr error) {

	startTime := time.Now()
	metrics := common.LogFields{}

	brokerCoordinator := config.BrokerClient.GetBrokerDialCoordinator()
	personalCompartmentIDs := brokerCoordinator.PersonalCompartmentIDs()
	commonCompartmentIDs := brokerCoordinator.CommonCompartmentIDs()

	if len(personalCompartmentIDs) == 0 && len(commonCompartmentIDs) == 0 {
		return nil, false, errors.TraceNew("no compartment IDs")
	}

	// In personal pairing mode, RFC 1918/4193 private IP addresses are
	// included in SDPs.
	hasPersonalCompartmentIDs := len(personalCompartmentIDs) > 0

	// Initialize the WebRTC offer

	doTLSRandomization := config.WebRTCDialCoordinator.DoDTLSRandomization()
	useMediaStreams := config.WebRTCDialCoordinator.UseMediaStreams()
	trafficShapingParameters := config.WebRTCDialCoordinator.TrafficShapingParameters()
	clientRootObfuscationSecret := config.WebRTCDialCoordinator.ClientRootObfuscationSecret()

	webRTCConn, SDP, SDPMetrics, err := newWebRTCConnForOffer(
		ctx, &webRTCConfig{
			Logger:                      config.Logger,
			EnableDebugLogging:          config.EnableWebRTCDebugLogging,
			WebRTCDialCoordinator:       config.WebRTCDialCoordinator,
			ClientRootObfuscationSecret: clientRootObfuscationSecret,
			DoDTLSRandomization:         doTLSRandomization,
			UseMediaStreams:             useMediaStreams,
			TrafficShapingParameters:    trafficShapingParameters,
			ReliableTransport:           config.ReliableTransport,
		},
		hasPersonalCompartmentIDs)
	if err != nil {
		return nil, true, errors.Trace(err)
	}
	defer func() {
		// Cleanup on early return
		if retErr != nil {
			webRTCConn.Close()
		}
	}()

	duration := time.Since(startTime)
	metrics["inproxy_dial_webrtc_ice_gathering_duration"] = fmt.Sprintf("%d", duration/time.Millisecond)
	config.Logger.WithTraceFields(
		common.LogFields{"duration": duration.String()}).Info("ICE gathering complete")
	startTime = time.Now()

	// Send the ClientOffer request to the broker

	apiParams := common.APIParameters{}
	apiParams.Add(config.BaseAPIParameters)
	apiParams.Add(common.APIParameters(brokerCoordinator.MetricsForBrokerRequests()))

	packedParams, err := protocol.EncodePackedAPIParameters(apiParams)
	if err != nil {
		return nil, false, errors.Trace(err)
	}

	// Here, WebRTCDialCoordinator.NATType may be populated from discovery, or
	// replayed from a previous run on the same network ID.
	// WebRTCDialCoordinator.PortMappingTypes/PortMappingProbe may be
	// populated via the optional NATDiscover run above or in a previous dial.

	// ClientOffer applies BrokerDialCoordinator.OfferRequestTimeout or
	// OfferRequestPersonalTimeout as the request timeout.
	offerResponse, err := config.BrokerClient.ClientOffer(
		ctx,
		&ClientOfferRequest{
			Metrics: &ClientMetrics{
				BaseAPIParameters: packedParams,
				ProtocolVersion:   LatestProtocolVersion,
				NATType:           config.WebRTCDialCoordinator.NATType(),
				PortMappingTypes:  config.WebRTCDialCoordinator.PortMappingTypes(),
			},
			CommonCompartmentIDs:         commonCompartmentIDs,
			PersonalCompartmentIDs:       personalCompartmentIDs,
			ClientOfferSDP:               SDP,
			ICECandidateTypes:            SDPMetrics.iceCandidateTypes,
			ClientRootObfuscationSecret:  clientRootObfuscationSecret,
			DoDTLSRandomization:          doTLSRandomization,
			UseMediaStreams:              useMediaStreams,
			TrafficShapingParameters:     trafficShapingParameters,
			PackedDestinationServerEntry: config.PackedDestinationServerEntry,
			NetworkProtocol:              config.DialNetworkProtocol,
			DestinationAddress:           config.DialAddress,
		},
		hasPersonalCompartmentIDs)
	if err != nil {
		return nil, false, errors.Trace(err)
	}

	duration = time.Since(startTime)
	metrics["inproxy_dial_broker_offer_duration"] = fmt.Sprintf("%d", duration/time.Millisecond)
	config.Logger.WithTraceFields(
		common.LogFields{"duration": duration.String()}).Info("Broker offer complete")
	startTime = time.Now()

	// MustUpgrade has precedence over other cases to ensure the callback is
	// invoked. No retry when rate/entry limited or must upgrade; do retry on
	// no-match, as a match may soon appear.

	if offerResponse.MustUpgrade {

		if config.MustUpgrade != nil {
			config.MustUpgrade()
		}
		return nil, false, errors.TraceNew("must upgrade")

	} else if offerResponse.Limited {

		// Note that the Limited return flag is now returned by the broker in
		// non-rate limiting cases, including invalid server entry tags and
		// proxy answer failures. The Limited flag has been overloaded these
		// cases since it's the current best choice, in these scenarios, for
		// having existing clients abort the in-proxy dial without discarding
		// the broker client.

		return nil, false, errors.TraceNew("limited")

	} else if offerResponse.NoMatch {

		return nil, true, errors.TraceNew("no match")
	}

	if offerResponse.SelectedProtocolVersion < ProtocolVersion1 ||
		(useMediaStreams &&
			offerResponse.SelectedProtocolVersion < ProtocolVersion2) ||
		offerResponse.SelectedProtocolVersion > LatestProtocolVersion {
		return nil, false, errors.Tracef(
			"Unsupported protocol version: %d",
			offerResponse.SelectedProtocolVersion)
	}

	// Establish the WebRTC DataChannel connection

	err = webRTCConn.SetRemoteSDP(
		offerResponse.ProxyAnswerSDP, hasPersonalCompartmentIDs)
	if err != nil {
		return nil, true, errors.Trace(err)
	}

	awaitReadyToProxyCtx, awaitReadyToProxyCancelFunc := context.WithTimeout(
		ctx,
		common.ValueOrDefault(
			config.WebRTCDialCoordinator.WebRTCAwaitReadyToProxyTimeout(), readyToProxyAwaitTimeout))
	defer awaitReadyToProxyCancelFunc()

	err = webRTCConn.AwaitReadyToProxy(awaitReadyToProxyCtx, offerResponse.ConnectionID)
	if err != nil {
		return nil, true, errors.Trace(err)
	}

	duration = time.Since(startTime)
	metrics["inproxy_dial_webrtc_connection_duration"] = fmt.Sprintf("%d", duration/time.Millisecond)
	config.Logger.WithTraceFields(
		common.LogFields{"duration": duration.String()}).Info("WebRTC connection complete")

	return &clientWebRTCDialResult{
		conn:         webRTCConn,
		connectionID: offerResponse.ConnectionID,
		relayPacket:  offerResponse.RelayPacketToServer,
		metrics:      metrics,
	}, false, nil
}

// GetMetrics implements the common.MetricsSource interface.
func (conn *ClientConn) GetMetrics() common.LogFields {
	metrics := common.LogFields{}
	metrics.Add(conn.metrics)
	metrics.Add(conn.webRTCConn.GetMetrics())
	return metrics
}

func (conn *ClientConn) Close() error {
	return errors.Trace(conn.webRTCConn.Close())
}

func (conn *ClientConn) IsClosed() bool {
	return conn.webRTCConn.IsClosed()
}

func (conn *ClientConn) Read(p []byte) (int, error) {
	n, err := conn.webRTCConn.Read(p)
	return n, errors.Trace(err)
}

// Write relays p through the in-proxy connection. len(p) should be under
// 32K.
func (conn *ClientConn) Write(p []byte) (int, error) {
	n, err := conn.webRTCConn.Write(p)
	return n, errors.Trace(err)
}

func (conn *ClientConn) LocalAddr() net.Addr {
	return conn.webRTCConn.LocalAddr()
}

func (conn *ClientConn) RemoteAddr() net.Addr {
	// Do not return conn.webRTCConn.RemoteAddr(), which is always nil.
	return conn.remoteAddr
}

func (conn *ClientConn) SetDeadline(t time.Time) error {
	return conn.webRTCConn.SetDeadline(t)
}

func (conn *ClientConn) SetReadDeadline(t time.Time) error {
	return conn.webRTCConn.SetReadDeadline(t)
}

func (conn *ClientConn) SetWriteDeadline(t time.Time) error {

	// Limitation: this is a workaround; webRTCConn doesn't support
	// SetWriteDeadline, but common/quic calls SetWriteDeadline on
	// net.PacketConns to avoid hanging on EAGAIN when the conn is an actual
	// UDP socket. See the comment in common/quic.writeTimeoutUDPConn. In
	// this case, the conn is not a UDP socket and that particular
	// SetWriteDeadline use case doesn't apply. Silently ignore the deadline
	// and report no error.

	return nil
}

func (conn *ClientConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, err := conn.webRTCConn.Read(b)
	return n, conn.webRTCConn.RemoteAddr(), err
}

func (conn *ClientConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	n, err := conn.webRTCConn.Write(b)
	return n, err
}
