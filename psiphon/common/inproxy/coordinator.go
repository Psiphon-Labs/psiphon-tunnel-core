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
	"net"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
)

// RoundTripper provides a request/response round trip network transport with
// blocking circumvention capabilities. A typical implementation is domain
// fronted HTTPS. RoundTripper is used by clients and proxies to make
// requests to brokers.
//
// The RoundTrip implementation must apply any specified delay before the
// network round trip begins; and apply the specified timeout to the network
// round trip, excluding any delay.
//
// Close must interrupt any in-flight requests and close all network
// resources.
type RoundTripper interface {
	RoundTrip(
		ctx context.Context,
		roundTripDelay time.Duration,
		roundTripTimeout time.Duration,
		requestPayload []byte) (responsePayload []byte, err error)
	Close() error
}

// RoundTripperFailedError is an error type that should be returned from
// RoundTripper.RoundTrip when the round trip transport has permanently
// failed. When RoundTrip returns an error of type RoundTripperFailedError to
// a broker client, the broker client will invoke
// BrokerClientRoundTripperFailed.
type RoundTripperFailedError struct {
	err error
}

func NewRoundTripperFailedError(err error) *RoundTripperFailedError {
	return &RoundTripperFailedError{err: err}
}

func (e *RoundTripperFailedError) Error() string {
	return e.err.Error()
}

// BrokerDialCoordinator provides in-proxy dial parameters and configuration,
// used by both clients and proxies, and an interface for signaling when
// parameters are successful or not, to facilitate replay of successful
// parameters.
//
// Each BrokerDialCoordinator should provide values selected in the context of
// a single network, as identified by a network ID. A distinct
// BrokerDialCoordinator should be created for each in-proxy broker dial,
// with new or replayed parameters selected as appropriate. Multiple in-proxy
// client dials and/or proxy runs may share a single BrokerDialCoordinator,
// reducing round trips required to make broker requests. A
// BrokerDialCoordinator implementation must be safe for concurrent calls.
//
// The Psiphon client is expected to create a new BrokerDialCoordinator for
// use by in-proxy clients when the underlying network changes and tunnels
// are redialed. Similarly, in-proxy proxies should be restarted with a new
// BrokerDialCoordinator when the underlying network changes.
type BrokerDialCoordinator interface {

	// Returns the network ID for the network this BrokerDialCoordinator is
	// associated with. For a single BrokerDialCoordinator, the NetworkID value
	// should not change. Replay-facilitating calls, Succeeded/Failed, all
	// assume the network and network ID remain static. The network ID value
	// is used by in-proxy dials to track internal state that depends on the
	// current network; this includes the port mapping types supported by the
	// network.
	NetworkID() string

	// Returns the network type for the current network, or NetworkTypeUnknown
	// if unknown.
	NetworkType() NetworkType

	// CommonCompartmentIDs is the list of common, Psiphon-managed, in-proxy
	// compartment IDs known to a client. These IDs are delivered through
	// tactics, or embedded in OSLs.
	//
	// At most MaxCompartmentIDs may be sent to a broker; if necessary, the
	// provider may return a subset of known compartment IDs and replay when
	// the overall dial is a success; and/or retain only the most recently
	// discovered compartment IDs.
	//
	// CommonCompartmentIDs is not called for proxies.
	CommonCompartmentIDs() []ID

	// PersonalCompartmentIDs are compartment IDs distributed from proxy
	// operators to client users out-of-band and provide optional access
	// control. For example, a proxy operator may want to provide access only
	// to certain users, and/or users want to use only a proxy run by a
	// certain operator.
	//
	// At most MaxCompartmentIDs may be sent to a broker; for typical use
	// cases, both clients and proxies will specify a single personal
	// compartment ID.
	PersonalCompartmentIDs() []ID

	// DisableWaitToShareSession indicates whether to disable
	// waitToShareSession, where concurrent broker client requests will wait
	// for an in-flight Noise session handshake to complete before
	// proceeding. Without waitToShareSession, multiple Noise session
	// handshakes may be performed concurrently, with the last session
	// retained for reuse. See the comment in BrokerClient.roundTrip, which
	// describes waitToShareSession and its isReadyToShare limitation.
	//
	// In general, waitToShareSession will reduce broker Noise session
	// overhead when there are many concurrent requests and no established
	// session. In certain conditions, waitToShareSession might be faster, if
	// a request waits briefly for another in-flight session establishment.
	//
	// Due to the isReadyToShare limitation, it is expected to be more optimal
	// to disable waitToShareSession for in-proxy clients, so that multiple
	// concurrent INPROXY tunnel protocol dials don't serialize, with all but
	// the first dial awaiting the completion of the first dial's ClientOffer
	// round trip, including the ProxyAnswer. For proxies, it remains
	// preferable to use waitToShareSession, meaning that an initial
	// ProxyAnnounce must complete before others will launch.
	DisableWaitToShareSession() bool

	// BrokerClientPrivateKey is the client or proxy's private key to be used
	// in the secure session established with a broker. Clients should
	// generate ephemeral keys; this is done automatically when a zero-value
	// SessionPrivateKey is returned. Proxies may generate, persist, and
	// long-lived keys to enable traffic attribution to a proxy, identified
	// by a proxy ID, the corresponding public key.
	BrokerClientPrivateKey() SessionPrivateKey

	// BrokerPublicKey is the public key for the broker selected by the
	// provider and reachable via BrokerClientRoundTripper. The broker is
	// authenticated in the secure session.
	BrokerPublicKey() SessionPublicKey

	// BrokerRootObfuscationSecret is the root obfuscation secret for the
	// broker and used in the secure session.
	BrokerRootObfuscationSecret() ObfuscationSecret

	// BrokerClientRoundTripper returns a RoundTripper to use for broker
	// requests. The provider handles selecting a broker and broker
	// addressing, as well as providing a round trip network transport with
	// blocking circumvention capabilities. A typical implementation is
	// domain fronted HTTPS. The RoundTripper should offer persistent network
	// connections and request multiplexing, for example with HTTP/2, so that
	// a single connection can be used for many concurrent requests.
	//
	// Clients and proxies make round trips to establish a secure session with
	// the broker, on top of the provided transport, and to exchange API
	// requests with the broker.
	//
	// The implementation must return a RoundTripper connecting to the same
	// broker for every call, as multiple-request sequences such as
	// ProxyAnnounce and ProxyAnswer depend on broker state.
	BrokerClientRoundTripper() (RoundTripper, error)

	// BrokerClientRoundTripperSucceeded is called after a successful round
	// trip using the specified RoundTripper. This signal is used to set
	// replay for the round tripper's successful dial parameters.
	// BrokerClientRoundTripperSucceeded is called once per successful round
	// trip; the provider can choose to set replay only once.
	BrokerClientRoundTripperSucceeded(roundTripper RoundTripper)

	// BrokerClientRoundTripperSucceeded is called after a failed round trip
	// using the specified RoundTripper. This signal is used to clear replay
	// for the round tripper's unsuccessful dial parameters. The provider
	// will arrange for a new RoundTripper to be returned from the next
	// BrokerClientRoundTripper call, discarding the current RoundTripper
	// after closing its network resources.
	BrokerClientRoundTripperFailed(roundTripper RoundTripper)

	// BrokerClientNoMatch is called after a Client Offer fails due to no
	// match. This signal may be used to rotate to a new broker in order to
	// find a match. In personal pairing mode, clients should rotate on no
	// match, as the corresponding proxy may be announcing only on another
	// broker. In common pairing mode, clients may rotate, in case common
	// proxies are not well balanced across brokers.
	BrokerClientNoMatch(roundTripper RoundTripper)

	// MetricsForBrokerRequests returns the metrics, associated with the
	// broker client instance, which are to be added to the base API
	// parameters included in client and proxy requests sent to the broker.
	// This includes fronting_provider_id, which varies depending on the
	// broker client dial and isn't a fixed base API parameter value.
	MetricsForBrokerRequests() common.LogFields

	SessionHandshakeRoundTripTimeout() time.Duration
	AnnounceRequestTimeout() time.Duration
	AnnounceDelay() time.Duration
	AnnounceMaxBackoffDelay() time.Duration
	AnnounceDelayJitter() float64
	AnswerRequestTimeout() time.Duration
	OfferRequestTimeout() time.Duration
	OfferRequestPersonalTimeout() time.Duration
	OfferRetryDelay() time.Duration
	OfferRetryJitter() float64
	RelayedPacketRequestTimeout() time.Duration
	DSLRequestTimeout() time.Duration
}

// WebRTCDialCoordinator provides in-proxy dial parameters and configuration,
// used by both clients and proxies, and an interface for signaling when
// parameters are successful or not, to facilitate replay of successful
// parameters.
//
// Each WebRTCDialCoordinator should provide values selected in the context of
// a single network, as identified by a network ID. A distinct
// WebRTCDialCoordinator should be created for each client in-proxy dial, with
// new or replayed parameters selected as appropriate. One proxy run uses a
// single WebRTCDialCoordinator for all proxied connections. The proxy should
// be restarted with a new WebRTCDialCoordinator when the underlying network
// changes.
//
// A WebRTCDialCoordinator implementation must be safe for concurrent calls.
type WebRTCDialCoordinator interface {

	// Returns the network ID for the network this WebRTCDialCoordinator is
	// associated with. For a single WebRTCDialCoordinator, the NetworkID
	// value should not change. Replay-facilitating calls, Succeeded/Failed,
	// all assume the network and network ID remain static. The network ID
	// value is used by in-proxy dials to track internal state that depends
	// on the current network; this includes the port mapping types supported
	// by the network.
	NetworkID() string

	// Returns the network type for the current network, or NetworkTypeUnknown
	// if unknown.
	NetworkType() NetworkType

	// ClientRootObfuscationSecret is the root obfuscation secret generated by
	// or replayed by the client, which will be used to drive and replay
	// obfuscation operations for the WebRTC dial, including any DTLS
	// randomization. The proxy receives the same root obfuscation secret,
	// relayed by the broker, and so the client's selection drives
	// obfuscation/replay on both sides.
	ClientRootObfuscationSecret() ObfuscationSecret

	// DoDTLSRandomization indicates whether to perform DTLS
	// Client/ServerHello randomization. DoDTLSRandomization is specified by
	// clients, which may use a weighted coin flip or a replay to determine
	// the value.
	DoDTLSRandomization() bool

	// UseMediaStreams indicates whether to use WebRTC media streams to tunnel
	// traffic. When false, a WebRTC data channel is used to tunnel traffic.
	UseMediaStreams() bool

	// TrafficShapingParameters returns parameters specifying how to perform
	// data channel or media stream traffic shapping -- random padding and
	// decoy messages. Returns nil when no traffic shaping is to be performed.
	TrafficShapingParameters() *TrafficShapingParameters

	// STUNServerAddress selects a STUN server to use for this dial. When
	// RFC5780 is true, the STUN server must support RFC5780 NAT discovery;
	// otherwise, only basic STUN bind operation support is required. Clients
	// and proxies will receive a list of STUN server candidates via tactics,
	// and select a candidate at random or replay for each dial. If
	// STUNServerAddress returns "", STUN operations are skipped but the dial
	// may still succeed if a port mapping can be established.
	STUNServerAddress(RFC5780 bool) string

	// STUNServerAddressSucceeded is called after a successful STUN operation
	// with the STUN server specified by the address. This signal is used to
	// set replay for successful STUN servers. STUNServerAddressSucceeded
	// will be called when the STUN opertion succeeds, regardless of the
	// outcome of the rest of the dial. RFC5780 is true when the STUN server
	// was used for NAT discovery.
	STUNServerAddressSucceeded(RFC5780 bool, address string)

	// STUNServerAddressFailed is called after a failed STUN operation and is
	// used to clear replay for the specified STUN server.
	STUNServerAddressFailed(RFC5780 bool, address string)

	// DiscoverNAT indicates whether a client dial should start with NAT
	// discovery. Discovering and reporting the client NAT type will assist
	// in broker matching. However, RFC5780 NAT discovery can slow down a
	// dial and potentially looks like atypical network traffic. Client NAT
	// discovery is controlled by tactics and may be disabled or set to run
	// with a small probability. Discovered NAT types and portmapping types
	// may be cached and used with future dials via SetNATType/NATType and
	// SetPortMappingTypes/PortMappingTypes.
	//
	// Proxies always perform NAT discovery on start up, since that doesn't
	// delay a client dial.
	DiscoverNAT() bool

	// DisableSTUN indicates whether to skip STUN operations.
	DisableSTUN() bool

	// DisablePortMapping indicates whether to skip port mapping operations.
	DisablePortMapping() bool

	// DisableInboundForMobileNetworks indicates that all attempts to set up
	// inbound operations -- including STUN and port mapping -- should be
	// skipped when the network type is NetworkTypeMobile. This skips
	// operations that can slow down dials and and unlikely to succeed on
	// most mobile networks with CGNAT.
	DisableInboundForMobileNetworks() bool

	// DisableIPv6ICECandidates omits all IPv6 ICE candidates.
	DisableIPv6ICECandidates() bool

	// NATType returns any persisted NAT type for the current network, as set
	// by SetNATType. When NATTypeUnknown is returned, NAT discovery may be
	// run.
	NATType() NATType

	// SetNATType is called when the NAT type for the current network has been
	// discovered. The provider should persist this value, associated with
	// the current network ID and with a reasonable TTL, so the value can be
	// reused in subsequent dials without having to re-run NAT discovery.
	SetNATType(t NATType)

	// PortMappingTypes returns any persisted, supported port mapping types
	// for the current network, as set by SetPortMappingTypes. When an empty
	// list is returned port mapping discovery may be run. A list containing
	// only PortMappingTypeNone indicates that no supported port mapping
	// types were discovered.
	PortMappingTypes() PortMappingTypes

	// SetPortMappingTypes is called with the supported port mapping types
	// discovered for the current network. The provider should persist this
	// value, associated with the current network ID and with a reasonable
	// TTL, so the value can be reused in subsequent dials without having to
	// re-run port mapping discovery.
	SetPortMappingTypes(t PortMappingTypes)

	// PortMappingProbe returns any persisted PortMappingProbe for the current
	// network, which is used to establish port mappings.
	PortMappingProbe() *PortMappingProbe

	// SetPortMappingProbe receives a PortMappingProbe instance, which caches
	// complete port mapping service details and is a required input for
	// subsequent port mapping establishment on the current network.
	SetPortMappingProbe(p *PortMappingProbe)

	// ResolveAddress resolves a domain and returns its IP address. Clients
	// and proxies may use this to hook into the Psiphon custom resolver. The
	// provider adds the custom resolver tactics and network ID parameters
	// required by psiphon/common.Resolver.
	ResolveAddress(ctx context.Context, network, address string) (string, error)

	// UDPListen creates a local UDP socket. The socket should be bound to a
	// specific interface as required for VPN modes, and set a write timeout
	// to mitigate the issue documented in psiphon/common.WriteTimeoutUDPConn.
	UDPListen(ctx context.Context) (net.PacketConn, error)

	// UDPConn creates a local UDP socket "connected" to the specified remote
	// address. The socket should be excluded from VPN routing. This socket
	// is used to determine the local address of the active interface the OS
	// will select for the specified network ("udp4" for IPv4 or "udp6" for
	// IPv6) and remote destination. For this use case, the socket will not
	// be used to send network traffic.
	UDPConn(ctx context.Context, network, remoteAddress string) (net.PacketConn, error)

	// BindToDevice binds a socket, specified by the file descriptor, to an
	// interface that isn't routed through a VPN when Psiphon is running in
	// VPN mode. BindToDevice is used in cases where a custom dialer cannot
	// be used, and UDPListen cannot be called. If no file descriptor
	// operation is required, BindToDevice should take no action and return
	// nil.
	BindToDevice(fileDescriptor int) error

	// ProxyUpstreamDial is used by the proxy when dialing a TCP or UDP
	// upstream connection to a destination Psiphon server. This dial
	// callback allows for TCP/UDP-level dial tactics parameters to be
	// applied, as appropriate, to the upstream dial from the proxy vantage
	// point; and possible replay of those parameters. In addition,
	// underlying sockets should be bound to a specific interface as required
	// when the proxy app is also running a VPN.
	ProxyUpstreamDial(ctx context.Context, network, address string) (net.Conn, error)

	DiscoverNATTimeout() time.Duration
	WebRTCAnswerTimeout() time.Duration
	WebRTCAwaitPortMappingTimeout() time.Duration
	WebRTCAwaitReadyToProxyTimeout() time.Duration
	ProxyDestinationDialTimeout() time.Duration
	ProxyRelayInactivityTimeout() time.Duration
}
