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
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
)

const (
	ProxyProtocolVersion1 = 1
	MaxCompartmentIDs     = 10
)

// ID is a unique identifier used to identify inproxy connections and actors.
type ID [32]byte

// MakeID generates a new ID using crypto/rand.
func MakeID() (ID, error) {
	var id ID
	for {
		_, err := rand.Read(id[:])
		if err != nil {
			return id, errors.Trace(err)
		}
		if !id.Zero() {
			return id, nil
		}
	}
}

// IDFromString returns an ID given its string encoding.
func IDFromString(s string) (ID, error) {
	var id ID
	return id, errors.Trace(fromBase64String(s, id[:]))
}

func fromBase64String(s string, b []byte) error {
	value, err := base64.RawStdEncoding.DecodeString(s)
	if err != nil {
		return errors.Trace(err)
	}
	if len(value) != len(b) {
		return errors.TraceNew("invalid length")
	}
	copy(b, value)
	return nil
}

// IDsFromStrings returns a list of IDs given a list of string encodings.
func IDsFromStrings(strs []string) ([]ID, error) {
	var ids []ID
	for _, str := range strs {
		id, err := IDFromString(str)
		if err != nil {
			return nil, errors.Trace(err)
		}
		ids = append(ids, id)
	}
	return ids, nil
}

// MarshalText emits IDs as base64.
func (id ID) MarshalText() ([]byte, error) {
	return []byte(id.String()), nil
}

// String emits IDs as base64.
func (id ID) String() string {
	return base64.RawStdEncoding.EncodeToString([]byte(id[:]))
}

// Equal indicates whether two IDs are equal. It uses a constant time
// comparison.
func (id ID) Equal(x ID) bool {
	return subtle.ConstantTimeCompare(id[:], x[:]) == 1
}

// Zero indicates whether the ID is the zero value.
func (id ID) Zero() bool {
	var zero ID
	return id.Equal(zero)
}

// HaveCommonIDs indicates whether two lists of IDs have a common entry.
func HaveCommonIDs(a, b []ID) bool {
	for _, x := range a {
		for _, y := range b {
			// Each comparison is constant time, but the number of comparisons
			// varies and might leak the size of a list.
			if x.Equal(y) {
				return true
			}
		}
	}
	return false
}

// NetworkType is the type of a network, such as WiFi or Mobile. This enum is
// used for compact API message encoding.
type NetworkType int32

const (
	NetworkTypeUnknown NetworkType = iota
	NetworkTypeWiFi
	NetworkTypeMobile
)

// NetworkProtocol is an Internet protocol, such as TCP or UDP. This enum is
// used for compact API message encoding.
type NetworkProtocol int32

const (
	NetworkProtocolTCP NetworkProtocol = iota
	NetworkProtocolUDP
)

// NetworkProtocolFromString converts a "net" package network protocol string
// value to a NetworkProtocol.
func NetworkProtocolFromString(networkProtocol string) (NetworkProtocol, error) {
	switch networkProtocol {
	case "tcp":
		return NetworkProtocolTCP, nil
	case "udp":
		return NetworkProtocolUDP, nil
	}
	var p NetworkProtocol
	return p, errors.Tracef("unknown network protocol: %s", networkProtocol)
}

// String converts a NetworkProtocol to a "net" package network protocol string.
func (p NetworkProtocol) String() string {
	switch p {
	case NetworkProtocolTCP:
		return "tcp"
	case NetworkProtocolUDP:
		return "udp"
	}
	// This case will cause net dials to fail.
	return ""
}

// IsStream indicates if the NetworkProtocol is stream-oriented (e.g., TCP)
// and not packet-oriented (e.g., UDP).
func (p NetworkProtocol) IsStream() bool {
	switch p {
	case NetworkProtocolTCP:
		return true
	case NetworkProtocolUDP:
		return false
	}
	return false
}

// ProxyMetrics are network topolology and resource metrics provided by a
// proxy to a broker. The broker uses this information when matching proxies
// and clients.
type ProxyMetrics struct {
	BaseAPIParameters             protocol.PackedAPIParameters `cbor:"1,keyasint,omitempty"`
	ProxyProtocolVersion          int32                        `cbor:"2,keyasint,omitempty"`
	NATType                       NATType                      `cbor:"3,keyasint,omitempty"`
	PortMappingTypes              PortMappingTypes             `cbor:"4,keyasint,omitempty"`
	MaxClients                    int32                        `cbor:"6,keyasint,omitempty"`
	ConnectingClients             int32                        `cbor:"7,keyasint,omitempty"`
	ConnectedClients              int32                        `cbor:"8,keyasint,omitempty"`
	LimitUpstreamBytesPerSecond   int64                        `cbor:"9,keyasint,omitempty"`
	LimitDownstreamBytesPerSecond int64                        `cbor:"10,keyasint,omitempty"`
	PeakUpstreamBytesPerSecond    int64                        `cbor:"11,keyasint,omitempty"`
	PeakDownstreamBytesPerSecond  int64                        `cbor:"12,keyasint,omitempty"`
}

// ClientMetrics are network topolology metrics provided by a client to a
// broker. The broker uses this information when matching proxies and
// clients.
type ClientMetrics struct {
	BaseAPIParameters    protocol.PackedAPIParameters `cbor:"1,keyasint,omitempty"`
	ProxyProtocolVersion int32                        `cbor:"2,keyasint,omitempty"`
	NATType              NATType                      `cbor:"3,keyasint,omitempty"`
	PortMappingTypes     PortMappingTypes             `cbor:"4,keyasint,omitempty"`
}

// ProxyAnnounceRequest is an API request sent from a proxy to a broker,
// announcing that it is available for a client connection. Proxies send one
// ProxyAnnounceRequest for each available client connection. The broker will
// match the proxy with a a client and return WebRTC connection information
// in the response.
//
// PersonalCompartmentIDs limits the clients to those that supply one of the
// specified compartment IDs; personal compartment IDs are distributed from
// proxy operators to client users out-of-band and provide optional access
// control.
//
// The proxy's session public key is an implicit and cryptographically
// verified proxy ID.
type ProxyAnnounceRequest struct {
	PersonalCompartmentIDs []ID          `cbor:"1,keyasint,omitempty"`
	Metrics                *ProxyMetrics `cbor:"2,keyasint,omitempty"`
}

// WebRTCSessionDescription is compatible with pion/webrtc.SessionDescription
// and facilitates the PSIPHON_ENABLE_INPROXY build tag exclusion of pion
// dependencies.
type WebRTCSessionDescription struct {
	Type int    `cbor:"1,keyasint,omitempty"`
	SDP  string `cbor:"2,keyasint,omitempty"`
}

// TODO: send ProxyAnnounceRequest/ClientOfferRequest.Metrics only with the
// first request in a session and cache.

// ProxyAnnounceResponse returns the connection information for a matched
// client. To establish a WebRTC connection, the proxy uses the client's
// offer SDP to create its own answer SDP and send that to the broker in a
// subsequent ProxyAnswerRequest. The ConnectionID is a unique identifier for
// this single connection and must be relayed back in the ProxyAnswerRequest.
//
// ClientRootObfuscationSecret is generated (or replayed) by the client and
// sent to the proxy and used to drive obfuscation operations.
//
// DestinationAddress is the dial address for the Psiphon server the proxy is
// to relay client traffic with. The broker validates that the dial address
// corresponds to a valid Psiphon server.
//
// OperatorMessageJSON is an optional message bundle to be forwarded to the
// user interface for display to the user; for example, to alert the proxy
// operator of configuration issue; the JSON schema is not defined here.
type ProxyAnnounceResponse struct {
	OperatorMessageJSON         string                               `cbor:"1,keyasint,omitempty"`
	TacticsPayload              []byte                               `cbor:"2,keyasint,omitempty"`
	Limited                     bool                                 `cbor:"3,keyasint,omitempty"`
	NoMatch                     bool                                 `cbor:"4,keyasint,omitempty"`
	ConnectionID                ID                                   `cbor:"5,keyasint,omitempty"`
	ClientProxyProtocolVersion  int32                                `cbor:"6,keyasint,omitempty"`
	ClientOfferSDP              WebRTCSessionDescription             `cbor:"7,keyasint,omitempty"`
	ClientRootObfuscationSecret ObfuscationSecret                    `cbor:"8,keyasint,omitempty"`
	DoDTLSRandomization         bool                                 `cbor:"9,keyasint,omitempty"`
	TrafficShapingParameters    *DataChannelTrafficShapingParameters `cbor:"10,keyasint,omitempty"`
	NetworkProtocol             NetworkProtocol                      `cbor:"11,keyasint,omitempty"`
	DestinationAddress          string                               `cbor:"12,keyasint,omitempty"`
}

// ClientOfferRequest is an API request sent from a client to a broker,
// requesting a proxy connection. The client sends its WebRTC offer SDP with
// this request.
//
// Clients specify known compartment IDs and are matched with proxies in those
// compartments. CommonCompartmentIDs are comparment IDs managed by Psiphon
// and revealed through tactics or bundled with server lists.
// PersonalCompartmentIDs are compartment IDs shared privately between users,
// out-of-band.
//
// ClientRootObfuscationSecret is generated (or replayed) by the client and
// sent to the proxy and used to drive obfuscation operations.
//
// To specify the Psiphon server it wishes to proxy to, the client sends the
// full, digitally signed Psiphon server entry to the broker and also the
// specific dial address that it has selected for that server. The broker
// validates the server entry signature, the server in-proxy capability, and
// that the dial address corresponds to the network protocol, IP address or
// domain, and destination port for a valid Psiphon tunnel protocol run by
// the specified server entry.
type ClientOfferRequest struct {
	Metrics                      *ClientMetrics                       `cbor:"1,keyasint,omitempty"`
	CommonCompartmentIDs         []ID                                 `cbor:"2,keyasint,omitempty"`
	PersonalCompartmentIDs       []ID                                 `cbor:"3,keyasint,omitempty"`
	ClientOfferSDP               WebRTCSessionDescription             `cbor:"4,keyasint,omitempty"`
	ICECandidateTypes            ICECandidateTypes                    `cbor:"5,keyasint,omitempty"`
	ClientRootObfuscationSecret  ObfuscationSecret                    `cbor:"6,keyasint,omitempty"`
	DoDTLSRandomization          bool                                 `cbor:"7,keyasint,omitempty"`
	TrafficShapingParameters     *DataChannelTrafficShapingParameters `cbor:"8,keyasint,omitempty"`
	PackedDestinationServerEntry []byte                               `cbor:"9,keyasint,omitempty"`
	NetworkProtocol              NetworkProtocol                      `cbor:"10,keyasint,omitempty"`
	DestinationAddress           string                               `cbor:"11,keyasint,omitempty"`
}

// DataChannelTrafficShapingParameters specifies a data channel traffic
// shaping configuration, including random padding and decoy messages.
// Clients determine their own traffic shaping configuration, and generate
// and send a configuration for the peer proxy to use.
type DataChannelTrafficShapingParameters struct {
	MinPaddedMessages       int     `cbor:"1,keyasint,omitempty"`
	MaxPaddedMessages       int     `cbor:"2,keyasint,omitempty"`
	MinPaddingSize          int     `cbor:"3,keyasint,omitempty"`
	MaxPaddingSize          int     `cbor:"4,keyasint,omitempty"`
	MinDecoyMessages        int     `cbor:"5,keyasint,omitempty"`
	MaxDecoyMessages        int     `cbor:"6,keyasint,omitempty"`
	MinDecoySize            int     `cbor:"7,keyasint,omitempty"`
	MaxDecoySize            int     `cbor:"8,keyasint,omitempty"`
	DecoyMessageProbability float64 `cbor:"9,keyasint,omitempty"`
}

// ClientOfferResponse returns the connecting information for a matched proxy.
// The proxy's WebRTC SDP is an answer to the offer sent in
// ClientOfferRequest and is used to begin dialing the WebRTC connection.
//
// Once the client completes its connection to the Psiphon server, it must
// relay a BrokerServerReport to the server on behalf of the broker. This
// relay is conducted within a secure session. First, the client sends
// RelayPacketToServer to the server. Then the client relays any responses to
// the broker using ClientRelayedPacketRequests and continues to relay using
// ClientRelayedPacketRequests until complete. ConnectionID identifies this
// connection and its relayed BrokerServerReport.
type ClientOfferResponse struct {
	Limited                      bool                     `cbor:"1,keyasint,omitempty"`
	NoMatch                      bool                     `cbor:"2,keyasint,omitempty"`
	ConnectionID                 ID                       `cbor:"3,keyasint,omitempty"`
	SelectedProxyProtocolVersion int32                    `cbor:"4,keyasint,omitempty"`
	ProxyAnswerSDP               WebRTCSessionDescription `cbor:"5,keyasint,omitempty"`
	RelayPacketToServer          []byte                   `cbor:"6,keyasint,omitempty"`
}

// TODO: Encode SDPs using CBOR without field names, simliar to packed metrics?

// ProxyAnswerRequest is an API request sent from a proxy to a broker,
// following ProxyAnnounceResponse, with the WebRTC answer SDP corresponding
// to the client offer SDP received in ProxyAnnounceResponse. ConnectionID
// identifies the connection begun in ProxyAnnounceResponse.
//
// If the proxy was unable to establish an answer SDP or failed for some other
// reason, it should still send ProxyAnswerRequest with AnswerError
// populated; the broker will signal the client to abort this connection.
type ProxyAnswerRequest struct {
	ConnectionID                 ID                       `cbor:"1,keyasint,omitempty"`
	SelectedProxyProtocolVersion int32                    `cbor:"2,keyasint,omitempty"`
	ProxyAnswerSDP               WebRTCSessionDescription `cbor:"3,keyasint,omitempty"`
	ICECandidateTypes            ICECandidateTypes        `cbor:"4,keyasint,omitempty"`
	AnswerError                  string                   `cbor:"5,keyasint,omitempty"`
}

// ProxyAnswerResponse is the acknowledgement for a ProxyAnswerRequest.
type ProxyAnswerResponse struct {
}

// ClientRelayedPacketRequest is an API request sent from a client to a
// broker, relaying a secure session packet from the Psiphon server to the
// broker. This relay is a continuation of the broker/server exchange begun
// with ClientOfferResponse.RelayPacketToServer. PacketFromServer is the next
// packet from the server.
//
// When a broker attempts to use an existing session which has expired on the
// server, the packet from the server may contain a signed reset session
// token, which is used to automatically reset and start establishing a new
// session before relaying the payload.
type ClientRelayedPacketRequest struct {
	ConnectionID     ID     `cbor:"1,keyasint,omitempty"`
	PacketFromServer []byte `cbor:"2,keyasint,omitempty"`
}

// ClientRelayedPacketResponse returns the next packet from the broker to the
// server. When PacketToServer is empty, the broker/server exchange is done
// and the client stops relaying packets.
type ClientRelayedPacketResponse struct {
	PacketToServer []byte `cbor:"1,keyasint,omitempty"`
}

// BrokerServerReport is a one-way API call sent from a broker to a
// Psiphon server. This delivers, to the server, information that neither the
// client nor the proxy is trusted to report. ProxyID is the proxy ID to be
// logged with server_tunnel to attribute traffic to a specific proxy.
// ClientIP is the original client IP as seen by the broker; this is the IP
// value to be used in GeoIP-related operations including traffic rules,
// tactics, and OSL progress. ProxyIP is the proxy IP as seen by the broker;
// this value should match the Psiphon's server observed client IP.
// Additional fields are metrics to be logged with server_tunnel.
//
// Using a one-way message here means that, once a broker/server session is
// established, the entire relay can be encasulated in a single additional
// field sent in the Psiphon API handshake. This minimizes observable and
// potentially fingerprintable traffic flows as the client does not need to
// relay any further session packets before starting the tunnel. The
// trade-off is that the broker doesn't get an indication from the server
// that the message was accepted or rejects and cannot directly, in real time
// log any tunnel error associated with the server rejecting the message, or
// log that the relay was completed successfully. These events can be logged
// on the server and logs reconciled using the in-proxy Connection ID.
type BrokerServerReport struct {
	ProxyID                     ID               `cbor:"1,keyasint,omitempty"`
	ConnectionID                ID               `cbor:"2,keyasint,omitempty"`
	MatchedCommonCompartments   bool             `cbor:"3,keyasint,omitempty"`
	MatchedPersonalCompartments bool             `cbor:"4,keyasint,omitempty"`
	ProxyNATType                NATType          `cbor:"5,keyasint,omitempty"`
	ProxyPortMappingTypes       PortMappingTypes `cbor:"6,keyasint,omitempty"`
	ClientNATType               NATType          `cbor:"7,keyasint,omitempty"`
	ClientPortMappingTypes      PortMappingTypes `cbor:"8,keyasint,omitempty"`
	ClientIP                    string           `cbor:"9,keyasint,omitempty"`
	ProxyIP                     string           `cbor:"10,keyasint,omitempty"`
}

// GetNetworkType extracts the network_type from base API metrics and returns
// a corresponding NetworkType. This is the one base metric that is used in
// the broker logic, and not simply logged.
func GetNetworkType(packedBaseParams protocol.PackedAPIParameters) NetworkType {
	baseNetworkType, ok := packedBaseParams.GetNetworkType()
	if !ok {
		return NetworkTypeUnknown
	}
	switch baseNetworkType {
	case "WIFI":
		return NetworkTypeWiFi
	case "MOBILE":
		return NetworkTypeMobile
	}
	return NetworkTypeUnknown
}

// Sanity check values.
const (
	maxICECandidateTypes = 10
	maxPortMappingTypes  = 10

	maxPaddedMessages = 100
	maxPaddingSize    = 16384
	maxDecoyMessages  = 100
	maxDecoySize      = 16384
)

// ValidateAndGetParametersAndLogFields validates the ProxyMetrics and returns
// Psiphon API parameters for processing and common.LogFields for logging.
func (metrics *ProxyMetrics) ValidateAndGetParametersAndLogFields(
	baseAPIParameterValidator common.APIParameterValidator,
	formatter common.APIParameterLogFieldFormatter,
	geoIPData common.GeoIPData) (common.APIParameters, common.LogFields, error) {

	if metrics.BaseAPIParameters == nil {
		return nil, nil, errors.TraceNew("missing base API parameters")
	}

	baseParams, err := protocol.DecodePackedAPIParameters(metrics.BaseAPIParameters)
	if err != nil {
		return nil, nil, errors.Trace(err)
	}

	err = baseAPIParameterValidator(baseParams)
	if err != nil {
		return nil, nil, errors.Trace(err)
	}

	if metrics.ProxyProtocolVersion != ProxyProtocolVersion1 {
		return nil, nil, errors.Tracef("invalid proxy protocol version: %v", metrics.ProxyProtocolVersion)
	}

	if !metrics.NATType.IsValid() {
		return nil, nil, errors.Tracef("invalid NAT type: %v", metrics.NATType)
	}

	if len(metrics.PortMappingTypes) > maxPortMappingTypes {
		return nil, nil, errors.Tracef("invalid portmapping types length: %d", len(metrics.PortMappingTypes))
	}

	if !metrics.PortMappingTypes.IsValid() {
		return nil, nil, errors.Tracef("invalid portmapping types: %v", metrics.PortMappingTypes)
	}

	logFields := formatter(geoIPData, baseParams)

	logFields["proxy_protocol_version"] = metrics.ProxyProtocolVersion
	logFields["nat_type"] = metrics.NATType
	logFields["port_mapping_types"] = metrics.PortMappingTypes
	logFields["max_clients"] = metrics.MaxClients
	logFields["connecting_clients"] = metrics.ConnectingClients
	logFields["connected_clients"] = metrics.ConnectedClients
	logFields["limit_upstream_bytes_per_second"] = metrics.LimitUpstreamBytesPerSecond
	logFields["limit_downstream_bytes_per_second"] = metrics.LimitDownstreamBytesPerSecond
	logFields["peak_upstream_bytes_per_second"] = metrics.PeakUpstreamBytesPerSecond
	logFields["peak_downstream_bytes_per_second"] = metrics.PeakDownstreamBytesPerSecond

	return baseParams, logFields, nil
}

// ValidateAndGetLogFields validates the ClientMetrics and returns
// common.LogFields for logging.
func (metrics *ClientMetrics) ValidateAndGetLogFields(
	baseAPIParameterValidator common.APIParameterValidator,
	formatter common.APIParameterLogFieldFormatter,
	geoIPData common.GeoIPData) (common.LogFields, error) {

	if metrics.BaseAPIParameters == nil {
		return nil, errors.TraceNew("missing base API parameters")
	}

	baseParams, err := protocol.DecodePackedAPIParameters(metrics.BaseAPIParameters)
	if err != nil {
		return nil, errors.Trace(err)
	}

	err = baseAPIParameterValidator(baseParams)
	if err != nil {
		return nil, errors.Trace(err)
	}

	if metrics.ProxyProtocolVersion != ProxyProtocolVersion1 {
		return nil, errors.Tracef("invalid proxy protocol version: %v", metrics.ProxyProtocolVersion)
	}

	if !metrics.NATType.IsValid() {
		return nil, errors.Tracef("invalid NAT type: %v", metrics.NATType)
	}

	if len(metrics.PortMappingTypes) > maxPortMappingTypes {
		return nil, errors.Tracef("invalid portmapping types length: %d", len(metrics.PortMappingTypes))
	}

	if !metrics.PortMappingTypes.IsValid() {
		return nil, errors.Tracef("invalid portmapping types: %v", metrics.PortMappingTypes)
	}

	logFields := formatter(geoIPData, baseParams)

	logFields["proxy_protocol_version"] = metrics.ProxyProtocolVersion
	logFields["nat_type"] = metrics.NATType
	logFields["port_mapping_types"] = metrics.PortMappingTypes

	return logFields, nil
}

// ValidateAndGetParametersAndLogFields validates the ProxyAnnounceRequest and
// returns Psiphon API parameters for processing and common.LogFields for
// logging.
func (request *ProxyAnnounceRequest) ValidateAndGetParametersAndLogFields(
	maxCompartmentIDs int,
	baseAPIParameterValidator common.APIParameterValidator,
	formatter common.APIParameterLogFieldFormatter,
	geoIPData common.GeoIPData) (common.APIParameters, common.LogFields, error) {

	if len(request.PersonalCompartmentIDs) > maxCompartmentIDs {
		return nil, nil, errors.Tracef("invalid compartment IDs length: %d", len(request.PersonalCompartmentIDs))
	}

	if request.Metrics == nil {
		return nil, nil, errors.TraceNew("missing metrics")
	}

	apiParams, logFields, err := request.Metrics.ValidateAndGetParametersAndLogFields(
		baseAPIParameterValidator, formatter, geoIPData)
	if err != nil {
		return nil, nil, errors.Trace(err)
	}

	// PersonalCompartmentIDs are user-generated and shared out-of-band;
	// values are not logged since they may link users.

	hasPersonalCompartmentIDs := len(request.PersonalCompartmentIDs) > 0

	logFields["has_personal_compartment_ids"] = hasPersonalCompartmentIDs

	return apiParams, logFields, nil
}

// ValidateAndGetLogFields validates the ClientOfferRequest and returns
// common.LogFields for logging.
func (request *ClientOfferRequest) ValidateAndGetLogFields(
	maxCompartmentIDs int,
	lookupGeoIP LookupGeoIP,
	baseAPIParameterValidator common.APIParameterValidator,
	formatter common.APIParameterLogFieldFormatter,
	geoIPData common.GeoIPData) ([]byte, common.LogFields, error) {

	if len(request.CommonCompartmentIDs) > maxCompartmentIDs {
		return nil, nil, errors.Tracef(
			"invalid compartment IDs length: %d", len(request.CommonCompartmentIDs))
	}

	if len(request.PersonalCompartmentIDs) > maxCompartmentIDs {
		return nil, nil, errors.Tracef(
			"invalid compartment IDs length: %d", len(request.PersonalCompartmentIDs))
	}

	// The client offer SDP may contain no ICE candidates.
	errorOnNoCandidates := false

	// Client offer SDP candidate addresses must match the country and ASN of
	// the client. Don't facilitate connections to arbitrary destinations.
	filteredSDP, sdpMetrics, err := filterSDPAddresses(
		[]byte(request.ClientOfferSDP.SDP), errorOnNoCandidates, lookupGeoIP, geoIPData)
	if err != nil {
		return nil, nil, errors.Trace(err)
	}

	// The client's self-reported ICECandidateTypes are used instead of the
	// candidate types that can be derived from the SDP, since port mapping
	// types are edited into the SDP in a way that makes them
	// indistinguishable from host candidate types.

	if !request.ICECandidateTypes.IsValid() {
		return nil, nil, errors.Tracef(
			"invalid ICE candidate types: %v", request.ICECandidateTypes)
	}

	if request.Metrics == nil {
		return nil, nil, errors.TraceNew("missing metrics")
	}

	logFields, err := request.Metrics.ValidateAndGetLogFields(
		baseAPIParameterValidator, formatter, geoIPData)
	if err != nil {
		return nil, nil, errors.Trace(err)
	}

	if request.TrafficShapingParameters != nil {
		err := request.TrafficShapingParameters.Validate()
		if err != nil {
			return nil, nil, errors.Trace(err)
		}
	}

	// CommonCompartmentIDs are generated and managed and are a form of
	// obfuscation secret, so are not logged. PersonalCompartmentIDs are
	// user-generated and shared out-of-band; values are not logged since
	// they may link users.

	hasCommonCompartmentIDs := len(request.CommonCompartmentIDs) > 0
	hasPersonalCompartmentIDs := len(request.PersonalCompartmentIDs) > 0

	logFields["has_common_compartment_ids"] = hasCommonCompartmentIDs
	logFields["has_personal_compartment_ids"] = hasPersonalCompartmentIDs
	logFields["ice_candidate_types"] = request.ICECandidateTypes
	logFields["has_IPv6"] = sdpMetrics.hasIPv6
	logFields["filtered_ice_candidates"] = sdpMetrics.filteredICECandidates

	return filteredSDP, logFields, nil
}

// Validate validates the that client has not specified excess traffic shaping
// padding or decoy traffic.
func (params *DataChannelTrafficShapingParameters) Validate() error {

	if params.MinPaddedMessages < 0 ||
		params.MinPaddedMessages > params.MaxPaddedMessages ||
		params.MaxPaddedMessages > maxPaddedMessages {
		return errors.TraceNew("invalid padded messages")
	}

	if params.MinPaddingSize < 0 ||
		params.MinPaddingSize > params.MaxPaddingSize ||
		params.MaxPaddingSize > maxPaddingSize {
		return errors.TraceNew("invalid padding size")
	}

	if params.MinDecoyMessages < 0 ||
		params.MinDecoyMessages > params.MaxDecoyMessages ||
		params.MaxDecoyMessages > maxDecoyMessages {
		return errors.TraceNew("invalid decoy messages")
	}

	if params.MinDecoySize < 0 ||
		params.MinDecoySize > params.MaxDecoySize ||
		params.MaxDecoySize > maxDecoySize {
		return errors.TraceNew("invalid decoy size")
	}

	return nil
}

// ValidateAndGetLogFields validates the ProxyAnswerRequest and returns
// common.LogFields for logging.
func (request *ProxyAnswerRequest) ValidateAndGetLogFields(
	lookupGeoIP LookupGeoIP,
	baseAPIParameterValidator common.APIParameterValidator,
	formatter common.APIParameterLogFieldFormatter,
	geoIPData common.GeoIPData) ([]byte, common.LogFields, error) {

	// The proxy answer SDP must contain at least one ICE candidate.
	errorOnNoCandidates := true

	// Proxy answer SDP candidate addresses must match the country and ASN of
	// the proxy. Don't facilitate connections to arbitrary destinations.
	filteredSDP, sdpMetrics, err := filterSDPAddresses(
		[]byte(request.ProxyAnswerSDP.SDP), errorOnNoCandidates, lookupGeoIP, geoIPData)
	if err != nil {
		return nil, nil, errors.Trace(err)
	}

	// The proxy's self-reported ICECandidateTypes are used instead of the
	// candidate types that can be derived from the SDP, since port mapping
	// types are edited into the SDP in a way that makes them
	// indistinguishable from host candidate types.

	if !request.ICECandidateTypes.IsValid() {
		return nil, nil, errors.Tracef(
			"invalid ICE candidate types: %v", request.ICECandidateTypes)
	}

	if request.SelectedProxyProtocolVersion != ProxyProtocolVersion1 {
		return nil, nil, errors.Tracef(
			"invalid select proxy protocol version: %v", request.SelectedProxyProtocolVersion)
	}

	logFields := formatter(geoIPData, common.APIParameters{})

	logFields["connection_id"] = request.ConnectionID
	logFields["ice_candidate_types"] = request.ICECandidateTypes
	logFields["has_IPv6"] = sdpMetrics.hasIPv6
	logFields["filtered_ice_candidates"] = sdpMetrics.filteredICECandidates
	logFields["answer_error"] = request.AnswerError

	return filteredSDP, logFields, nil
}

// ValidateAndGetLogFields validates the ClientRelayedPacketRequest and returns
// common.LogFields for logging.
func (request *ClientRelayedPacketRequest) ValidateAndGetLogFields(
	baseAPIParameterValidator common.APIParameterValidator,
	formatter common.APIParameterLogFieldFormatter,
	geoIPData common.GeoIPData) (common.LogFields, error) {

	logFields := formatter(geoIPData, common.APIParameters{})

	logFields["connection_id"] = request.ConnectionID

	return logFields, nil
}

// ValidateAndGetLogFields validates the BrokerServerReport and returns
// common.LogFields for logging.
func (request *BrokerServerReport) ValidateAndGetLogFields() (common.LogFields, error) {

	if !request.ProxyNATType.IsValid() {
		return nil, errors.Tracef("invalid proxy NAT type: %v", request.ProxyNATType)
	}

	if !request.ProxyPortMappingTypes.IsValid() {
		return nil, errors.Tracef("invalid proxy portmapping types: %v", request.ProxyPortMappingTypes)
	}

	if !request.ClientNATType.IsValid() {
		return nil, errors.Tracef("invalid client NAT type: %v", request.ClientNATType)
	}

	if !request.ClientPortMappingTypes.IsValid() {
		return nil, errors.Tracef("invalid client portmapping types: %v", request.ClientPortMappingTypes)
	}

	// Neither ClientIP nor ProxyIP is logged.

	logFields := common.LogFields{}

	logFields["proxy_id"] = request.ProxyID
	logFields["connection_id"] = request.ConnectionID
	logFields["matched_common_compartments"] = request.MatchedCommonCompartments
	logFields["matched_personal_compartments"] = request.MatchedPersonalCompartments
	logFields["proxy_nat_type"] = request.ProxyNATType
	logFields["proxy_port_mapping_types"] = request.ProxyPortMappingTypes
	logFields["client_nat_type"] = request.ClientNATType
	logFields["client_port_mapping_types"] = request.ClientPortMappingTypes

	return common.LogFields{}, nil
}

func MarshalProxyAnnounceRequest(request *ProxyAnnounceRequest) ([]byte, error) {
	payload, err := marshalRecord(request, recordTypeAPIProxyAnnounceRequest)
	return payload, errors.Trace(err)
}

func UnmarshalProxyAnnounceRequest(payload []byte) (*ProxyAnnounceRequest, error) {
	var request *ProxyAnnounceRequest
	err := unmarshalRecord(recordTypeAPIProxyAnnounceRequest, payload, &request)
	return request, errors.Trace(err)
}

func MarshalProxyAnnounceResponse(response *ProxyAnnounceResponse) ([]byte, error) {
	payload, err := marshalRecord(response, recordTypeAPIProxyAnnounceResponse)
	return payload, errors.Trace(err)
}

func UnmarshalProxyAnnounceResponse(payload []byte) (*ProxyAnnounceResponse, error) {
	var response *ProxyAnnounceResponse
	err := unmarshalRecord(recordTypeAPIProxyAnnounceResponse, payload, &response)
	return response, errors.Trace(err)
}

func MarshalProxyAnswerRequest(request *ProxyAnswerRequest) ([]byte, error) {
	payload, err := marshalRecord(request, recordTypeAPIProxyAnswerRequest)
	return payload, errors.Trace(err)
}

func UnmarshalProxyAnswerRequest(payload []byte) (*ProxyAnswerRequest, error) {
	var request *ProxyAnswerRequest
	err := unmarshalRecord(recordTypeAPIProxyAnswerRequest, payload, &request)
	return request, errors.Trace(err)
}

func MarshalProxyAnswerResponse(response *ProxyAnswerResponse) ([]byte, error) {
	payload, err := marshalRecord(response, recordTypeAPIProxyAnswerResponse)
	return payload, errors.Trace(err)
}

func UnmarshalProxyAnswerResponse(payload []byte) (*ProxyAnswerResponse, error) {
	var response *ProxyAnswerResponse
	err := unmarshalRecord(recordTypeAPIProxyAnswerResponse, payload, &response)
	return response, errors.Trace(err)
}

func MarshalClientOfferRequest(request *ClientOfferRequest) ([]byte, error) {
	payload, err := marshalRecord(request, recordTypeAPIClientOfferRequest)
	return payload, errors.Trace(err)
}

func UnmarshalClientOfferRequest(payload []byte) (*ClientOfferRequest, error) {
	var request *ClientOfferRequest
	err := unmarshalRecord(recordTypeAPIClientOfferRequest, payload, &request)
	return request, errors.Trace(err)
}

func MarshalClientOfferResponse(response *ClientOfferResponse) ([]byte, error) {
	payload, err := marshalRecord(response, recordTypeAPIClientOfferResponse)
	return payload, errors.Trace(err)
}

func UnmarshalClientOfferResponse(payload []byte) (*ClientOfferResponse, error) {
	var response *ClientOfferResponse
	err := unmarshalRecord(recordTypeAPIClientOfferResponse, payload, &response)
	return response, errors.Trace(err)
}

func MarshalClientRelayedPacketRequest(request *ClientRelayedPacketRequest) ([]byte, error) {
	payload, err := marshalRecord(request, recordTypeAPIClientRelayedPacketRequest)
	return payload, errors.Trace(err)
}

func UnmarshalClientRelayedPacketRequest(payload []byte) (*ClientRelayedPacketRequest, error) {
	var request *ClientRelayedPacketRequest
	err := unmarshalRecord(recordTypeAPIClientRelayedPacketRequest, payload, &request)
	return request, errors.Trace(err)
}

func MarshalClientRelayedPacketResponse(response *ClientRelayedPacketResponse) ([]byte, error) {
	payload, err := marshalRecord(response, recordTypeAPIClientRelayedPacketResponse)
	return payload, errors.Trace(err)
}

func UnmarshalClientRelayedPacketResponse(payload []byte) (*ClientRelayedPacketResponse, error) {
	var response *ClientRelayedPacketResponse
	err := unmarshalRecord(recordTypeAPIClientRelayedPacketResponse, payload, &response)
	return response, errors.Trace(err)
}

func MarshalBrokerServerReport(request *BrokerServerReport) ([]byte, error) {
	payload, err := marshalRecord(request, recordTypeAPIBrokerServerReport)
	return payload, errors.Trace(err)
}

func UnmarshalBrokerServerReport(payload []byte) (*BrokerServerReport, error) {
	var request *BrokerServerReport
	err := unmarshalRecord(recordTypeAPIBrokerServerReport, payload, &request)
	return request, errors.Trace(err)
}
