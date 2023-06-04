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
	"encoding/hex"
	"fmt"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/pion/webrtc/v3"
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
	_, err := rand.Read(id[:])
	if err != nil {
		return id, errors.Trace(err)
	}
	return id, nil
}

// IDFromString returns an ID given its string encoding.
func IDFromString(s string) (ID, error) {
	var id ID
	value, err := hex.DecodeString(s)
	if err != nil {
		return id, errors.Trace(err)
	}
	if len(value) != len(id) {
		return id, errors.TraceNew("invalid length")
	}
	copy(id[:], value)
	return id, nil
}

// MarshalText emits IDs as hex.
func (id ID) MarshalText() ([]byte, error) {
	return []byte(id.String()), nil
}

// String emits IDs as hex.
func (id ID) String() string {
	return fmt.Sprintf("%x", []byte(id[:]))
}

// Equal indicates whether two IDs are equal. It uses a constant time
// comparison.
func (id ID) Equal(x ID) bool {
	return subtle.ConstantTimeCompare(id[:], x[:]) == 1
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

// TransportSecret is a value used to validate a broker transport front, such
// as a CDN.
type TransportSecret [32]byte

// Equal indicates whether two TransportSecrets are equal. It uses a constant
// time comparison.
func (s TransportSecret) Equal(t TransportSecret) bool {
	return subtle.ConstantTimeCompare(s[:], t[:]) == 1
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

// ProxyMetrics are network topolology and resource metrics provided by a
// proxy to a broker. The broker uses this information when matching proxies
// and clients.
type ProxyMetrics struct {
	BaseMetrics                   BaseMetrics      `cbor:"1,keyasint,omitempty"`
	ProxyProtocolVersion          int32            `cbor:"2,keyasint,omitempty"`
	NATType                       NATType          `cbor:"3,keyasint,omitempty"`
	PortMappingTypes              PortMappingTypes `cbor:"4,keyasint,omitempty"`
	MaxClients                    int32            `cbor:"6,keyasint,omitempty"`
	ConnectingClients             int32            `cbor:"7,keyasint,omitempty"`
	ConnectedClients              int32            `cbor:"8,keyasint,omitempty"`
	LimitUpstreamBytesPerSecond   int64            `cbor:"9,keyasint,omitempty"`
	LimitDownstreamBytesPerSecond int64            `cbor:"10,keyasint,omitempty"`
	PeakUpstreamBytesPerSecond    int64            `cbor:"11,keyasint,omitempty"`
	PeakDownstreamBytesPerSecond  int64            `cbor:"12,keyasint,omitempty"`
}

// ClientMetrics are network topolology metrics provided by a client to a
// broker. The broker uses this information when matching proxies and
// clients.
type ClientMetrics struct {
	BaseMetrics          BaseMetrics      `cbor:"1,keyasint,omitempty"`
	ProxyProtocolVersion int32            `cbor:"2,keyasint,omitempty"`
	NATType              NATType          `cbor:"3,keyasint,omitempty"`
	PortMappingTypes     PortMappingTypes `cbor:"4,keyasint,omitempty"`
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
	ConnectionID                ID                                   `cbor:"2,keyasint,omitempty"`
	ClientProxyProtocolVersion  int32                                `cbor:"3,keyasint,omitempty"`
	ClientOfferSDP              webrtc.SessionDescription            `cbor:"4,keyasint,omitempty"`
	ClientRootObfuscationSecret ObfuscationSecret                    `cbor:"5,keyasint,omitempty"`
	DoDTLSRandomization         bool                                 `cbor:"7,keyasint,omitempty"`
	TrafficShapingParameters    *DataChannelTrafficShapingParameters `cbor:"8,keyasint,omitempty"`
	NetworkProtocol             NetworkProtocol                      `cbor:"9,keyasint,omitempty"`
	DestinationAddress          string                               `cbor:"10,keyasint,omitempty"`
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
	Metrics                     *ClientMetrics                       `cbor:"1,keyasint,omitempty"`
	CommonCompartmentIDs        []ID                                 `cbor:"2,keyasint,omitempty"`
	PersonalCompartmentIDs      []ID                                 `cbor:"3,keyasint,omitempty"`
	ClientOfferSDP              webrtc.SessionDescription            `cbor:"4,keyasint,omitempty"`
	ICECandidateTypes           ICECandidateTypes                    `cbor:"5,keyasint,omitempty"`
	ClientRootObfuscationSecret ObfuscationSecret                    `cbor:"6,keyasint,omitempty"`
	DoDTLSRandomization         bool                                 `cbor:"7,keyasint,omitempty"`
	TrafficShapingParameters    *DataChannelTrafficShapingParameters `cbor:"8,keyasint,omitempty"`
	DestinationServerEntryJSON  []byte                               `cbor:"9,keyasint,omitempty"`
	NetworkProtocol             NetworkProtocol                      `cbor:"10,keyasint,omitempty"`
	DestinationAddress          string                               `cbor:"11,keyasint,omitempty"`
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

// TODO: Encode SDPs using CBOR without field names, simliar to base metrics
// transformation? Same with DestinationServerEntryJSON.

// ClientOfferResponse returns the connecting information for a matched proxy.
// The proxy's WebRTC SDP is an answer to the offer sent in
// ClientOfferRequest and is used to begin dialing the WebRTC connection.
//
// Once the client completes its connection to the Psiphon server, it must
// relay a BrokerServerRequest to the server on behalf of the broker. This
// relay is conducted within a secure session. First, the client sends
// RelayPacketToServer to the server. Then the client relays the response to
// the broker using ClientRelayedPacketRequests and continues to relay using
// ClientRelayedPacketRequests until complete. ConnectionID identifies this
// connection and its relayed BrokerServerRequest.
type ClientOfferResponse struct {
	ConnectionID                 ID                        `cbor:"1,keyasint,omitempty"`
	SelectedProxyProtocolVersion int32                     `cbor:"2,keyasint,omitempty"`
	ProxyAnswerSDP               webrtc.SessionDescription `cbor:"3,keyasint,omitempty"`
	RelayPacketToServer          []byte                    `cbor:"4,keyasint,omitempty"`
}

// ProxyAnswerRequest is an API request sent from a proxy to a broker,
// following ProxyAnnounceResponse, with the WebRTC answer SDP corresponding
// to the client offer SDP received in ProxyAnnounceResponse. ConnectionID
// identifies the connection begun in ProxyAnnounceResponse.
//
// If the proxy was unable to establish an answer SDP or failed for some other
// reason, it should still send ProxyAnswerRequest with AnswerError
// populated; the broker will signal the client to abort this connection.
type ProxyAnswerRequest struct {
	ConnectionID                 ID                        `cbor:"1,keyasint,omitempty"`
	SelectedProxyProtocolVersion int32                     `cbor:"2,keyasint,omitempty"`
	ProxyAnswerSDP               webrtc.SessionDescription `cbor:"3,keyasint,omitempty"`
	ICECandidateTypes            ICECandidateTypes         `cbor:"4,keyasint,omitempty"`
	AnswerError                  string                    `cbor:"5,keyasint,omitempty"`
}

// ProxyAnswerResponse is the acknowledgement for a ProxyAnswerRequest.
type ProxyAnswerResponse struct {
}

// ClientRelayedPacketRequest is an API request sent from a client to a
// broker, relaying a secure session packet from the Psiphon server to the
// broker. This relay is a continuation of the broker/server exchange begun
// with ClientOfferResponse.RelayPacketToServer. PacketFromServer is the next
// packet from the server. SessionInvalid indicates, to the broker, that the
// session is invalid -- it may have expired -- and so the broker should
// begin establishing a new session, and then send its BrokerServerRequest in
// that new session.
type ClientRelayedPacketRequest struct {
	ConnectionID     ID     `cbor:"1,keyasint,omitempty"`
	PacketFromServer []byte `cbor:"2,keyasint,omitempty"`
	SessionInvalid   bool   `cbor:"3,keyasint,omitempty"`
}

// ClientRelayedPacketResponse returns the next packet from the broker to the
// server. When PacketToServer is empty, the broker/server exchange is done
// and the client stops relaying packets.
type ClientRelayedPacketResponse struct {
	PacketToServer []byte `cbor:"1,keyasint,omitempty"`
}

// BrokerServerRequest is an API request sent from a broker to a Psiphon
// server. This delivers, to the server, information that neither the client
// nor the proxy is trusted to report. ProxyID is the proxy ID to be logged
// with server_tunnel to attribute traffic to a specific proxy. ClientIP is
// the original client IP as seen by the broker; this is the IP value to be
// used in GeoIP-related operations including traffic rules, tactics, and OSL
// progress. ProxyIP is the proxy IP as seen by the broker; this value should
// match the Psiphon's server observed client IP. Additional fields are
// metrics to be logged with server_tunnel.
type BrokerServerRequest struct {
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

// BrokerServerResponse returns an acknowledgement of the BrokerServerRequest
// to the broker from the Psiphon server. The ConnectionID must match the
// value in the BrokerServerRequest.
type BrokerServerResponse struct {
	ConnectionID ID     `cbor:"1,keyasint,omitempty"`
	ErrorMessage string `cbor:"2,keyasint,omitempty"`
}

// BaseMetrics is a compact encoding of Psiphon base API metrics, such as
// sponsor_id, client_platform, and so on.
type BaseMetrics map[int]interface{}

// GetNetworkType extracts the network_type from base metrics and returns a
// corresponding NetworkType. This is the one base metric that is used in the
// broker logic, and not simply logged.
func (metrics BaseMetrics) GetNetworkType() NetworkType {
	key, ok := baseMetricsNameToInt["network_type"]
	if !ok {
		return NetworkTypeUnknown
	}
	value, ok := metrics[key]
	if !ok {
		return NetworkTypeUnknown
	}
	strValue, ok := value.(string)
	if !ok {
		return NetworkTypeUnknown
	}
	switch strValue {
	case "WIFI":
		return NetworkTypeWiFi
	case "MOBILE":
		return NetworkTypeMobile
	}
	return NetworkTypeUnknown
}

func EncodeBaseMetrics(params common.APIParameters) (BaseMetrics, error) {
	metrics := BaseMetrics{}
	for name, value := range params {
		key, ok := baseMetricsNameToInt[name]
		if !ok {
			// The API metric to be sent is not in baseMetricsNameToInt. This
			// will occur if baseMetricsNameToInt is not updated when new API
			// metrics are added. Fail the operation and, ultimately, the
			// dial rather than proceeding without the metric.
			return nil, errors.Tracef("unknown name: %s", name)
		}
		metrics[key] = value

	}
	return metrics, nil
}

func DecodeBaseMetrics(metrics BaseMetrics) common.APIParameters {
	params := common.APIParameters{}
	for key, value := range metrics {
		name, ok := baseMetricsIntToName[key]
		if !ok {
			// The API metric received is not in baseMetricsNameToInt. Skip
			// logging it and proceed.
			continue
		}
		params[name] = value

	}
	return params
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

// ValidateAndGetLogFields validates the ProxyMetrics and returns
// common.LogFields for logging.
func (metrics *ProxyMetrics) ValidateAndGetLogFields(
	baseMetricsValidator common.APIParameterValidator,
	formatter common.APIParameterLogFieldFormatter,
	geoIPData common.GeoIPData) (common.LogFields, error) {

	if metrics.BaseMetrics == nil {
		return nil, errors.TraceNew("missing base metrics")
	}

	baseMetrics := DecodeBaseMetrics(metrics.BaseMetrics)

	err := baseMetricsValidator(baseMetrics)
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

	logFields := formatter(geoIPData, baseMetrics)

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

	return logFields, nil
}

// ValidateAndGetLogFields validates the ClientMetrics and returns
// common.LogFields for logging.
func (metrics *ClientMetrics) ValidateAndGetLogFields(
	baseMetricsValidator common.APIParameterValidator,
	formatter common.APIParameterLogFieldFormatter,
	geoIPData common.GeoIPData) (common.LogFields, error) {

	if metrics.BaseMetrics == nil {
		return nil, errors.TraceNew("missing base metrics")
	}

	baseMetrics := DecodeBaseMetrics(metrics.BaseMetrics)

	err := baseMetricsValidator(baseMetrics)
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

	logFields := formatter(geoIPData, baseMetrics)

	logFields["proxy_protocol_version"] = metrics.ProxyProtocolVersion
	logFields["nat_type"] = metrics.NATType
	logFields["port_mapping_types"] = metrics.PortMappingTypes

	return logFields, nil
}

// ValidateAndGetLogFields validates the ProxyAnnounceRequest and returns
// common.LogFields for logging.
func (request *ProxyAnnounceRequest) ValidateAndGetLogFields(
	baseMetricsValidator common.APIParameterValidator,
	formatter common.APIParameterLogFieldFormatter,
	geoIPData common.GeoIPData) (common.LogFields, error) {

	if len(request.PersonalCompartmentIDs) > MaxCompartmentIDs {
		return nil, errors.Tracef("invalid compartment IDs length: %d", len(request.PersonalCompartmentIDs))
	}

	if request.Metrics == nil {
		return nil, errors.TraceNew("missing metrics")
	}

	logFields, err := request.Metrics.ValidateAndGetLogFields(
		baseMetricsValidator, formatter, geoIPData)
	if err != nil {
		return nil, errors.Trace(err)
	}

	// PersonalCompartmentIDs are user-generated and shared out-of-band;
	// values are not logged since they may link users.

	hasPersonalCompartmentIDs := len(request.PersonalCompartmentIDs) > 0

	logFields["has_personal_compartment_ids"] = hasPersonalCompartmentIDs

	return logFields, nil
}

// ValidateAndGetLogFields validates the ClientOfferRequest and returns
// common.LogFields for logging.
func (request *ClientOfferRequest) ValidateAndGetLogFields(
	lookupGeoIP LookupGeoIP,
	baseMetricsValidator common.APIParameterValidator,
	formatter common.APIParameterLogFieldFormatter,
	geoIPData common.GeoIPData) (common.LogFields, error) {

	if len(request.CommonCompartmentIDs) > MaxCompartmentIDs {
		return nil, errors.Tracef("invalid compartment IDs length: %d", len(request.CommonCompartmentIDs))
	}

	if len(request.PersonalCompartmentIDs) > MaxCompartmentIDs {
		return nil, errors.Tracef("invalid compartment IDs length: %d", len(request.PersonalCompartmentIDs))
	}

	// Client offer SDP candidate addresses must match the country and ASN of
	// the client. Don't facilitate connections to arbitrary destinations.
	sdpMetrics, err := ValidateSDPAddresses([]byte(request.ClientOfferSDP.SDP), lookupGeoIP, geoIPData)
	if err != nil {
		return nil, errors.Trace(err)
	}

	// The client's self-reported ICECandidateTypes are used instead of the
	// candidate types that can be derived from the SDP, since port mapping
	// types are edited into the SDP in a way that makes them
	// indistinguishable from host candidate types.

	if !request.ICECandidateTypes.IsValid() {
		return nil, errors.Tracef("invalid ICE candidate types: %v", request.ICECandidateTypes)
	}

	if request.Metrics == nil {
		return nil, errors.TraceNew("missing metrics")
	}

	logFields, err := request.Metrics.ValidateAndGetLogFields(
		baseMetricsValidator, formatter, geoIPData)
	if err != nil {
		return nil, errors.Trace(err)
	}

	if request.TrafficShapingParameters != nil {
		err := request.TrafficShapingParameters.Validate()
		if err != nil {
			return nil, errors.Trace(err)
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
	logFields["has_IPv6"] = sdpMetrics.HasIPv6

	return logFields, nil
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
	baseMetricsValidator common.APIParameterValidator,
	formatter common.APIParameterLogFieldFormatter,
	geoIPData common.GeoIPData) (common.LogFields, error) {

	// Proxy answer SDP candidate addresses must match the country and ASN of
	// the proxy. Don't facilitate connections to arbitrary destinations.
	sdpMetrics, err := ValidateSDPAddresses([]byte(request.ProxyAnswerSDP.SDP), lookupGeoIP, geoIPData)
	if err != nil {
		return nil, errors.Trace(err)
	}

	// The proxy's self-reported ICECandidateTypes are used instead of the
	// candidate types that can be derived from the SDP, since port mapping
	// types are edited into the SDP in a way that makes them
	// indistinguishable from host candidate types.

	if !request.ICECandidateTypes.IsValid() {
		return nil, errors.Tracef("invalid ICE candidate types: %v", request.ICECandidateTypes)
	}

	if request.SelectedProxyProtocolVersion != ProxyProtocolVersion1 {
		return nil, errors.Tracef("invalid select proxy protocol version: %v", request.SelectedProxyProtocolVersion)
	}

	logFields := formatter(geoIPData, common.APIParameters{})

	logFields["connection_id"] = request.ConnectionID
	logFields["ice_candidate_types"] = request.ICECandidateTypes
	logFields["has_IPv6"] = sdpMetrics.HasIPv6
	logFields["answer_error"] = request.AnswerError

	return logFields, nil
}

// ValidateAndGetLogFields validates the ClientRelayedPacketRequest and returns
// common.LogFields for logging.
func (request *ClientRelayedPacketRequest) ValidateAndGetLogFields(
	baseMetricsValidator common.APIParameterValidator,
	formatter common.APIParameterLogFieldFormatter,
	geoIPData common.GeoIPData) (common.LogFields, error) {

	logFields := formatter(geoIPData, common.APIParameters{})

	logFields["connection_id"] = request.ConnectionID
	logFields["session_invalid"] = request.SessionInvalid

	return logFields, nil
}

// ValidateAndGetLogFields validates the BrokerServerRequest and returns
// common.LogFields for logging.
func (request *BrokerServerRequest) ValidateAndGetLogFields() (common.LogFields, error) {

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

func MarshalBrokerServerRequest(request *BrokerServerRequest) ([]byte, error) {
	payload, err := marshalRecord(request, recordTypeAPIBrokerServerRequest)
	return payload, errors.Trace(err)
}

func UnmarshalBrokerServerRequest(payload []byte) (*BrokerServerRequest, error) {
	var request *BrokerServerRequest
	err := unmarshalRecord(recordTypeAPIBrokerServerRequest, payload, &request)
	return request, errors.Trace(err)
}

func MarshalBrokerServerResponse(response *BrokerServerResponse) ([]byte, error) {
	payload, err := marshalRecord(response, recordTypeAPIBrokerServerResponse)
	return payload, errors.Trace(err)
}

func UnmarshalBrokerServerResponse(payload []byte) (*BrokerServerResponse, error) {
	var response *BrokerServerResponse
	err := unmarshalRecord(recordTypeAPIBrokerServerResponse, payload, &response)
	return response, errors.Trace(err)
}

var (
	baseMetricsNameToInt map[string]int
	baseMetricsIntToName map[int]string
)

func init() {

	// Initialize maps from base metrics JSON field names to CBOR field
	// numbers. This list must be updated when new base metrics are added,
	// and the new metrics must be appended so as to maintain the field
	// number ordering.

	names := []string{
		"server_secret",
		"client_session_id",
		"propagation_channel_id",
		"sponsor_id",
		"client_version",
		"client_platform",
		"client_features",
		"client_build_rev",
		"device_region",
		"session_id",
		"relay_protocol",
		"ssh_client_version",
		"upstream_proxy_type",
		"upstream_proxy_custom_header_names",
		"fronting_provider_id",
		"meek_dial_address",
		"meek_resolved_ip_address",
		"meek_sni_server_name",
		"meek_host_header",
		"meek_transformed_host_name",
		"user_agent",
		"tls_profile",
		"tls_version",
		"server_entry_region",
		"server_entry_source",
		"server_entry_timestamp",
		"applied_tactics_tag",
		"dial_port_number",
		"quic_version",
		"quic_dial_sni_address",
		"quic_disable_client_path_mtu_discovery",
		"upstream_bytes_fragmented",
		"upstream_min_bytes_written",
		"upstream_max_bytes_written",
		"upstream_min_delayed",
		"upstream_max_delayed",
		"padding",
		"pad_response",
		"is_replay",
		"egress_region",
		"dial_duration",
		"candidate_number",
		"established_tunnels_count",
		"upstream_ossh_padding",
		"meek_cookie_size",
		"meek_limit_request",
		"meek_tls_padding",
		"network_latency_multiplier",
		"client_bpf",
		"network_type",
		"conjure_cached",
		"conjure_delay",
		"conjure_transport",
		"split_tunnel",
		"split_tunnel_regions",
		"dns_preresolved",
		"dns_preferred",
		"dns_transform",
		"dns_attempt",
	}

	baseMetricsNameToInt = make(map[string]int)
	baseMetricsIntToName = make(map[int]string)
	for i, name := range names {
		baseMetricsNameToInt[name] = i
		baseMetricsIntToName[i] = name
	}
}
