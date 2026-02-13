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
	"encoding/binary"
	"math"
	"strconv"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
)

const (

	// ProtocolVersion1 represents protocol version 1, the initial in-proxy
	// protocol version number.
	ProtocolVersion1 = int32(1)

	// ProtocolVersion2 represents protocol version 2, which adds support for
	// proxying over WebRTC media streams.
	ProtocolVersion2 = int32(2)

	// LatestProtocolVersion is the current, default protocol version number.
	LatestProtocolVersion = ProtocolVersion2

	// MinimumProxyProtocolVersion is the minimum required protocol version
	// number for proxies.
	MinimumProxyProtocolVersion = ProtocolVersion1

	// MinimumClientProtocolVersion is the minimum supported protocol version
	// number for clients.
	MinimumClientProtocolVersion = ProtocolVersion1

	MaxCompartmentIDs = 10
)

// minimumProxyProtocolVersion and minimumClientProtocolVersion are variable
// to enable overriding the values in tests. These value should not be
// overridden outside of test cases.
var (
	minimumProxyProtocolVersion  = MinimumProxyProtocolVersion
	minimumClientProtocolVersion = MinimumClientProtocolVersion
)

// negotiateProtocolVersion selects the in-proxy protocol version for a new
// proxy/client match, based on the client's and proxy's reported protocol
// versions, and the client's selected protocol options. Returns false if no
// protocol version selection is possible.
//
// The broker performs the negotiation on behalf of the proxy and client. Both
// the proxy and client initially specify the latest protocol version they
// support. The client specifies the protocol options to use, based on
// tactics and replay.
//
// negotiateProtocolVersion is used by the matcher when searching for
// potential matches; for this reason, the failure case is expected and
// returns a simple boolean intead of formating an error message.
//
// Existing, legacy proxies have the equivalent of an "if
// announceResponse.SelectedProtocolVersion != ProtocolVersion1" check, so
// the SelectedProtocolVersion must be downgraded in that case, if a match is
// possible.
func negotiateProtocolVersion(
	proxyProtocolVersion int32,
	clientProtocolVersion int32,
	useMediaStreams bool) (int32, bool) {

	// When not using WebRTC media streams, introduced in ProtocolVersion2,
	// potentially downgrade if either the proxy or client supports only
	// ProtocolVersion1.

	if (proxyProtocolVersion == ProtocolVersion1 ||
		clientProtocolVersion == ProtocolVersion1) &&
		!useMediaStreams {
		return ProtocolVersion1, true
	}

	// Select the client's protocol version.

	if proxyProtocolVersion >= clientProtocolVersion {
		return clientProtocolVersion, true
	}

	// No selection is possible. This includes the case where the proxy
	// supports up to ProtocolVersion1 and the client has specified media
	// streams.

	return 0, false
}

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
	NetworkTypeWired
	NetworkTypeVPN
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
// Limitation: Currently, there is no MaxReducedPersonalClients config, as
// We assumed that users would not want the personal connections to be reduced.
type ProxyMetrics struct {
	BaseAPIParameters             protocol.PackedAPIParameters `cbor:"1,keyasint,omitempty"`
	ProtocolVersion               int32                        `cbor:"2,keyasint,omitempty"`
	NATType                       NATType                      `cbor:"3,keyasint,omitempty"`
	PortMappingTypes              PortMappingTypes             `cbor:"4,keyasint,omitempty"`
	MaxCommonClients              int32                        `cbor:"6,keyasint,omitempty"`
	ConnectingClients             int32                        `cbor:"7,keyasint,omitempty"`
	ConnectedClients              int32                        `cbor:"8,keyasint,omitempty"`
	LimitUpstreamBytesPerSecond   int64                        `cbor:"9,keyasint,omitempty"`
	LimitDownstreamBytesPerSecond int64                        `cbor:"10,keyasint,omitempty"`
	PeakUpstreamBytesPerSecond    int64                        `cbor:"11,keyasint,omitempty"`
	PeakDownstreamBytesPerSecond  int64                        `cbor:"12,keyasint,omitempty"`
	MaxPersonalClients            int32                        `cbor:"13,keyasint,omitempty"`
}

// ClientMetrics are network topolology metrics provided by a client to a
// broker. The broker uses this information when matching proxies and
// clients.
type ClientMetrics struct {
	BaseAPIParameters protocol.PackedAPIParameters `cbor:"1,keyasint,omitempty"`
	ProtocolVersion   int32                        `cbor:"2,keyasint,omitempty"`
	NATType           NATType                      `cbor:"3,keyasint,omitempty"`
	PortMappingTypes  PortMappingTypes             `cbor:"4,keyasint,omitempty"`
}

// ProxyAnnounceRequest is an API request sent from a proxy to a broker,
// announcing that it is available for a client connection. Proxies send one
// ProxyAnnounceRequest for each available client connection. The broker will
// match the proxy with a client and return WebRTC connection information
// in the response.
//
// PersonalCompartmentIDs limits the clients to those that supply one of the
// specified compartment IDs; personal compartment IDs are distributed from
// proxy operators to client users out-of-band and provide optional access
// control.
//
// When CheckTactics is set, the broker will check for new tactics or indicate
// that the proxy's cached tactics TTL may be extended. Tactics information
// is returned in the response TacticsPayload. To minimize broker processing
// overhead, proxies with multiple workers should designate just one worker
// to set CheckTactics.
//
// When PreCheckTactics is set, the broker checks tactics as with
// CheckTactics, but responds immediately without awaiting a match. This
// option enables the proxy to quickly establish the shared Noise protocol
// session and launch all workers.
//
// The proxy's session public key is an implicit and cryptographically
// verified proxy ID.
type ProxyAnnounceRequest struct {
	PersonalCompartmentIDs []ID          `cbor:"1,keyasint,omitempty"`
	Metrics                *ProxyMetrics `cbor:"2,keyasint,omitempty"`
	CheckTactics           bool          `cbor:"3,keyasint,omitempty"`
	PreCheckTactics        bool          `cbor:"4,keyasint,omitempty"`
}

// WebRTCSessionDescription is compatible with pion/webrtc.SessionDescription
// and facilitates the PSIPHON_DISABLE_INPROXY build tag exclusion of pion
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
// MustUpgrade is an optional flag that is set by the broker, based on the
// submitted ProtocolVersion, when the proxy app must be upgraded in order to
// function properly. Potential must-upgrade scenarios include changes to the
// personal pairing broker rendezvous algorithm, where no protocol backwards
// compatibility accommodations can ensure a rendezvous and match. When
// MustUpgrade is set, NoMatch is implied.

type ProxyAnnounceResponse struct {
	TacticsPayload              []byte                    `cbor:"2,keyasint,omitempty"`
	Limited                     bool                      `cbor:"3,keyasint,omitempty"`
	NoMatch                     bool                      `cbor:"4,keyasint,omitempty"`
	MustUpgrade                 bool                      `cbor:"13,keyasint,omitempty"`
	ConnectionID                ID                        `cbor:"5,keyasint,omitempty"`
	SelectedProtocolVersion     int32                     `cbor:"6,keyasint,omitempty"`
	ClientOfferSDP              WebRTCSessionDescription  `cbor:"7,keyasint,omitempty"`
	ClientRootObfuscationSecret ObfuscationSecret         `cbor:"8,keyasint,omitempty"`
	DoDTLSRandomization         bool                      `cbor:"9,keyasint,omitempty"`
	UseMediaStreams             bool                      `cbor:"14,keyasint,omitempty"`
	TrafficShapingParameters    *TrafficShapingParameters `cbor:"10,keyasint,omitempty"`
	NetworkProtocol             NetworkProtocol           `cbor:"11,keyasint,omitempty"`
	DestinationAddress          string                    `cbor:"12,keyasint,omitempty"`
	ClientRegion                string                    `cbor:"15,keyasint,omitempty"`
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
	Metrics                      *ClientMetrics            `cbor:"1,keyasint,omitempty"`
	CommonCompartmentIDs         []ID                      `cbor:"2,keyasint,omitempty"`
	PersonalCompartmentIDs       []ID                      `cbor:"3,keyasint,omitempty"`
	ClientOfferSDP               WebRTCSessionDescription  `cbor:"4,keyasint,omitempty"`
	ICECandidateTypes            ICECandidateTypes         `cbor:"5,keyasint,omitempty"`
	ClientRootObfuscationSecret  ObfuscationSecret         `cbor:"6,keyasint,omitempty"`
	DoDTLSRandomization          bool                      `cbor:"7,keyasint,omitempty"`
	UseMediaStreams              bool                      `cbor:"12,keyasint,omitempty"`
	TrafficShapingParameters     *TrafficShapingParameters `cbor:"8,keyasint,omitempty"`
	PackedDestinationServerEntry []byte                    `cbor:"9,keyasint,omitempty"`
	NetworkProtocol              NetworkProtocol           `cbor:"10,keyasint,omitempty"`
	DestinationAddress           string                    `cbor:"11,keyasint,omitempty"`
}

// TrafficShapingParameters specifies data channel or media stream traffic
// shaping configuration, including random padding and decoy messages (or
// packets). Clients determine their own traffic shaping configuration, and
// generate and send a configuration for the peer proxy to use.
type TrafficShapingParameters struct {
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
//
// MustUpgrade is an optional flag that is set by the broker, based on the
// submitted ProtocolVersion, when the client app must be upgraded in order
// to function properly. Potential must-upgrade scenarios include changes to
// the personal pairing broker rendezvous algorithm, where no protocol
// backwards compatibility accommodations can ensure a rendezvous and match.
// When MustUpgrade is set, NoMatch is implied.
type ClientOfferResponse struct {
	Limited                 bool                     `cbor:"1,keyasint,omitempty"`
	NoMatch                 bool                     `cbor:"2,keyasint,omitempty"`
	MustUpgrade             bool                     `cbor:"7,keyasint,omitempty"`
	ConnectionID            ID                       `cbor:"3,keyasint,omitempty"`
	SelectedProtocolVersion int32                    `cbor:"4,keyasint,omitempty"`
	ProxyAnswerSDP          WebRTCSessionDescription `cbor:"5,keyasint,omitempty"`
	RelayPacketToServer     []byte                   `cbor:"6,keyasint,omitempty"`
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
	ConnectionID      ID                       `cbor:"1,keyasint,omitempty"`
	ProxyAnswerSDP    WebRTCSessionDescription `cbor:"3,keyasint,omitempty"`
	ICECandidateTypes ICECandidateTypes        `cbor:"4,keyasint,omitempty"`
	AnswerError       string                   `cbor:"5,keyasint,omitempty"`

	// These fields are no longer used.
	//
	// SelectedProtocolVersion int32 `cbor:"2,keyasint,omitempty"`
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
	ClientNATType               NATType          `cbor:"7,keyasint,omitempty"`
	ClientPortMappingTypes      PortMappingTypes `cbor:"8,keyasint,omitempty"`
	ClientIP                    string           `cbor:"9,keyasint,omitempty"`
	ProxyIP                     string           `cbor:"10,keyasint,omitempty"`
	ProxyMetrics                *ProxyMetrics    `cbor:"11,keyasint,omitempty"`
	ProxyIsPriority             bool             `cbor:"12,keyasint,omitempty"`

	// These legacy fields are now sent in ProxyMetrics.
	ProxyNATType          NATType          `cbor:"5,keyasint,omitempty"`
	ProxyPortMappingTypes PortMappingTypes `cbor:"6,keyasint,omitempty"`
}

// ClientDSLRequest is a client DSL request that the broker relays to the DSL
// backend. The broker's role is to provide a blocking resistant initial
// hop; DSL requests are not direct components of the in-proxy protocol.
type ClientDSLRequest struct {
	RequestPayload []byte `cbor:"1,keyasint,omitempty"`
}

// ClientDSLResponse is a DSL response relayed back to the client.
type ClientDSLResponse struct {
	ResponsePayload []byte `cbor:"1,keyasint,omitempty"`
}

// ProxyQualityKey is the key that proxy quality is indexed on a proxy ID and
// a proxy ASN. Quality is tracked at a fine-grained level, with the proxy ID
// representing, typically, an individual device, and the proxy ASN
// representing the network the device used at the time a quality tunnel was
// reported.
type ProxyQualityKey [36]byte

// MakeProxyQualityKey creates a ProxyQualityKey using the given proxy ID and
// proxy ASN. In the key, the proxy ID remains encoded as-is, and the ASN is
// encoded in the 4-byte representation (see RFC6793).
func MakeProxyQualityKey(proxyID ID, proxyASN string) ProxyQualityKey {
	var key ProxyQualityKey
	copy(key[0:32], proxyID[:])
	ASN, err := strconv.ParseInt(proxyASN, 10, 0)
	if err != nil || ASN < 0 || ASN > math.MaxUint32 {
		// In cases including failed or misconfigured GeoIP lookups -- with
		// values such as server.GEOIP_UNKNOWN_VALUE or invalid AS numbers --
		// fall back to a reserved AS number (see RFC5398). This is, effectively, a less
		// fine-grained key.
		//
		// Note that GeoIP lookups are performed server-side and a proxy
		// itself cannot force this downgrade (to obtain false quality
		// classification across different networks).
		ASN = 65536
	}
	binary.BigEndian.PutUint32(key[32:36], uint32(ASN))
	return key
}

// ProxyQualityASNCounts is tunnel quality data, a map from client ASNs to
// counts of quality tunnels that a proxy relayed for those client ASNs.
type ProxyQualityASNCounts map[string]int

// ProxyQualityRequestCounts is ProxyQualityASNCounts for a set of proxies.
type ProxyQualityRequestCounts map[ProxyQualityKey]ProxyQualityASNCounts

// ServerProxyQualityRequest is an API request sent from a server to a broker,
// reporting a set of proxy IDs/ASNs that have relayed quality tunnels -- as
// determined by bytes transferred and duration thresholds -- for clients in
// the given ASNs. This quality data is used, by brokers, to prioritize
// well-performing proxies, and to match clients with proxies that worked
// successfully for the client's ASN.
//
// QualityCounts is a map from proxy ID/ASN to ASN quality tunnel counts.
//
// DialParameters specifies additional parameters to log with proxy quality
// broker events, including any relevant server broker dial parameters.
// Unlike clients and proxies, servers do not send BaseAPIParameters to
// brokers.
type ServerProxyQualityRequest struct {
	QualityCounts  ProxyQualityRequestCounts    `cbor:"1,keyasint,omitempty"`
	DialParameters protocol.PackedAPIParameters `cbor:"2,keyasint,omitempty"`
}

// ServerProxyQualityResponse is the acknowledgement for a
// ServerProxyQualityRequest.
type ServerProxyQualityResponse struct {
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
	case "WIRED":
		return NetworkTypeWired
	case "VPN":
		return NetworkTypeVPN
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

	maxQualityCounts = 10000
)

// ValidateAndGetParametersAndLogFields validates the ProxyMetrics and returns
// Psiphon API parameters for processing and common.LogFields for logging.
func (metrics *ProxyMetrics) ValidateAndGetParametersAndLogFields(
	baseAPIParameterValidator common.APIParameterValidator,
	formatter common.APIParameterLogFieldFormatter,
	logFieldPrefix string,
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

	if metrics.ProtocolVersion < ProtocolVersion1 || metrics.ProtocolVersion > LatestProtocolVersion {
		return nil, nil, errors.Tracef("invalid protocol version: %v", metrics.ProtocolVersion)
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

	logFields := formatter(logFieldPrefix, geoIPData, baseParams)

	logFields[logFieldPrefix+"protocol_version"] = metrics.ProtocolVersion
	logFields[logFieldPrefix+"nat_type"] = metrics.NATType
	logFields[logFieldPrefix+"port_mapping_types"] = metrics.PortMappingTypes
	logFields[logFieldPrefix+"max_common_clients"] = metrics.MaxCommonClients
	logFields[logFieldPrefix+"max_personal_clients"] = metrics.MaxPersonalClients
	logFields[logFieldPrefix+"max_clients"] = metrics.MaxCommonClients + metrics.MaxPersonalClients
	logFields[logFieldPrefix+"connecting_clients"] = metrics.ConnectingClients
	logFields[logFieldPrefix+"connected_clients"] = metrics.ConnectedClients
	logFields[logFieldPrefix+"limit_upstream_bytes_per_second"] = metrics.LimitUpstreamBytesPerSecond
	logFields[logFieldPrefix+"limit_downstream_bytes_per_second"] = metrics.LimitDownstreamBytesPerSecond
	logFields[logFieldPrefix+"peak_upstream_bytes_per_second"] = metrics.PeakUpstreamBytesPerSecond
	logFields[logFieldPrefix+"peak_downstream_bytes_per_second"] = metrics.PeakDownstreamBytesPerSecond

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

	if metrics.ProtocolVersion < ProtocolVersion1 || metrics.ProtocolVersion > LatestProtocolVersion {
		return nil, errors.Tracef("invalid protocol version: %v", metrics.ProtocolVersion)
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

	logFields := formatter("", geoIPData, baseParams)

	logFields["protocol_version"] = metrics.ProtocolVersion
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

	// A proxy may specify at most 1 personal compartment ID. This is
	// currently a limitation of the multi-queue implementation; see comment
	// in announcementMultiQueue.enqueue.
	if len(request.PersonalCompartmentIDs) > 1 {
		return nil, nil, errors.Tracef(
			"invalid compartment IDs length: %d", len(request.PersonalCompartmentIDs))
	}

	if request.Metrics == nil {
		return nil, nil, errors.TraceNew("missing metrics")
	}

	apiParams, logFields, err := request.Metrics.ValidateAndGetParametersAndLogFields(
		baseAPIParameterValidator, formatter, "", geoIPData)
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

	// UseMediaStreams requires at least ProtocolVersion2.
	if request.UseMediaStreams &&
		request.Metrics.ProtocolVersion < ProtocolVersion2 {

		return nil, nil, errors.Tracef(
			"invalid protocol version: %d", request.Metrics.ProtocolVersion)
	}

	if len(request.CommonCompartmentIDs) > maxCompartmentIDs {
		return nil, nil, errors.Tracef(
			"invalid compartment IDs length: %d", len(request.CommonCompartmentIDs))
	}

	if len(request.PersonalCompartmentIDs) > maxCompartmentIDs {
		return nil, nil, errors.Tracef(
			"invalid compartment IDs length: %d", len(request.PersonalCompartmentIDs))
	}

	if len(request.CommonCompartmentIDs) > 0 && len(request.PersonalCompartmentIDs) > 0 {
		return nil, nil, errors.TraceNew("multiple compartment ID types")
	}

	// The client offer SDP may contain no ICE candidates.
	errorOnNoCandidates := false

	// The client offer SDP may include RFC 1918/4193 private IP addresses in
	// personal pairing mode. filterSDPAddresses should not filter out
	// private IP addresses based on the broker's local interfaces; this
	// filtering occurs on the proxy that receives the SDP.
	allowPrivateIPAddressCandidates :=
		len(request.PersonalCompartmentIDs) > 0 &&
			len(request.CommonCompartmentIDs) == 0
	filterPrivateIPAddressCandidates := false

	// Client offer SDP candidate addresses must match the country and ASN of
	// the client. Don't facilitate connections to arbitrary destinations.
	filteredSDP, sdpMetrics, err := filterSDPAddresses(
		[]byte(request.ClientOfferSDP.SDP),
		errorOnNoCandidates,
		lookupGeoIP,
		geoIPData,
		allowPrivateIPAddressCandidates,
		filterPrivateIPAddressCandidates)
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
	logFields["has_private_IP"] = sdpMetrics.hasPrivateIP
	logFields["filtered_ice_candidates"] = sdpMetrics.filteredICECandidates
	logFields["use_media_streams"] = request.UseMediaStreams

	return filteredSDP, logFields, nil
}

// Validate validates the that client has not specified excess traffic shaping
// padding or decoy traffic.
func (params *TrafficShapingParameters) Validate() error {

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
	geoIPData common.GeoIPData,
	proxyAnnouncementHasPersonalCompartmentIDs bool) ([]byte, common.LogFields, error) {

	// The proxy answer SDP must contain at least one ICE candidate.
	errorOnNoCandidates := true

	// The proxy answer SDP may include RFC 1918/4193 private IP addresses in
	// personal pairing mode. filterSDPAddresses should not filter out
	// private IP addresses based on the broker's local interfaces; this
	// filtering occurs on the client that receives the SDP.
	allowPrivateIPAddressCandidates := proxyAnnouncementHasPersonalCompartmentIDs
	filterPrivateIPAddressCandidates := false

	// Proxy answer SDP candidate addresses must match the country and ASN of
	// the proxy. Don't facilitate connections to arbitrary destinations.
	filteredSDP, sdpMetrics, err := filterSDPAddresses(
		[]byte(request.ProxyAnswerSDP.SDP),
		errorOnNoCandidates,
		lookupGeoIP,
		geoIPData,
		allowPrivateIPAddressCandidates,
		filterPrivateIPAddressCandidates)
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

	logFields := formatter("", geoIPData, common.APIParameters{})

	logFields["connection_id"] = request.ConnectionID
	logFields["ice_candidate_types"] = request.ICECandidateTypes
	logFields["has_IPv6"] = sdpMetrics.hasIPv6
	logFields["has_private_IP"] = sdpMetrics.hasPrivateIP
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

	logFields := formatter("", geoIPData, common.APIParameters{})

	logFields["connection_id"] = request.ConnectionID

	return logFields, nil
}

// ValidateAndGetLogFields validates the BrokerServerReport and returns
// common.LogFields for logging.
func (report *BrokerServerReport) ValidateAndGetLogFields(
	baseAPIParameterValidator common.APIParameterValidator,
	formatter common.APIParameterLogFieldFormatter,
	proxyMetricsPrefix string) (common.LogFields, error) {

	// Neither ClientIP nor ProxyIP is logged.

	if !report.ClientNATType.IsValid() {
		return nil, errors.Tracef("invalid client NAT type: %v", report.ClientNATType)
	}

	if !report.ClientPortMappingTypes.IsValid() {
		return nil, errors.Tracef("invalid client portmapping types: %v", report.ClientPortMappingTypes)
	}

	var logFields common.LogFields

	if report.ProxyMetrics == nil {

		// Backwards compatibility for reports without ProxyMetrics.

		if !report.ProxyNATType.IsValid() {
			return nil, errors.Tracef("invalid proxy NAT type: %v", report.ProxyNATType)
		}

		if !report.ProxyPortMappingTypes.IsValid() {
			return nil, errors.Tracef("invalid proxy portmapping types: %v", report.ProxyPortMappingTypes)
		}

		logFields = common.LogFields{}

		logFields["inproxy_proxy_nat_type"] = report.ProxyNATType
		logFields["inproxy_proxy_port_mapping_types"] = report.ProxyPortMappingTypes

	} else {

		var err error
		_, logFields, err = report.ProxyMetrics.ValidateAndGetParametersAndLogFields(
			baseAPIParameterValidator,
			formatter,
			proxyMetricsPrefix,
			common.GeoIPData{}) // Proxy GeoIP data is added by the caller.
		if err != nil {
			return nil, errors.Trace(err)
		}

	}

	logFields["inproxy_proxy_id"] = report.ProxyID
	logFields["inproxy_connection_id"] = report.ConnectionID
	logFields["inproxy_matched_common_compartments"] = report.MatchedCommonCompartments
	logFields["inproxy_matched_personal_compartments"] = report.MatchedPersonalCompartments
	logFields["inproxy_client_nat_type"] = report.ClientNATType
	logFields["inproxy_client_port_mapping_types"] = report.ClientPortMappingTypes
	logFields["inproxy_proxy_is_priority"] = report.ProxyIsPriority

	// TODO:
	// - log IPv4 vs. IPv6 information
	// - relay and log broker transport stats, such as meek HTTP version

	return logFields, nil
}

// ValidateAndGetLogFields validates the ServerProxyQualityRequest and returns
// common.LogFields for logging.
func (request *ServerProxyQualityRequest) ValidateAndGetLogFields() (common.LogFields, error) {

	if len(request.QualityCounts) > maxQualityCounts {
		return nil, errors.Tracef("invalid quality count length: %d", len(request.QualityCounts))
	}

	// Currently, there is no custom validator or formatter for
	// DialParameters, as there is for the BaseAPIParameters sent by clients
	// and proxies:
	//
	// - The DialParameters inputs, used only to annotate logs, are from a
	//   trusted Psiphon server.
	//
	// - Psiphon servers do not send fields required by the existing
	//   BaseAPIParameters validators, such as sponsor ID.
	//
	// - No formatter transforms, such as "0"/"1" to bool, are currently
	//   expected; and server.getRequestLogFields is inefficient when a
	//   couple of log fields are expected; for an example for any future
	//   special case formatter, see
	//   server.getInproxyBrokerServerReportParameterLogFieldFormatter.

	dialParams, err := protocol.DecodePackedAPIParameters(request.DialParameters)
	if err != nil {
		return nil, errors.Trace(err)
	}

	logFields := common.LogFields(dialParams)

	return logFields, nil
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

func MarshalServerProxyQualityRequest(request *ServerProxyQualityRequest) ([]byte, error) {
	payload, err := marshalRecord(request, recordTypeAPIServerProxyQualityRequest)
	return payload, errors.Trace(err)
}

func UnmarshalServerProxyQualityRequest(payload []byte) (*ServerProxyQualityRequest, error) {
	var request *ServerProxyQualityRequest
	err := unmarshalRecord(recordTypeAPIServerProxyQualityRequest, payload, &request)
	return request, errors.Trace(err)
}

func MarshalServerProxyQualityResponse(response *ServerProxyQualityResponse) ([]byte, error) {
	payload, err := marshalRecord(response, recordTypeAPIServerProxyQualityResponse)
	return payload, errors.Trace(err)
}

func UnmarshalServerProxyQualityResponse(payload []byte) (*ServerProxyQualityResponse, error) {
	var response *ServerProxyQualityResponse
	err := unmarshalRecord(recordTypeAPIServerProxyQualityResponse, payload, &response)
	return response, errors.Trace(err)
}

func MarshalClientDSLRequest(request *ClientDSLRequest) ([]byte, error) {
	payload, err := marshalRecord(request, recordTypeAPIClientDSLRequest)
	return payload, errors.Trace(err)
}

func UnmarshalClientDSLRequest(payload []byte) (*ClientDSLRequest, error) {
	var request *ClientDSLRequest
	err := unmarshalRecord(recordTypeAPIClientDSLRequest, payload, &request)
	return request, errors.Trace(err)
}

func MarshalClientDSLResponse(response *ClientDSLResponse) ([]byte, error) {
	payload, err := marshalRecord(response, recordTypeAPIClientDSLResponse)
	return payload, errors.Trace(err)
}

func UnmarshalClientDSLResponse(payload []byte) (*ClientDSLResponse, error) {
	var response *ClientDSLResponse
	err := unmarshalRecord(recordTypeAPIClientDSLResponse, payload, &response)
	return response, errors.Trace(err)
}
