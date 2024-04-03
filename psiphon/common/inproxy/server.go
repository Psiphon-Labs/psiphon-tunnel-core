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
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
)

// MaxRelayRoundTrips is a sanity/anti-DoS check against clients that attempt
// to relay more packets than are required for both a session handshake and
// application-level request round trip.
const MaxRelayRoundTrips = 10

// ServerBrokerSessions manages the secure sessions that handle
// BrokerServerReports from brokers. Each in-proxy-capable Psiphon server
// maintains a ServerBrokerSessions, with a set of established sessions for
// each broker. Session messages are relayed between the broker and the
// server by the client.
type ServerBrokerSessions struct {
	sessions *ResponderSessions
}

// NewServerBrokerSessions create a new ServerBrokerSessions, with the
// specified key material. The expected brokers are authenticated with
// brokerPublicKeys, an allow list.
func NewServerBrokerSessions(
	serverPrivateKey SessionPrivateKey,
	serverRootObfuscationSecret ObfuscationSecret,
	brokerPublicKeys []SessionPublicKey) (*ServerBrokerSessions, error) {

	sessions, err := NewResponderSessionsForKnownInitiators(
		serverPrivateKey, serverRootObfuscationSecret, brokerPublicKeys)
	if err != nil {
		return nil, errors.Trace(err)
	}

	return &ServerBrokerSessions{
		sessions: sessions,
	}, nil
}

// SetKnownBrokerPublicKeys updates the set of broker public keys which are
// allowed to establish sessions with the server. Any existing sessions with
// keys not in the new list are deleted. Existing sessions with keys which
// remain in the list are retained.
func (s *ServerBrokerSessions) SetKnownBrokerPublicKeys(
	brokerPublicKeys []SessionPublicKey) error {

	return errors.Trace(s.sessions.SetKnownInitiatorPublicKeys(brokerPublicKeys))
}

// ProxiedConnectionHandler is a callback, provided by the Psiphon server,
// that receives information from a BrokerServerReport for the client
// associated with the callback.
//
// The server must use the brokerVerifiedOriginalClientIP for all GeoIP
// operations associated with the client, including traffic rule selection
// and client-side tactics selection.
//
// Since the BrokerServerReport may be delivered later than the Psiphon
// handshake request -- in the case where the broker/server session needs to
// be established there will be additional round trips -- the server should
// delay traffic rule application, tactics responses, and allowing tunneled
// traffic until after the ProxiedConnectionHandler callback is invoked for
// the client. As a consequence, Psiphon Servers should be configured to
// require Proxies to be used for designated protocols. It's expected that
// server-side tactics such as packet manipulation will be applied based on
// the proxy's IP address.
//
// The fields in logFields should be added to server_tunnel logs.
type ProxiedConnectionHandler func(
	brokerVerifiedOriginalClientIP string,
	logFields common.LogFields)

// HandlePacket handles a broker/server session packet, which are relayed by
// clients. In Psiphon, the packets may be exchanged in the Psiphon
// handshake, or in subsequent SSH requests and responses. When the
// broker/server session is already established, it's expected that the
// BrokerServerReport arrives in the packet that accompanies the Psiphon
// handshake, and so no additional round trip is required.
//
// Once the session is established and a verified BrokerServerReport arrives,
// the information from that report is sent to the ProxiedConnectionHandler
// callback. The callback should be associated with the client that is
// relaying the packets.
//
// clientConnectionID is the in-proxy connection ID specified by the client in
// its Psiphon handshake.
//
// When the retOut return value is not nil, it should be relayed back to the
// client in the handshake response or other tunneled response. When retOut
// is nil, the relay is complete.
//
// In the session reset token case, HandlePacket will return a non-nil retOut
// along with a retErr; the server should both log retErr and also relay the
// packet to the broker.
func (s *ServerBrokerSessions) HandlePacket(
	logger common.Logger,
	in []byte,
	clientConnectionID ID,
	handler ProxiedConnectionHandler) (retOut []byte, retErr error) {

	handleUnwrappedReport := func(initiatorID ID, unwrappedReportPayload []byte) ([]byte, error) {

		brokerReport, err := UnmarshalBrokerServerReport(unwrappedReportPayload)
		if err != nil {
			return nil, errors.Trace(err)
		}

		logFields, err := brokerReport.ValidateAndGetLogFields()
		if err != nil {
			return nil, errors.Trace(err)
		}

		// The initiatorID is the broker's public key.
		logFields["inproxy_broker_id"] = initiatorID

		logFields["inproxy_connection_id"] = brokerReport.ConnectionID
		logFields["inproxy_proxy_id"] = brokerReport.ProxyID

		// !matched_common_compartments implies a personal compartment ID match
		logFields["inproxy_matched_common_compartments"] = brokerReport.MatchedCommonCompartments
		logFields["inproxy_proxy_nat_type"] = brokerReport.ProxyNATType
		logFields["inproxy_proxy_port_mapping_types"] = brokerReport.ProxyPortMappingTypes
		logFields["inproxy_client_nat_type"] = brokerReport.ClientNATType
		logFields["inproxy_client_port_mapping_types"] = brokerReport.ClientPortMappingTypes

		// TODO: log IPv4 vs. IPv6 information.

		ok := true

		// The client must supply same connection ID to server that the broker
		// sends to the server.
		if brokerReport.ConnectionID != clientConnectionID {

			// Limitation: as the BrokerServerReport is a one-way message with
			// no response, the broker will not be notified of tunnel failure
			// errors including "connection ID mismatch", and cannot log this
			// connection attempt outcome.

			logger.WithTraceFields(common.LogFields{
				"client_inproxy_connection_id": clientConnectionID,
				"broker_inproxy_connection_id": brokerReport.ConnectionID,
			}).Error("connection ID mismatch")

			ok = false
		}

		if ok {

			handler(brokerReport.ClientIP, logFields)
		}

		// Returns nil, as there is no response to the report, and so no
		// additional packet to relay.

		return nil, nil
	}

	out, err := s.sessions.HandlePacket(in, handleUnwrappedReport)
	return out, errors.Trace(err)
}
