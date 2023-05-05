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

// ServerBrokerSessions manages the secure sessions that handle
// BrokerServerRequests from brokers. Each in-proxy-capable Psiphon server
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

// ProxiedConnectionHandler is a callback, provided by the Psiphon server,
// that receives information from a BrokerServerRequest for the client
// associated with the callback.
//
// The server must use the brokerVerifiedOriginalClientIP for all GeoIP
// operations associated with the client, including traffic rule selection
// and client-side tactics selection.
//
// Since the BrokerServerRequest may be delivered later than the Psiphon
// handshake -- in the case where the broker/server session needs to be
// established there will be additional round trips -- the server should
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
// clients. In Psiphon, the packets may be sent in the Psiphon handshake, or
// in subsequent requests; while responses should be returned in the
// handshake response or responses for later requests. When the broker/server
// session is already established, it's expected that the BrokerServerRequest
// arrives in the packet that accompanies the Psiphon handshake, and so no
// additional round trip is required.
//
// Once the session is established and a verified BrokerServerRequest arrives,
// the information from that request is sent to the ProxiedConnectionHandler
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
// When the retErr return value is not nil, it should be logged, and an error
// flag (but not the retErr value) relayed back to the client. retErr may be
// non-nil in expected conditions, such as the broker attempting to use a
// session which has expired.
func (s *ServerBrokerSessions) HandlePacket(
	logger common.Logger,
	in []byte,
	clientConnectionID ID,
	handler ProxiedConnectionHandler) (retOut []byte, retErr error) {

	handleUnwrappedRequest := func(initiatorID ID, unwrappedRequestPayload []byte) ([]byte, error) {

		brokerRequest, err := UnmarshalBrokerServerRequest(unwrappedRequestPayload)
		if err != nil {
			return nil, errors.Trace(err)
		}

		logFields, err := brokerRequest.ValidateAndGetLogFields()
		if err != nil {
			return nil, errors.Trace(err)
		}

		// The initiatorID is the broker's public key.
		logFields["broker_id"] = initiatorID

		var errorMessage string

		// The client must supply same connection ID to server that the broker
		// sends to the server.
		if brokerRequest.ConnectionID != clientConnectionID {

			// Errors such as this are not error return values, as this is not
			// an error in the session protocol. Instead, a response is sent
			// to the broker containing the error message, which the broker may log.

			errorMessage = "connection ID mismatch"

			logger.WithTraceFields(common.LogFields{
				"client_connection_id": clientConnectionID,
				"broker_connection_id": brokerRequest.ConnectionID,
			}).Error(errorMessage)
		}

		if errorMessage == "" {

			handler(brokerRequest.ClientIP, logFields)
		}

		brokerResponse, err := MarshalBrokerServerResponse(
			&BrokerServerResponse{
				ConnectionID: brokerRequest.ConnectionID,
				ErrorMessage: errorMessage,
			})
		if err != nil {
			return nil, errors.Trace(err)
		}

		return brokerResponse, nil
	}

	// An error here may be due to the broker using a session that has
	// expired. In that case, the client should relay back that the session
	// failed, and the broker will start reestablishing the session.
	//
	// TODO: distinguish between session expired, an expected error, and
	// unexpected errors and then log only unexpected errors? However, expiry
	// may be rare, and still useful to log.

	out, err := s.sessions.HandlePacket(
		in, handleUnwrappedRequest)
	if err != nil {
		return nil, errors.Trace(err)
	}

	return out, nil
}
