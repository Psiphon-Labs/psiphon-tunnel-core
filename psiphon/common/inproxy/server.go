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
	"time"

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
//
// ServerBrokerSessions runs a ProxyQualityReporter which sends proxy quality
// reports back to the same brokers.
type ServerBrokerSessions struct {
	config               *ServerBrokerSessionsConfig
	sessions             *ResponderSessions
	proxyQualityReporter *ProxyQualityReporter
}

// ServerBrokerSessionsConfig specifies the configuration for a
// ServerBrokerSessions instance.
type ServerBrokerSessionsConfig struct {

	// Logger provides a logging facility.
	Logger common.Logger

	// ServerPrivateKey is the server's session private key. It must
	// correspond to the server session public key that a broker finds in a
	// signed Psiphon server entry.
	ServerPrivateKey SessionPrivateKey

	// ServerRootObfuscationSecret is the server's root obfuscation secret, as
	// found in the server's signed Psiphon server entry.
	ServerRootObfuscationSecret ObfuscationSecret

	// BrokerPublicKeys specifies the public keys corresponding to known
	// brokers that are trusted to connect to the server; which are also the
	// brokers to which the server will send its proxy quality reports.
	BrokerPublicKeys []SessionPublicKey

	// BrokerRootObfuscationSecrets are the obfuscation secrets corresponding
	// to the entries in BrokerPublicKeys.
	BrokerRootObfuscationSecrets []ObfuscationSecret

	// BrokerRoundTripperMaker constructs round trip transports used to send
	// proxy quality requests to the specified broker.
	BrokerRoundTripperMaker ProxyQualityBrokerRoundTripperMaker

	// ProxyMetricsValidator is used to further validate the proxy metrics
	// fields relayed by the broker in broker server reports.
	ProxyMetricsValidator common.APIParameterValidator

	// ProxyMetricsValidator is used to log-format the proxy metrics fields
	// relayed by the broker in broker server reports.
	ProxyMetricsFormatter common.APIParameterLogFieldFormatter

	// ProxyMetricsPrefix specifies an optional prefix to be prepended to
	// proxy metric fields when logging.
	ProxyMetricsPrefix string
}

// NewServerBrokerSessions create a new ServerBrokerSessions, with the
// specified key material. The expected brokers are authenticated with
// brokerPublicKeys, an allow list.
func NewServerBrokerSessions(
	config *ServerBrokerSessionsConfig) (*ServerBrokerSessions, error) {

	sessions, err := NewResponderSessionsForKnownInitiators(
		config.ServerPrivateKey,
		config.ServerRootObfuscationSecret,
		config.BrokerPublicKeys)
	if err != nil {
		return nil, errors.Trace(err)
	}

	s := &ServerBrokerSessions{
		config:   config,
		sessions: sessions,
	}

	s.proxyQualityReporter, err = NewProxyQualityReporter(
		config.Logger,
		s,
		config.ServerPrivateKey,
		config.BrokerPublicKeys,
		config.BrokerRootObfuscationSecrets,
		config.BrokerRoundTripperMaker)
	if err != nil {
		return nil, errors.Trace(err)
	}

	return s, nil
}

// Start launches the proxy quality reporter.
func (s *ServerBrokerSessions) Start() error {

	err := s.proxyQualityReporter.Start()
	if err != nil {
		return errors.Trace(err)
	}

	return nil
}

// Stop terminates the proxy quality reporter.
func (s *ServerBrokerSessions) Stop() {

	s.proxyQualityReporter.Stop()
}

// SetKnownBrokers updates the set of broker public keys which are
// allowed to establish sessions with the server. Any existing sessions with
// keys not in the new list are deleted. Existing sessions with keys which
// remain in the list are retained.
//
// The broker public keys also identify those brokers to which the proxy
// quality reporter will send quality requests. The broker obfuscation
// secrets are used by the reporter.
func (s *ServerBrokerSessions) SetKnownBrokers(
	brokerPublicKeys []SessionPublicKey,
	brokerRootObfuscationSecrets []ObfuscationSecret) error {

	err := s.sessions.SetKnownInitiatorPublicKeys(
		brokerPublicKeys)
	if err != nil {
		return errors.Trace(err)
	}

	err = s.proxyQualityReporter.SetKnownBrokers(
		brokerPublicKeys, brokerRootObfuscationSecrets)
	if err != nil {
		return errors.Trace(err)
	}

	return nil
}

// SetProxyQualityRequestParameters overrides default values for proxy quality
// reporter parameters.
func (s *ServerBrokerSessions) SetProxyQualityRequestParameters(
	maxRequestEntries int,
	requestDelay time.Duration,
	requestTimeout time.Duration,
	requestRetries int) {

	s.proxyQualityReporter.SetRequestParameters(
		maxRequestEntries,
		requestDelay,
		requestTimeout,
		requestRetries)
}

// ReportQuality enqueues a proxy quality event in the proxy quality reporter.
// See ProxyQualityReporter.ReportQuality for details.
func (s *ServerBrokerSessions) ReportQuality(
	proxyID ID, proxyASN string, clientASN string) {

	s.proxyQualityReporter.ReportQuality(proxyID, proxyASN, clientASN)
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
	brokerReportedProxyID ID,
	brokerMatchedPersonalCompartments bool,
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

		logFields, err := brokerReport.ValidateAndGetLogFields(
			s.config.ProxyMetricsValidator,
			s.config.ProxyMetricsFormatter,
			s.config.ProxyMetricsPrefix)
		if err != nil {
			return nil, errors.Trace(err)
		}

		// The initiatorID is the broker's public key.
		logFields["inproxy_broker_id"] = initiatorID

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
			handler(
				brokerReport.ClientIP,
				brokerReport.ProxyID,
				brokerReport.MatchedPersonalCompartments,
				logFields)
		}

		// Returns nil, as there is no response to the report, and so no
		// additional packet to relay.

		return nil, nil
	}

	out, err := s.sessions.HandlePacket(in, handleUnwrappedReport)
	return out, errors.Trace(err)
}
