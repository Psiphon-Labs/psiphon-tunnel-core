/*
 * Copyright (c) 2025, Psiphon Inc.
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

package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/inproxy"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/parameters"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
)

// MakeInproxyProxyQualityBrokerRoundTripper creates a new
// InproxyProxyQualityBrokerRoundTripper for an in-proxy broker specified by
// public key.
func MakeInproxyProxyQualityBrokerRoundTripper(
	support *SupportServices,
	brokerPublicKey inproxy.SessionPublicKey) (
	*InproxyProxyQualityBrokerRoundTripper, common.APIParameters, error) {

	// Lookup the broker dial information in InproxyAllBrokerSpecs.
	//
	// Assumes no GeoIP targeting for InproxyAllBrokerSpecs.

	p, err := support.ServerTacticsParametersCache.Get(NewGeoIPData())
	if err != nil {
		return nil, nil, errors.Trace(err)
	}

	if p.IsNil() {
		return nil, nil, errors.TraceNew("missing tactics")
	}

	// Fall back to InproxyBrokerSpecs if InproxyAllBrokerSpecs is not
	// configured.
	brokerSpecs := p.InproxyBrokerSpecs(
		parameters.InproxyAllBrokerSpecs, parameters.InproxyBrokerSpecs)

	// InproxyProxyQualityReporterTrustedCACertificates and
	// InproxyProxyQualityReporterAdditionalHeaders are intended to support
	// testing.
	trustedCACertificates := p.String(
		parameters.InproxyProxyQualityReporterTrustedCACertificates)
	if trustedCACertificates != "" {
		// Convert JSON-escaped "/n" back to PEM newlines.
		trustedCACertificates = strings.ReplaceAll(trustedCACertificates, "\\n", "\n")
	}
	additionalHeaders := p.HTTPHeaders(
		parameters.InproxyProxyQualityReporterAdditionalHeaders)

	// This linear search over all broker specs is suitable for a handful of
	// brokers, and assumes broker round trippers are reused and not
	// recreated continuously.

	brokerPublicKeyStr := brokerPublicKey.String()

	for _, brokerSpec := range brokerSpecs {
		if brokerSpec.BrokerPublicKey == brokerPublicKeyStr {
			roundTripper, err := NewInproxyProxyQualityBrokerRoundTripper(
				brokerSpec, trustedCACertificates, additionalHeaders)
			if err != nil {
				return nil, nil, errors.Trace(err)
			}
			return roundTripper, roundTripper.dialParams, nil
		}
	}

	return nil, nil, errors.Tracef("broker public key not found: %s", brokerPublicKeyStr)
}

// InproxyProxyQualityBrokerRoundTripper is a broker request round trip
// network transport which implements the inproxy.RoundTripper interface.
type InproxyProxyQualityBrokerRoundTripper struct {
	transport         *http.Transport
	conns             *common.Conns[net.Conn]
	requestURL        string
	additionalHeaders http.Header
	dialParams        common.APIParameters
}

// NewInproxyProxyQualityBrokerRoundTripper initializes a new
// InproxyProxyQualityBrokerRoundTripper, using the dial parameters in the
// input InproxyBrokerSpec.
func NewInproxyProxyQualityBrokerRoundTripper(
	brokerSpec *parameters.InproxyBrokerSpec,
	trustedCACertificates string,
	additionalHeaders http.Header) (*InproxyProxyQualityBrokerRoundTripper, error) {

	// While server to broker connections are not expected to be subject to
	// blocking, this transport currently uses CDN fronts, as already
	// specified for client and proxy broker connections. Direct server to
	// broker connections are not supported, but could be added in the future.
	//
	// The CDN path may, in fact, assist with performance and scaling, given
	// that requests routed through CDNs will be multiplexed over existing
	// CDN-to-origin connections, and not use additional ephemeral ports on
	// the broker origin host.

	frontingProviderID,
		frontingTransport,
		frontingDialAddress,
		_, // SNIServerName is ignored
		verifyServerName,
		verifyPins,
		hostHeader,
		err := brokerSpec.BrokerFrontingSpecs.SelectParameters()
	if err != nil {
		return nil, errors.Trace(err)
	}

	if frontingTransport != protocol.FRONTING_TRANSPORT_HTTPS {
		return nil, errors.TraceNew("unsupported fronting transport")
	}

	// The following wires up simplified domain fronted requests, including
	// the basic, distinct dial/SNI and host header values. Certificate
	// validation based on FrontingSpec parameters, including pins, includes
	// a subset of the functionality from psiphon.CustomTLSDial.
	//
	// psiphon.DialMeek/CustomTLSDial features omitted here include dial
	// parameter replay, the QUIC transport, and obfuscation techniques
	// including custom DNS resolution, SNI transforms, utls TLS
	// fingerprints, and TCP and TLS fragmentation, TLS padding, and other
	// mechanisms.

	// FrontingSpec.Addresses may include a port; default to 443 if none.
	dialAddress := frontingDialAddress
	if _, _, err := net.SplitHostPort(dialAddress); err != nil {
		dialAddress = net.JoinHostPort(frontingDialAddress, "443")
	}

	var tlsConfigRootCAs *x509.CertPool
	if trustedCACertificates != "" {
		tlsConfigRootCAs = x509.NewCertPool()
		if !tlsConfigRootCAs.AppendCertsFromPEM([]byte(trustedCACertificates)) {
			return nil, errors.TraceNew("AppendCertsFromPEM failed")
		}
	}

	conns := common.NewConns[net.Conn]()

	transport := &http.Transport{
		DialTLSContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			conn, err := (&net.Dialer{}).DialContext(ctx, network, dialAddress)
			if err != nil {
				return nil, errors.Trace(err)
			}

			// Track conn to facilitate InproxyProxyQualityBrokerRoundTripper.Close
			// interrupting and closing all connections.
			conn = &inproxyProxyQualityBrokerRoundTripperConn{Conn: conn, conns: conns}
			if !conns.Add(conn) {
				conn.Close()
				return nil, errors.Trace(err)
			}

			tlsConn := tls.Client(
				conn,
				&tls.Config{
					InsecureSkipVerify: true,
					VerifyPeerCertificate: func(
						rawCerts [][]byte, _ [][]*x509.Certificate) error {

						var verifiedChains [][]*x509.Certificate
						var err error
						if verifyServerName != "" {
							verifiedChains, err = common.VerifyServerCertificate(
								tlsConfigRootCAs, rawCerts, verifyServerName)
							if err != nil {
								return errors.Trace(err)
							}
						}
						if len(verifyPins) > 0 {
							err := common.VerifyCertificatePins(
								verifyPins, verifiedChains)
							if err != nil {
								return errors.Trace(err)
							}
						}
						return nil
					},
				})
			err = tlsConn.HandshakeContext(ctx)
			if err != nil {
				conn.Close()
				return nil, errors.Trace(err)
			}
			return tlsConn, nil
		},
	}

	url := &url.URL{
		Scheme: "https",
		Host:   hostHeader,
		Path:   "/",
	}

	// Note that there's currently no custom log formatter (or validator) in
	// inproxy.ServerProxyQualityRequest.ValidateAndGetLogFields, so field
	// transforms, such as "0"/"1" to bool, are not yet supported here.

	dialParams := common.APIParameters{
		"fronting_provider_id": frontingProviderID,
	}

	return &InproxyProxyQualityBrokerRoundTripper{
		transport:         transport,
		conns:             conns,
		requestURL:        url.String(),
		additionalHeaders: additionalHeaders,
		dialParams:        dialParams,
	}, nil
}

type inproxyProxyQualityBrokerRoundTripperConn struct {
	net.Conn
	conns *common.Conns[net.Conn]
}

func (conn *inproxyProxyQualityBrokerRoundTripperConn) Close() error {
	conn.conns.Remove(conn)
	return errors.Trace(conn.Conn.Close())
}

// RoundTrip performs a broker request round trip.
func (r *InproxyProxyQualityBrokerRoundTripper) RoundTrip(
	ctx context.Context,
	roundTripDelay time.Duration,
	roundTripTimeout time.Duration,
	requestPayload []byte) (retResponsePayload []byte, retErr error) {

	defer func() {
		// Wrap every return with RoundTripperFailedError to conform with the
		// inproxy.RoundTripper interface. This is a simplification of the
		// logic in InproxyBrokerRoundTripper.RoundTrip, which conditionally
		// wraps errors based on various heuristics and conditions that are
		// more relevant to clients and proxies with long polling and
		// multiple concurrent requests.
		if retErr != nil {
			retErr = inproxy.NewRoundTripperFailedError(retErr)
		}
	}()

	// Proxy quality broker round trips are not expected to apply a delay here.
	if roundTripDelay > 0 {
		return nil, errors.TraceNew("roundTripDelay unsupported")
	}

	request, err := http.NewRequestWithContext(
		ctx, "POST", r.requestURL, bytes.NewReader(requestPayload))
	if err != nil {
		return nil, errors.Trace(err)
	}

	for name, value := range r.additionalHeaders {
		request.Header[name] = value
	}

	response, err := r.transport.RoundTrip(request)
	if err != nil {
		return nil, errors.Trace(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, errors.Tracef(
			"unexpected response status code %d", response.StatusCode)
	}

	responsePayload, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, errors.Trace(err)
	}

	return responsePayload, nil
}

// Close interrupts any in-flight request and closes all underlying network
// connections.
func (r *InproxyProxyQualityBrokerRoundTripper) Close() error {
	r.conns.CloseAll()
	return nil
}
