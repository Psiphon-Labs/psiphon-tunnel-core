/*
 * Copyright (c) 2026, Psiphon Inc.
 * All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

package server

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"net"
	"net/netip"
	"sync/atomic"
	"time"

	tls "github.com/Psiphon-Labs/psiphon-tls"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/inproxy"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/light"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/obfuscator"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/quic"
)

func listenLightTLSTunnel(
	support *SupportServices,
	listener net.Listener,
	listenerTunnelProtocol string,
	listenerPort int) (net.Listener, error) {

	tlsConfig, passthroughAddress, err := makeLightTunnelTLSConfig(
		support, listenerTunnelProtocol, listenerPort)
	if err != nil {
		listener.Close()
		return nil, errors.Trace(err)
	}

	listener = tls.NewListener(listener, tlsConfig)
	additionalMetrics := common.LogFields{"passthrough_address": passthroughAddress}

	return newLightTunnelListener(
		support,
		listener,
		light.TransportTLS,
		exportLightTLSKeyingMaterial,
		additionalMetrics)
}

func listenLightQUICTunnel(
	support *SupportServices,
	listenerTunnelProtocol string,
	listenerAddress string,
	listenerPort int) (net.Listener, error) {

	if !protocol.TunnelProtocolUsesLightQUICEgress(
		listenerTunnelProtocol) {

		return nil, errors.TraceNew("invalid Light QUIC tunnel protocol")
	}

	tlsCertificate, err := tls.X509KeyPair(
		[]byte(support.Config.LightCertificate),
		[]byte(support.Config.LightPrivateKey))
	if err != nil {
		return nil, errors.Trace(err)
	}

	rootObfuscationSecret, err := hex.DecodeString(
		support.Config.LightRootObfuscationSecret)
	if err != nil {
		return nil, errors.Trace(err)
	}
	obfuscationKey, err := light.DeriveTunnelQUICObfuscationKey(
		rootObfuscationSecret)
	if err != nil {
		return nil, errors.Trace(err)
	}

	listener, err := quic.Listen(
		CommonLogger(log),
		func(peerAddress string, err error, logFields common.LogFields) {
			logIrregularTunnel(
				support,
				listenerTunnelProtocol,
				listenerPort,
				peerAddress,
				errors.Trace(err),
				LogFields(logFields))
		},
		listenerAddress,
		nil,
		false,
		0,
		hex.EncodeToString(obfuscationKey),
		nil,
		&tlsCertificate,
		false,
		false)
	if err != nil {
		return nil, errors.Trace(err)
	}

	return newLightTunnelListener(
		support,
		listener,
		light.TransportQUIC,
		exportLightQUICKeyingMaterial,
		nil)
}

func makeLightTunnelTLSConfig(
	support *SupportServices,
	listenerTunnelProtocol string,
	listenerPort int) (*tls.Config, string, error) {

	if !protocol.TunnelProtocolUsesLightTLSEgress(
		listenerTunnelProtocol) {

		return nil, "", errors.TraceNew("invalid Light TLS tunnel protocol")
	}

	tlsCertificate, err := tls.X509KeyPair(
		[]byte(support.Config.LightCertificate),
		[]byte(support.Config.LightPrivateKey))
	if err != nil {
		return nil, "", errors.Trace(err)
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{tlsCertificate},
		NextProtos:   []string{"http/1.1"},
		MinVersion:   tls.VersionTLS13,
	}

	passthroughAddress := support.Config.
		TunnelProtocolPassthroughAddresses[listenerTunnelProtocol]
	if passthroughAddress == "" {
		return nil, "", errors.TraceNew("missing Light TLS passthrough address")
	}

	rootObfuscationSecret, err := hex.DecodeString(
		support.Config.LightRootObfuscationSecret)
	if err != nil {
		return nil, "", errors.Trace(err)
	}
	passthroughKey, err := light.DeriveTunnelTLSPassthroughKey(
		rootObfuscationSecret)
	if err != nil {
		return nil, "", errors.Trace(err)
	}

	seedHistory := obfuscator.NewSeedHistory(nil)
	config.PassthroughAddress = passthroughAddress
	config.PassthroughVerifyMessage = func(message []byte) bool {
		return obfuscator.VerifyTLSPassthroughMessage(
			true,
			hex.EncodeToString(passthroughKey),
			message)
	}
	config.PassthroughLogInvalidMessage = func(clientIP string) {
		logIrregularTunnel(
			support,
			listenerTunnelProtocol,
			listenerPort,
			clientIP,
			errors.TraceNew("invalid passthrough message"),
			nil)
	}
	config.PassthroughHistoryAddNew = func(
		clientIP string,
		clientRandom []byte) bool {

		ok, logFields := seedHistory.AddNewWithTTL(
			true,
			clientIP,
			"client-random",
			clientRandom,
			obfuscator.TLS_PASSTHROUGH_HISTORY_TTL)

		if logFields != nil {
			logIrregularTunnel(
				support,
				listenerTunnelProtocol,
				listenerPort,
				clientIP,
				errors.TraceNew("duplicate passthrough message"),
				LogFields(*logFields))
		}

		return ok
	}

	return config, passthroughAddress, nil
}

type lightTunnelListener struct {
	net.Listener
	support               *SupportServices
	egressProtocol        uint8
	exportKeyingMaterial  func(context.Context, net.Conn) ([]byte, error)
	trustedProxyPublicKey ed25519.PublicKey
	additionalMetrics     common.LogFields
}

func newLightTunnelListener(
	support *SupportServices,
	listener net.Listener,
	egressProtocol uint8,
	exportKeyingMaterial func(context.Context, net.Conn) ([]byte, error),
	additionalMetrics common.LogFields) (net.Listener, error) {

	var trustedProxyPublicKey ed25519.PublicKey
	if support.Config.LightTrustedProxyAuthorizationPublicKey != "" {
		publicKey, err := base64.StdEncoding.DecodeString(
			support.Config.LightTrustedProxyAuthorizationPublicKey)
		if err != nil {
			listener.Close()
			return nil, errors.Trace(err)
		}
		if len(publicKey) != ed25519.PublicKeySize {
			listener.Close()
			return nil, errors.TraceNew("invalid trusted proxy public key")
		}
		trustedProxyPublicKey = ed25519.PublicKey(publicKey)
	}

	return &lightTunnelListener{
		Listener:              listener,
		support:               support,
		egressProtocol:        egressProtocol,
		exportKeyingMaterial:  exportKeyingMaterial,
		trustedProxyPublicKey: trustedProxyPublicKey,
		additionalMetrics:     additionalMetrics,
	}, nil
}

func (listener *lightTunnelListener) Accept() (net.Conn, error) {
	conn, err := listener.Listener.Accept()
	if err != nil {
		return nil, errors.Trace(err)
	}

	return NewLightTunnelConn(
		conn,
		listener.egressProtocol,
		func(ctx context.Context) ([]byte, error) {
			return listener.exportKeyingMaterial(ctx, conn)
		},
		listener.trustedProxyPublicKey,
		listener.support.GeoIPService.Lookup,
		listener.additionalMetrics), nil
}

func exportLightTLSKeyingMaterial(
	ctx context.Context,
	conn net.Conn) ([]byte, error) {

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return nil, errors.TraceNew("invalid TLS connection")
	}

	err := tlsConn.HandshakeContext(ctx)
	if err != nil {
		return nil, errors.Trace(err)
	}

	state := tlsConn.ConnectionState()
	exporter, err := state.ExportKeyingMaterial(
		light.TunnelProxyReportExporterLabel,
		nil,
		light.TunnelProxyReportExporterSize)
	if err != nil {
		return nil, errors.Trace(err)
	}

	return exporter, nil
}

func exportLightQUICKeyingMaterial(
	ctx context.Context,
	conn net.Conn) ([]byte, error) {

	if err := ctx.Err(); err != nil {
		return nil, errors.Trace(err)
	}
	quicConn, ok := conn.(*quic.Conn)
	if !ok {
		return nil, errors.TraceNew("invalid QUIC connection")
	}
	return quicConn.ExportKeyingMaterial(
		light.TunnelProxyReportExporterLabel,
		nil,
		light.TunnelProxyReportExporterSize)
}

// LightTunnelConn verifies the proxy report and handles Light framing on a
// proxy-to-server connection. It implements net.Conn and common.MetricsSource.
type LightTunnelConn struct {
	net.Conn

	exportKeyingMaterial   func(context.Context) ([]byte, error)
	expectedEgressProtocol uint8
	trustedProxyPublicKey  ed25519.PublicKey
	lookupGeoIP            func(string) GeoIPData
	additionalMetrics      common.LogFields

	initialized    atomic.Bool
	framingConn    net.Conn
	clientIP       netip.Addr
	proxyReport    *light.TunnelProxyReport
	proxyID        inproxy.ID
	trustedProxy   bool
	tunnelProtocol string
}

// NewLightTunnelConn wraps conn with LightTunnelConn. initialize must succeed
// before Read or Write can be used.
func NewLightTunnelConn(
	conn net.Conn,
	expectedEgressProtocol uint8,
	exportKeyingMaterial func(context.Context) ([]byte, error),
	trustedProxyPublicKey ed25519.PublicKey,
	lookupGeoIP func(string) GeoIPData,
	additionalMetrics common.LogFields) *LightTunnelConn {

	return &LightTunnelConn{
		Conn:                   conn,
		expectedEgressProtocol: expectedEgressProtocol,
		exportKeyingMaterial:   exportKeyingMaterial,
		trustedProxyPublicKey:  trustedProxyPublicKey,
		lookupGeoIP:            lookupGeoIP,
		additionalMetrics:      additionalMetrics,
	}
}

// initialize is called by sshServer.handshakeTunnelTransport before starting SSH.
func (conn *LightTunnelConn) initialize(ctx context.Context) error {
	if conn.initialized.Load() {
		return nil
	}

	interruptOnDone := context.AfterFunc(ctx, func() {
		_ = conn.Conn.Close()
	})
	defer interruptOnDone()

	exporter, err := conn.exportKeyingMaterial(ctx)
	if err != nil {
		return errors.Trace(err)
	}

	report, proxyID, err := light.ReadAndVerifyTunnelProxyReport(
		conn.Conn,
		exporter)
	if err != nil {
		return errors.Trace(err)
	}
	if err := ctx.Err(); err != nil {
		return errors.Trace(err)
	}

	switch conn.expectedEgressProtocol {
	case light.TransportTLS:
		if report.EgressTLSProfile == 0 || report.EgressQUICVersion != 0 {
			return light.NewIrregularTunnelError(
				errors.TraceNew("unexpected Light egress parameters"))
		}
	case light.TransportQUIC:
		if report.EgressTLSProfile != 0 || report.EgressQUICVersion == 0 {
			return light.NewIrregularTunnelError(
				errors.TraceNew("unexpected Light egress parameters"))
		}
	default:
		return errors.TraceNew("invalid Light egress protocol")
	}

	// Ingress is proxy-reported; only the egress transport is independently
	// verified by the server. Filters such as traffic rules must not rely on
	// the ingress variant for security-sensitive authorization.
	tunnelProtocol, err := getLightTunnelProtocol(
		report.IngressProtocol, conn.expectedEgressProtocol)
	if err != nil {
		return light.NewIrregularTunnelError(errors.Trace(err))
	}

	trustedProxy := false
	if len(report.TrustedProxyAuthorization) > 0 {
		// Reject a supplied trusted proxy authorization if it cannot be verified,
		// including when no verification key is configured. The tunnel fails,
		// instead of downgrading to untrusted, and irregular tunnel events may
		// be monitored for invalid or expired authorizations.
		_, err := light.VerifyTunnelTrustedProxyAuthorization(
			conn.trustedProxyPublicKey,
			report.ProxyPublicKey,
			report.TrustedProxyAuthorization,
			time.Now())
		if err != nil {
			return light.NewIrregularTunnelError(
				errors.TraceMsg(
					err,
					"invalid trusted proxy authorization"))
		}
		trustedProxy = true
	}

	clientIP, ok := netip.AddrFromSlice(report.ClientIP)
	if !ok {
		return light.NewIrregularTunnelError(
			errors.TraceNew("invalid client IP"))
	}

	conn.proxyReport = report
	conn.proxyID = proxyID
	conn.trustedProxy = trustedProxy
	conn.tunnelProtocol = tunnelProtocol
	conn.clientIP = clientIP
	conn.framingConn = light.NewLightFramingConn(conn.Conn)
	conn.initialized.Store(true)

	return nil
}

func getLightTunnelProtocol(
	ingressProtocol, egressProtocol uint8) (string, error) {

	switch {
	case ingressProtocol == light.TransportTLS &&
		egressProtocol == light.TransportTLS:

		return protocol.TUNNEL_PROTOCOL_LIGHT_TLS_TLS_SSH, nil
	case ingressProtocol == light.TransportTLS &&
		egressProtocol == light.TransportQUIC:

		return protocol.TUNNEL_PROTOCOL_LIGHT_TLS_QUIC_SSH, nil
	case ingressProtocol == light.TransportQUIC &&
		egressProtocol == light.TransportTLS:

		return protocol.TUNNEL_PROTOCOL_LIGHT_QUIC_TLS_SSH, nil
	case ingressProtocol == light.TransportQUIC &&
		egressProtocol == light.TransportQUIC:

		return protocol.TUNNEL_PROTOCOL_LIGHT_QUIC_QUIC_SSH, nil
	default:
		return "", errors.TraceNew("invalid Light tunnel protocol")
	}
}

// TunnelProtocol returns the Light tunnel protocol based on the proxy's
// reported ingress transport and the server's egress transport.
func (conn *LightTunnelConn) TunnelProtocol() string {
	return conn.tunnelProtocol
}

// GetTrustedClientIP returns the trusted original client IP, or "" if unavailable.
func (conn *LightTunnelConn) GetTrustedClientIP() string {
	if !conn.initialized.Load() || !conn.trustedProxy {
		return ""
	}
	return conn.clientIP.String()
}

func (conn *LightTunnelConn) Read(buffer []byte) (int, error) {
	if !conn.initialized.Load() {
		return 0, errors.TraceNew("Light tunnel not initialized")
	}
	return conn.framingConn.Read(buffer)
}

func (conn *LightTunnelConn) Write(buffer []byte) (int, error) {
	if !conn.initialized.Load() {
		return 0, errors.TraceNew("Light tunnel not initialized")
	}
	return conn.framingConn.Write(buffer)
}

// GetMetrics implements common.MetricsSource.
func (conn *LightTunnelConn) GetMetrics() common.LogFields {

	var logFields common.LogFields
	if metricsSource, ok := conn.Conn.(common.MetricsSource); ok {
		logFields = metricsSource.GetMetrics()
	}
	if logFields == nil {
		logFields = make(common.LogFields)
	}

	logFields.Add(conn.additionalMetrics)

	if conn.lookupGeoIP != nil {
		proxyGeoIPData := conn.lookupGeoIP(
			common.IPAddressFromAddr(conn.RemoteAddr()))
		proxyGeoIPData.SetLogFieldsWithPrefix(
			"",
			"light_proxy",
			LogFields(logFields))
	}

	if !conn.initialized.Load() {
		return logFields
	}

	logFields.Add(conn.proxyReport.GetMetrics())
	logFields["light_proxy_id"] = conn.proxyID.String()
	logFields["light_proxy_is_trusted"] = conn.trustedProxy

	// These egress values are observed by the server, not reported by the proxy.
	//
	// TODO: as a future enhancement, other tunnel protocols where the server
	// terminates the client's TLS or QUIC, such as TLS-OSSH and unfronted
	// meek, could also log the SNI observed on the wire, rather than relying
	// on client-reported values.
	switch conn.expectedEgressProtocol {
	case light.TransportTLS:
		transportConn, ok := conn.Conn.(*tls.Conn)
		if !ok {
			log.WithTrace().Error("Unexpected Light TLS connection type")
			break
		}

		state := transportConn.ConnectionState()
		metrics := transportConn.ConnectionMetrics()
		logFields["light_egress_tls_sni"] = common.TruncateUTF8String(
			state.ServerName, MAX_API_PARAM_STRING_LENGTH)
		logFields["light_egress_tls_fragmented"] = metrics.ClientHelloFragmented
		logFields["light_egress_tls_padding"] = metrics.ClientHelloPaddingLength
		logFields["light_egress_tls_did_resume"] = state.DidResume

	case light.TransportQUIC:
		transportConn, ok := conn.Conn.(*quic.Conn)
		if !ok {
			log.WithTrace().Error("Unexpected Light QUIC connection type")
			break
		}

		state, err := transportConn.GetTLSConnectionState()
		if err != nil {
			log.WithTraceFields(LogFields{"error": err}).Warning(
				"Light QUIC metrics failed")
			break
		}
		logFields["light_egress_quic_sni"] = common.TruncateUTF8String(
			state.ServerName, MAX_API_PARAM_STRING_LENGTH)
		logFields["light_egress_quic_did_resume"] = state.DidResume

	default:
		log.WithTraceFields(LogFields{
			"egress_protocol": conn.expectedEgressProtocol,
		}).Error("Unexpected Light egress protocol")
	}

	return logFields
}
