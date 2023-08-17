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

package server

import (
	"net"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/obfuscator"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/values"
	tris "github.com/Psiphon-Labs/tls-tris"
)

// TLSTunnelServer tunnels TCP traffic (in the case of Psiphon, Obfuscated SSH
// traffic) over TLS.
type TLSTunnelServer struct {
	support                *SupportServices
	listener               net.Listener
	listenerTunnelProtocol string
	listenerPort           int
	passthroughAddress     string
	tlsConfig              *tris.Config
	obfuscatorSeedHistory  *obfuscator.SeedHistory
}

func ListenTLSTunnel(
	support *SupportServices,
	listener net.Listener,
	listenerTunnelProtocol string,
	listenerPort int,
) (net.Listener, error) {

	server, err := NewTLSTunnelServer(support, listener, listenerTunnelProtocol, listenerPort)
	if err != nil {
		return nil, errors.Trace(err)
	}

	return tris.NewListener(server.listener, server.tlsConfig), nil
}

// NewTLSTunnelServer initializes a new TLSTunnelServer.
func NewTLSTunnelServer(
	support *SupportServices,
	listener net.Listener,
	listenerTunnelProtocol string,
	listenerPort int) (*TLSTunnelServer, error) {

	passthroughAddress := support.Config.TunnelProtocolPassthroughAddresses[listenerTunnelProtocol]

	tlsServer := &TLSTunnelServer{
		support:                support,
		listener:               listener,
		listenerTunnelProtocol: listenerTunnelProtocol,
		listenerPort:           listenerPort,
		passthroughAddress:     passthroughAddress,
		obfuscatorSeedHistory:  obfuscator.NewSeedHistory(nil),
	}

	tlsConfig, err := tlsServer.makeTLSTunnelConfig()
	if err != nil {
		return nil, errors.Trace(err)
	}
	tlsServer.tlsConfig = tlsConfig

	return tlsServer, nil
}

// makeTLSTunnelConfig creates a TLS config for a TLSTunnelServer listener.
func (server *TLSTunnelServer) makeTLSTunnelConfig() (*tris.Config, error) {

	// Limitation: certificate value changes on restart.

	certificate, privateKey, err := common.GenerateWebServerCertificate(values.GetHostName())
	if err != nil {
		return nil, errors.Trace(err)
	}

	tlsCertificate, err := tris.X509KeyPair(
		[]byte(certificate), []byte(privateKey))
	if err != nil {
		return nil, errors.Trace(err)
	}

	var minVersion uint16
	if protocol.TunnelProtocolUsesTLSOSSH(server.listenerTunnelProtocol) {
		// Use min TLS 1.3 so cert is not plaintext on the wire.
		minVersion = tris.VersionTLS13
	} else {
		// Need to support older TLS versions for backwards compatibility.
		// Vary the minimum version to frustrate scanning/fingerprinting of unfronted servers.
		// Limitation: like the certificate, this value changes on restart.
		minVersionCandidates := []uint16{tris.VersionTLS10, tris.VersionTLS11, tris.VersionTLS12}
		minVersion = minVersionCandidates[prng.Intn(len(minVersionCandidates))]
	}

	config := &tris.Config{
		Certificates:            []tris.Certificate{tlsCertificate},
		NextProtos:              []string{"http/1.1"},
		MinVersion:              minVersion,
		UseExtendedMasterSecret: true,
	}

	// When configured, initialize passthrough mode, an anti-probing defense.
	// Clients must prove knowledge of the obfuscated key via a message sent in
	// the TLS ClientHello random field.
	//
	// When clients fail to provide a valid message, the client connection is
	// relayed to the designated passthrough address, typically another web site.
	// The entire flow is relayed, including the original ClientHello, so the
	// client will perform a TLS handshake with the passthrough target.
	//
	// Irregular events are logged for invalid client activity.

	if server.passthroughAddress != "" {

		config.PassthroughAddress = server.passthroughAddress

		config.PassthroughVerifyMessage = func(
			message []byte) bool {

			return obfuscator.VerifyTLSPassthroughMessage(
				true,
				// Meek obfuscated key used for legacy reasons. See comment for
				// MeekObfuscatedKey.
				server.support.Config.MeekObfuscatedKey,
				message)
		}

		config.PassthroughLogInvalidMessage = func(
			clientIP string) {

			logIrregularTunnel(
				server.support,
				server.listenerTunnelProtocol,
				server.listenerPort,
				clientIP,
				errors.TraceNew("invalid passthrough message"),
				nil)
		}

		config.PassthroughHistoryAddNew = func(
			clientIP string,
			clientRandom []byte) bool {

			// Use a custom, shorter TTL based on the validity period of the
			// passthrough message.
			TTL := obfuscator.TLS_PASSTHROUGH_TIME_PERIOD

			// strictMode is true as legitimate clients never retry TLS
			// connections using a previous random value.

			ok, logFields := server.obfuscatorSeedHistory.AddNewWithTTL(
				true,
				clientIP,
				"client-random",
				clientRandom,
				TTL)

			if logFields != nil {
				logIrregularTunnel(
					server.support,
					server.listenerTunnelProtocol,
					server.listenerPort,
					clientIP,
					errors.TraceNew("duplicate passthrough message"),
					LogFields(*logFields))
			}

			return ok
		}
	}

	return config, nil
}
