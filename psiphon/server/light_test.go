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
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	std_errors "errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/inproxy"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/light"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/osl"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	"github.com/patrickmn/go-cache"
)

func TestLightTunnelConn(t *testing.T) {

	proxyPrivateKey, err := inproxy.GenerateSessionPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	proxyPublicKey, err := proxyPrivateKey.GetPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	issuerPublicKey, issuerPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrongIssuerPublicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	authorization := &light.TunnelTrustedProxyAuthorization{
		Version:        light.TunnelTrustedProxyAuthorizationVersion,
		ProxyPublicKey: proxyPublicKey[:],
		NotBeforeUnix:  now.Add(-2 * time.Hour).Unix(),
		NotAfterUnix:   now.Add(time.Hour).Unix(),
	}
	trustedAuthorization, err := light.SignTunnelTrustedProxyAuthorization(
		issuerPrivateKey, authorization)
	if err != nil {
		t.Fatal(err)
	}
	authorization.NotAfterUnix = now.Add(-time.Hour).Unix()
	expiredAuthorization, err := light.SignTunnelTrustedProxyAuthorization(
		issuerPrivateKey, authorization)
	if err != nil {
		t.Fatal(err)
	}

	exporter := prng.Bytes(light.TunnelProxyReportExporterSize)

	for _, testCase := range []struct {
		name            string
		authorization   []byte
		issuerPublicKey ed25519.PublicKey
		wrongExporter   bool
		quicReport      bool
		egressProtocol  uint8
		expectedError   string
		expectedTrusted bool
	}{
		{
			name:           "Untrusted",
			egressProtocol: light.TransportTLS,
		},
		{
			name:            "Trusted",
			authorization:   trustedAuthorization,
			issuerPublicKey: issuerPublicKey,
			egressProtocol:  light.TransportTLS,
			expectedTrusted: true,
		},
		{
			name:           "WrongExporter",
			wrongExporter:  true,
			egressProtocol: light.TransportTLS,
			expectedError:  "invalid signature",
		},
		{
			name:           "MissingIssuerKey",
			authorization:  trustedAuthorization,
			egressProtocol: light.TransportTLS,
			expectedError:  "invalid trusted proxy authorization",
		},
		{
			name:            "WrongIssuerKey",
			authorization:   trustedAuthorization,
			issuerPublicKey: wrongIssuerPublicKey,
			egressProtocol:  light.TransportTLS,
			expectedError:   "invalid trusted proxy authorization",
		},
		{
			name:            "ExpiredAuthorization",
			authorization:   expiredAuthorization,
			issuerPublicKey: issuerPublicKey,
			egressProtocol:  light.TransportTLS,
			expectedError:   "invalid trusted proxy authorization",
		},
		{
			name:           "TLSReportOnQUICListener",
			egressProtocol: light.TransportQUIC,
			expectedError:  "unexpected Light egress parameters",
		},
		{
			name:           "QUICReportOnTLSListener",
			quicReport:     true,
			egressProtocol: light.TransportTLS,
			expectedError:  "unexpected Light egress parameters",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			report := &light.TunnelProxyReport{
				Version:                   light.TunnelProxyReportVersion,
				TrustedProxyAuthorization: testCase.authorization,
				ClientIP:                  net.ParseIP("192.0.2.1").To4(),
				IngressProtocol:           light.TransportTLS,
				IngressTLSProfile:         24, // CHROME-133 wire value.
				EgressTLSProfile:          24,
			}
			if testCase.quicReport {
				report.EgressTLSProfile = 0
				report.EgressQUICVersion = 1 // QUICv1 wire value.
			}
			reportExporter := exporter
			if testCase.wrongExporter {
				reportExporter = prng.Bytes(light.TunnelProxyReportExporterSize)
			}
			var frame bytes.Buffer
			err := light.WriteTunnelProxyReport(
				&frame, proxyPrivateKey, reportExporter, report, 0, 1024)
			if err != nil {
				t.Fatal(err)
			}

			transport := &lightCloseTrackingConn{Conn: &testConn{b: frame.Bytes()}}
			conn := NewLightTunnelConn(
				transport,
				testCase.egressProtocol,
				func(context.Context) ([]byte, error) { return exporter, nil },
				testCase.issuerPublicKey,
				nil,
				nil)
			server := &sshServer{
				support:     &SupportServices{Config: &Config{}},
				shutdownCtx: context.Background(),
			}
			result, err := server.handshakeTunnelTransport(conn)
			if testCase.expectedError != "" {
				if result != nil || !transport.closed.Load() {
					t.Fatal("failed report must close transport and return nil")
				}
				var irregularErr *light.IrregularTunnelError
				if !std_errors.As(err, &irregularErr) ||
					!strings.Contains(err.Error(), testCase.expectedError) {

					t.Fatalf("unexpected initialization error: %v", err)
				}
				if conn.initialized.Load() || conn.GetTrustedClientIP() != "" {
					t.Fatal("rejected report initialized the tunnel")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if result != conn || transport.closed.Load() {
				t.Fatal("successful report must return the live Light connection")
			}
			if !conn.initialized.Load() {
				t.Fatal("tunnel not initialized")
			}
			expectedClientIP := ""
			if testCase.expectedTrusted {
				expectedClientIP = "192.0.2.1"
			}
			if conn.GetTrustedClientIP() != expectedClientIP {
				t.Fatal("unexpected trusted client IP")
			}
		})
	}
}

func TestLightTunnelRejectProxyID(t *testing.T) {
	proxyID := inproxy.ID{1}
	otherProxyID := inproxy.ID{2}

	for _, tunnelProtocol := range protocol.LightTunnelProtocols {
		t.Run(tunnelProtocol, func(t *testing.T) {
			for _, testCase := range []struct {
				name          string
				proxyID       any
				expectedError string
			}{
				{"Missing", nil, "missing param: light_proxy_id"},
				{"Mismatch", otherProxyID.String(), "Light proxy ID mismatch"},
			} {
				t.Run(testCase.name, func(t *testing.T) {
					client := &sshClient{
						tunnelProtocol: tunnelProtocol,
						lightProxyID:   proxyID,
					}
					// A claimed non-Light protocol must not bypass the ID check.
					params := common.APIParameters{
						"propagation_channel_id": "0",
						"sponsor_id":             "0000000000000000",
						"client_version":         "1",
						"client_platform":        "Windows",
						"relay_protocol":         protocol.TUNNEL_PROTOCOL_SSH,
					}
					if testCase.proxyID != nil {
						params["light_proxy_id"] = testCase.proxyID
					}
					_, err := handshakeAPIRequestHandler(nil, client, params)
					if err == nil || !strings.Contains(err.Error(), testCase.expectedError) {
						t.Fatalf("unexpected proxy ID result: %v", err)
					}
					if client.handshakeState.completed {
						t.Fatal("rejected proxy ID completed the handshake")
					}
				})
			}
		})
	}
}

func TestLightTunnelRejectSplitTunnel(t *testing.T) {
	proxyID := inproxy.ID{1}
	for _, tunnelProtocol := range protocol.LightTunnelProtocols {
		for _, ownRegion := range []bool{false, true} {
			client := &sshClient{
				tunnelProtocol: tunnelProtocol,
				lightProxyID:   proxyID,
			}
			params := common.APIParameters{
				"propagation_channel_id": "0",
				"sponsor_id":             "0000000000000000",
				"client_version":         "1",
				"client_platform":        "Windows",
				"relay_protocol":         tunnelProtocol,
				"light_proxy_id":         proxyID.String(),
			}
			if ownRegion {
				params["split_tunnel"] = "1"
			} else {
				params["split_tunnel_regions"] = []interface{}{"CA"}
			}
			_, err := handshakeAPIRequestHandler(nil, client, params)
			if err == nil ||
				!strings.Contains(err.Error(), "split tunnel is not supported with Light tunnels") {

				t.Fatalf("unexpected split tunnel result for %s: %v", tunnelProtocol, err)
			}
			if client.handshakeState.completed {
				t.Fatal("rejected split tunnel request completed the handshake")
			}
		}
	}
}

func TestUntrustedClientGeoIPLoggingAndOSL(t *testing.T) {
	client := &sshClient{
		isUntrustedClientGeoIP:   true,
		clientGeoIPData:          NewGeoIPData(),
		untrustedClientGeoIPData: GeoIPData{Country: "CA", ASN: "1234"},
		sessionID:                "test",
		sshServer: &sshServer{
			oslSessionCache: cache.New(cache.NoExpiration, 0),
			support:         &SupportServices{OSLConfig: &osl.Config{}},
		},
		handshakeState: handshakeState{apiParams: common.APIParameters{
			"propagation_channel_id": "test",
		}},
	}
	fields := client.addUntrustedClientGeoIPLogFields(make(LogFields))
	if fields["client_region"] != "CA" || fields["client_asn"] != "1234" ||
		fields["is_untrusted_client_geoip"] != true || client.clientGeoIPData != NewGeoIPData() {
		t.Fatal("reported GeoIP must be logged without changing policy GeoIP")
	}
	client.setOSLConfig()
	if client.oslClientSeedState == nil {
		t.Fatal("untrusted client did not create OSL state")
	}
	cached := new(osl.ClientSeedState)
	client.sshServer.oslSessionCache.Set(client.sessionID, cached, cache.NoExpiration)
	client.setOSLConfig()
	retained, ok := client.sshServer.oslSessionCache.Get(client.sessionID)
	if client.oslClientSeedState == nil || client.oslClientSeedState == cached ||
		!ok || retained != cached {
		t.Fatal("untrusted client resumed or consumed cached OSL state")
	}
}

type lightCloseTrackingConn struct {
	net.Conn
	closed atomic.Bool
}

func (conn *lightCloseTrackingConn) Close() error {
	conn.closed.Store(true)
	return conn.Conn.Close()
}
