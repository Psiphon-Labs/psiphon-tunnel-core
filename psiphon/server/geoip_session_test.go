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
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/crypto/ssh"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	"github.com/patrickmn/go-cache"
)

type geoIPSessionTestConn struct {
	ssh.Conn
}

func (geoIPSessionTestConn) User() string { return "geoip-session-test" }
func (geoIPSessionTestConn) Close() error { return nil }
func (geoIPSessionTestConn) Wait() error  { return nil }

func TestGeoIPSessionCacheLifecycle(t *testing.T) {
	peerGeoIP := GeoIPData{Country: "US", ASN: "64512"}
	clientGeoIP := GeoIPData{Country: "CA", ASN: "64513"}
	for _, testCase := range []struct {
		name           string
		tunnelProtocol string
		trustedLight   bool
		expected       GeoIPData
	}{
		{"Direct", protocol.TUNNEL_PROTOCOL_SSH, false, peerGeoIP},
		{"Inproxy", protocol.TunnelProtocolPlusInproxyWebRTC(protocol.TUNNEL_PROTOCOL_SSH), false, peerGeoIP},
		{"TrustedLight", protocol.TUNNEL_PROTOCOL_LIGHT_TLS_TLS_SSH, true, clientGeoIP},
		{"UntrustedLight", protocol.TUNNEL_PROTOCOL_LIGHT_TLS_TLS_SSH, false, NewGeoIPData()},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			metadata := geoIPSessionTestConn{}
			config := &Config{
				SSHUserName: metadata.User(),
				SSHPassword: strings.Repeat("a", 2*SSH_PASSWORD_BYTE_LENGTH),
			}
			server := &sshServer{
				support:           &SupportServices{Config: config},
				clients:           make(map[string]*sshClient),
				geoIPSessionCache: cache.New(GEOIP_SESSION_CACHE_TTL, 0),
			}
			sessionID := strings.Repeat("b", 2*protocol.PSIPHON_API_CLIENT_SESSION_ID_LENGTH)
			password, err := json.Marshal(protocol.SSHPasswordPayload{
				SessionId: sessionID, SshPassword: config.SSHPassword,
			})
			if err != nil {
				t.Fatal(err)
			}
			newClient := func(tunnelProtocol string, geoIP GeoIPData) *sshClient {
				t.Helper()
				client, err := newSshClient(
					server, nil, tunnelProtocol, nil, "", false,
					&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}, geoIP)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(client.stopRunning)
				return client
			}
			authenticate := func(client *sshClient) {
				t.Helper()
				if _, err := client.passwordCallback(metadata, password); err != nil {
					t.Fatal(err)
				}
			}
			checkCache := func() time.Time {
				t.Helper()
				value, expiry, found := server.geoIPSessionCache.GetWithExpiration(sessionID)
				geoIP, ok := value.(GeoIPData)
				if !found || !ok || geoIP != testCase.expected {
					t.Fatalf("unexpected cached GeoIP: got %+v, want %+v", value, testCase.expected)
				}
				return expiry
			}
			authenticateAnother := func() {
				t.Helper()
				candidate := newClient(protocol.TUNNEL_PROTOCOL_SSH,
					GeoIPData{Country: "JP", ASN: "64514"})
				authenticate(candidate)
				if candidate.isFirstTunnelInSession {
					t.Fatal("existing session was treated as a first tunnel")
				}
			}

			client := newClient(testCase.tunnelProtocol, peerGeoIP)
			if testCase.trustedLight {
				// handleClient sets these fields after verifying proxy trust.
				client.isUntrustedClientGeoIP = false
				client.clientIP = "127.0.0.2"
				client.clientGeoIPData = clientGeoIP
			}
			authenticate(client)
			if !client.isFirstTunnelInSession {
				t.Fatal("new session was not treated as a first tunnel")
			}
			provisionalExpiry := checkCache()
			if !provisionalExpiry.After(time.Now()) {
				t.Fatal("authentication did not create an expiring cache entry")
			}

			// A second authentication must neither replace the selected GeoIP
			// nor extend the provisional entry's lifetime.
			authenticateAnother()
			if !checkCache().Equal(provisionalExpiry) {
				t.Fatal("another authentication changed the provisional expiry")
			}

			client.sshConn = &ssh.ServerConn{Conn: metadata}
			if !server.registerEstablishedClient(client) {
				t.Fatal("registration failed")
			}
			if !checkCache().IsZero() {
				t.Fatal("registered session cache entry expires")
			}
			authenticateAnother()
			if !checkCache().IsZero() {
				t.Fatal("another authentication changed the registered expiry")
			}

			// Follow the disconnect sequence after the registered tunnel ends.
			server.markGeoIPSessionCacheToExpire(sessionID)
			server.unregisterEstablishedClient(client)
			if !checkCache().After(time.Now()) {
				t.Fatal("disconnected session cache entry has no expiry")
			}
			if server.clients[sessionID] != nil {
				t.Fatal("disconnected client remains registered")
			}
		})
	}
}
