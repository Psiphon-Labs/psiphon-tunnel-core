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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

package light

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	tls "github.com/Psiphon-Labs/psiphon-tls"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"golang.org/x/net/dns/dnsmessage"
)

func newDestinationPolicyTestProxy(t *testing.T) (*Proxy, *testProxyEventReceiver) {
	t.Helper()
	_, _, cert, key, err := generateCert()
	if err != nil {
		t.Fatal(err)
	}
	config := &ProxyConfig{
		ProxyID:        prng.HexString(proxyIDSize),
		ObfuscationKey: prng.HexString(32),
		TLSCertificate: cert, TLSPrivateKey: key,
		PassthroughAddress: "127.0.0.1:1",
	}
	// Synthetic public addresses are checked locally; none is dialed.
	for _, ip := range []string{"1.2.3.4", "1.2.3.5", "2001:1111::1", "2001:1111::2"} {
		if common.IsBogon(net.ParseIP(ip)) {
			t.Fatalf("fixture is a bogon: %s", ip)
		}
		config.DialAddresses = append(config.DialAddresses,
			ProxyAddress{IPAddress: ip, Port: 443, Protocol: LIGHT_PROTOCOL_TLS})
		listenIP := "127.0.0.1"
		if net.ParseIP(ip).To4() == nil {
			listenIP = "::1"
		}
		config.ListenAddresses = append(config.ListenAddresses,
			ProxyAddress{IPAddress: listenIP, Port: 0, Protocol: LIGHT_PROTOCOL_TLS})
	}
	receiver := newTestProxyEventReceiver(false, 0, false, "")
	proxy, err := NewProxy(config, func(string) common.GeoIPData { return common.GeoIPData{} }, receiver)
	if err != nil {
		t.Fatal(err)
	}
	return proxy, receiver
}

func TestLightProxyDestinationPolicy(t *testing.T) {
	proxy, _ := newDestinationPolicyTestProxy(t)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	proxy.tunnelDialAuthorizationPublicKey = publicKey
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	for _, address := range proxy.config.DialAddresses {
		for _, port := range []int{443, 8443} {
			destination := net.JoinHostPort(address.IPAddress, strconv.Itoa(port))
			if _, _, err := proxy.resolve(ctx, destination); err == nil {
				t.Fatalf("fallback accepted self destination %s", destination)
			}
			ip := net.ParseIP(address.IPAddress)
			if v4 := ip.To4(); v4 != nil {
				ip = v4
			}
			authorization, err := SignTunnelDialAuthorization(privateKey, &TunnelDialAuthorization{
				Version: TunnelDialAuthorizationVersion, IPAddress: ip,
				VerifyPin: prng.Bytes(32), RootObfuscationSecret: prng.Bytes(TunnelRootObfuscationSecretSize),
				TLSPort: uint16(port), QUICPort: uint16(port),
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, egress := range []uint8{TransportTLS, TransportQUIC} {
				header := &lightHeader{TunnelDialAuthorization: authorization, EgressProtocol: egress}
				_, _, _, _, _, err := proxy.dialTunnelServer(ctx, header, "127.0.0.1", LIGHT_PROTOCOL_TLS, "", false, 0, false, false)
				if err == nil || !strings.Contains(err.Error(), "IP is bogon or proxy address") {
					t.Fatalf("signed self destination %s, egress %d: %v", destination, egress, err)
				}
				proxy.config.AllowBogons = true
				_, _, _, _, _, err = proxy.dialTunnelServer(ctx, header, "127.0.0.1", LIGHT_PROTOCOL_TLS, "", false, 0, false, false)
				proxy.config.AllowBogons = false
				// Passing the address check reaches the intentionally absent
				// dialer; no packet is sent to the synthetic public address.
				if err == nil || !strings.Contains(err.Error(), "missing proxy") {
					t.Fatalf("AllowBogons did not bypass self check: %v", err)
				}
			}
			proxy.config.AllowBogons = true
			_, _, err = proxy.resolve(ctx, destination)
			proxy.config.AllowBogons = false
			if err != nil {
				t.Fatalf("AllowBogons rejected fallback: %v", err)
			}
		}
	}
	if _, _, err := proxy.resolve(ctx, "2.3.4.5:443"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := proxy.resolve(ctx, "127.0.0.1:443"); err == nil {
		t.Fatal("accepted bogon")
	}

	// A DNS response containing a proxy IP must be rejected before caching.
	listener, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	defer func() { listener.Close(); <-done }()
	go func() {
		defer close(done)
		buffer := make([]byte, 4096)
		for {
			n, peer, err := listener.ReadFrom(buffer)
			if err != nil {
				return
			}
			var request dnsmessage.Message
			if err := request.Unpack(buffer[:n]); err != nil {
				t.Error(err)
				return
			}
			response := dnsmessage.Message{
				Header:    dnsmessage.Header{ID: request.ID, Response: true, RecursionAvailable: true},
				Questions: request.Questions,
			}
			for _, question := range request.Questions {
				if question.Type == dnsmessage.TypeA {
					response.Answers = append(response.Answers, dnsmessage.Resource{
						Header: dnsmessage.ResourceHeader{Name: question.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60},
						Body:   &dnsmessage.AResource{A: [4]byte{1, 2, 3, 5}},
					})
				}
			}
			payload, err := response.Pack()
			if err != nil {
				t.Error(err)
				return
			}
			if _, err := listener.WriteTo(payload, peer); err != nil {
				return
			}
		}
	}()
	proxy.dnsResolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "udp4", listener.LocalAddr().String())
	}}
	destination := "self.example:8443"
	if _, _, err := proxy.resolve(ctx, destination); err == nil || !strings.Contains(err.Error(), "proxy address") {
		t.Fatalf("DNS self destination was not rejected: %v", err)
	}
	if _, found := proxy.dnsCache.Get(destination); found {
		t.Fatal("cached disallowed DNS result")
	}
	proxy.config.AllowBogons = true
	if _, _, err := proxy.resolve(ctx, destination); err != nil {
		t.Fatal(err)
	}
}

type destinationPolicyTestConn struct{ net.Conn }

func (c destinationPolicyTestConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
}

func TestLightProxyMalformedDestinationRedaction(t *testing.T) {
	for _, tc := range []struct{ name, destination, expected string }{
		{"Address", "[private.example:443", "invalid destination address"},
		{"Port", "private.example:invalid-port", "invalid destination port"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			proxy, receiver := newDestinationPolicyTestProxy(t)
			receiver.connectionStats = make(chan *ConnectionStats, 1)
			// Exercise the header and logging path over an in-memory TLS
			// connection; passthrough authentication is tested separately.
			proxy.tlsConfig = &tls.Config{Certificates: proxy.tlsConfig.Certificates}
			server, client := net.Pipe()
			defer server.Close()
			defer client.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			result := make(chan error, 1)
			go func() { result <- proxy.handleConn(ctx, destinationPolicyTestConn{server}, 0) }()
			conn := newLightConn(tls.Client(client, &tls.Config{InsecureSkipVerify: true}),
				&lightHeader{DestinationAddress: tc.destination})
			conn.SetDeadline(time.Now().Add(5 * time.Second))
			// Drain the TLS close alert while the proxy rejects the header.
			drained := make(chan struct{})
			go func() { defer close(drained); _, _ = io.Copy(io.Discard, conn) }()
			_, _ = conn.Write([]byte{1})
			err := <-result
			client.Close()
			<-drained
			if err == nil || !strings.Contains(err.Error(), tc.expected) ||
				strings.Contains(err.Error(), "private.example") || strings.Contains(err.Error(), "invalid-port") {
				t.Fatalf("unexpected destination error: %v", err)
			}
			stats := <-receiver.connectionStats
			if strings.Contains(stats.Failure, "private.example") || strings.Contains(stats.Failure, "invalid-port") || stats.DestinationAddress != "" {
				t.Fatalf("destination leaked into connection stats: %+v", stats)
			}
		})
	}
}
