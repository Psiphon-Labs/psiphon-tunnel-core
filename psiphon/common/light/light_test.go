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
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	std_errors "errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	tls "github.com/Psiphon-Labs/psiphon-tls"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/inproxy"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/obfuscator"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/parameters"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/proxyheader"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/quic"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/tlsdialer"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/transforms"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/internal/testutils"
	ietf_quic "github.com/Psiphon-Labs/quic-go"
	"github.com/fxamacker/cbor/v2"
	proxyproto "github.com/pires/go-proxyproto"
	"golang.org/x/sync/errgroup"
)

func TestLightProxy(t *testing.T) {
	for _, tlsTrafficShaping := range []bool{false, true} {
		tlsTrafficShaping := tlsTrafficShaping
		for _, addProxyHeader := range []bool{false, true} {
			addProxyHeader := addProxyHeader
			for _, sharedProxyLimits := range []bool{false, true} {
				sharedProxyLimits := sharedProxyLimits
				t.Run(
					fmt.Sprintf(
						"tlsTrafficShaping=%t/addProxyHeader=%t/sharedProxyLimits=%t",
						tlsTrafficShaping, addProxyHeader, sharedProxyLimits),
					func(t *testing.T) {
						err := runTestLightProxy(
							tlsTrafficShaping,
							addProxyHeader,
							sharedProxyLimits)
						if err != nil {
							t.Fatal(err.Error())
						}
					})
			}
		}
	}
}

func runTestLightProxy(
	tlsTrafficShaping, addProxyHeader, sharedProxyLimits bool) error {

	// Exercise multiple concurrent clients and concurrent dials over over one
	// proxy. The proxied traffic is an inner TLS connection to an "echo"
	// server, and the echoed bytes are verified. The outer proxy TLS
	// connection is observed and expected padding target ranges are also
	// verified.

	const (
		numClients              = 2
		numConnectionsPerClient = 10
		payloadSize             = 10 * 1024 * 1024
		bytesPerSecond          = 1 << 30

		testClientPlatform          = "Android"
		testClientBuildRev          = "01020304"
		testDeviceRegion            = "US"
		testClientRegion            = "CA"
		testProviderID              = "01020304"
		testSponsorID               = "0102030405060708"
		testProxyEntryTracker int64 = 0x0102030405060708
		testNetworkType             = "WIFI"
		testTLSProfile              = protocol.TLS_PROFILE_CHROME_133
		testTLSPaddingLength        = 128
	)

	recommendedFragmentClientHelloProbability := 0.0
	recommendedTLSPaddingProbability := 0.0
	recommendedMinTLSPadding := 0
	recommendedMaxTLSPadding := 0
	expectedTLSClientHelloFragmented := false
	expectedTLSClientHelloPadding := 0
	if tlsTrafficShaping {
		recommendedFragmentClientHelloProbability = 1.0
		recommendedTLSPaddingProbability = 1.0
		recommendedMinTLSPadding = testTLSPaddingLength
		recommendedMaxTLSPadding = testTLSPaddingLength
		expectedTLSClientHelloFragmented = true
		expectedTLSClientHelloPadding = testTLSPaddingLength
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	serverGroup, serverCtx := errgroup.WithContext(ctx)

	echoListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return errors.Trace(err)
	}
	defer echoListener.Close()

	echoAddress := echoListener.Addr().String()

	var proxyProtocolHeaderCount atomic.Int64
	var proxyProtocolHeaderKeyID []byte
	var proxyProtocolHeaderKey []byte
	var proxyProtocolHeaderMACKeys map[string]string
	var proxyProtocolHeaderCustomTLV []byte
	var proxyProtocolHeaderCustomTLVs map[string]string
	var proxyProtocolHeaderTargetDestinationAddresses map[string][]string

	if addProxyHeader {
		proxyProtocolHeaderKeyID = []byte{0x00, 0x00, 0x00, 0x01}
		proxyProtocolHeaderKey = prng.Bytes(proxyheader.ProxyProtocolHeaderMACKeySize)
		proxyProtocolHeaderMACKey := append(
			append([]byte(nil), proxyProtocolHeaderKeyID...),
			proxyProtocolHeaderKey...)
		proxyProtocolHeaderMACKeys = map[string]string{
			testSponsorID: base64.StdEncoding.EncodeToString(proxyProtocolHeaderMACKey)}
		proxyProtocolHeaderCustomTLV = append(
			[]byte{byte(proxyproto.PP2_TYPE_MAX_CUSTOM)}, prng.Bytes(16)...)
		proxyProtocolHeaderCustomTLVs = map[string]string{
			testSponsorID: base64.StdEncoding.EncodeToString(
				proxyProtocolHeaderCustomTLV)}
		echoHost, echoPortStr, err := net.SplitHostPort(echoAddress)
		if err != nil {
			return errors.Trace(err)
		}
		proxyProtocolHeaderTargetDestinationAddresses = map[string][]string{
			testSponsorID: {echoHost}}
		echoIP := net.ParseIP(echoHost)
		if echoIP == nil {
			return errors.TraceNew("invalid echo IP")
		}
		echoPort, err := strconv.Atoi(echoPortStr)
		if err != nil {
			return errors.Trace(err)
		}

		echoListener = &proxyproto.Listener{
			Listener: echoListener,
			ValidateHeader: func(header *proxyproto.Header) error {
				wireHeader, err := header.Format()
				if err != nil {
					return errors.Trace(err)
				}

				timestamp, sourceIP, destinationIP, destinationPort, err :=
					proxyheader.VerifyProxyProtocolHeader(
						proxyProtocolHeaderKeyID,
						proxyProtocolHeaderKey,
						wireHeader)
				if err != nil {
					return errors.Trace(err)
				}
				if time.Now().Sub(timestamp).Abs() > 5*time.Second ||
					!sourceIP.IsLoopback() ||
					!destinationIP.Equal(echoIP) ||
					destinationPort != echoPort {

					return errors.TraceNew("unexpected PROXY header value")
				}

				tlvs, err := header.TLVs()
				if err != nil {
					return errors.Trace(err)
				}
				if len(tlvs) != 2 ||
					tlvs[0].Type != proxyproto.PP2Type(proxyProtocolHeaderCustomTLV[0]) ||
					!bytes.Equal(tlvs[0].Value, proxyProtocolHeaderCustomTLV[1:]) {

					return errors.TraceNew("unexpected PROXY header custom TLV")
				}
				proxyProtocolHeaderCount.Add(1)
				return nil
			},
		}
	}

	serverGroup.Go(func() error {

		_, _, echoCertPEM, echoKeyPEM, err := generateCert()
		if err != nil {
			return errors.Trace(err)
		}

		echoCert, err := tls.X509KeyPair(echoCertPEM, echoKeyPEM)
		if err != nil {
			return errors.Trace(err)
		}

		return runTLSEchoServer(
			serverCtx,
			echoListener,
			&tls.Config{
				Certificates: []tls.Certificate{echoCert},
				MinVersion:   tls.VersionTLS13,
			})
	})

	proxyListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return errors.Trace(err)
	}

	proxyPort := proxyListener.Addr().(*net.TCPAddr).Port
	err = proxyListener.Close()
	if err != nil {
		return errors.Trace(err)
	}

	// Exercise the dual dialer.
	dialAddresses := []ProxyAddress{
		{IPAddress: "127.0.0.1", Port: proxyPort, Protocol: LIGHT_PROTOCOL_TLS},
		{IPAddress: "::1", Port: proxyPort, Protocol: LIGHT_PROTOCOL_TLS},
	}

	proxyConfig, proxyEntry, err := Generate(
		testProviderID,
		nil,
		dialAddresses,
		"example.org",
		"",
		0.0,
		"",
		0.0,
		recommendedFragmentClientHelloProbability,
		recommendedTLSPaddingProbability,
		recommendedMinTLSPadding,
		recommendedMaxTLSPadding,
		0,
		[]string{echoAddress},
		proxyProtocolHeaderMACKeys,
		proxyProtocolHeaderCustomTLVs,
		proxyProtocolHeaderTargetDestinationAddresses,
		echoListener.Addr().String(),
		"",
		"")
	if err != nil {
		return errors.Trace(err)
	}

	entry, err := DecodeAndValidateProxyEntry(proxyEntry)
	if err != nil {
		return errors.Trace(err)
	}
	// Exercise legacy-only decoding as well as endpoint selection.
	legacyEntry := *entry
	legacyEntry.DialAddresses = nil
	legacyEntry.ProxyID = ""
	legacyProxyEntry, err := protocol.CBOREncoding.Marshal(
		&SignedProxyEntry{ProxyEntry: legacyEntry})
	if err != nil {
		return errors.Trace(err)
	}

	entry.Protocol = ""
	entry.DialAddressIPv4 = ""
	entry.DialAddressIPv6 = ""
	entry.DialAddresses = entry.DialAddresses[1:]
	proxyEntry, err = protocol.CBOREncoding.Marshal(
		&SignedProxyEntry{ProxyEntry: *entry})
	if err != nil {
		return errors.Trace(err)
	}

	lookupGeoIP := func(string) common.GeoIPData {
		return common.GeoIPData{Country: testClientRegion}
	}

	params, err := parameters.NewParameters(nil)
	if err != nil {
		return errors.Trace(err)
	}

	receiver := newTestProxyEventReceiver(
		expectedTLSClientHelloFragmented,
		expectedTLSClientHelloPadding,
		addProxyHeader,
		testClientRegion)
	receiver.expectedDeviceRegion = testDeviceRegion

	maxConcurrent := numClients * numConnectionsPerClient * 2
	if sharedProxyLimits {
		proxyConfig.ProxyLimits, err = common.NewProxyLimits(&common.ProxyLimitsConfig{
			MaxCommonClients:               maxConcurrent,
			CommonUpstreamBytesPerSecond:   bytesPerSecond,
			CommonDownstreamBytesPerSecond: bytesPerSecond,
		})
		if err != nil {
			return errors.Trace(err)
		}
	} else {
		proxyConfig.MaxConcurrent = &maxConcurrent
		proxyConfig.LimitUpstreamBytesPerSecond = bytesPerSecond
		proxyConfig.LimitDownstreamBytesPerSecond = bytesPerSecond
	}

	proxyConfig.EmitActivity = true
	proxyConfig.AllowBogons = true
	proxyConfig.EnableDebugLogs = true

	proxy, err := NewProxy(
		proxyConfig,
		lookupGeoIP,
		receiver)
	if err != nil {
		return errors.Trace(err)
	}

	serverGroup.Go(func() error {
		return proxy.Run(serverCtx)
	})

	select {
	case <-receiver.listening:
	case <-ctx.Done():
		return errors.Trace(ctx.Err())
	}

	err = proxy.SetLimits(
		nil,
		1<<30,
		1<<30)
	if sharedProxyLimits {
		if err == nil {
			return errors.TraceNew("unexpected SetLimits success")
		}
	} else if err != nil {
		return errors.Trace(err)
	}

	newClientConfig := func() *ClientConfig {
		return &ClientConfig{
			Logger: testutils.NewTestLogger(),
			TCPDialer: func(ctx context.Context, addr string) (net.Conn, error) {
				conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
				if err != nil {
					return nil, errors.Trace(err)
				}
				return newPaddingCheckerConn(conn), nil
			},
			TLSDialer: func(
				ctx context.Context,
				underlyingConn net.Conn,
				_ string,
				tlsProfile string,
				randomizedTLSProfileSeed *prng.Seed,
				sni string,
				fragmentClientHello bool,
				tlsPadding int,
				passthroughMessage []byte,
				verifyPin string) (net.Conn, error) {

				return dialTLS(
					params,
					ctx,
					underlyingConn,
					tlsProfile,
					randomizedTLSProfileSeed,
					sni,
					fragmentClientHello,
					tlsPadding,
					passthroughMessage,
					verifyPin)
			},
			SponsorID:         testSponsorID,
			ClientPlatform:    testClientPlatform,
			ClientBuildRev:    testClientBuildRev,
			DeviceRegion:      testDeviceRegion,
			SessionID:         prng.HexString(protocol.PSIPHON_API_CLIENT_SESSION_ID_LENGTH),
			ProxyEntryTracker: testProxyEntryTracker,
			ProxyEntry:        legacyProxyEntry,
		}
	}

	// The first client has both an IPv4 and an IPv6 address and uses the dual
	// dialer; the second has only an IPv6 address. The first client's IPv6
	// TCP dials cycle through three outcomes: success; failure, after which
	// IPv4 is dialed at once; and no response, after which IPv4 is dialed
	// following the stagger delay.
	var dualDialerIPv6Dials atomic.Int64
	expectedDualDialerIPv6Count := 0
	for i := 1; i <= numConnectionsPerClient; i++ {
		if i%3 == 0 {
			expectedDualDialerIPv6Count += 1
		}
	}

	clients := make([]*Client, numClients)
	for i := 0; i < numClients; i++ {
		clientConfig := newClientConfig()
		if i == 1 {
			clientConfig.ProxyEntry = proxyEntry
		} else {
			tcpDialer := clientConfig.TCPDialer
			clientConfig.TCPDialer = func(
				ctx context.Context, addr string) (net.Conn, error) {

				if strings.HasPrefix(addr, "[") {
					switch dualDialerIPv6Dials.Add(1) % 3 {
					case 1:
						return nil, errors.TraceNew("IPv6 dial failed")
					case 2:
						<-ctx.Done()
						return nil, errors.Trace(ctx.Err())
					}
				}
				return tcpDialer(ctx, addr)
			}
		}
		client, err := NewClient(clientConfig)
		if err != nil {
			return errors.Trace(err)
		}
		if client.GetMetrics(false).ProxyID != proxy.ID {
			return errors.TraceNew("unexpected proxy ID")
		}
		clients[i] = client
	}

	// All clients reuse the same dialer, but the probabilities are deterministic: 0.0 or 1.0.
	tlsFragmentClientHello := prng.FlipWeightedCoin(
		clients[0].GetRecommendedFragmentClientHelloProbability())

	tlsPadding := 0
	if prng.FlipWeightedCoin(clients[0].GetRecommendedTLSPaddingProbability()) {
		tlsPadding = prng.Range(
			clients[0].GetRecommendedMinTLSPadding(),
			clients[0].GetRecommendedMaxTLSPadding())
	}

	// Exercise dynamic rate limit changes

	var updateLimitsOnce sync.Once
	var updateLimitsErr error
	updateLimits := func() error {
		updateLimitsOnce.Do(func() {
			updatedBytesPerSecond := bytesPerSecond + bytesPerSecond/2
			if sharedProxyLimits {
				updateLimitsErr = proxyConfig.ProxyLimits.SetCommonLimits(
					maxConcurrent, updatedBytesPerSecond, updatedBytesPerSecond)
			} else {
				updateLimitsErr = proxy.SetLimits(
					&maxConcurrent, updatedBytesPerSecond, updatedBytesPerSecond)
			}
		})
		return updateLimitsErr
	}

	clientGroup, clientCtx := errgroup.WithContext(ctx)
	for _, client := range clients {
		client := client
		for i := 0; i < numConnectionsPerClient; i++ {
			clientGroup.Go(func() error {
				err := runLightClient(
					clientCtx,
					client,
					testNetworkType,
					LIGHT_PROTOCOL_TLS,
					testTLSProfile,
					"",
					nil,
					tlsFragmentClientHello,
					tlsPadding,
					echoAddress,
					payloadSize,
					updateLimits,
					nil,
					nil)
				if err != nil {
					return errors.Trace(err)
				}
				return nil
			})
		}
	}

	err = clientGroup.Wait()
	if err != nil {
		return errors.Trace(err)
	}

	dualDialerMetrics := clients[0].GetMetrics(false)
	if dualDialerMetrics.DialIPv6Count != expectedDualDialerIPv6Count ||
		dualDialerMetrics.DialIPv4Count !=
			numConnectionsPerClient-expectedDualDialerIPv6Count {

		return errors.Tracef(
			"unexpected dual dialer counts: IPv4 %d, IPv6 %d",
			dualDialerMetrics.DialIPv4Count,
			dualDialerMetrics.DialIPv6Count)
	}

	if addProxyHeader {
		expectedProxyProtocolHeaderCount :=
			int64(numClients * numConnectionsPerClient)
		proxyProtocolHeaderCount := proxyProtocolHeaderCount.Load()
		if proxyProtocolHeaderCount != expectedProxyProtocolHeaderCount {
			return errors.Tracef(
				"unexpected PROXY protocol header count: %d",
				proxyProtocolHeaderCount)
		}
	}

	err = receiver.awaitActivityRegion(ctx)
	if err != nil {
		return errors.Trace(err)
	}

	proxy.Pause()

	_, err = clients[0].Dial(
		ctx,
		nil,
		0,
		testNetworkType,
		LIGHT_PROTOCOL_TLS,
		testTLSProfile,
		nil,
		"",
		nil,
		nil,
		false,
		clients[0].GetRecommendedSNI(),
		tlsFragmentClientHello,
		tlsPadding,
		echoAddress,
		nil)
	if err == nil {
		return errors.TraceNew("unexpected success")
	}

	proxy.Resume()

	conn, err := clients[0].Dial(
		ctx,
		nil,
		0,
		testNetworkType,
		LIGHT_PROTOCOL_TLS,
		testTLSProfile,
		nil,
		"",
		nil,
		nil,
		false,
		clients[0].GetRecommendedSNI(),
		tlsFragmentClientHello,
		tlsPadding,
		echoAddress,
		nil)
	if err != nil {
		return errors.Trace(err)
	}
	conn.Close()

	cancel()

	err = serverGroup.Wait()
	if err != nil {
		return errors.Trace(err)
	}

	err = receiver.checkResults()
	if err != nil {
		return errors.Trace(err)
	}

	return nil
}

func TestLightProxyTunnel(t *testing.T) {
	if err := runTestLightProxyTunnel(); err != nil {
		t.Fatal(err)
	}
}

func runTestLightProxyTunnel() error {

	const (
		testProviderID        = "01020304"
		testSponsorID         = "0102030405060708"
		testClientPlatform    = "Android"
		testClientBuildRev    = "01020304"
		testNetworkType       = "WIFI"
		testIngressTLSProfile = protocol.TLS_PROFILE_CHROME_133
		testIngressSNI        = "ingress.example.org"
		testEgressTLSProfile  = protocol.TLS_PROFILE_RANDOMIZED
		testEgressSNI         = "egress.example.org"
		testProxyPlatform     = "Windows"
		testProxyVersion      = int64(123)
	)

	testProxyBuildRev := []byte{0x01, 0x02, 0x03, 0x04}
	testPersonalCompartmentID := prng.Bytes(personalCompartmentIDSize)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()

	group, ctx := errgroup.WithContext(ctx)

	tunnelTLSListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return errors.Trace(err)
	}
	defer tunnelTLSListener.Close()

	tunnelVerifyPin, _, tunnelCertPEM, tunnelKeyPEM, err := generateCert()
	if err != nil {
		return errors.Trace(err)
	}
	tunnelCert, err := tls.X509KeyPair(tunnelCertPEM, tunnelKeyPEM)
	if err != nil {
		return errors.Trace(err)
	}

	tunnelRootObfuscationSecret := prng.Bytes(
		TunnelRootObfuscationSecretSize)
	tunnelQUICObfuscationKey, err := DeriveTunnelQUICObfuscationKey(
		tunnelRootObfuscationSecret)
	if err != nil {
		return errors.Trace(err)
	}
	var tunnelQUICListener net.Listener
	var tunnelQUICPort uint16
	if quic.Enabled() {
		tunnelQUICListener, err = quic.Listen(
			nil,
			nil,
			"127.0.0.1:0",
			nil,
			false,
			0,
			hex.EncodeToString(tunnelQUICObfuscationKey),
			nil,
			&tunnelCert,
			false,
			false)
		if err != nil {
			return errors.Trace(err)
		}
		defer tunnelQUICListener.Close()
		tunnelQUICPort = uint16(tunnelQUICListener.Addr().(*net.UDPAddr).Port)
	}

	dialAuthorizationPublicKey, dialAuthorizationPrivateKey, err :=
		ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return errors.Trace(err)
	}

	tunnelTLSAddress := tunnelTLSListener.Addr().(*net.TCPAddr)
	tunnelDialAuthorization, err := SignTunnelDialAuthorization(
		dialAuthorizationPrivateKey,
		&TunnelDialAuthorization{
			Version:               TunnelDialAuthorizationVersion,
			IPAddress:             tunnelTLSAddress.IP.To4(),
			VerifyPin:             tunnelVerifyPin,
			RootObfuscationSecret: tunnelRootObfuscationSecret,
			TLSPort:               uint16(tunnelTLSAddress.Port),
			QUICPort:              tunnelQUICPort,
		})
	if err != nil {
		return errors.Trace(err)
	}

	proxyPrivateKey, err := inproxy.GenerateSessionPrivateKey()
	if err != nil {
		return errors.Trace(err)
	}
	proxyPublicKey, err := proxyPrivateKey.GetPublicKey()
	if err != nil {
		return errors.Trace(err)
	}
	proxyCurvePublicKey, err := proxyPublicKey.ToCurve25519()
	if err != nil {
		return errors.Trace(err)
	}
	expectedProxyID := inproxy.ID(proxyCurvePublicKey)

	trustedProxyIssuerPublicKey, trustedProxyIssuerPrivateKey, err :=
		ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return errors.Trace(err)
	}
	now := time.Now()
	trustedProxyAuthorization, err := SignTunnelTrustedProxyAuthorization(
		trustedProxyIssuerPrivateKey,
		&TunnelTrustedProxyAuthorization{
			Version:        TunnelTrustedProxyAuthorizationVersion,
			ProxyPublicKey: proxyPublicKey[:],
			NotBeforeUnix:  now.Add(-time.Hour).Unix(),
			NotAfterUnix:   now.Add(time.Hour).Unix(),
		})
	if err != nil {
		return errors.Trace(err)
	}

	tunnelTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{tunnelCert},
		MinVersion:   tls.VersionTLS13,
	}

	reports := make(chan *TunnelProxyReport, 1)
	verifyReport := func(
		expectedEgressProtocol uint8) func(
		*TunnelProxyReport, inproxy.ID) error {

		return func(
			report *TunnelProxyReport,
			proxyID inproxy.ID) error {

			if proxyID != expectedProxyID ||
				!bytes.Equal(report.ProxyPublicKey, proxyPublicKey[:]) {

				return errors.TraceNew("unexpected proxy ID")
			}
			if !net.IP(report.ClientIP).IsLoopback() {
				return errors.TraceNew("unexpected client IP")
			}
			if report.ProxyPlatform !=
				encodeClientPlatform(testProxyPlatform) ||
				report.ProxyVersion != testProxyVersion ||
				!bytes.Equal(
					report.ProxyBuildRev, testProxyBuildRev) {

				return errors.TraceNew("unexpected proxy properties")
			}
			if report.IngressSNI != testIngressSNI ||
				report.IngressDidResume {

				return errors.TraceNew("unexpected transport properties")
			}
			switch expectedEgressProtocol {
			case TransportTLS:
				if report.EgressTLSProfile !=
					encodeTLSProfile(testEgressTLSProfile) ||
					report.EgressQUICVersion != 0 {

					return errors.TraceNew(
						"unexpected egress TLS properties")
				}
			case TransportQUIC:
				if report.EgressTLSProfile != 0 ||
					report.EgressQUICVersion != encodeQUICVersion(
						protocol.QUIC_VERSION_V1) {

					return errors.TraceNew(
						"unexpected egress QUIC properties")
				}
			default:
				return errors.TraceNew("unexpected egress protocol")
			}

			switch report.IngressProtocol {
			case TransportTLS:
				if report.IngressQUICVersion != 0 ||
					report.IngressTLSClientHelloFragmented ||
					report.IngressTLSPadding != 0 {

					return errors.TraceNew(
						"unexpected ingress TLS properties")
				}

			case TransportQUIC:
				if report.IngressTLSProfile != 0 ||
					report.IngressTLSClientHelloFragmented ||
					report.IngressTLSPadding != 0 {

					return errors.TraceNew(
						"unexpected ingress QUIC properties")
				}

			default:
				return errors.TraceNew("unexpected ingress protocol")
			}

			_, err := VerifyTunnelTrustedProxyAuthorization(
				trustedProxyIssuerPublicKey,
				report.ProxyPublicKey,
				report.TrustedProxyAuthorization,
				now)
			if err != nil {
				return errors.Trace(err)
			}
			reports <- report
			return nil
		}
	}

	group.Go(func() error {
		return runTLSTunnelEchoServer(
			ctx,
			tunnelTLSListener,
			tunnelTLSConfig,
			verifyReport(TransportTLS))
	})

	if tunnelQUICListener != nil {
		group.Go(func() error {
			return runQUICTunnelEchoServer(
				ctx,
				tunnelQUICListener,
				tunnelTLSConfig,
				verifyReport(TransportQUIC))
		})
	}

	listenAddresses := []ProxyAddress{
		{IPAddress: "127.0.0.1", Port: 0, Protocol: LIGHT_PROTOCOL_TLS},
	}
	dialAddresses := []ProxyAddress{
		{IPAddress: "127.0.0.1", Port: 443, Protocol: LIGHT_PROTOCOL_TLS},
	}
	if quic.Enabled() {
		listenAddresses = append(listenAddresses,
			ProxyAddress{IPAddress: "127.0.0.1", Port: 0, Protocol: LIGHT_PROTOCOL_QUIC})
		dialAddresses = append(dialAddresses,
			ProxyAddress{IPAddress: "127.0.0.1", Port: 443, Protocol: LIGHT_PROTOCOL_QUIC})
	}

	// Generate the entry with placeholder dial ports, then replace them
	// with the ports assigned when the local listeners bind.
	proxyConfig, proxyEntry, err := Generate(
		testProviderID,
		listenAddresses,
		dialAddresses,
		testIngressSNI,
		"",
		0.0,
		"",
		0.0,
		0.0,
		0.0,
		0,
		0,
		0,
		nil,
		nil,
		nil,
		nil,
		tunnelTLSListener.Addr().String(),
		base64.RawStdEncoding.EncodeToString(testPersonalCompartmentID),
		expectedProxyID.String())
	if err != nil {
		return errors.Trace(err)
	}
	if proxyConfig.ProxyID != "" {
		return errors.TraceNew("unexpected configured tunnel proxy ID")
	}

	var egressRandomizedTLSProfileSeed, tls12RandomizedTLSProfileSeed *prng.Seed
	for i := 0; i < 100; i++ {
		seed, err := prng.NewSeed()
		if err != nil {
			return errors.Trace(err)
		}
		supportsTLS13, err := tlsdialer.TLSProfileSupportsTLS13(
			testEgressTLSProfile, seed)
		if err != nil {
			return errors.Trace(err)
		}
		if supportsTLS13 {
			egressRandomizedTLSProfileSeed = seed
		} else {
			tls12RandomizedTLSProfileSeed = seed
		}
		if egressRandomizedTLSProfileSeed != nil && tls12RandomizedTLSProfileSeed != nil {
			break
		}
	}
	if egressRandomizedTLSProfileSeed == nil || tls12RandomizedTLSProfileSeed == nil {
		return errors.TraceNew("missing TLS 1.2 or TLS 1.3 randomized seed")
	}
	proxyConfig.AllowBogons = false
	proxyConfig.EmitActivity = true
	proxyConfig.TunnelDialAuthorizationPublicKey =
		dialAuthorizationPublicKey
	proxyConfig.TunnelProxyPrivateKey = proxyPrivateKey
	proxyConfig.TunnelTrustedProxyAuthorization =
		trustedProxyAuthorization
	proxyConfig.ProxyPlatform = testProxyPlatform
	proxyConfig.ProxyVersion = testProxyVersion
	proxyConfig.ProxyBuildRev = testProxyBuildRev
	proxyConfig.ProxyLimits, err = common.NewProxyLimits(&common.ProxyLimitsConfig{
		MaxCommonClients:   1,
		MaxPersonalClients: 1,
	})
	if err != nil {
		return errors.Trace(err)
	}
	var upstreamDials atomic.Int64
	proxyConfig.TLSPassthroughDialer = net.Dial
	proxyConfig.ProxyTLSDialer = func(
		ctx context.Context,
		address string,
		tlsProfile string,
		randomizedTLSProfileSeed *prng.Seed,
		sni string,
		fragmentClientHello bool,
		tlsPadding int,
		passthroughMessage []byte,
		verifyPin string) (net.Conn, []byte, time.Time, time.Time, error) {

		upstreamDials.Add(1)
		var completedTCP time.Time
		var completedTLS time.Time

		if tlsProfile != testEgressTLSProfile ||
			randomizedTLSProfileSeed == nil ||
			*randomizedTLSProfileSeed !=
				*egressRandomizedTLSProfileSeed ||
			sni != testEgressSNI ||
			fragmentClientHello ||
			tlsPadding != 0 {

			return nil, nil, completedTCP, completedTLS, errors.TraceNew(
				"unexpected proxy TLS dial parameters")
		}

		tunnelTLSPassthroughKey, err := DeriveTunnelTLSPassthroughKey(
			tunnelRootObfuscationSecret)
		if err != nil {
			return nil, nil, completedTCP, completedTLS, errors.Trace(err)
		}
		if !obfuscator.VerifyTLSPassthroughMessage(
			true,
			hex.EncodeToString(tunnelTLSPassthroughKey),
			passthroughMessage) {

			return nil, nil, completedTCP, completedTLS, errors.TraceNew(
				"invalid TLS passthrough message")
		}

		expectedVerifyPin :=
			base64.StdEncoding.EncodeToString(tunnelVerifyPin)
		if verifyPin != expectedVerifyPin {
			return nil, nil, completedTCP, completedTLS, errors.TraceNew("unexpected TLS verify pin")
		}

		underlyingConn, err := (&net.Dialer{}).DialContext(
			ctx, "tcp", address)
		if err != nil {
			return nil, nil, completedTCP, completedTLS, errors.Trace(err)
		}
		completedTCP = time.Now().UTC()

		tlsConn := tls.Client(underlyingConn, &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS13,
			ServerName:         sni,
		})
		err = tlsConn.HandshakeContext(ctx)
		if err != nil {
			tlsConn.Close()
			return nil, nil, completedTCP, completedTLS, errors.Trace(err)
		}

		state := tlsConn.ConnectionState()
		rawCerts := make([][]byte, len(state.PeerCertificates))
		for i, cert := range state.PeerCertificates {
			rawCerts[i] = cert.Raw
		}
		err = common.VerifyServerCertificatePinsOnly(
			rawCerts, "", []string{verifyPin})
		if err != nil {
			tlsConn.Close()
			return nil, nil, completedTCP, completedTLS, errors.Trace(err)
		}

		completedTLS = time.Now().UTC()

		exporter, err := state.ExportKeyingMaterial(
			TunnelProxyReportExporterLabel,
			nil,
			TunnelProxyReportExporterSize)
		if err != nil {
			tlsConn.Close()
			return nil, nil, completedTCP, completedTLS, errors.Trace(err)
		}

		return tlsConn, exporter, completedTCP, completedTLS, nil
	}
	proxyConfig.ProxyQUICDialer = func(
		ctx context.Context,
		address string,
		sni string,
		quicVersion string,
		clientHelloSeed *prng.Seed,
		paddingSeed *prng.Seed,
		obfuscationKey string,
		verifyPin string) (net.Conn, []byte, time.Time, error) {

		upstreamDials.Add(1)
		var completedQUIC time.Time

		if sni != testEgressSNI ||
			quicVersion != protocol.QUIC_VERSION_V1 ||
			clientHelloSeed != nil ||
			paddingSeed != nil ||
			obfuscationKey != hex.EncodeToString(
				tunnelQUICObfuscationKey) ||
			verifyPin != base64.StdEncoding.EncodeToString(
				tunnelVerifyPin) {

			return nil, nil, completedQUIC, errors.TraceNew(
				"unexpected proxy QUIC dial parameters")
		}

		remoteAddr, err := net.ResolveUDPAddr("udp", address)
		if err != nil {
			return nil, nil, completedQUIC, errors.Trace(err)
		}
		packetConn, err := net.ListenPacket("udp4", "0.0.0.0:0")
		if err != nil {
			return nil, nil, completedQUIC, errors.Trace(err)
		}

		conn, err := quic.Dial(
			ctx,
			packetConn,
			remoteAddr,
			sni,
			quicVersion,
			clientHelloSeed,
			obfuscationKey,
			paddingSeed,
			nil,
			false,
			0,
			false,
			false,
			verifyPin,
			common.WrapClientSessionCache(
				tls.NewLRUClientSessionCache(0), sni))
		if err != nil {
			return nil, nil, completedQUIC, errors.Trace(err)
		}
		completedQUIC = time.Now().UTC()

		quicConn := conn.(*quic.Conn)
		exporter, err := quicConn.ExportKeyingMaterial(
			TunnelProxyReportExporterLabel,
			nil,
			TunnelProxyReportExporterSize)
		if err != nil {
			conn.Close()
			return nil, nil, completedQUIC, errors.Trace(err)
		}

		return conn, exporter, completedQUIC, nil
	}

	receiver := newTestProxyEventReceiver(false, 0, false, "")
	receiver.connectionStats = make(chan *ConnectionStats, 1)

	// Test: tunnel mode rejects a configured proxy ID.

	invalidConfig := *proxyConfig
	invalidConfig.ProxyID = expectedProxyID.String()
	if _, err := NewProxy(
		&invalidConfig,
		func(string) common.GeoIPData { return common.GeoIPData{} },
		receiver); err == nil {

		return errors.TraceNew("accepted configured tunnel proxy ID")
	}

	// Test: personal pairing requires explicit proxy limits.

	missingLimitsConfig := *proxyConfig
	missingLimitsConfig.ProxyLimits = nil
	if _, err := NewProxy(
		&missingLimitsConfig,
		func(string) common.GeoIPData { return common.GeoIPData{} },
		receiver); err == nil {

		return errors.TraceNew("accepted personal proxy without ProxyLimits")
	}

	proxy, err := NewProxy(
		proxyConfig,
		func(string) common.GeoIPData { return common.GeoIPData{} },
		receiver)
	if err != nil {
		return errors.Trace(err)
	}

	// Bogon destinations must be rejected for all enabled egress protocols.
	for _, egressProtocol := range []uint8{TransportTLS, TransportQUIC} {
		if egressProtocol == TransportQUIC && !quic.Enabled() {
			continue
		}
		header := &lightHeader{
			TunnelDialAuthorization: tunnelDialAuthorization,
			EgressProtocol:          egressProtocol,
			EgressSNI:               testEgressSNI,
		}
		if egressProtocol == TransportTLS {
			header.EgressTLSProfile = encodeTLSProfile(testEgressTLSProfile)
			header.EgressRandomizedTLSProfileSeed = egressRandomizedTLSProfileSeed[:]
		} else {
			header.EgressQUICVersion = encodeQUICVersion(protocol.QUIC_VERSION_V1)
		}
		conn, _, _, _, _, err := proxy.dialTunnelServer(
			ctx,
			header,
			"127.0.0.1",
			LIGHT_PROTOCOL_TLS,
			testIngressSNI,
			false,
			0,
			false,
			false)
		if conn != nil {
			conn.Close()
		}
		if err == nil || !strings.Contains(err.Error(), "IP is bogon") {
			return errors.Tracef("expected bogon rejection: %v", err)
		}
	}
	proxyConfig.AllowBogons = true

	group.Go(func() error {
		return proxy.Run(ctx)
	})

	select {
	case <-receiver.listening:
	case <-ctx.Done():
		return errors.Trace(ctx.Err())
	}
	if len(receiver.listeningAddresses) != len(proxyConfig.ListenAddresses) {
		return errors.TraceNew("unexpected listener count")
	}

	entry, err := DecodeAndValidateProxyEntry(proxyEntry)
	if err != nil {
		return errors.Trace(err)
	}

	if entry.Protocol != "" || entry.DialAddressIPv4 != "" || entry.DialAddressIPv6 != "" {
		return errors.TraceNew("tunnel entry includes legacy endpoints")
	}

	for i, listenAddress := range proxyConfig.ListenAddresses {
		boundAddress, err := parseProxyAddress(
			receiver.listeningAddresses[i], listenAddress.Protocol)
		if err != nil {
			return errors.Trace(err)
		}
		if boundAddress.IPAddress != listenAddress.IPAddress ||
			boundAddress.Port == 0 {

			return errors.TraceNew("unexpected bound proxy address")
		}
		entry.DialAddresses[i] = boundAddress
	}

	proxyEntry, err = protocol.CBOREncoding.Marshal(
		&SignedProxyEntry{ProxyEntry: *entry})
	if err != nil {
		return errors.Trace(err)
	}

	params, err := parameters.NewParameters(nil)
	if err != nil {
		return errors.Trace(err)
	}

	client, err := NewClient(&ClientConfig{
		Logger: testutils.NewTestLogger(),
		TCPDialer: func(
			ctx context.Context, addr string) (net.Conn, error) {

			conn, err := (&net.Dialer{}).DialContext(
				ctx, "tcp", addr)
			if err != nil {
				return nil, errors.Trace(err)
			}
			return newPaddingCheckerConn(conn), nil
		},
		TLSDialer: func(
			ctx context.Context,
			underlyingConn net.Conn,
			_ string,
			tlsProfile string,
			randomizedTLSProfileSeed *prng.Seed,
			sni string,
			fragmentClientHello bool,
			tlsPadding int,
			passthroughMessage []byte,
			verifyPin string) (net.Conn, error) {

			return dialTLS(
				params,
				ctx,
				underlyingConn,
				tlsProfile,
				randomizedTLSProfileSeed,
				sni,
				fragmentClientHello,
				tlsPadding,
				passthroughMessage,
				verifyPin)
		},
		QUICDialer: func(
			ctx context.Context,
			address string,
			sni string,
			quicVersion string,
			clientHelloSeed *prng.Seed,
			paddingSeed *prng.Seed,
			obfuscatedQUICNonceTransformerParameters *transforms.ObfuscatorSeedTransformerParameters,
			disablePathMTUDiscovery bool,
			obfuscationKey string,
			verifyPin string) (net.Conn, error) {

			remoteAddr, err := net.ResolveUDPAddr("udp", address)
			if err != nil {
				return nil, errors.Trace(err)
			}
			packetConn, err := net.ListenPacket("udp4", "0.0.0.0:0")
			if err != nil {
				return nil, errors.Trace(err)
			}

			return quic.Dial(
				ctx,
				packetConn,
				remoteAddr,
				sni,
				quicVersion,
				clientHelloSeed,
				obfuscationKey,
				paddingSeed,
				obfuscatedQUICNonceTransformerParameters,
				disablePathMTUDiscovery,
				0,
				false,
				false,
				verifyPin,
				common.WrapClientSessionCache(
					tls.NewLRUClientSessionCache(0), sni))
		},
		TunnelMode:     true,
		SponsorID:      testSponsorID,
		ClientPlatform: testClientPlatform,
		ClientBuildRev: testClientBuildRev,
		DeviceRegion:   "US",
		SessionID: prng.HexString(
			protocol.PSIPHON_API_CLIENT_SESSION_ID_LENGTH),
		ProxyEntryTracker: 0x0102030405060708,
		ProxyEntry:        proxyEntry,
	})
	if err != nil {
		return errors.Trace(err)
	}
	if client.GetMetrics(false).ProxyID != proxy.ID ||
		proxy.ID != expectedProxyID.String() {

		return errors.TraceNew("unexpected proxy ID")
	}

	// Common and personal entries share endpoints and transport credentials.
	entry.PersonalCompartmentID = nil
	commonClientConfig := *client.config
	commonClientConfig.ProxyEntry, err = protocol.CBOREncoding.Marshal(
		&SignedProxyEntry{ProxyEntry: *entry})
	if err != nil {
		return errors.Trace(err)
	}
	commonClient, err := NewClient(&commonClientConfig)
	if err != nil {
		return errors.Trace(err)
	}
	if commonClient.GetMetrics(false).ProxyID != proxy.ID {
		return errors.TraceNew("unexpected common proxy ID")
	}

	for _, ingress := range []struct {
		protocol    string
		quicVersion string
	}{
		{protocol: LIGHT_PROTOCOL_TLS},
		{
			protocol:    LIGHT_PROTOCOL_QUIC,
			quicVersion: protocol.QUIC_VERSION_V1,
		},
	} {
		if ingress.protocol == LIGHT_PROTOCOL_QUIC && !quic.Enabled() {
			continue
		}
		for _, egress := range []struct {
			protocol                 uint8
			tlsProfile               string
			randomizedTLSProfileSeed *prng.Seed
			quicVersion              string
		}{
			{
				protocol:                 TransportTLS,
				tlsProfile:               testEgressTLSProfile,
				randomizedTLSProfileSeed: egressRandomizedTLSProfileSeed,
			},
			{
				protocol:    TransportQUIC,
				quicVersion: protocol.QUIC_VERSION_V1,
			},
		} {
			if egress.protocol == TransportQUIC && !quic.Enabled() {
				continue
			}
			runClient := func(
				client *Client, expectedPersonal bool, expectedFailure string,
				modifyHeader func(*lightHeader)) error {

				dialsBefore := upstreamDials.Load()
				var expectedTLSProfile, expectedQUICVersion uint8
				err := runLightClient(
					ctx,
					client,
					testNetworkType,
					ingress.protocol,
					testIngressTLSProfile,
					ingress.quicVersion,
					nil,
					false,
					0,
					"",
					64*1024,
					func() error { return nil },
					&TunnelDialParameters{
						TunnelDialAuthorization: tunnelDialAuthorization,
						EgressProtocol:          egress.protocol,
						EgressTLSProfile:        egress.tlsProfile,
						EgressRandomizedTLSProfileSeed: egress.
							randomizedTLSProfileSeed,
						EgressQUICVersion: egress.quicVersion,
						EgressSNI:         testEgressSNI,
					},
					func(header *lightHeader) {
						if modifyHeader != nil {
							modifyHeader(header)
						}
						expectedTLSProfile = header.TLSProfile
						expectedQUICVersion = header.QUICVersion
					})
				if expectedFailure == "" && err != nil {
					return errors.Trace(err)
				}
				if expectedFailure != "" && err == nil {
					return errors.TraceNew("unexpected admission success")
				}

				var stats *ConnectionStats
				select {
				case stats = <-receiver.connectionStats:
				case <-ctx.Done():
					return errors.Trace(ctx.Err())
				}
				if stats.MatchedPersonalCompartments != expectedPersonal {
					return errors.TraceNew("unexpected connection pairing status")
				}
				if expectedFailure != "" {
					if !strings.Contains(stats.Failure, expectedFailure) ||
						upstreamDials.Load() != dialsBefore {

						return errors.TraceNew("expected rejection before upstream dial")
					}
					return nil
				}
				if stats.Failure != "" {
					return errors.TraceNew(stats.Failure)
				}
				if egress.protocol == TransportTLS && stats.ProxyCompletedUpstreamTLS.IsZero() {
					return errors.TraceNew("missing upstream TLS completion time")
				}
				if stats.SponsorID != "" ||
					stats.ClientPlatform != "" ||
					stats.ClientBuildRev != "" ||
					stats.DeviceRegion != "" ||
					stats.SessionID != "" ||
					stats.ProxyEntryTracker != 0 ||
					stats.NetworkType != "" ||
					stats.ClientConnectionNum != 0 {

					return errors.TraceNew("tunnel header exposed client attributes")
				}
				select {
				case report := <-reports:
					if report.IngressTLSProfile != expectedTLSProfile ||
						report.IngressQUICVersion != expectedQUICVersion {

						return errors.TraceNew("unexpected ingress profile/version")
					}
					if report.MatchedPersonalCompartments != expectedPersonal {
						return errors.TraceNew("unexpected report pairing status")
					}
				case <-ctx.Done():
					return errors.Trace(ctx.Err())
				}
				return nil
			}

			// Test: common and personal tunnels relay on the same listeners for
			// every enabled ingress/egress transport combination.

			if err := runClient(commonClient, false, "", nil); err != nil {
				return errors.Trace(err)
			}
			if err := runClient(client, true, "", nil); err != nil {
				return errors.Trace(err)
			}

			// Test: upgraded clients may report unknown ingress profile/version codes.

			err := runClient(commonClient, false, "",
				func(header *lightHeader) {
					if ingress.protocol == LIGHT_PROTOCOL_TLS {
						header.TLSProfile = 255
					} else {
						header.QUICVersion = 255
					}
				})
			if err != nil {
				return errors.Trace(err)
			}

			// Test: an invalid tunnel dial authorization and a client-chosen
			// destination are rejected before upstream dialing.

			err = runClient(commonClient, false, "VerifyTunnelDialAuthorization",
				func(header *lightHeader) {
					authorization := append(
						[]byte(nil), header.TunnelDialAuthorization...)
					authorization[len(authorization)-1] ^= 0xff
					header.TunnelDialAuthorization = authorization
				})
			if err != nil {
				return errors.Trace(err)
			}
			err = runClient(commonClient, false, "unexpected destination address",
				func(header *lightHeader) {
					header.DestinationAddress = "127.0.0.1:1"
				})
			if err != nil {
				return errors.Trace(err)
			}

			// Test: missing ingress TLS profiles are rejected before upstream dialing.

			if ingress.protocol == LIGHT_PROTOCOL_TLS {
				err := runClient(commonClient, false, "missing ingress TLS profile",
					func(header *lightHeader) {
						header.TLSProfile = 0
					})
				if err != nil {
					return errors.Trace(err)
				}
			}
			if ingress.protocol != LIGHT_PROTOCOL_TLS || egress.protocol != TransportTLS {
				continue
			}

			// Test: TLS 1.2-only egress profiles are rejected before upstream dialing.

			for _, randomized := range []bool{false, true} {
				err := runClient(commonClient, false, "egress TLS profile does not support TLS 1.3",
					func(header *lightHeader) {
						header.EgressTLSProfile = encodeTLSProfile(protocol.TLS_PROFILE_CHROME_58)
						header.EgressRandomizedTLSProfileSeed = nil
						if randomized {
							header.EgressTLSProfile = encodeTLSProfile(testEgressTLSProfile)
							header.EgressRandomizedTLSProfileSeed = tls12RandomizedTLSProfileSeed[:]
						}
					})
				if err != nil {
					return errors.Trace(err)
				}
			}

			// Test: invalid personal compartment IDs are rejected.

			for _, id := range [][]byte{
				prng.Bytes(personalCompartmentIDSize),
				testPersonalCompartmentID[:personalCompartmentIDSize-1],
				prng.Bytes(personalCompartmentIDSize + 1),
			} {
				// Bypass entry validation to exercise the proxy's header validation.
				commonClient.proxyEntry.PersonalCompartmentID = id
				err := runClient(commonClient, false, "invalid personal compartment ID", nil)
				if err != nil {
					return errors.Trace(err)
				}
			}
			commonClient.proxyEntry.PersonalCompartmentID = nil

			// Test: common and personal clients have separate capacity limits.

			for _, personal := range []bool{false, true} {
				acquire := proxyConfig.ProxyLimits.TryAcquireCommonClient
				blockedClient, allowedClient := commonClient, client
				if personal {
					acquire = proxyConfig.ProxyLimits.TryAcquirePersonalClient
					blockedClient, allowedClient = client, commonClient
				}
				release, ok := acquire()
				if !ok {
					return errors.TraceNew("missing proxy capacity")
				}
				err := runClient(blockedClient, personal, "proxy capacity exceeded", nil)
				if err == nil {
					err = runClient(allowedClient, !personal, "", nil)
				}
				release()
				if err != nil {
					return errors.Trace(err)
				}
			}
		}
	}

	cancel()

	err = group.Wait()
	if err != nil {
		return errors.Trace(err)
	}

	receiver.mutex.Lock()
	validActivity := receiver.activityBytesUp > 0 &&
		receiver.activityBytesDown > 0 &&
		receiver.lastActivityConnectionCount == 0
	receiver.mutex.Unlock()
	if !validActivity {
		return errors.TraceNew("unexpected final activity stats")
	}

	return errors.Trace(receiver.checkResults())
}

func TestLightTunnelMessages(t *testing.T) {
	if err := runTestLightTunnelMessages(); err != nil {
		t.Fatal(err)
	}
}

func runTestLightTunnelMessages() error {

	extendSignedPayload := func(
		encoded []byte, sign func([]byte) []byte) ([]byte, error) {

		var signedPayload signedTunnelPayload
		err := cbor.Unmarshal(encoded, &signedPayload)
		if err != nil {
			return nil, errors.Trace(err)
		}
		var fields map[uint64]interface{}
		err = cbor.Unmarshal(signedPayload.Payload, &fields)
		if err != nil {
			return nil, errors.Trace(err)
		}
		fields[255] = true
		payload, err := protocol.CBOREncoding.Marshal(fields)
		if err != nil {
			return nil, errors.Trace(err)
		}
		encoded, err = protocol.CBOREncoding.Marshal(map[uint64]interface{}{
			0: true,
			1: sign(payload),
			2: payload,
		})
		return encoded, errors.Trace(err)
	}

	dialAuthorizationPublicKey, dialAuthorizationPrivateKey, err :=
		ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return errors.Trace(err)
	}
	otherDialAuthorizationPublicKey, _, err :=
		ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return errors.Trace(err)
	}

	dialAuthorization := &TunnelDialAuthorization{
		Version:               TunnelDialAuthorizationVersion,
		IPAddress:             net.ParseIP("192.0.2.1").To4(),
		VerifyPin:             prng.Bytes(32),
		RootObfuscationSecret: prng.Bytes(TunnelRootObfuscationSecretSize),
		TLSPort:               443,
		QUICPort:              443,
	}

	// Test: valid dial authorization

	encodedDialAuthorization, err := SignTunnelDialAuthorization(
		dialAuthorizationPrivateKey, dialAuthorization)
	if err != nil {
		return errors.Trace(err)
	}
	verifiedDialAuthorization, err := VerifyTunnelDialAuthorization(
		dialAuthorizationPublicKey, encodedDialAuthorization)
	if err != nil {
		return errors.Trace(err)
	}
	if !bytes.Equal(
		verifiedDialAuthorization.IPAddress,
		dialAuthorization.IPAddress) ||
		!bytes.Equal(
			verifiedDialAuthorization.VerifyPin,
			dialAuthorization.VerifyPin) ||
		!bytes.Equal(
			verifiedDialAuthorization.RootObfuscationSecret,
			dialAuthorization.RootObfuscationSecret) ||
		verifiedDialAuthorization.TLSPort !=
			dialAuthorization.TLSPort ||
		verifiedDialAuthorization.QUICPort !=
			dialAuthorization.QUICPort {

		return errors.TraceNew("unexpected dial authorization")
	}

	// Test: unknown dial authorization payload and envelope fields are accepted

	encodedDialAuthorization, err = extendSignedPayload(
		encodedDialAuthorization, func(payload []byte) []byte {
			return ed25519.Sign(
				dialAuthorizationPrivateKey,
				makeTunnelSignatureInput(tunnelDialAuthorizationSignatureDomain, payload))
		})
	if err != nil {
		return errors.Trace(err)
	}
	_, err = VerifyTunnelDialAuthorization(
		dialAuthorizationPublicKey, encodedDialAuthorization)
	if err != nil {
		return errors.Trace(err)
	}

	// Test: wrong dial authorization signing key

	_, err = VerifyTunnelDialAuthorization(
		otherDialAuthorizationPublicKey,
		encodedDialAuthorization)
	if err == nil {
		return errors.TraceNew("unexpected success")
	}

	// Test: signatures cover unknown dial authorization payload fields

	modifiedDialAuthorization :=
		append([]byte(nil), encodedDialAuthorization...)
	modifiedDialAuthorization[len(modifiedDialAuthorization)-1] ^= 1
	_, err = VerifyTunnelDialAuthorization(
		dialAuthorizationPublicKey,
		modifiedDialAuthorization)
	if err == nil {
		return errors.TraceNew("unexpected success")
	}

	signInvalidDialAuthorization := func(
		authorization *TunnelDialAuthorization) ([]byte, error) {

		payload, err := protocol.CBOREncoding.Marshal(authorization)
		if err != nil {
			return nil, errors.Trace(err)
		}
		return signTunnelPayload(
			dialAuthorizationPrivateKey,
			tunnelDialAuthorizationSignatureDomain,
			payload,
			maxTunnelDialAuthorizationSize)
	}

	// Test: signed invalid IP address

	invalidDialAuthorization := *dialAuthorization
	invalidDialAuthorization.IPAddress = []byte{1}
	encodedInvalidDialAuthorization, err :=
		signInvalidDialAuthorization(&invalidDialAuthorization)
	if err != nil {
		return errors.Trace(err)
	}
	_, err = VerifyTunnelDialAuthorization(
		dialAuthorizationPublicKey,
		encodedInvalidDialAuthorization)
	if err == nil {
		return errors.TraceNew("unexpected success")
	}

	// Test: signed invalid verify pin

	invalidDialAuthorization = *dialAuthorization
	invalidDialAuthorization.VerifyPin = prng.Bytes(31)
	encodedInvalidDialAuthorization, err =
		signInvalidDialAuthorization(&invalidDialAuthorization)
	if err != nil {
		return errors.Trace(err)
	}
	_, err = VerifyTunnelDialAuthorization(
		dialAuthorizationPublicKey,
		encodedInvalidDialAuthorization)
	if err == nil {
		return errors.TraceNew("unexpected success")
	}

	// Test: signed invalid root obfuscation secret

	invalidDialAuthorization = *dialAuthorization
	invalidDialAuthorization.RootObfuscationSecret = prng.Bytes(
		TunnelRootObfuscationSecretSize - 1)
	encodedInvalidDialAuthorization, err =
		signInvalidDialAuthorization(&invalidDialAuthorization)
	if err != nil {
		return errors.Trace(err)
	}
	_, err = VerifyTunnelDialAuthorization(
		dialAuthorizationPublicKey,
		encodedInvalidDialAuthorization)
	if err == nil {
		return errors.TraceNew("unexpected success")
	}

	// Test: signed missing tunnel port

	invalidDialAuthorization = *dialAuthorization
	invalidDialAuthorization.TLSPort = 0
	invalidDialAuthorization.QUICPort = 0
	encodedInvalidDialAuthorization, err =
		signInvalidDialAuthorization(&invalidDialAuthorization)
	if err != nil {
		return errors.Trace(err)
	}
	_, err = VerifyTunnelDialAuthorization(
		dialAuthorizationPublicKey,
		encodedInvalidDialAuthorization)
	if err == nil {
		return errors.TraceNew("unexpected success")
	}

	proxyPrivateKey, err := inproxy.GenerateSessionPrivateKey()
	if err != nil {
		return errors.Trace(err)
	}
	proxyPublicKey, err := proxyPrivateKey.GetPublicKey()
	if err != nil {
		return errors.Trace(err)
	}
	otherProxyPrivateKey, err := inproxy.GenerateSessionPrivateKey()
	if err != nil {
		return errors.Trace(err)
	}
	otherProxyPublicKey, err := otherProxyPrivateKey.GetPublicKey()
	if err != nil {
		return errors.Trace(err)
	}

	trustedProxyIssuerPublicKey, trustedProxyIssuerPrivateKey, err :=
		ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return errors.Trace(err)
	}
	otherTrustedProxyIssuerPublicKey, _, err :=
		ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return errors.Trace(err)
	}

	now := time.Now()
	trustedProxyAuthorization := &TunnelTrustedProxyAuthorization{
		Version:        TunnelTrustedProxyAuthorizationVersion,
		ProxyPublicKey: proxyPublicKey[:],
		NotBeforeUnix:  now.Add(-time.Hour).Unix(),
		NotAfterUnix:   now.Add(time.Hour).Unix(),
	}

	// Test: valid trusted proxy authorization

	encodedTrustedProxyAuthorization, err :=
		SignTunnelTrustedProxyAuthorization(
			trustedProxyIssuerPrivateKey,
			trustedProxyAuthorization)
	if err != nil {
		return errors.Trace(err)
	}
	_, err = VerifyTunnelTrustedProxyAuthorization(
		trustedProxyIssuerPublicKey,
		proxyPublicKey[:],
		encodedTrustedProxyAuthorization,
		now)
	if err != nil {
		return errors.Trace(err)
	}

	// Test: unknown trusted proxy authorization payload and envelope fields
	// are accepted

	encodedTrustedProxyAuthorization, err = extendSignedPayload(
		encodedTrustedProxyAuthorization, func(payload []byte) []byte {
			return ed25519.Sign(
				trustedProxyIssuerPrivateKey,
				makeTunnelSignatureInput(tunnelTrustedProxyAuthorizationSignatureDomain, payload))
		})
	if err != nil {
		return errors.Trace(err)
	}
	_, err = VerifyTunnelTrustedProxyAuthorization(
		trustedProxyIssuerPublicKey, proxyPublicKey[:],
		encodedTrustedProxyAuthorization, now)
	if err != nil {
		return errors.Trace(err)
	}

	// Test: wrong trusted proxy authorization issuer

	_, err = VerifyTunnelTrustedProxyAuthorization(
		otherTrustedProxyIssuerPublicKey,
		proxyPublicKey[:],
		encodedTrustedProxyAuthorization,
		now)
	if err == nil {
		return errors.TraceNew("unexpected success")
	}

	// Test: wrong trusted proxy public key

	_, err = VerifyTunnelTrustedProxyAuthorization(
		trustedProxyIssuerPublicKey,
		otherProxyPublicKey[:],
		encodedTrustedProxyAuthorization,
		now)
	if err == nil {
		return errors.TraceNew("unexpected success")
	}

	// Test: trusted proxy authorization not yet valid

	futureTrustedProxyAuthorization := *trustedProxyAuthorization
	futureTrustedProxyAuthorization.NotBeforeUnix =
		now.Add(time.Hour).Unix()
	futureTrustedProxyAuthorization.NotAfterUnix =
		now.Add(2 * time.Hour).Unix()
	encodedFutureTrustedProxyAuthorization, err :=
		SignTunnelTrustedProxyAuthorization(
			trustedProxyIssuerPrivateKey,
			&futureTrustedProxyAuthorization)
	if err != nil {
		return errors.Trace(err)
	}
	_, err = VerifyTunnelTrustedProxyAuthorization(
		trustedProxyIssuerPublicKey,
		proxyPublicKey[:],
		encodedFutureTrustedProxyAuthorization,
		now)
	if err == nil {
		return errors.TraceNew("unexpected success")
	}

	// Test: trusted proxy authorization expired

	expiredTrustedProxyAuthorization := *trustedProxyAuthorization
	expiredTrustedProxyAuthorization.NotBeforeUnix =
		now.Add(-2 * time.Hour).Unix()
	expiredTrustedProxyAuthorization.NotAfterUnix =
		now.Add(-time.Hour).Unix()
	encodedExpiredTrustedProxyAuthorization, err :=
		SignTunnelTrustedProxyAuthorization(
			trustedProxyIssuerPrivateKey,
			&expiredTrustedProxyAuthorization)
	if err != nil {
		return errors.Trace(err)
	}
	_, err = VerifyTunnelTrustedProxyAuthorization(
		trustedProxyIssuerPublicKey,
		proxyPublicKey[:],
		encodedExpiredTrustedProxyAuthorization,
		now)
	if err == nil {
		return errors.TraceNew("unexpected success")
	}

	exporter := prng.Bytes(TunnelProxyReportExporterSize)
	report := &TunnelProxyReport{
		Version:                   TunnelProxyReportVersion,
		ProxyPublicKey:            proxyPublicKey[:],
		TrustedProxyAuthorization: encodedTrustedProxyAuthorization,
		ClientIP:                  net.ParseIP("192.0.2.2").To4(),
		ProxyPlatform:             encodeClientPlatform("Android"),
		ProxyVersion:              1,
		ProxyBuildRev:             []byte{0x01},
		IngressProtocol:           TransportTLS,
		IngressTLSProfile:         encodeTLSProfile(protocol.TLS_PROFILE_CHROME_133),
		IngressSNI:                "ingress.example.org",
		EgressTLSProfile:          encodeTLSProfile(protocol.TLS_PROFILE_RANDOMIZED),
	}

	// Test: reject unspecified/multicast client IPs; allow private/loopback IPs.

	for _, testCase := range []struct {
		clientIP string
		valid    bool
	}{
		{"0.0.0.0", false},
		{"::", false},
		{"224.0.0.1", false},
		{"ff02::1", false},
		{"192.168.1.2", true},
		{"fd00::1", true},
		{"127.0.0.1", true},
		{"::1", true},
	} {
		ipReport := *report
		ipReport.ClientIP = netip.MustParseAddr(testCase.clientIP).AsSlice()
		err := validateTunnelProxyReport(&ipReport)
		if (err == nil) != testCase.valid {
			return errors.Tracef(
				"unexpected client IP validation for %s: %v", testCase.clientIP, err)
		}
	}

	// Test: missing egress transport

	missingEgressReport := *report
	missingEgressReport.EgressTLSProfile = 0
	if validateTunnelProxyReport(&missingEgressReport) == nil {
		return errors.TraceNew("unexpected success")
	}

	// Test: multiple egress transports

	multipleEgressReport := *report
	multipleEgressReport.EgressQUICVersion = encodeQUICVersion(
		protocol.QUIC_VERSION_V1)
	if validateTunnelProxyReport(&multipleEgressReport) == nil {
		return errors.TraceNew("unexpected success")
	}

	// Test: empty report SNI is allowed; invalid UTF-8 and oversized SNI are rejected.

	for _, sni := range []string{"", "\xff", strings.Repeat("a", maxTunnelSNI+1)} {
		sniReport := *report
		sniReport.IngressSNI = sni
		var frame bytes.Buffer
		err := WriteTunnelProxyReport(
			&frame, proxyPrivateKey, exporter, &sniReport,
			0, maxTunnelProxyReportPadding)
		if (err == nil) != (sni == "") {
			return errors.TraceNew("unexpected report SNI validation")
		}
	}

	// Test: valid proxy report

	var reportFrame bytes.Buffer
	err = WriteTunnelProxyReport(
		&reportFrame,
		proxyPrivateKey,
		exporter,
		report,
		0,
		maxTunnelProxyReportPadding)
	if err != nil {
		return errors.Trace(err)
	}
	verifiedReport, proxyID, err := ReadAndVerifyTunnelProxyReport(
		bytes.NewReader(reportFrame.Bytes()),
		exporter)
	if err != nil {
		return errors.Trace(err)
	}
	expectedCurvePublicKey, err := proxyPublicKey.ToCurve25519()
	if err != nil {
		return errors.Trace(err)
	}
	if proxyID != inproxy.ID(expectedCurvePublicKey) ||
		!bytes.Equal(verifiedReport.ProxyPublicKey, proxyPublicKey[:]) {

		return errors.TraceNew("unexpected proxy report")
	}

	// Test: report padding bounds, size cap, and preservation of following bytes.

	for _, testCase := range []struct {
		minPadding, maxPadding   int
		expectedMin, expectedMax int
		invalid                  bool
	}{
		{0, 0, 0, 0, false},
		{64, 64, 64, 64, false},
		{16, 128, 16, 128, false},
		{1 << 20, 1 << 20, 1024, maxTunnelProxyReportSize, false},
		{-1, 0, 0, 0, true},
		{2, 1, 0, 0, true},
	} {
		var frame bytes.Buffer
		err := WriteTunnelProxyReport(
			&frame, proxyPrivateKey, exporter, report,
			testCase.minPadding, testCase.maxPadding)
		if testCase.invalid {
			if err == nil {
				return errors.TraceNew("accepted invalid report padding range")
			}
			continue
		}
		if err != nil {
			return errors.Trace(err)
		}
		if frame.Len()-2 > maxTunnelProxyReportSize {
			return errors.TraceNew("padded report exceeds size limit")
		}
		var signedReport signedTunnelPayload
		if err := cbor.Unmarshal(frame.Bytes()[2:], &signedReport); err != nil {
			return errors.Trace(err)
		}
		if len(signedReport.Padding) < testCase.expectedMin ||
			len(signedReport.Padding) > testCase.expectedMax {

			return errors.TraceNew("unexpected report padding length")
		}
		if testCase.minPadding > maxTunnelProxyReportSize &&
			frame.Len()-2 < maxTunnelProxyReportSize-maxTunnelProxyReportEnvelopeOverhead {

			return errors.TraceNew("report padding did not fill the available frame budget")
		}
		frame.WriteString("following tunnel bytes")
		if _, _, err := ReadAndVerifyTunnelProxyReport(&frame, exporter); err != nil {
			return errors.Trace(err)
		}
		if frame.String() != "following tunnel bytes" {
			return errors.TraceNew("report reader consumed following tunnel bytes")
		}
	}

	// Test: unknown platform, TLS profile, and QUIC version codes in reports
	// are accepted and decode to empty strings in metrics.

	for _, transport := range []uint8{TransportTLS, TransportQUIC} {
		unknownReport := *report
		unknownReport.ProxyPlatform = 255
		unknownReport.IngressProtocol = transport
		unknownReport.IngressTLSProfile = 255
		unknownReport.EgressTLSProfile = 255
		metricSuffix := "tls_profile"
		if transport == TransportQUIC {
			unknownReport.IngressTLSProfile = 0
			unknownReport.IngressQUICVersion = 255
			unknownReport.EgressTLSProfile = 0
			unknownReport.EgressQUICVersion = 255
			metricSuffix = "quic_version"
		}
		var frame bytes.Buffer
		err := WriteTunnelProxyReport(
			&frame, proxyPrivateKey, exporter, &unknownReport,
			0, maxTunnelProxyReportPadding)
		if err != nil {
			return errors.Trace(err)
		}
		verifiedReport, _, err := ReadAndVerifyTunnelProxyReport(&frame, exporter)
		if err != nil {
			return errors.Trace(err)
		}
		metrics := verifiedReport.GetMetrics()
		for _, name := range []string{
			"light_proxy_platform",
			"light_proxy_" + metricSuffix,
			"light_proxy_egress_" + metricSuffix,
		} {
			if metrics[name] != "" {
				return errors.Tracef("unexpected metric %s: %v", name, metrics[name])
			}
		}
	}

	// Test: unknown proxy report payload and envelope fields are accepted

	encodedExtendedReport, err := extendSignedPayload(
		reportFrame.Bytes()[2:], func(payload []byte) []byte {
			return ed25519.Sign(
				ed25519.PrivateKey(proxyPrivateKey[:]),
				makeTunnelProxyReportSignatureInput(exporter, payload))
		})
	if err != nil {
		return errors.Trace(err)
	}
	extendedReportFrame := make([]byte, 2+len(encodedExtendedReport))
	binary.BigEndian.PutUint16(
		extendedReportFrame[:2], uint16(len(encodedExtendedReport)))
	copy(extendedReportFrame[2:], encodedExtendedReport)
	_, _, err = ReadAndVerifyTunnelProxyReport(
		bytes.NewReader(extendedReportFrame), exporter)
	if err != nil {
		return errors.Trace(err)
	}

	// Test: proxy report bound to exporter

	otherExporter := append([]byte(nil), exporter...)
	otherExporter[0] ^= 1
	_, _, err = ReadAndVerifyTunnelProxyReport(
		bytes.NewReader(extendedReportFrame),
		otherExporter)
	if err == nil {
		return errors.TraceNew("unexpected success")
	}

	// Test: signatures cover unknown proxy report payload fields

	modifiedReportFrame := append([]byte(nil), extendedReportFrame...)
	modifiedReportFrame[len(modifiedReportFrame)-1] ^= 1
	_, _, err = ReadAndVerifyTunnelProxyReport(
		bytes.NewReader(modifiedReportFrame),
		exporter)
	if err == nil {
		return errors.TraceNew("unexpected success")
	}

	// Test: proxy report signing key does not match public key

	mismatchedReport := *report
	mismatchedReport.ProxyPublicKey = otherProxyPublicKey[:]
	mismatchedReportPayload, err :=
		protocol.CBOREncoding.Marshal(&mismatchedReport)
	if err != nil {
		return errors.Trace(err)
	}
	mismatchedReportSignature := ed25519.Sign(
		ed25519.PrivateKey(proxyPrivateKey[:]),
		makeTunnelProxyReportSignatureInput(
			exporter, mismatchedReportPayload))
	encodedMismatchedReport, err := protocol.CBOREncoding.Marshal(
		&signedTunnelPayload{
			Signature: mismatchedReportSignature,
			Payload:   mismatchedReportPayload,
		})
	if err != nil {
		return errors.Trace(err)
	}
	mismatchedReportFrame := make(
		[]byte, 2+len(encodedMismatchedReport))
	binary.BigEndian.PutUint16(
		mismatchedReportFrame[:2],
		uint16(len(encodedMismatchedReport)))
	copy(mismatchedReportFrame[2:], encodedMismatchedReport)
	_, _, err = ReadAndVerifyTunnelProxyReport(
		bytes.NewReader(mismatchedReportFrame),
		exporter)
	if err == nil {
		return errors.TraceNew("unexpected success")
	}

	// Test: zero-length proxy report frame

	_, _, err = ReadAndVerifyTunnelProxyReport(
		bytes.NewReader([]byte{0, 0}),
		exporter)
	if err == nil {
		return errors.TraceNew("unexpected success")
	}

	// Test: oversized proxy report frame

	oversizedReportFrame := make([]byte, 2)
	binary.BigEndian.PutUint16(
		oversizedReportFrame,
		uint16(maxTunnelProxyReportSize+1))
	_, _, err = ReadAndVerifyTunnelProxyReport(
		bytes.NewReader(oversizedReportFrame),
		exporter)
	if err == nil {
		return errors.TraceNew("unexpected success")
	}

	// Test: truncated proxy report frame

	truncatedReportFrame := extendedReportFrame[:len(extendedReportFrame)-1]
	_, _, err = ReadAndVerifyTunnelProxyReport(
		bytes.NewReader(truncatedReportFrame),
		exporter)
	if err == nil {
		return errors.TraceNew("unexpected success")
	}

	return nil
}

func TestLightProxyAddresses(t *testing.T) {
	dialAddresses := []ProxyAddress{
		{IPAddress: "192.0.2.1", Port: 443, Protocol: LIGHT_PROTOCOL_TLS},
		{IPAddress: "2001:db8::1", Port: 443, Protocol: LIGHT_PROTOCOL_QUIC},
	}
	listenAddresses := []ProxyAddress{
		{IPAddress: "0.0.0.0", Port: 0, Protocol: LIGHT_PROTOCOL_TLS},
		{IPAddress: "::", Port: 0, Protocol: LIGHT_PROTOCOL_QUIC},
	}

	// Test: paired public and local endpoints, and default listen addresses

	if err := ValidateProxyAddresses(dialAddresses, listenAddresses); err != nil {
		t.Fatal(err)
	}
	if err := ValidateProxyAddresses(dialAddresses, nil); err != nil {
		t.Fatal(err)
	}

	// Test: mismatched endpoint counts and protocols

	if err := ValidateProxyAddresses(
		dialAddresses, listenAddresses[:1]); err == nil {

		t.Fatal("unexpected success")
	}
	mismatchedAddresses := append([]ProxyAddress(nil), listenAddresses...)
	mismatchedAddresses[1].Protocol = LIGHT_PROTOCOL_TLS
	if err := ValidateProxyAddresses(
		dialAddresses, mismatchedAddresses); err == nil {

		t.Fatal("unexpected success")
	}

	// Test: mismatched endpoint IP address families

	for i, mismatchedIP := range []string{"::", "0.0.0.0"} {
		mismatchedAddresses := append([]ProxyAddress(nil), listenAddresses...)
		mismatchedAddresses[i].IPAddress = mismatchedIP
		if err := ValidateProxyAddresses(
			dialAddresses, mismatchedAddresses); err == nil {

			t.Fatal("unexpected success")
		}
	}

	// Test: duplicate local endpoints, including equivalent IP representations

	for _, duplicateIP := range []string{"127.0.0.1", "::ffff:127.0.0.1"} {
		err := ValidateProxyAddresses(
			[]ProxyAddress{dialAddresses[0], dialAddresses[0]},
			[]ProxyAddress{
				{IPAddress: "127.0.0.1", Port: 8443, Protocol: LIGHT_PROTOCOL_TLS},
				{IPAddress: duplicateIP, Port: 8443, Protocol: LIGHT_PROTOCOL_TLS},
			})
		if err == nil {
			t.Fatal("unexpected success")
		}
	}

	// Test: invalid public endpoints

	for _, address := range []ProxyAddress{
		{IPAddress: "invalid", Port: 443, Protocol: LIGHT_PROTOCOL_TLS},
		{IPAddress: "0.0.0.0", Port: 443, Protocol: LIGHT_PROTOCOL_TLS},
		{IPAddress: "192.0.2.1", Port: 0, Protocol: LIGHT_PROTOCOL_TLS},
		{IPAddress: "192.0.2.1", Port: 65536, Protocol: LIGHT_PROTOCOL_TLS},
		{IPAddress: "192.0.2.1", Port: 443, Protocol: "invalid"},
	} {
		if err := ValidateProxyAddresses(
			[]ProxyAddress{address}, nil); err == nil {

			t.Fatal("unexpected success")
		}
	}

	encodeEntry := func(entry ProxyEntry) []byte {
		t.Helper()
		encoded, err := protocol.CBOREncoding.Marshal(
			&SignedProxyEntry{ProxyEntry: entry})
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	}

	// Test: explicit proxy ID and endpoints

	entry := ProxyEntry{
		DialAddresses:  dialAddresses,
		ProxyID:        base64.RawStdEncoding.EncodeToString(prng.Bytes(proxyIDSize)),
		ObfuscationKey: []byte{1},
		VerifyPin:      []byte{2},
	}
	decoded, err := DecodeAndValidateProxyEntry(encodeEntry(entry))
	if err != nil {
		t.Fatal(err)
	}

	// Test: a proxy ID that is not unpadded base64 is rejected

	invalidEntry := entry
	invalidEntry.ProxyID = "test-proxy"
	_, err = DecodeAndValidateProxyEntry(encodeEntry(invalidEntry))
	if err == nil {
		t.Fatal("unexpected success")
	}
	if decoded.ProxyID != entry.ProxyID ||
		len(decoded.DialAddresses) != len(dialAddresses) {

		t.Fatal("unexpected proxy entry")
	}

	// Test: non-legacy entries require an explicit proxy ID and valid endpoints

	entry.ProxyID = ""
	entry.Protocol = LIGHT_PROTOCOL_TLS
	entry.DialAddressIPv4 = "192.0.2.1:443"
	if _, err := DecodeAndValidateProxyEntry(encodeEntry(entry)); err == nil {
		t.Fatal("unexpected success")
	}

	entry.ProxyID = "test-proxy"
	entry.DialAddresses = []ProxyAddress{
		{IPAddress: "192.0.2.1", Port: 0, Protocol: LIGHT_PROTOCOL_TLS},
	}
	if _, err := DecodeAndValidateProxyEntry(encodeEntry(entry)); err == nil {
		t.Fatal("unexpected success")
	}

	// Test: legacy entries retain their derived proxy ID

	entry.ProxyID = ""
	entry.DialAddresses = nil
	decoded, err = DecodeAndValidateProxyEntry(encodeEntry(entry))
	if err != nil {
		t.Fatal(err)
	}
	if decoded.ProxyID != makeLegacyProxyID(
		entry.DialAddressIPv4, hex.EncodeToString(entry.ObfuscationKey)) ||
		len(decoded.DialAddresses) != 1 ||
		decoded.DialAddresses[0] != dialAddresses[0] {

		t.Fatal("unexpected legacy proxy entry")
	}

	// Test: one generated fallback entry supports legacy TLS and non-legacy TLS/QUIC.

	config, encoded, err := Generate(
		"",
		nil,
		dialAddresses,
		"example.org",
		"",
		0.0,
		"",
		0.0,
		0.0,
		0.0,
		0,
		0,
		0,
		nil,
		nil,
		nil,
		nil,
		"example.org:443",
		"",
		"")
	if err != nil {
		t.Fatal(err)
	}
	decoded, err = DecodeAndValidateProxyEntry(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded.DialAddresses) != len(dialAddresses) ||
		decoded.DialAddresses[0] != dialAddresses[0] ||
		decoded.DialAddresses[1] != dialAddresses[1] {

		t.Fatal("generated entry lost endpoints")
	}

	var legacy struct {
		ProxyEntry struct {
			Protocol         string `cbor:"1,keyasint"`
			DialAddressIPv4  string `cbor:"2,keyasint"`
			ObfuscationKey   []byte `cbor:"4,keyasint"`
			VerifyPin        []byte `cbor:"5,keyasint"`
			VerifyServerName string `cbor:"6,keyasint"`
			DialAddressIPv6  string `cbor:"7,keyasint"`
		} `cbor:"2,keyasint"`
	}
	if err := cbor.Unmarshal(encoded, &legacy); err != nil {
		t.Fatal(err)
	}
	legacyProxyID := makeLegacyProxyID(
		legacy.ProxyEntry.DialAddressIPv4,
		hex.EncodeToString(legacy.ProxyEntry.ObfuscationKey))
	if legacy.ProxyEntry.Protocol != LIGHT_PROTOCOL_TLS ||
		legacy.ProxyEntry.DialAddressIPv4 != dialAddresses[0].String() ||
		legacy.ProxyEntry.DialAddressIPv6 != "" ||
		legacy.ProxyEntry.VerifyServerName == "" ||
		!bytes.Equal(legacy.ProxyEntry.VerifyPin, decoded.VerifyPin) ||
		legacyProxyID != config.ProxyID ||
		decoded.ProxyID != config.ProxyID {

		t.Fatal("incompatible legacy proxy entry")
	}
}

func TestLightClientDialValidation(t *testing.T) {

	// Authorization contents are verified by the proxy.
	tlsParameters := TunnelDialParameters{
		TunnelDialAuthorization: []byte{1},
		EgressProtocol:          TransportTLS,
		EgressTLSProfile:        protocol.TLS_PROFILE_CHROME_133,
	}
	missingAuthorization := tlsParameters
	missingAuthorization.TunnelDialAuthorization = nil

	mixedTLSParameters := tlsParameters
	mixedTLSParameters.EgressQUICVersion = protocol.QUIC_VERSION_V1

	mixedQUICParameters := mixedTLSParameters
	mixedQUICParameters.EgressProtocol = TransportQUIC

	missingEgressSeed := tlsParameters
	missingEgressSeed.EgressProtocol = TransportQUIC
	missingEgressSeed.EgressTLSProfile = ""
	missingEgressSeed.EgressQUICVersion = protocol.QUIC_VERSION_RANDOMIZED_V1

	for _, testCase := range []struct {
		name               string
		tunnelMode         bool
		quicVersion        string
		destinationAddress string
		tunnelParameters   *TunnelDialParameters
		expectedError      string
	}{
		{
			"FallbackWithTunnelParameters", false, "", "example.org:443", &tlsParameters,
			"unexpected tunnel dial parameters",
		},
		{
			"TunnelWithoutParameters", true, "", "", nil,
			"missing tunnel dial parameters",
		},
		{
			"TunnelWithDestination", true, "", "example.org:443", &tlsParameters,
			"unexpected destination address",
		},
		{
			"MissingAuthorization", true, "", "", &missingAuthorization,
			"invalid tunnel dial authorization",
		},
		{
			"GQUICIngress", false, protocol.QUIC_VERSION_GQUIC43, "example.org:443", nil,
			"invalid ingress QUIC version",
		},
		{
			"MissingRandomizedQUICSeed", false, protocol.QUIC_VERSION_RANDOMIZED_V1, "example.org:443", nil,
			"missing ingress QUIC dial root obfuscation seed",
		},
		{
			"MissingObfuscatedQUICSeed", false, protocol.QUIC_VERSION_OBFUSCATED_V1, "example.org:443", nil,
			"missing ingress QUIC dial root obfuscation seed",
		},
		{
			"TLSEgressWithQUICParameters", true, "", "", &mixedTLSParameters,
			"unexpected egress QUIC version",
		},
		{
			"QUICEgressWithTLSParameters", true, "", "", &mixedQUICParameters,
			"unexpected egress TLS parameters",
		},
		{
			"MissingEgressQUICSeed", true, "", "", &missingEgressSeed,
			"missing egress QUIC dial root obfuscation seed",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			dialed := false
			client := &Client{
				config: &ClientConfig{
					Logger:     testutils.NewTestLogger(),
					TunnelMode: testCase.tunnelMode,
					TCPDialer: func(context.Context, string) (net.Conn, error) {
						dialed = true
						return nil, errors.TraceNew("unexpected TCP dial")
					},
					QUICDialer: func(
						context.Context, string, string, string,
						*prng.Seed, *prng.Seed,
						*transforms.ObfuscatorSeedTransformerParameters,
						bool, string, string) (net.Conn, error) {

						dialed = true
						return nil, errors.TraceNew("unexpected QUIC dial")
					},
				},
				proxyEntry: &ProxyEntry{
					DialAddresses: []ProxyAddress{
						{IPAddress: "192.0.2.1", Port: 443, Protocol: LIGHT_PROTOCOL_TLS},
						{IPAddress: "192.0.2.1", Port: 443, Protocol: LIGHT_PROTOCOL_QUIC},
					},
				},
				protocols: []string{LIGHT_PROTOCOL_TLS, LIGHT_PROTOCOL_QUIC},
			}
			ingressProtocol := LIGHT_PROTOCOL_TLS
			if testCase.quicVersion != "" {
				ingressProtocol = LIGHT_PROTOCOL_QUIC
			}
			conn, err := client.Dial(
				context.Background(),
				nil,
				0,
				"",
				ingressProtocol,
				protocol.TLS_PROFILE_CHROME_133,
				nil,
				testCase.quicVersion,
				nil,
				nil,
				false,
				"",
				false,
				0,
				testCase.destinationAddress,
				testCase.tunnelParameters)
			if conn != nil {
				conn.Close()
				t.Fatal("unexpected connection")
			}
			if err == nil || !strings.Contains(err.Error(), testCase.expectedError) {
				t.Fatalf("unexpected validation error: %v", err)
			}
			if dialed {
				t.Fatal("invalid parameters reached a dialer")
			}
		})
	}
}

func TestIsLoopbackAddress(t *testing.T) {
	tests := []struct {
		address string
		want    bool
	}{
		{"127.0.0.1:8080", true},
		{"[::1]:8080", true},
		{"localhost:8080", true},
		{"LOCALHOST:8080", true},
		{"192.168.0.1:8080", false},
		{"invalid", false},
	}
	for _, test := range tests {
		if got := isLoopbackAddress(test.address); got != test.want {
			t.Errorf("isLoopbackAddress(%q) = %v, want %v", test.address, got, test.want)
		}
	}
}

func TestLightProxyPassthrough(t *testing.T) {
	if err := runTestLightProxyPassthrough(); err != nil {
		t.Fatal(err)
	}
}

func runTestLightProxyPassthrough() error {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()

	group, ctx := errgroup.WithContext(ctx)

	_, _, webCertPEM, webKeyPEM, err := generateCert()
	if err != nil {
		return errors.Trace(err)
	}
	webCert, err := tls.X509KeyPair(webCertPEM, webKeyPEM)
	if err != nil {
		return errors.Trace(err)
	}

	webListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return errors.Trace(err)
	}
	defer webListener.Close()

	group.Go(func() error {
		return runTLSEchoServer(ctx, webListener, &tls.Config{
			Certificates: []tls.Certificate{webCert},
		})
	})

	proxyListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return errors.Trace(err)
	}
	proxyAddress := proxyListener.Addr().String()
	proxyPort := proxyListener.Addr().(*net.TCPAddr).Port
	proxyListener.Close()

	dialAddresses := []ProxyAddress{
		{IPAddress: "127.0.0.1", Port: proxyPort, Protocol: LIGHT_PROTOCOL_TLS},
	}

	var proxyQUICAddress *net.UDPAddr
	if quic.Enabled() {
		packetConn, err := net.ListenUDP(
			"udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
		if err != nil {
			return errors.Trace(err)
		}
		proxyQUICAddress = packetConn.LocalAddr().(*net.UDPAddr)
		packetConn.Close()
		dialAddresses = append(dialAddresses, ProxyAddress{
			IPAddress: "127.0.0.1",
			Port:      proxyQUICAddress.Port,
			Protocol:  LIGHT_PROTOCOL_QUIC,
		})
	}

	_, _, proxyCertPEM, proxyKeyPEM, err := generateCert()
	if err != nil {
		return errors.Trace(err)
	}
	proxyCert, err := tls.X509KeyPair(proxyCertPEM, proxyKeyPEM)
	if err != nil {
		return errors.Trace(err)
	}

	receiver := newTestProxyEventReceiver(false, 0, false, "")

	// Use a short deadline and inactivity timeout value to check that
	// passthrough relays are exempt from these timeouts.
	timeout := 1 * time.Second

	obfuscationKey := prng.HexString(32)

	proxy, err := NewProxy(
		&ProxyConfig{
			ProxyID:              prng.HexString(proxyIDSize),
			DialAddresses:        dialAddresses,
			ObfuscationKey:       obfuscationKey,
			TLSCertificate:       proxyCertPEM,
			TLSPrivateKey:        proxyKeyPEM,
			PassthroughAddress:   webListener.Addr().String(),
			AllowBogons:          true,
			PreHeaderDeadlineMin: timeout.String(),
			PreHeaderDeadlineMax: timeout.String(),
			InactivityTimeout:    timeout.String(),
		},
		func(string) common.GeoIPData { return common.GeoIPData{} },
		receiver)
	if err != nil {
		return errors.Trace(err)
	}

	group.Go(func() error {
		return proxy.Run(ctx)
	})

	select {
	case <-receiver.listening:
	case <-ctx.Done():
		return errors.Trace(ctx.Err())
	}

	conn, err := tls.Dial("tcp", proxyAddress, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return errors.Trace(err)
	}

	if !bytes.Equal(
		conn.ConnectionState().PeerCertificates[0].Raw,
		webCert.Certificate[0]) {

		conn.Close()
		return errors.TraceNew("did not receive passthrough certificate")
	}

	// Check that the passthrough relay is not subject to the proxy's
	// inactivity timeout: perform an echo round trip, whose client bytes
	// would re-arm an active inactivity deadline; hold the connection idle
	// for longer than the timeout; then perform another round trip.

	echo := func(message string) error {
		request := []byte(message)
		_, err := conn.Write(request)
		if err != nil {
			return errors.Trace(err)
		}
		response := make([]byte, len(request))
		_, err = io.ReadFull(conn, response)
		if err != nil {
			return errors.Trace(err)
		}
		if !bytes.Equal(request, response) {
			return errors.TraceNew("unexpected echo response")
		}
		return nil
	}

	err = echo("passthrough echo 1")
	if err != nil {
		conn.Close()
		return errors.Trace(err)
	}

	time.Sleep(2 * timeout)

	err = echo("passthrough echo 2")
	if err != nil {
		conn.Close()
		return errors.Trace(err)
	}

	conn.Close()

	if quic.Enabled() {

		// Check that a ClientHello random accepted on one ingress protocol
		// is not accepted again on the other. The dials set only the
		// random, as a peer without the obfuscation key could.

		dialTLSGetsProxyCert := func(random []byte) (bool, error) {
			conn, err := tls.Dial("tcp", proxyAddress, &tls.Config{
				InsecureSkipVerify: true,
				GetClientHelloRandom: func() ([]byte, error) {
					return random, nil
				},
			})
			if err != nil {
				return false, errors.Trace(err)
			}
			defer conn.Close()
			return bytes.Equal(
				conn.ConnectionState().PeerCertificates[0].Raw,
				proxyCert.Certificate[0]), nil
		}

		dialQUIC := func(random []byte) error {
			packetConn, err := net.ListenUDP(
				"udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
			if err != nil {
				return errors.Trace(err)
			}
			defer packetConn.Close()
			dialCtx, dialCancel := context.WithTimeout(ctx, 2*timeout)
			defer dialCancel()
			conn, err := ietf_quic.Dial(
				dialCtx,
				packetConn,
				proxyQUICAddress,
				&tls.Config{
					InsecureSkipVerify: true,
					NextProtos:         []string{"h3"},
					ServerName:         "www.example.org",
				},
				&ietf_quic.Config{
					Versions: []ietf_quic.Version{ietf_quic.Version1},
					GetClientHelloRandom: func() ([]byte, error) {
						return random, nil
					},
				})
			if err != nil {
				return errors.Trace(err)
			}
			_ = conn.CloseWithError(0, "")
			return nil
		}

		random, err := obfuscator.MakeTLSPassthroughMessage(
			true, obfuscationKey)
		if err != nil {
			return errors.Trace(err)
		}
		ok, err := dialTLSGetsProxyCert(random)
		if err != nil {
			return errors.Trace(err)
		}
		if !ok {
			return errors.TraceNew("did not receive proxy certificate")
		}
		err = dialQUIC(random)
		if err == nil {
			return errors.TraceNew("unexpected QUIC replay success")
		}

		random, err = obfuscator.MakeTLSPassthroughMessage(
			true, obfuscationKey)
		if err != nil {
			return errors.Trace(err)
		}
		err = dialQUIC(random)
		if err != nil {
			return errors.Trace(err)
		}
		ok, err = dialTLSGetsProxyCert(random)
		if err != nil {
			return errors.Trace(err)
		}
		if ok {
			return errors.TraceNew("unexpected TLS replay success")
		}
	}

	cancel()
	return errors.Trace(group.Wait())
}

func runLightClient(
	ctx context.Context,
	client *Client,
	networkType string,
	ingressProtocol string,
	tlsProfile string,
	quicVersion string,
	quicDialRootObfuscationSeed *prng.Seed,
	tlsFragmentClientHello bool,
	tlsPadding int,
	destinationAddress string,
	payloadSize int,
	updateLimits func() error,
	tunnelDialParameters *TunnelDialParameters,
	modifyHeader func(*lightHeader)) error {

	conn, err := client.Dial(
		ctx,
		nil,
		0,
		networkType,
		ingressProtocol,
		tlsProfile,
		nil,
		quicVersion,
		quicDialRootObfuscationSeed,
		nil,
		false,
		client.GetRecommendedSNI(),
		tlsFragmentClientHello,
		tlsPadding,
		destinationAddress,
		tunnelDialParameters)
	if err != nil {
		return errors.Trace(err)
	}
	defer conn.Close()

	interruptOnDone := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer interruptOnDone()

	// Bypass client validation to exercise proxy header validation.
	if modifyHeader != nil {
		modifyHeader(conn.header)
	}

	innerTLSConn := tls.Client(conn, &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true,
	})

	err = innerTLSConn.Handshake()
	if err != nil {
		return errors.Trace(err)
	}

	payload := prng.Bytes(payloadSize)

	var readWriteGroup errgroup.Group
	echoed := make([]byte, len(payload))
	readWriteGroup.Go(func() error {
		_, err := innerTLSConn.Write(payload)
		return errors.Trace(err)
	})

	readWriteGroup.Go(func() error {
		half := len(echoed) / 2
		_, err := io.ReadFull(innerTLSConn, echoed[:half])
		if err != nil {
			return errors.Trace(err)
		}

		// Invoke dynamic rate limit change while bulk relaying
		err = updateLimits()
		if err != nil {
			return errors.Trace(err)
		}

		_, err = io.ReadFull(innerTLSConn, echoed[half:])
		return errors.Trace(err)
	})

	err = readWriteGroup.Wait()
	if ctx.Err() != nil {
		return errors.Trace(ctx.Err())
	}
	if err != nil {
		return errors.Trace(err)
	}

	if !bytes.Equal(payload, echoed) {
		return errors.TraceNew("echo payload mismatch")
	}

	err = innerTLSConn.Close()
	if err != nil {
		return errors.Trace(err)
	}

	if ingressProtocol == LIGHT_PROTOCOL_TLS {
		paddingCheckerConn := conn.activityConn.Conn.(*paddingCheckerConn)
		err = paddingCheckerConn.checkResults()
		if err != nil {
			return errors.Trace(err)
		}
	}

	// TODO: add QUIC-specific Light padding traffic shape validation.

	return nil
}

func dialTLS(
	params *parameters.Parameters,
	ctx context.Context,
	underlyingConn net.Conn,
	tlsProfile string,
	randomizedTLSProfileSeed *prng.Seed,
	sni string,
	fragmentClientHello bool,
	tlsPadding int,
	passthroughMessage []byte,
	verifyPin string) (net.Conn, error) {

	tlsConfig := &tlsdialer.Config{
		Parameters: params,
		Dial: func(context.Context, string, string) (net.Conn, error) {
			return underlyingConn, nil
		},
		SNIServerName:            sni,
		VerifyPins:               []string{verifyPin},
		VerifyPinsOnly:           true,
		TLSProfile:               tlsProfile,
		RandomizedTLSProfileSeed: randomizedTLSProfileSeed,
		FragmentClientHello:      fragmentClientHello,
		TLSPadding:               tlsPadding,
		PassthroughMessage:       passthroughMessage,
	}

	conn, err := tlsdialer.Dial(
		ctx,
		"tcp",
		underlyingConn.RemoteAddr().String(),
		tlsConfig)
	if err != nil {
		return nil, errors.Trace(err)
	}

	// Now that the outer TLS handshake is complete, start checking padding
	// target range of the inner TLS handshake.
	underlyingConn.(*common.ActivityMonitoredConn).
		Conn.(*paddingCheckerConn).startChecking()

	return conn, nil
}

func runTLSTunnelEchoServer(
	ctx context.Context,
	listener net.Listener,
	config *tls.Config,
	verifyReport func(*TunnelProxyReport, inproxy.ID) error) error {

	return runTunnelEchoServer(
		ctx,
		tls.NewListener(listener, config),
		config,
		func(ctx context.Context, conn net.Conn) ([]byte, error) {
			tlsConn := conn.(*tls.Conn)
			err := tlsConn.HandshakeContext(ctx)
			if err != nil {
				return nil, errors.Trace(err)
			}

			state := tlsConn.ConnectionState()
			exporter, err := state.ExportKeyingMaterial(
				TunnelProxyReportExporterLabel,
				nil,
				TunnelProxyReportExporterSize)
			if err != nil {
				return nil, errors.Trace(err)
			}
			return exporter, nil
		},
		verifyReport)
}

func runQUICTunnelEchoServer(
	ctx context.Context,
	listener net.Listener,
	config *tls.Config,
	verifyReport func(*TunnelProxyReport, inproxy.ID) error) error {

	return runTunnelEchoServer(
		ctx,
		listener,
		config,
		func(_ context.Context, conn net.Conn) ([]byte, error) {
			quicConn, ok := conn.(*quic.Conn)
			if !ok {
				return nil, errors.TraceNew("invalid QUIC connection")
			}
			exporter, err := quicConn.ExportKeyingMaterial(
				TunnelProxyReportExporterLabel,
				nil,
				TunnelProxyReportExporterSize)
			if err != nil {
				return nil, errors.Trace(err)
			}
			return exporter, nil
		},
		verifyReport)
}

func runTunnelEchoServer(
	ctx context.Context,
	listener net.Listener,
	config *tls.Config,
	exportKeyingMaterial func(context.Context, net.Conn) ([]byte, error),
	verifyReport func(*TunnelProxyReport, inproxy.ID) error) error {

	mainGroup, ctx := errgroup.WithContext(ctx)

	mainGroup.Go(func() error {
		<-ctx.Done()
		return listener.Close()
	})

	mainGroup.Go(func() error {
		var connGroup errgroup.Group

		for {
			conn, err := listener.Accept()
			if err != nil {
				if ctx.Err() != nil {
					return connGroup.Wait()
				}
				return errors.Trace(err)
			}

			connGroup.Go(func() error {
				defer conn.Close()

				exporter, err := exportKeyingMaterial(ctx, conn)
				if err != nil {
					return errors.Trace(err)
				}

				report, proxyID, err :=
					ReadAndVerifyTunnelProxyReport(
						conn, exporter)
				if err != nil {
					return errors.Trace(err)
				}
				err = verifyReport(report, proxyID)
				if err != nil {
					return errors.Trace(err)
				}

				innerTLSConn := tls.Server(
					NewLightFramingConn(conn), config)
				err = innerTLSConn.HandshakeContext(ctx)
				if err != nil {
					return errors.Trace(err)
				}

				// The client's final small write may be a padded frame, and
				// a QUIC close discards data not yet read, so the connection
				// can end partway through that frame.
				_, err = io.Copy(innerTLSConn, innerTLSConn)
				if err != nil &&
					!std_errors.Is(err, io.EOF) &&
					!std_errors.Is(err, io.ErrUnexpectedEOF) &&
					ctx.Err() == nil {

					return errors.Trace(err)
				}
				return nil
			})
		}
	})

	return errors.Trace(mainGroup.Wait())
}

func runTLSEchoServer(
	ctx context.Context,
	listener net.Listener,
	config *tls.Config) error {

	listener = tls.NewListener(listener, config)

	mainGroup, ctx := errgroup.WithContext(ctx)

	mainGroup.Go(func() error {
		<-ctx.Done()
		return listener.Close()
	})

	mainGroup.Go(func() error {
		var connGroup errgroup.Group

		for {
			conn, err := listener.Accept()
			if err != nil {
				if ctx.Err() != nil {
					return connGroup.Wait()
				}
				return errors.Trace(err)
			}

			connGroup.Go(func() error {
				defer conn.Close()
				_, err = io.Copy(conn, conn)
				if err != nil && err != io.EOF {
					return errors.Trace(err)
				}
				return nil
			})
		}
	})

	return errors.Trace(mainGroup.Wait())
}

type writeRecorderConn struct {
	net.Conn
	buffer     bytes.Buffer
	writeSizes []int
}

func (conn *writeRecorderConn) Write(b []byte) (int, error) {
	conn.writeSizes = append(conn.writeSizes, len(b))
	return conn.buffer.Write(b)
}

func (conn *writeRecorderConn) Read(b []byte) (int, error) {
	return conn.buffer.Read(b)
}

func TestLightConnMinPaddedWrites(t *testing.T) {

	// A large write within the first minPaddedWrites writes, such as an SSH
	// KEX reply, must not stop padding of the small writes that follow.

	recorder := &writeRecorderConn{}
	writer := newLightConn(recorder, nil)
	reader := newLightConn(recorder, nil)

	large := prng.Bytes(stopPaddingWriteSizeThreshold + 1)
	small := prng.Bytes(50)
	var written []byte

	write := func(b []byte) int {
		n, err := writer.Write(b)
		if err != nil || n != len(b) {
			t.Fatalf("Write failed: %d %v", n, err)
		}
		written = append(written, b...)
		return recorder.writeSizes[len(recorder.writeSizes)-1]
	}

	// 17 is the TLS record overhead assumed by lightConn.Write.
	minPaddedSize := paddingMinTargetSize - 17

	if n := write(large); n != len(large)+4 {
		t.Fatalf("unexpected first write size: %d", n)
	}
	for i := 1; i < writer.minPaddedWrites; i++ {
		if n := write(small); n < minPaddedSize {
			t.Fatalf("unexpected padded write %d size: %d", i, n)
		}
	}

	// After minPaddedWrites, a large write stops padding.

	if n := write(large); n != len(large)+2 {
		t.Fatalf("unexpected stop padding write size: %d", n)
	}
	if n := write(small); n != len(small) {
		t.Fatalf("unexpected unpadded write size: %d", n)
	}

	read := make([]byte, len(written))
	_, err := io.ReadFull(reader, read)
	if err != nil {
		t.Fatalf("ReadFull failed: %v", err)
	}
	if !bytes.Equal(read, written) {
		t.Fatalf("unexpected payload")
	}

	// A conn from NewLightFramingConn stops padding after maxPaddedWrites
	// small writes.

	recorder = &writeRecorderConn{}
	writer = NewLightFramingConn(recorder).(*lightConn)
	if writer.maxPaddedWrites < maxPaddedWritesMin ||
		writer.maxPaddedWrites > maxPaddedWritesMax {
		t.Fatalf("unexpected maxPaddedWrites: %d", writer.maxPaddedWrites)
	}
	for i := 0; i < writer.maxPaddedWrites; i++ {
		if n := write(small); n < minPaddedSize {
			t.Fatalf("unexpected padded write %d size: %d", i, n)
		}
	}
	if n := write(small); n != len(small)+2 {
		t.Fatalf("unexpected stop padding write size: %d", n)
	}
	if n := write(small); n != len(small) {
		t.Fatalf("unexpected unpadded write size: %d", n)
	}
}

type paddingCheckerConn struct {
	net.Conn

	mutex        sync.Mutex
	enabled      bool
	readChecked  bool
	readBuffer   []byte
	readErr      error
	writeChecked bool
	writeBuffer  []byte
	writeErr     error
}

func newPaddingCheckerConn(conn net.Conn) *paddingCheckerConn {

	return &paddingCheckerConn{
		Conn: conn,
	}
}

func (conn *paddingCheckerConn) Read(b []byte) (int, error) {
	n, err := conn.Conn.Read(b)
	if n > 0 {
		conn.checkTLSRecordLength(false, b[:n])
	}
	return n, err
}

func (conn *paddingCheckerConn) Write(b []byte) (int, error) {
	n, err := conn.Conn.Write(b)
	if n > 0 {
		conn.checkTLSRecordLength(true, b[:n])
	}
	return n, err
}

func (conn *paddingCheckerConn) checkResults() error {
	conn.mutex.Lock()
	defer conn.mutex.Unlock()

	if !conn.readChecked || !conn.writeChecked {
		return errors.TraceNew("checks incomplete")
	}
	if conn.readErr != nil {
		return conn.readErr
	}
	return conn.writeErr
}

func (conn *paddingCheckerConn) startChecking() {
	conn.mutex.Lock()
	defer conn.mutex.Unlock()

	conn.enabled = true
}

func (conn *paddingCheckerConn) checkTLSRecordLength(isWrite bool, b []byte) {
	conn.mutex.Lock()
	defer conn.mutex.Unlock()

	if !conn.enabled {
		return
	}

	buffer := &conn.readBuffer
	checked := &conn.readChecked
	checkErr := &conn.readErr
	if isWrite {
		buffer = &conn.writeBuffer
		checked = &conn.writeChecked
		checkErr = &conn.writeErr
	}

	// Limitation: only checks the first read (proxy padding) and first write
	// (client padding).
	if *checked {
		return
	}

	// Buffer in case the net.Conn read/write isn't the full TLS record.
	*buffer = append(*buffer, b...)
	if len(*buffer) < 5 {
		return
	}

	recordSize := int(binary.BigEndian.Uint16((*buffer)[3:5]))
	if len(*buffer) < 5+recordSize {
		return
	}

	// If the initial inner payload already exceeds the padding target,
	// lightConn adds no padding, and the TLS record may exceed
	// paddingMaxTargetSize.
	if recordSize < paddingMinTargetSize {
		*checkErr = errors.Tracef(
			"TLS record size %d below padding target minimum %d",
			recordSize,
			paddingMinTargetSize)
	}

	*checked = true
	*buffer = nil
}

type testProxyEventReceiver struct {
	listening                        chan struct{}
	listeningAddresses               []string
	mutex                            sync.Mutex
	statsErr                         error
	activityBytesUp                  int64
	activityBytesDown                int64
	lastActivityConnectionCount      int64
	successfulConnectionStats        int
	expectedTLSClientHelloFragmented bool
	expectedTLSClientHelloPadding    int
	expectedProxyProtocolHeaderAdded bool
	expectedActivityRegion           string
	expectedDeviceRegion             string
	activityRegionSeen               chan struct{}
	activityRegionSeenOnce           sync.Once
	connectionStats                  chan *ConnectionStats
}

func newTestProxyEventReceiver(
	expectedTLSClientHelloFragmented bool,
	expectedTLSClientHelloPadding int,
	expectedProxyProtocolHeaderAdded bool,
	expectedActivityRegion string) *testProxyEventReceiver {

	return &testProxyEventReceiver{
		listening:                        make(chan struct{}),
		expectedTLSClientHelloFragmented: expectedTLSClientHelloFragmented,
		expectedTLSClientHelloPadding:    expectedTLSClientHelloPadding,
		expectedProxyProtocolHeaderAdded: expectedProxyProtocolHeaderAdded,
		expectedActivityRegion:           expectedActivityRegion,
		activityRegionSeen:               make(chan struct{}),
	}
}

func (r *testProxyEventReceiver) Listening(address, ingressProtocol string) {
	r.listeningAddresses = append(r.listeningAddresses, address)
	fmt.Printf("[Listening] %s %s\n", address, ingressProtocol)
}

func (r *testProxyEventReceiver) Started() {
	fmt.Printf("[Started]\n")
	close(r.listening)
}

func (r *testProxyEventReceiver) Paused() {
	fmt.Printf("[Paused]\n")
}

func (r *testProxyEventReceiver) Resumed() {
	fmt.Printf("[Resumed]\n")
}

func (r *testProxyEventReceiver) Accepted() {
	fmt.Printf("[Accepted]\n")
}

func (r *testProxyEventReceiver) Rejected() {
	fmt.Printf("[Rejected]\n")
}

func (r *testProxyEventReceiver) Activity(stats *ActivityStats) {
	r.mutex.Lock()
	r.activityBytesUp += stats.BytesUp
	r.activityBytesDown += stats.BytesDown
	r.lastActivityConnectionCount = stats.CurrentConnectionCount
	r.mutex.Unlock()

	if r.expectedActivityRegion != "" {
		for _, activity := range []map[string]RegionActivitySnapshot{
			stats.PersonalRegionActivity, stats.CommonRegionActivity,
		} {
			regionStats, ok := activity[r.expectedActivityRegion]
			if ok && (regionStats.BytesUp > 0 || regionStats.BytesDown > 0 ||
				regionStats.ConnectingClients > 0 || regionStats.ConnectedClients > 0) {
				r.activityRegionSeenOnce.Do(func() {
					close(r.activityRegionSeen)
				})
			}
		}
	}

	const activityFormat = `[Activity] proxyID: %s, providerID: %s, ` +
		`bytesUp: %d, bytesDown: %d, bytesDuration: %s, ` +
		`currentConnectionCount: %d` + "\n"

	fmt.Printf(
		activityFormat,
		stats.ProxyID,
		stats.ProxyProviderID,
		stats.BytesUp,
		stats.BytesDown,
		stats.BytesDuration,
		stats.CurrentConnectionCount)
}

func (r *testProxyEventReceiver) awaitActivityRegion(ctx context.Context) error {
	if r.expectedActivityRegion == "" {
		return nil
	}

	select {
	case <-r.activityRegionSeen:
		return nil
	case <-ctx.Done():
		return errors.Tracef(
			"missing activity for region %s: %v",
			r.expectedActivityRegion,
			ctx.Err())
	}
}

func (r *testProxyEventReceiver) Connection(stats *ConnectionStats) {
	r.checkConnectionStats(stats)

	const connectionFormat = `[Connection] proxyID: %s, ` +
		`proxyConnectionNum: %d, sponsorID: %s, platform: %s, ` +
		`buildRev: %s, deviceRegion: %s, sessionID: %s, ` +
		`tracker: %d, networkType: %s, clientConnectionNum: %d, ` +
		`destination: %s, tlsProfile: %s, sni: %s, ` +
		`tlsClientHelloFragmented: %t, tlsClientHelloPadding: %d, ` +
		`tlsDidResume: %t, ` +
		`clientTCPDuration: %s, clientTLSDuration: %s, ` +
		`completedTCP: %s, completedTLS: %s, completedLightHeader: %s, ` +
		`completedUpstreamDNS: %s, completedUpstreamTCP: %s, ` +
		`completedUpstreamTLS: %s, completedUpstreamQUIC: %s, upstreamDNSCached: %v, ` +
		`proxyProtocolHeaderAdded: %t, proxyProtocolHeaderReplaced: %t, ` +
		`bytesRead: %d, bytesWritten: %d, ` +
		`failure: %s` + "\n"

	fmt.Printf(
		connectionFormat,
		stats.ProxyID,
		stats.ProxyConnectionNum,
		stats.SponsorID,
		stats.ClientPlatform,
		stats.ClientBuildRev,
		stats.DeviceRegion,
		stats.SessionID,
		stats.ProxyEntryTracker,
		stats.NetworkType,
		stats.ClientConnectionNum,
		stats.DestinationAddress,
		stats.TLSProfile,
		stats.SNI,
		stats.TLSClientHelloFragmented,
		stats.TLSClientHelloPadding,
		stats.TLSDidResume,
		stats.ClientTCPDuration,
		stats.ClientTLSDuration,
		stats.ProxyCompletedTCP.Format(time.RFC3339Nano),
		stats.ProxyCompletedTLS.Format(time.RFC3339Nano),
		stats.ProxyCompletedLightHeader.Format(time.RFC3339Nano),
		stats.ProxyCompletedUpstreamDNS.Format(time.RFC3339Nano),
		stats.ProxyCompletedUpstreamTCP.Format(time.RFC3339Nano),
		stats.ProxyCompletedUpstreamTLS.Format(time.RFC3339Nano),
		stats.ProxyCompletedUpstreamQUIC.Format(time.RFC3339Nano),
		stats.UpstreamDNSCached,
		stats.ProxyProtocolHeaderAdded,
		stats.ProxyProtocolHeaderReplaced,
		stats.BytesRead,
		stats.BytesWritten,
		stats.Failure)

	if r.connectionStats != nil {
		r.connectionStats <- stats
	}
}

func (r *testProxyEventReceiver) checkConnectionStats(stats *ConnectionStats) {
	if stats.Failure != "" {
		return
	}

	r.mutex.Lock()
	defer r.mutex.Unlock()

	r.successfulConnectionStats++

	if r.statsErr != nil {
		return
	}

	if stats.ProxyCompletedUpstreamTCP.IsZero() == stats.ProxyCompletedUpstreamQUIC.IsZero() {
		r.statsErr = errors.TraceNew("expected exactly one upstream TCP or QUIC completion time")
		return
	}

	if r.expectedDeviceRegion != "" && stats.DeviceRegion != r.expectedDeviceRegion {
		r.statsErr = errors.TraceNew("unexpected DeviceRegion")
		return
	}

	if stats.TLSClientHelloFragmented != r.expectedTLSClientHelloFragmented {
		r.statsErr = errors.TraceNew("unexpected TLSClientHelloFragmented")
		return
	}

	if stats.TLSClientHelloPadding != r.expectedTLSClientHelloPadding {
		r.statsErr = errors.TraceNew("unexpected TLSClientHelloPadding")
		return
	}

	if stats.ProxyProtocolHeaderAdded != r.expectedProxyProtocolHeaderAdded {
		r.statsErr = errors.TraceNew("unexpected ProxyProtocolHeaderAdded")
		return
	}

	if stats.ProxyProtocolHeaderReplaced {
		r.statsErr = errors.TraceNew("unexpected ProxyProtocolHeaderReplaced")
	}
}

func (r *testProxyEventReceiver) checkResults() error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if r.statsErr != nil {
		return r.statsErr
	}

	if r.successfulConnectionStats == 0 {
		return errors.TraceNew("missing successful connection stats")
	}

	return nil
}

func (r *testProxyEventReceiver) IrregularConnection(_ string, _ common.GeoIPData, irregularity string) {
	fmt.Printf("[IrregularConnection] %s\n", irregularity)
}

func (r *testProxyEventReceiver) DebugLog(_ string, message string) {
}

func (r *testProxyEventReceiver) InfoLog(_ string, message string) {
	fmt.Printf("[InfoLog] %s\n", message)
}

func (r *testProxyEventReceiver) WarningLog(_ string, message string) {
	fmt.Printf("[WarningLog] %s\n", message)
}

func (r *testProxyEventReceiver) ErrorLog(_ string, message string) {
	fmt.Printf("[ErrorLog] %s\n", message)
}

func TestEncodeTLSProfile(t *testing.T) {

	if encodeTLSProfile("unknown-tls-profile") != 0 {
		t.Error("unexpected unknown TLS profile encoding")
	}

	for _, tlsProfile := range protocol.SupportedTLSProfiles {

		encoded := encodeTLSProfile(tlsProfile)

		if encoded == 0 {
			t.Error("unexpected supported TLS profile encoding")
		}

		if decodeTLSProfile(encoded) != tlsProfile {
			t.Error("unexpected supported TLS profile decoding")
		}
	}
}

func TestEncodeQUICVersion(t *testing.T) {

	if encodeQUICVersion("unknown-QUIC-version") != 0 {
		t.Error("unexpected unknown QUIC version encoding")
	}

	for _, QUICVersion := range protocol.SupportedQUICv1Versions {

		encoded := encodeQUICVersion(QUICVersion)

		if encoded == 0 {
			t.Error("unexpected supported QUIC version encoding")
		}

		if decodeQUICVersion(encoded) != QUICVersion {
			t.Error("unexpected supported QUIC version decoding")
		}
	}
}

func TestTunnelQUICDerivation(t *testing.T) {

	rootSecret := prng.Bytes(TunnelRootObfuscationSecretSize)
	tlsKey, err := DeriveTunnelTLSPassthroughKey(rootSecret)
	if err != nil {
		t.Fatal(err)
	}
	quicKey, err := DeriveTunnelQUICObfuscationKey(rootSecret)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(tlsKey, quicKey) {
		t.Fatal("expected distinct transport keys")
	}

	rootSeed, err := prng.NewSeed()
	if err != nil {
		t.Fatal(err)
	}
	for _, quicVersion := range protocol.SupportedQUICv1Versions {
		t.Run(quicVersion, func(t *testing.T) {
			clientHelloSeed, paddingSeed, err :=
				deriveQUICDialSeeds(rootSeed, quicVersion)
			if err != nil {
				t.Fatal(err)
			}
			if (clientHelloSeed != nil) != protocol.QUICVersionHasRandomizedClientHello(quicVersion) ||
				(paddingSeed != nil) != protocol.QUICVersionIsObfuscated(quicVersion) {

				t.Fatal("unexpected QUIC version seeds")
			}

			replayedClientHelloSeed, replayedPaddingSeed, err :=
				deriveQUICDialSeeds(rootSeed, quicVersion)
			if err != nil {
				t.Fatal(err)
			}
			if (clientHelloSeed != nil && *clientHelloSeed != *replayedClientHelloSeed) ||
				(paddingSeed != nil && *paddingSeed != *replayedPaddingSeed) {

				t.Fatal("unexpected replayed QUIC seeds")
			}

			ipv4ClientHelloSeed, ipv4PaddingSeed, err :=
				deriveQUICDialIPAddressFamilySeeds(rootSeed, quicVersion, false)
			if err != nil {
				t.Fatal(err)
			}
			ipv6ClientHelloSeed, ipv6PaddingSeed, err :=
				deriveQUICDialIPAddressFamilySeeds(rootSeed, quicVersion, true)
			if err != nil {
				t.Fatal(err)
			}
			if (clientHelloSeed != nil && *ipv4ClientHelloSeed == *ipv6ClientHelloSeed) ||
				(paddingSeed != nil && *ipv4PaddingSeed == *ipv6PaddingSeed) {

				t.Fatal("expected distinct address-family QUIC dial seeds")
			}
		})
	}
}

func TestLightActivityByteCountAssignment(t *testing.T) {
	for _, isPersonal := range []bool{false, true} {
		for _, region := range []string{"CA", ""} {
			t.Run(fmt.Sprintf("Personal=%t/Region=%s", isPersonal, region), func(t *testing.T) {
				proxy := &Proxy{
					personalRegionActivity: make(map[string]*regionActivity),
					commonRegionActivity:   make(map[string]*regionActivity),
				}
				activity := proxy.getOrCreateRegionActivity(region, isPersonal)
				counter := new(bytesCounter)
				counter.UpdateProgress(7, 11, 0)
				counter.assignByteCountsToActivity(activity)
				var workers sync.WaitGroup
				for i := 0; i < 4; i++ {
					workers.Add(1)
					go func() {
						defer workers.Done()
						for j := 0; j < 1000; j++ {
							counter.UpdateProgress(1, 2, 0)
						}
					}()
				}
				workers.Wait()

				mutex, statsMap, other := &proxy.commonStatsMutex,
					proxy.commonRegionActivity, proxy.personalRegionActivity
				if isPersonal {
					mutex, statsMap, other = &proxy.personalStatsMutex,
						proxy.personalRegionActivity, proxy.commonRegionActivity
				}
				wantRegion := region
				if wantRegion == "" {
					wantRegion = "None"
				}
				got := proxy.snapshotAndResetRegionActivity(mutex, statsMap)
				want := RegionActivitySnapshot{
					BytesUp: 4007, BytesDown: 8011, ConnectingClients: 1,
				}
				if len(got) != 1 || got[wantRegion] != want || len(other) != 0 {
					t.Fatalf("incorrect byte assignment: got %v, other %v", got, other)
				}

				activity.connectedClients.Add(1)
				activity.connectingClients.Add(-1)
				got = proxy.snapshotAndResetRegionActivity(mutex, statsMap)
				if got[wantRegion] != (RegionActivitySnapshot{ConnectedClients: 1}) {
					t.Fatalf("active bucket lost or interval bytes not reset: %v", got)
				}
				counter.UpdateProgress(3, 5, 0)
				activity.connectedClients.Add(-1)
				got = proxy.snapshotAndResetRegionActivity(mutex, statsMap)
				if got[wantRegion] != (RegionActivitySnapshot{BytesUp: 3, BytesDown: 5}) {
					t.Fatalf("final bytes were lost after disconnect: %v", got)
				}
				got = proxy.snapshotAndResetRegionActivity(mutex, statsMap)
				if len(got) != 0 || len(statsMap) != 0 {
					t.Fatal("idle region bucket was not pruned")
				}
			})
		}
	}
}
