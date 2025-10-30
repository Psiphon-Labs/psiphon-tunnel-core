//go:build PSIPHON_ENABLE_INPROXY

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
	"bytes"
	"context"
	std_tls "crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	_ "net/http/pprof"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	tls "github.com/Psiphon-Labs/psiphon-tls"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/quic"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/internal/testutils"
	"golang.org/x/sync/errgroup"
)

func TestInproxy(t *testing.T) {
	err := runTestInproxy(false)
	if err != nil {
		t.Error(errors.Trace(err).Error())
	}
}

func TestInproxyMustUpgrade(t *testing.T) {
	err := runTestInproxy(true)
	if err != nil {
		t.Error(errors.Trace(err).Error())
	}
}

func runTestInproxy(doMustUpgrade bool) error {

	// Note: use the environment variable PION_LOG_TRACE=all to emit WebRTC logging.

	numProxies := 5
	proxyMaxClients := 3
	numClients := 10

	bytesToSend := 1 << 20
	targetElapsedSeconds := 2

	baseAPIParameters := common.APIParameters{
		"sponsor_id":      strings.ToUpper(prng.HexString(8)),
		"client_platform": "test-client-platform",
	}

	testCompartmentID, _ := MakeID()
	testCommonCompartmentIDs := []ID{testCompartmentID}

	testNetworkID := "NETWORK-ID-1"
	testNetworkType := NetworkTypeUnknown
	testNATType := NATTypeUnknown
	testSTUNServerAddress := "stun.voipgate.com:3478"
	testDisableSTUN := false
	testDisablePortMapping := false

	testNewTacticsPayload := []byte(prng.HexString(100))
	testNewTacticsTag := "new-tactics-tag"
	testUnchangedTacticsPayload := []byte(prng.HexString(100))

	currentNetworkCtx, currentNetworkCancelFunc := context.WithCancel(context.Background())
	defer currentNetworkCancelFunc()

	// TODO: test port mapping

	stunServerAddressSucceededCount := int32(0)
	stunServerAddressSucceeded := func(bool, string) { atomic.AddInt32(&stunServerAddressSucceededCount, 1) }
	stunServerAddressFailedCount := int32(0)
	stunServerAddressFailed := func(bool, string) { atomic.AddInt32(&stunServerAddressFailedCount, 1) }

	roundTripperSucceededCount := int32(0)
	roundTripperSucceded := func(RoundTripper) { atomic.AddInt32(&roundTripperSucceededCount, 1) }
	roundTripperFailedCount := int32(0)
	roundTripperFailed := func(RoundTripper) { atomic.AddInt32(&roundTripperFailedCount, 1) }
	noMatch := func(RoundTripper) {}

	var receivedProxyMustUpgrade chan struct{}
	var receivedClientMustUpgrade chan struct{}
	if doMustUpgrade {

		receivedProxyMustUpgrade = make(chan struct{})
		receivedClientMustUpgrade = make(chan struct{})

		// trigger MustUpgrade
		minimumProxyProtocolVersion = LatestProtocolVersion + 1
		minimumClientProtocolVersion = LatestProtocolVersion + 1

		// Minimize test parameters for MustUpgrade case
		numProxies = 1
		proxyMaxClients = 1
		numClients = 1
		testDisableSTUN = true
		testDisablePortMapping = true
	}

	testCtx, stopTest := context.WithCancel(context.Background())
	defer stopTest()

	testGroup := new(errgroup.Group)

	// Enable test to run without requiring host firewall exceptions
	SetAllowBogonWebRTCConnections(true)
	defer SetAllowBogonWebRTCConnections(false)

	// Init logging and profiling

	logger := testutils.NewTestLogger()

	pprofListener, err := net.Listen("tcp", "127.0.0.1:0")
	go http.Serve(pprofListener, nil)
	defer pprofListener.Close()
	logger.WithTrace().Info(fmt.Sprintf("PPROF: http://%s/debug/pprof", pprofListener.Addr()))

	// Start echo servers

	tcpEchoListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return errors.Trace(err)
	}
	defer tcpEchoListener.Close()
	go runTCPEchoServer(tcpEchoListener)

	// QUIC tests UDP proxying, and provides reliable delivery of echoed data
	quicEchoServer, err := newQuicEchoServer()
	if err != nil {
		return errors.Trace(err)
	}
	defer quicEchoServer.Close()
	go quicEchoServer.Run()

	// Create signed server entry with capability

	serverPrivateKey, err := GenerateSessionPrivateKey()
	if err != nil {
		return errors.Trace(err)
	}
	serverPublicKey, err := serverPrivateKey.GetPublicKey()
	if err != nil {
		return errors.Trace(err)
	}
	serverRootObfuscationSecret, err := GenerateRootObfuscationSecret()
	if err != nil {
		return errors.Trace(err)
	}

	serverEntry := make(protocol.ServerEntryFields)
	serverEntry["ipAddress"] = "127.0.0.1"
	_, tcpPort, _ := net.SplitHostPort(tcpEchoListener.Addr().String())
	_, udpPort, _ := net.SplitHostPort(quicEchoServer.Addr().String())
	serverEntry["inproxyOSSHPort"], _ = strconv.Atoi(tcpPort)
	serverEntry["inproxyQUICPort"], _ = strconv.Atoi(udpPort)
	serverEntry["capabilities"] = []string{"INPROXY-WEBRTC-OSSH", "INPROXY-WEBRTC-QUIC-OSSH"}
	serverEntry["inproxySessionPublicKey"] = base64.RawStdEncoding.EncodeToString(serverPublicKey[:])
	serverEntry["inproxySessionRootObfuscationSecret"] = base64.RawStdEncoding.EncodeToString(serverRootObfuscationSecret[:])
	testServerEntryTag := prng.HexString(16)
	serverEntry["tag"] = testServerEntryTag

	serverEntrySignaturePublicKey, serverEntrySignaturePrivateKey, err :=
		protocol.NewServerEntrySignatureKeyPair()
	if err != nil {
		return errors.Trace(err)
	}
	err = serverEntry.AddSignature(serverEntrySignaturePublicKey, serverEntrySignaturePrivateKey)
	if err != nil {
		return errors.Trace(err)
	}

	packedServerEntryFields, err := protocol.EncodePackedServerEntryFields(serverEntry)
	if err != nil {
		return errors.Trace(err)
	}
	packedDestinationServerEntry, err := protocol.CBOREncoding.Marshal(packedServerEntryFields)
	if err != nil {
		return errors.Trace(err)
	}

	// API parameter handlers

	apiParameterValidator := func(params common.APIParameters) error {
		if len(params) != len(baseAPIParameters) {
			return errors.TraceNew("unexpected base API parameter count")
		}
		for name, value := range params {
			if value.(string) != baseAPIParameters[name].(string) {
				return errors.Tracef(
					"unexpected base API parameter: %v: %v != %v",
					name,
					value.(string),
					baseAPIParameters[name].(string))
			}
		}
		return nil
	}

	apiParameterLogFieldFormatter := func(
		_ string, _ common.GeoIPData, params common.APIParameters) common.LogFields {
		logFields := common.LogFields{}
		logFields.Add(common.LogFields(params))
		return logFields
	}

	// Start broker

	logger.WithTrace().Info("START BROKER")

	brokerPrivateKey, err := GenerateSessionPrivateKey()
	if err != nil {
		return errors.Trace(err)
	}
	brokerPublicKey, err := brokerPrivateKey.GetPublicKey()
	if err != nil {
		return errors.Trace(err)
	}
	brokerRootObfuscationSecret, err := GenerateRootObfuscationSecret()
	if err != nil {
		return errors.Trace(err)
	}

	brokerListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return errors.Trace(err)
	}
	defer brokerListener.Close()

	brokerConfig := &BrokerConfig{

		Logger: logger,

		CommonCompartmentIDs: testCommonCompartmentIDs,

		APIParameterValidator: apiParameterValidator,

		APIParameterLogFieldFormatter: apiParameterLogFieldFormatter,

		GetTacticsPayload: func(_ common.GeoIPData, _ common.APIParameters) ([]byte, string, error) {
			// Exercise both new and unchanged tactics
			if prng.FlipCoin() {
				return testNewTacticsPayload, testNewTacticsTag, nil
			}
			return testUnchangedTacticsPayload, "", nil
		},

		IsValidServerEntryTag: func(serverEntryTag string) bool { return serverEntryTag == testServerEntryTag },

		PrivateKey: brokerPrivateKey,

		ObfuscationRootSecret: brokerRootObfuscationSecret,

		ServerEntrySignaturePublicKey: serverEntrySignaturePublicKey,

		AllowProxy:                     func(common.GeoIPData) bool { return true },
		AllowClient:                    func(common.GeoIPData) bool { return true },
		AllowDomainFrontedDestinations: func(common.GeoIPData) bool { return true },
		AllowMatch:                     func(common.GeoIPData, common.GeoIPData) bool { return true },
	}

	broker, err := NewBroker(brokerConfig)
	if err != nil {
		return errors.Trace(err)
	}

	// Enable proxy quality (and otherwise use the default quality parameters)

	enableProxyQuality := true
	broker.SetProxyQualityParameters(
		enableProxyQuality,
		proxyQualityTTL,
		proxyQualityPendingFailedMatchDeadline,
		proxyQualityFailedMatchThreshold)

	err = broker.Start()
	if err != nil {
		return errors.Trace(err)
	}
	defer broker.Stop()

	testGroup.Go(func() error {
		err := runHTTPServer(brokerListener, broker)
		if testCtx.Err() != nil {
			return nil
		}
		return errors.Trace(err)
	})

	// Stub server broker request handler (in Psiphon, this will be the
	// destination Psiphon server; here, it's not necessary to build this
	// handler into the destination echo server)
	//
	// The stub server broker request handler also triggers a server proxy
	// quality request in the other direction.

	makeServerBrokerClientRoundTripper := func(_ SessionPublicKey) (
		RoundTripper, common.APIParameters, error) {

		return newHTTPRoundTripper(brokerListener.Addr().String(), "server"), nil, nil
	}

	serverSessionsConfig := &ServerBrokerSessionsConfig{
		Logger:                       logger,
		ServerPrivateKey:             serverPrivateKey,
		ServerRootObfuscationSecret:  serverRootObfuscationSecret,
		BrokerPublicKeys:             []SessionPublicKey{brokerPublicKey},
		BrokerRootObfuscationSecrets: []ObfuscationSecret{brokerRootObfuscationSecret},
		BrokerRoundTripperMaker:      makeServerBrokerClientRoundTripper,
		ProxyMetricsValidator:        apiParameterValidator,
		ProxyMetricsFormatter:        apiParameterLogFieldFormatter,
		ProxyMetricsPrefix:           "",
	}

	serverSessions, err := NewServerBrokerSessions(serverSessionsConfig)
	if err != nil {
		return errors.Trace(err)
	}

	err = serverSessions.Start()
	if err != nil {
		return errors.Trace(err)
	}
	defer serverSessions.Stop()

	// Don't delay reporting quality.
	serverSessions.SetProxyQualityRequestParameters(
		proxyQualityReporterMaxRequestEntries,
		0,
		proxyQualityReporterRequestTimeout,
		proxyQualityReporterRequestRetries)

	var pendingBrokerServerReportsMutex sync.Mutex
	pendingBrokerServerReports := make(map[ID]bool)

	addPendingBrokerServerReport := func(connectionID ID) {
		pendingBrokerServerReportsMutex.Lock()
		defer pendingBrokerServerReportsMutex.Unlock()
		pendingBrokerServerReports[connectionID] = true
	}

	removePendingBrokerServerReport := func(connectionID ID) {
		pendingBrokerServerReportsMutex.Lock()
		defer pendingBrokerServerReportsMutex.Unlock()
		delete(pendingBrokerServerReports, connectionID)
	}

	hasPendingBrokerServerReports := func() bool {
		pendingBrokerServerReportsMutex.Lock()
		defer pendingBrokerServerReportsMutex.Unlock()
		return len(pendingBrokerServerReports) > 0
	}

	serverQualityGroup := new(errgroup.Group)
	var serverQualityProxyIDsMutex sync.Mutex
	serverQualityProxyIDs := make(map[ID]struct{})
	testProxyASN := "65537"
	testClientASN := "65538"

	handleBrokerServerReports := func(in []byte, clientConnectionID ID) ([]byte, error) {

		handler := func(
			brokerVerifiedOriginalClientIP string,
			brokerReportedProxyID ID,
			brokerMatchedPersonalCompartments bool,
			logFields common.LogFields) {

			// Mark the report as no longer outstanding
			removePendingBrokerServerReport(clientConnectionID)

			// Trigger an asynchronous proxy quality request to the broker.
			// This roughly follows the Psiphon server functionality, where a
			// quality request is made sometime after the Psiphon handshake
			// completes, once tunnel quality thresholds are achieved.

			serverQualityGroup.Go(func() error {
				serverSessions.ReportQuality(
					brokerReportedProxyID, testProxyASN, testClientASN)

				serverQualityProxyIDsMutex.Lock()
				serverQualityProxyIDs[brokerReportedProxyID] = struct{}{}
				serverQualityProxyIDsMutex.Unlock()

				return nil
			})

		}

		out, err := serverSessions.HandlePacket(logger, in, clientConnectionID, handler)
		return out, errors.Trace(err)
	}

	// Check that the tactics round trip succeeds

	var pendingProxyTacticsCallbacksMutex sync.Mutex
	pendingProxyTacticsCallbacks := make(map[SessionPrivateKey]bool)

	addPendingProxyTacticsCallback := func(proxyPrivateKey SessionPrivateKey) {
		pendingProxyTacticsCallbacksMutex.Lock()
		defer pendingProxyTacticsCallbacksMutex.Unlock()
		pendingProxyTacticsCallbacks[proxyPrivateKey] = true
	}

	hasPendingProxyTacticsCallbacks := func() bool {
		pendingProxyTacticsCallbacksMutex.Lock()
		defer pendingProxyTacticsCallbacksMutex.Unlock()
		return len(pendingProxyTacticsCallbacks) > 0
	}

	makeHandleTacticsPayload := func(
		proxyPrivateKey SessionPrivateKey,
		tacticsNetworkID string) func(_ string, _ []byte) bool {

		return func(networkID string, tacticsPayload []byte) bool {
			pendingProxyTacticsCallbacksMutex.Lock()
			defer pendingProxyTacticsCallbacksMutex.Unlock()

			// Check that the correct networkID is passed around; if not,
			// skip the delete, which will fail the test
			if networkID == tacticsNetworkID {

				// Certain state is reset when new tactics are applied -- the
				// return true case; exercise both cases
				if bytes.Equal(tacticsPayload, testNewTacticsPayload) {
					delete(pendingProxyTacticsCallbacks, proxyPrivateKey)
					return true
				}
				if bytes.Equal(tacticsPayload, testUnchangedTacticsPayload) {
					delete(pendingProxyTacticsCallbacks, proxyPrivateKey)
					return false
				}
			}
			panic("unexpected tactics payload")
		}
	}

	// Start proxies

	logger.WithTrace().Info("START PROXIES")

	for i := 0; i < numProxies; i++ {

		proxyPrivateKey, err := GenerateSessionPrivateKey()
		if err != nil {
			return errors.Trace(err)
		}

		brokerCoordinator := &testBrokerDialCoordinator{
			networkID:                   testNetworkID,
			networkType:                 testNetworkType,
			brokerClientPrivateKey:      proxyPrivateKey,
			brokerPublicKey:             brokerPublicKey,
			brokerRootObfuscationSecret: brokerRootObfuscationSecret,
			brokerClientRoundTripper: newHTTPRoundTripper(
				brokerListener.Addr().String(), "proxy"),
			brokerClientRoundTripperSucceeded: roundTripperSucceded,
			brokerClientRoundTripperFailed:    roundTripperFailed,

			// Minimize the delay before proxies reannounce after dial
			// failures, which may occur.
			announceDelay:           0,
			announceMaxBackoffDelay: 0,
			announceDelayJitter:     0.0,
		}

		webRTCCoordinator := &testWebRTCDialCoordinator{
			networkID:                  testNetworkID,
			networkType:                testNetworkType,
			natType:                    testNATType,
			disableSTUN:                testDisableSTUN,
			disablePortMapping:         testDisablePortMapping,
			stunServerAddress:          testSTUNServerAddress,
			stunServerAddressRFC5780:   testSTUNServerAddress,
			stunServerAddressSucceeded: stunServerAddressSucceeded,
			stunServerAddressFailed:    stunServerAddressFailed,
			setNATType:                 func(NATType) {},
			setPortMappingTypes:        func(PortMappingTypes) {},
			bindToDevice:               func(int) error { return nil },

			// Minimize the delay before proxies reannounce after failed
			// connections, which may occur.
			webRTCAwaitReadyToProxyTimeout: 5 * time.Second,
			proxyRelayInactivityTimeout:    5 * time.Second,
		}

		// Each proxy has its own broker client
		brokerClient, err := NewBrokerClient(brokerCoordinator)
		if err != nil {
			return errors.Trace(err)
		}

		tacticsNetworkID := prng.HexString(32)

		runCtx, cancelRun := context.WithCancel(testCtx)
		// No deferred cancelRun due to testGroup.Go below

		name := fmt.Sprintf("proxy-%d", i)

		proxy, err := NewProxy(&ProxyConfig{

			Logger: testutils.NewTestLoggerWithComponent(name),

			WaitForNetworkConnectivity: func() bool {
				return true
			},

			GetCurrentNetworkContext: func() context.Context {
				return currentNetworkCtx
			},

			GetBrokerClient: func() (*BrokerClient, error) {
				return brokerClient, nil
			},

			GetBaseAPIParameters: func(bool) (common.APIParameters, string, error) {
				return baseAPIParameters, tacticsNetworkID, nil
			},

			MakeWebRTCDialCoordinator: func() (WebRTCDialCoordinator, error) {
				return webRTCCoordinator, nil
			},

			HandleTacticsPayload: makeHandleTacticsPayload(proxyPrivateKey, tacticsNetworkID),

			MaxClients:                    proxyMaxClients,
			LimitUpstreamBytesPerSecond:   bytesToSend / targetElapsedSeconds,
			LimitDownstreamBytesPerSecond: bytesToSend / targetElapsedSeconds,

			ActivityUpdater: func(connectingClients int32, connectedClients int32,
				bytesUp int64, bytesDown int64, bytesDuration time.Duration) {

				fmt.Printf("[%s][%s] ACTIVITY: %d connecting, %d connected, %d up, %d down\n",
					time.Now().UTC().Format(time.RFC3339), name,
					connectingClients, connectedClients, bytesUp, bytesDown)
			},

			MustUpgrade: func() {
				close(receivedProxyMustUpgrade)
				cancelRun()
			},
		})
		if err != nil {
			return errors.Trace(err)
		}

		addPendingProxyTacticsCallback(proxyPrivateKey)

		testGroup.Go(func() error {
			proxy.Run(runCtx)
			return nil
		})
	}

	// Await proxy announcements before starting clients
	//
	// - Announcements may delay due to proxyAnnounceRetryDelay in Proxy.Run,
	//   plus NAT discovery
	//
	// - Don't wait for > numProxies announcements due to
	//   InitiatorSessions.NewRoundTrip waitToShareSession limitation

	if !doMustUpgrade {
		for {
			time.Sleep(100 * time.Millisecond)
			broker.matcher.announcementQueueMutex.Lock()
			n := broker.matcher.announcementQueue.getLen()
			broker.matcher.announcementQueueMutex.Unlock()
			if n >= numProxies {
				break
			}
		}
	}

	// Start clients

	var completedClientCount atomic.Int64

	logger.WithTrace().Info("START CLIENTS")

	clientsGroup := new(errgroup.Group)

	makeClientFunc := func(
		clientNum int,
		isTCP bool,
		brokerClient *BrokerClient,
		webRTCCoordinator WebRTCDialCoordinator) func() error {

		var networkProtocol NetworkProtocol
		var addr string
		var wrapWithQUIC bool
		if isTCP {
			networkProtocol = NetworkProtocolTCP
			addr = tcpEchoListener.Addr().String()
		} else {
			networkProtocol = NetworkProtocolUDP
			addr = quicEchoServer.Addr().String()
			wrapWithQUIC = true
		}

		return func() error {

			name := fmt.Sprintf("client-%d", clientNum)

			dialCtx, cancelDial := context.WithTimeout(testCtx, 60*time.Second)
			defer cancelDial()

			conn, err := DialClient(
				dialCtx,
				&ClientConfig{
					Logger:                       testutils.NewTestLoggerWithComponent(name),
					BaseAPIParameters:            baseAPIParameters,
					BrokerClient:                 brokerClient,
					WebRTCDialCoordinator:        webRTCCoordinator,
					ReliableTransport:            isTCP,
					DialNetworkProtocol:          networkProtocol,
					DialAddress:                  addr,
					PackedDestinationServerEntry: packedDestinationServerEntry,
					MustUpgrade: func() {
						close(receivedClientMustUpgrade)
						cancelDial()
					},
				})
			if err != nil {
				return errors.Trace(err)
			}

			var relayConn net.Conn
			relayConn = conn

			if wrapWithQUIC {

				udpAddr, err := net.ResolveUDPAddr("udp", addr)
				if err != nil {
					return errors.Trace(err)
				}

				disablePathMTUDiscovery := true
				quicConn, err := quic.Dial(
					dialCtx,
					conn,
					udpAddr,
					"test",
					"QUICv1",
					nil,
					quicEchoServer.ObfuscationKey(),
					nil,
					nil,
					disablePathMTUDiscovery,
					GetQUICMaxPacketSizeAdjustment(),
					false,
					false,
					common.WrapClientSessionCache(tls.NewLRUClientSessionCache(0), ""),
				)
				if err != nil {
					return errors.Trace(err)
				}
				relayConn = quicConn
			}

			addPendingBrokerServerReport(conn.GetConnectionID())
			signalRelayComplete := make(chan struct{})

			clientsGroup.Go(func() error {
				defer close(signalRelayComplete)

				in := conn.InitialRelayPacket()
				for in != nil {
					out, err := handleBrokerServerReports(in, conn.GetConnectionID())
					if err != nil {
						if out == nil {
							return errors.Trace(err)
						} else {
							fmt.Printf("HandlePacket returned packet and error: %v\n", err)
							// Proceed with reset session token packet
						}
					}

					if out == nil {
						// Relay is complete
						break
					}

					in, err = conn.RelayPacket(testCtx, out)
					if err != nil {
						return errors.Trace(err)
					}
				}

				return nil
			})

			sendBytes := prng.Bytes(bytesToSend)

			clientsGroup.Go(func() error {
				for n := 0; n < bytesToSend; {
					m := prng.Range(1024, 32768)
					if bytesToSend-n < m {
						m = bytesToSend - n
					}
					_, err := relayConn.Write(sendBytes[n : n+m])
					if err != nil {
						return errors.Trace(err)
					}
					n += m
				}
				fmt.Printf("[%s][%s] %d bytes sent\n",
					time.Now().UTC().Format(time.RFC3339), name, bytesToSend)
				return nil
			})

			clientsGroup.Go(func() error {
				buf := make([]byte, 32768)
				n := 0
				for n < bytesToSend {
					m, err := relayConn.Read(buf)
					if err != nil {
						return errors.Trace(err)
					}
					if !bytes.Equal(sendBytes[n:n+m], buf[:m]) {
						return errors.Tracef(
							"unexpected bytes: expected at index %d, received at index %d",
							bytes.Index(sendBytes, buf[:m]), n)
					}
					n += m
				}

				completed := completedClientCount.Add(1)

				fmt.Printf("[%s][%s] %d bytes received; relay complete (%d/%d)\n",
					time.Now().UTC().Format(time.RFC3339), name,
					bytesToSend, completed, numClients)

				select {
				case <-signalRelayComplete:
				case <-testCtx.Done():
				}

				fmt.Printf("[%s][%s] closing\n",
					time.Now().UTC().Format(time.RFC3339), name)

				relayConn.Close()
				conn.Close()

				return nil
			})

			return nil
		}
	}

	newClientBrokerClient := func(
		disableWaitToShareSession bool) (*BrokerClient, error) {

		clientPrivateKey, err := GenerateSessionPrivateKey()
		if err != nil {
			return nil, errors.Trace(err)
		}

		brokerCoordinator := &testBrokerDialCoordinator{
			networkID:   testNetworkID,
			networkType: testNetworkType,

			commonCompartmentIDs: testCommonCompartmentIDs,

			disableWaitToShareSession: disableWaitToShareSession,

			brokerClientPrivateKey:      clientPrivateKey,
			brokerPublicKey:             brokerPublicKey,
			brokerRootObfuscationSecret: brokerRootObfuscationSecret,
			brokerClientRoundTripper: newHTTPRoundTripper(
				brokerListener.Addr().String(), "client"),
			brokerClientRoundTripperSucceeded: roundTripperSucceded,
			brokerClientRoundTripperFailed:    roundTripperFailed,
			brokerClientNoMatch:               noMatch,
		}

		brokerClient, err := NewBrokerClient(brokerCoordinator)
		if err != nil {
			return nil, errors.Trace(err)
		}

		return brokerClient, nil
	}

	newClientWebRTCDialCoordinator := func(
		isMobile bool,
		useMediaStreams bool) (*testWebRTCDialCoordinator, error) {

		clientRootObfuscationSecret, err := GenerateRootObfuscationSecret()
		if err != nil {
			return nil, errors.Trace(err)
		}

		var trafficShapingParameters *TrafficShapingParameters
		if useMediaStreams {
			trafficShapingParameters = &TrafficShapingParameters{
				MinPaddedMessages:       0,
				MaxPaddedMessages:       10,
				MinPaddingSize:          0,
				MaxPaddingSize:          254,
				MinDecoyMessages:        0,
				MaxDecoyMessages:        10,
				MinDecoySize:            1,
				MaxDecoySize:            1200,
				DecoyMessageProbability: 0.5,
			}
		} else {
			trafficShapingParameters = &TrafficShapingParameters{
				MinPaddedMessages:       0,
				MaxPaddedMessages:       10,
				MinPaddingSize:          0,
				MaxPaddingSize:          1500,
				MinDecoyMessages:        0,
				MaxDecoyMessages:        10,
				MinDecoySize:            1,
				MaxDecoySize:            1500,
				DecoyMessageProbability: 0.5,
			}
		}

		webRTCCoordinator := &testWebRTCDialCoordinator{
			networkID:   testNetworkID,
			networkType: testNetworkType,

			natType:                    testNATType,
			disableSTUN:                testDisableSTUN,
			stunServerAddress:          testSTUNServerAddress,
			stunServerAddressRFC5780:   testSTUNServerAddress,
			stunServerAddressSucceeded: stunServerAddressSucceeded,
			stunServerAddressFailed:    stunServerAddressFailed,

			clientRootObfuscationSecret: clientRootObfuscationSecret,
			doDTLSRandomization:         prng.FlipCoin(),
			useMediaStreams:             useMediaStreams,
			trafficShapingParameters:    trafficShapingParameters,

			setNATType:          func(NATType) {},
			setPortMappingTypes: func(PortMappingTypes) {},
			bindToDevice:        func(int) error { return nil },

			// With STUN enabled (testDisableSTUN = false), there are cases
			// where the WebRTC peer connection is not successfully
			// established. With a short enough timeout here, clients will
			// redial and eventually succceed.
			webRTCAwaitReadyToProxyTimeout: 5 * time.Second,
		}

		if isMobile {
			webRTCCoordinator.networkType = NetworkTypeMobile
			webRTCCoordinator.disableInboundForMobileNetworks = true
		}

		return webRTCCoordinator, nil
	}

	sharedBrokerClient, err := newClientBrokerClient(false)
	if err != nil {
		return errors.Trace(err)
	}

	sharedBrokerClientDisableWait, err := newClientBrokerClient(true)
	if err != nil {
		return errors.Trace(err)
	}

	for i := 0; i < numClients; i++ {

		// Test a mix of TCP and UDP proxying; also test the
		// DisableInboundForMobileNetworks code path.

		isTCP := i%2 == 0
		isMobile := i%4 == 0
		useMediaStreams := i%4 < 2

		// Exercise BrokerClients shared by multiple clients, but also create
		// several broker clients.
		var brokerClient *BrokerClient
		switch i % 3 {
		case 0:
			brokerClient = sharedBrokerClient
		case 1:
			brokerClient = sharedBrokerClientDisableWait
		case 2:
			brokerClient, err = newClientBrokerClient(true)
			if err != nil {
				return errors.Trace(err)
			}
		}

		webRTCCoordinator, err := newClientWebRTCDialCoordinator(
			isMobile, useMediaStreams)
		if err != nil {
			return errors.Trace(err)
		}

		clientsGroup.Go(
			makeClientFunc(
				i,
				isTCP,
				brokerClient,
				webRTCCoordinator))
	}

	if doMustUpgrade {

		// Await MustUpgrade callbacks

		logger.WithTrace().Info("AWAIT MUST UPGRADE")

		<-receivedProxyMustUpgrade
		<-receivedClientMustUpgrade

		_ = clientsGroup.Wait()

	} else {

		// Await client transfers complete

		logger.WithTrace().Info("AWAIT DATA TRANSFER")

		err = clientsGroup.Wait()
		if err != nil {
			return errors.Trace(err)
		}

		logger.WithTrace().Info("DONE DATA TRANSFER")

		if hasPendingBrokerServerReports() {
			return errors.TraceNew("unexpected pending broker server requests")
		}

		if hasPendingProxyTacticsCallbacks() {
			return errors.TraceNew("unexpected pending proxy tactics callback")
		}

		err = serverQualityGroup.Wait()
		if err != nil {
			return errors.Trace(err)
		}

		// Inspect the broker's proxy quality state, to verify that the proxy
		// quality request was processed.
		//
		// Limitation: currently we don't check the priority
		// announcement _queue_, as announcements may have arrived before the
		// quality request, and announcements are promoted between queues.

		serverQualityProxyIDsMutex.Lock()
		defer serverQualityProxyIDsMutex.Unlock()
		for proxyID := range serverQualityProxyIDs {
			if !broker.proxyQualityState.HasQuality(proxyID, testProxyASN, "") {
				return errors.TraceNew("unexpected missing HasQuality (no client ASN)")
			}
			if !broker.proxyQualityState.HasQuality(proxyID, testProxyASN, testClientASN) {
				return errors.TraceNew("unexpected missing HasQuality (with client ASN)")
			}
		}

		// TODO: check that elapsed time is consistent with rate limit (+/-)

		// Check if STUN server replay callbacks were triggered
		if !testDisableSTUN {
			if atomic.LoadInt32(&stunServerAddressSucceededCount) < 1 {
				return errors.TraceNew("unexpected STUN server succeeded count")
			}
			// Allow for some STUN server failures
			if atomic.LoadInt32(&stunServerAddressFailedCount) >= int32(numProxies/2) {
				return errors.TraceNew("unexpected STUN server failed count")
			}
		}

		// Check if RoundTripper server replay callbacks were triggered
		if atomic.LoadInt32(&roundTripperSucceededCount) < 1 {
			return errors.TraceNew("unexpected round tripper succeeded count")
		}
		if atomic.LoadInt32(&roundTripperFailedCount) > 0 {
			return errors.TraceNew("unexpected round tripper failed count")
		}
	}

	// Await shutdowns

	stopTest()
	brokerListener.Close()

	err = testGroup.Wait()
	if err != nil {
		return errors.Trace(err)
	}

	return nil
}

func runHTTPServer(listener net.Listener, broker *Broker) error {

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		// For this test, clients set the path to "/client" and proxies
		// set the path to "/proxy" and we use that to create stub GeoIP
		// data to pass the not-same-ASN condition.
		var geoIPData common.GeoIPData
		geoIPData.ASN = r.URL.Path

		requestPayload, err := ioutil.ReadAll(
			http.MaxBytesReader(w, r.Body, BrokerMaxRequestBodySize))
		if err != nil {
			fmt.Printf("runHTTPServer ioutil.ReadAll failed: %v\n", err)
			http.Error(w, "", http.StatusNotFound)
			return
		}

		clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)

		extendTimeout := func(timeout time.Duration) {
			// TODO: set insufficient initial timeout, so extension is
			// required for success
			http.NewResponseController(w).SetWriteDeadline(time.Now().Add(timeout))
		}

		responsePayload, err := broker.HandleSessionPacket(
			r.Context(),
			extendTimeout,
			nil,
			clientIP,
			geoIPData,
			requestPayload)
		if err != nil {
			fmt.Printf("runHTTPServer HandleSessionPacket failed: %v\n", err)
			http.Error(w, "", http.StatusNotFound)
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write(responsePayload)
	})

	// WriteTimeout will be extended via extendTimeout.
	httpServer := &http.Server{
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  1 * time.Minute,
		Handler:      handler,
	}

	certificate, privateKey, _, err := common.GenerateWebServerCertificate("www.example.com")
	if err != nil {
		return errors.Trace(err)
	}
	tlsCert, err := tls.X509KeyPair([]byte(certificate), []byte(privateKey))
	if err != nil {
		return errors.Trace(err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	}

	err = httpServer.Serve(tls.NewListener(listener, tlsConfig))
	return errors.Trace(err)
}

type httpRoundTripper struct {
	httpClient   *http.Client
	endpointAddr string
	path         string
}

func newHTTPRoundTripper(endpointAddr string, path string) *httpRoundTripper {
	return &httpRoundTripper{
		httpClient: &http.Client{
			Transport: &http.Transport{
				ForceAttemptHTTP2:   true,
				MaxIdleConns:        2,
				IdleConnTimeout:     1 * time.Minute,
				TLSHandshakeTimeout: 10 * time.Second,
				TLSClientConfig: &std_tls.Config{
					InsecureSkipVerify: true,
				},
			},
		},
		endpointAddr: endpointAddr,
		path:         path,
	}
}

func (r *httpRoundTripper) RoundTrip(
	ctx context.Context,
	roundTripDelay time.Duration,
	roundTripTimeout time.Duration,
	requestPayload []byte) ([]byte, error) {

	if roundTripDelay > 0 {
		common.SleepWithContext(ctx, roundTripDelay)
	}

	requestCtx, requestCancelFunc := context.WithTimeout(ctx, roundTripTimeout)
	defer requestCancelFunc()

	url := fmt.Sprintf("https://%s/%s", r.endpointAddr, r.path)

	request, err := http.NewRequestWithContext(
		requestCtx, "POST", url, bytes.NewReader(requestPayload))
	if err != nil {
		return nil, errors.Trace(err)
	}

	response, err := r.httpClient.Do(request)
	if err != nil {
		return nil, errors.Trace(err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return nil, errors.Tracef("unexpected response status code: %d", response.StatusCode)
	}

	responsePayload, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, errors.Trace(err)
	}

	return responsePayload, nil
}

func (r *httpRoundTripper) Close() error {
	r.httpClient.CloseIdleConnections()
	return nil
}

func runTCPEchoServer(listener net.Listener) {

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Printf("runTCPEchoServer failed: %v\n", errors.Trace(err))
			return
		}
		go func(conn net.Conn) {
			buf := make([]byte, 32768)
			for {
				n, err := conn.Read(buf)
				if n > 0 {
					_, err = conn.Write(buf[:n])
				}
				if err != nil {
					fmt.Printf("runTCPEchoServer failed: %v\n", errors.Trace(err))
					return
				}
			}
		}(conn)
	}
}

type quicEchoServer struct {
	listener       net.Listener
	obfuscationKey string
}

func newQuicEchoServer() (*quicEchoServer, error) {

	obfuscationKey := prng.HexString(32)

	listener, err := quic.Listen(
		nil,
		nil,
		"127.0.0.1:0",
		true,
		GetQUICMaxPacketSizeAdjustment(),
		obfuscationKey,
		false)
	if err != nil {
		return nil, errors.Trace(err)
	}

	return &quicEchoServer{
		listener:       listener,
		obfuscationKey: obfuscationKey,
	}, nil
}

func (q *quicEchoServer) ObfuscationKey() string {
	return q.obfuscationKey
}

func (q *quicEchoServer) Close() error {
	return q.listener.Close()
}

func (q *quicEchoServer) Addr() net.Addr {
	return q.listener.Addr()
}

func (q *quicEchoServer) Run() {

	for {
		conn, err := q.listener.Accept()
		if err != nil {
			fmt.Printf("quicEchoServer failed: %v\n", errors.Trace(err))
			return
		}
		go func(conn net.Conn) {
			buf := make([]byte, 32768)
			for {
				n, err := conn.Read(buf)
				if n > 0 {
					_, err = conn.Write(buf[:n])
				}
				if err != nil {
					fmt.Printf("quicEchoServer failed: %v\n", errors.Trace(err))
					return
				}
			}
		}(conn)
	}
}
