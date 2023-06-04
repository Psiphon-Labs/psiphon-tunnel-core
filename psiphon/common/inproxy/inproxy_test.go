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
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/quic"
	"golang.org/x/sync/errgroup"
)

func TestInProxy(t *testing.T) {
	err := runTestInProxy()
	if err != nil {
		t.Errorf(errors.Trace(err).Error())
	}
}

func runTestInProxy() error {

	// Note: use the environment variable PION_LOG_TRACE=all to emit WebRTC logging.

	numProxies := 5
	proxyMaxClients := 2
	numClients := 10

	bytesToSend := 1 << 20
	targetElapsedSeconds := 2

	baseMetrics := common.APIParameters{
		"sponsor_id":      "test-sponsor-id",
		"client_platform": "test-client-platform",
	}

	testTransportSecret, _ := MakeID()

	testCompartmentID, _ := MakeID()
	testCommonCompartmentIDs := []ID{testCompartmentID}

	testNetworkID := "NETWORK-ID-1"
	testNetworkType := NetworkTypeUnknown
	testNATType := NATTypeUnknown
	testSTUNServerAddress := "stun.nextcloud.com:443"
	testDisableSTUN := false

	// TODO: test port mapping

	stunServerAddressSucceededCount := int32(0)
	stunServerAddressSucceeded := func(bool, string) { atomic.AddInt32(&stunServerAddressSucceededCount, 1) }
	stunServerAddressFailedCount := int32(0)
	stunServerAddressFailed := func(bool, string) { atomic.AddInt32(&stunServerAddressFailedCount, 1) }

	roundTripperSucceededCount := int32(0)
	roundTripperSucceded := func(RoundTripper) { atomic.AddInt32(&roundTripperSucceededCount, 1) }
	roundTripperFailedCount := int32(0)
	roundTripperFailed := func(RoundTripper) { atomic.AddInt32(&roundTripperFailedCount, 1) }

	testCtx, stopTest := context.WithCancel(context.Background())
	defer stopTest()

	testGroup := new(errgroup.Group)

	// Enable test to run without requiring host firewall exceptions
	setAllowLoopbackWebRTCConnections(true)

	// Init logging

	logger := newTestLogger()

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
	serverPublicKey, err := GetSessionPublicKey(serverPrivateKey)
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
	serverEntry["sshObfuscatedPort"], _ = strconv.Atoi(tcpPort)
	serverEntry["sshObfuscatedQUICPort"], _ = strconv.Atoi(udpPort)
	serverEntry["capabilities"] = []string{"OSSH", "QUIC", "inproxy"}
	serverEntry["inProxySessionPublicKey"] = base64.StdEncoding.EncodeToString(serverPublicKey[:])
	serverEntry["inProxySessionRootObfuscationSecret"] = base64.StdEncoding.EncodeToString(serverRootObfuscationSecret[:])
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

	serverEntryJSON, err := json.Marshal(serverEntry)
	if err != nil {
		return errors.Trace(err)
	}

	// Start broker

	brokerPrivateKey, err := GenerateSessionPrivateKey()
	if err != nil {
		return errors.Trace(err)
	}
	brokerPublicKey, err := GetSessionPublicKey(brokerPrivateKey)
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

		APIParameterValidator: func(params common.APIParameters) error {
			if len(params) != len(baseMetrics) {
				return errors.TraceNew("unexpected base metrics")
			}
			for name, value := range params {
				if value.(string) != baseMetrics[name].(string) {
					return errors.TraceNew("unexpected base metrics")
				}
			}
			return nil
		},

		APIParameterLogFieldFormatter: func(
			geoIPData common.GeoIPData, params common.APIParameters) common.LogFields {
			return common.LogFields(params)
		},

		TransportSecret: TransportSecret(testTransportSecret),

		PrivateKey: brokerPrivateKey,

		ObfuscationRootSecret: brokerRootObfuscationSecret,

		ServerEntrySignaturePublicKey: serverEntrySignaturePublicKey,

		IsValidServerEntryTag: func(serverEntryTag string) bool { return serverEntryTag == testServerEntryTag },

		AllowProxy:             func(common.GeoIPData) bool { return true },
		AllowClient:            func(common.GeoIPData) bool { return true },
		AllowDomainDestination: func(common.GeoIPData) bool { return true },
	}

	broker, err := NewBroker(brokerConfig)
	if err != nil {
		return errors.Trace(err)
	}

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

	serverSessions, err := NewServerBrokerSessions(
		serverPrivateKey, serverRootObfuscationSecret, []SessionPublicKey{brokerPublicKey})
	if err != nil {
		return errors.Trace(err)
	}

	var pendingBrokerServerRequestsMutex sync.Mutex
	pendingBrokerServerRequests := make(map[ID]bool)

	addPendingBrokerServerRequest := func(connectionID ID) {
		pendingBrokerServerRequestsMutex.Lock()
		defer pendingBrokerServerRequestsMutex.Unlock()
		pendingBrokerServerRequests[connectionID] = true
	}

	hasPendingBrokerServerRequests := func() bool {
		pendingBrokerServerRequestsMutex.Lock()
		defer pendingBrokerServerRequestsMutex.Unlock()
		return len(pendingBrokerServerRequests) > 0
	}

	handleBrokerServerRequests := func(in []byte, clientConnectionID ID) ([]byte, error) {

		handler := func(brokerVerifiedOriginalClientIP string, logFields common.LogFields) {
			pendingBrokerServerRequestsMutex.Lock()
			defer pendingBrokerServerRequestsMutex.Unlock()

			// Mark the request as no longer outstanding
			delete(pendingBrokerServerRequests, clientConnectionID)
		}

		out, err := serverSessions.HandlePacket(logger, in, clientConnectionID, handler)
		if err != nil {
			return nil, errors.Trace(err)
		}
		return out, nil
	}

	// Start proxies

	for i := 0; i < numProxies; i++ {

		proxyPrivateKey, err := GenerateSessionPrivateKey()
		if err != nil {
			return errors.Trace(err)
		}

		dialParams := &testDialParameters{
			networkID:                  testNetworkID,
			networkType:                testNetworkType,
			natType:                    testNATType,
			disableSTUN:                testDisableSTUN,
			stunServerAddress:          testSTUNServerAddress,
			stunServerAddressRFC5780:   testSTUNServerAddress,
			stunServerAddressSucceeded: stunServerAddressSucceeded,
			stunServerAddressFailed:    stunServerAddressFailed,

			brokerClientPrivateKey:      proxyPrivateKey,
			brokerPublicKey:             brokerPublicKey,
			brokerRootObfuscationSecret: brokerRootObfuscationSecret,
			brokerClientRoundTripper: newHTTPRoundTripper(
				brokerListener.Addr().String(), "proxy"),
			brokerClientRoundTripperSucceeded: roundTripperSucceded,
			brokerClientRoundTripperFailed:    roundTripperFailed,

			setNATType:          func(NATType) {},
			setPortMappingTypes: func(PortMappingTypes) {},
			bindToDevice:        func(int) error { return nil },
		}

		proxy, err := NewProxy(&ProxyConfig{
			Logger:                        logger,
			BaseMetrics:                   baseMetrics,
			DialParameters:                dialParams,
			MaxClients:                    proxyMaxClients,
			LimitUpstreamBytesPerSecond:   bytesToSend / targetElapsedSeconds,
			LimitDownstreamBytesPerSecond: bytesToSend / targetElapsedSeconds,
			ActivityUpdater: func(connectingClients int32, connectedClients int32,
				bytesUp int64, bytesDown int64, bytesDuration time.Duration) {

				fmt.Printf("[%s] ACTIVITY: %d connecting, %d connected, %d up, %d down\n",
					time.Now().UTC().Format(time.RFC3339),
					connectingClients, connectedClients, bytesUp, bytesDown)
			},
		})
		if err != nil {
			return errors.Trace(err)
		}

		testGroup.Go(func() error {
			proxy.Run(testCtx)
			return nil
		})
	}

	// Run clients

	clientsGroup := new(errgroup.Group)

	makeClientFunc := func(
		isTCP bool,
		isMobile bool,
		dialParams DialParameters,
		brokerClient *BrokerClient) func() error {

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

			dialCtx, cancelDial := context.WithTimeout(testCtx, 30*time.Second)
			defer cancelDial()

			conn, err := DialClient(
				dialCtx,
				&ClientConfig{
					Logger:                     logger,
					BaseMetrics:                baseMetrics,
					DialParameters:             dialParams,
					BrokerClient:               brokerClient,
					ReliableTransport:          isTCP,
					DialNetworkProtocol:        networkProtocol,
					DialAddress:                addr,
					DestinationServerEntryJSON: serverEntryJSON,
				})
			if err != nil {
				return errors.Trace(err)
			}

			var relayConn net.Conn
			relayConn = conn

			if wrapWithQUIC {
				quicConn, err := quic.Dial(
					dialCtx,
					conn,
					&net.UDPAddr{Port: 1}, // This address is ignored, but the zero value is not allowed
					"test", "QUICv1", nil, quicEchoServer.ObfuscationKey(), nil, nil, true)
				if err != nil {
					return errors.Trace(err)
				}
				relayConn = quicConn
			}

			addPendingBrokerServerRequest(conn.GetConnectionID())
			signalRelayComplete := make(chan struct{})

			clientsGroup.Go(func() error {
				defer close(signalRelayComplete)

				in := conn.InitialRelayPacket()
				for in != nil {
					out, err := handleBrokerServerRequests(in, conn.GetConnectionID())

					// In general, trying to use an expired session results in an expected error...
					sessionInvalid := err != nil

					// ...but no error is expected in this test run.
					if err != nil {
						fmt.Printf("handleBrokerServerRequests failed: %v\n", err)
					}

					in, err = conn.RelayPacket(testCtx, out, sessionInvalid)
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
				fmt.Printf("%d bytes sent\n", bytesToSend)
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
				fmt.Printf("%d bytes received\n", bytesToSend)

				select {
				case <-signalRelayComplete:
				case <-testCtx.Done():
				}

				relayConn.Close()
				conn.Close()

				return nil
			})

			return nil
		}
	}

	newClientParams := func(isMobile bool) (*testDialParameters, *BrokerClient, error) {

		clientPrivateKey, err := GenerateSessionPrivateKey()
		if err != nil {
			return nil, nil, errors.Trace(err)
		}

		clientRootObfuscationSecret, err := GenerateRootObfuscationSecret()
		if err != nil {
			return nil, nil, errors.Trace(err)
		}

		dialParams := &testDialParameters{
			commonCompartmentIDs: testCommonCompartmentIDs,

			networkID:                  testNetworkID,
			networkType:                testNetworkType,
			natType:                    testNATType,
			disableSTUN:                testDisableSTUN,
			stunServerAddress:          testSTUNServerAddress,
			stunServerAddressRFC5780:   testSTUNServerAddress,
			stunServerAddressSucceeded: stunServerAddressSucceeded,
			stunServerAddressFailed:    stunServerAddressFailed,

			brokerClientPrivateKey:      clientPrivateKey,
			brokerPublicKey:             brokerPublicKey,
			brokerRootObfuscationSecret: brokerRootObfuscationSecret,
			brokerClientRoundTripper: newHTTPRoundTripper(
				brokerListener.Addr().String(), "client"),
			brokerClientRoundTripperSucceeded: roundTripperSucceded,
			brokerClientRoundTripperFailed:    roundTripperFailed,

			clientRootObfuscationSecret: clientRootObfuscationSecret,
			doDTLSRandomization:         true,
			trafficShapingParameters: &DataChannelTrafficShapingParameters{
				MinPaddedMessages:       0,
				MaxPaddedMessages:       10,
				MinPaddingSize:          0,
				MaxPaddingSize:          1500,
				MinDecoyMessages:        0,
				MaxDecoyMessages:        10,
				MinDecoySize:            1,
				MaxDecoySize:            1500,
				DecoyMessageProbability: 0.5,
			},

			setNATType:          func(NATType) {},
			setPortMappingTypes: func(PortMappingTypes) {},
			bindToDevice:        func(int) error { return nil },
		}

		if isMobile {
			dialParams.networkType = NetworkTypeMobile
			dialParams.disableInboundForMobleNetworks = true
		}

		brokerClient, err := NewBrokerClient(dialParams)
		if err != nil {
			return nil, nil, errors.Trace(err)
		}

		return dialParams, brokerClient, nil
	}

	clientDialParams, clientBrokerClient, err := newClientParams(false)
	if err != nil {
		return errors.Trace(err)
	}

	clientMobileDialParams, clientMobileBrokerClient, err := newClientParams(true)
	if err != nil {
		return errors.Trace(err)
	}

	for i := 0; i < numClients; i++ {

		// Test a mix of TCP and UDP proxying; also test the
		// DisableInboundForMobleNetworks code path.

		isTCP := i%2 == 0
		isMobile := i%4 == 0

		// Exercise BrokerClients shared by multiple clients, but also create
		// several broker clients.
		if i%8 == 0 {
			clientDialParams, clientBrokerClient, err = newClientParams(false)
			if err != nil {
				return errors.Trace(err)
			}

			clientMobileDialParams, clientMobileBrokerClient, err = newClientParams(true)
			if err != nil {
				return errors.Trace(err)
			}
		}

		dialParams := clientDialParams
		brokerClient := clientBrokerClient
		if isMobile {
			dialParams = clientMobileDialParams
			brokerClient = clientMobileBrokerClient
		}

		clientsGroup.Go(makeClientFunc(isTCP, isMobile, dialParams, brokerClient))
	}

	// Await client transfers complete

	err = clientsGroup.Wait()
	if err != nil {
		return errors.Trace(err)
	}

	if hasPendingBrokerServerRequests() {
		return errors.TraceNew("unexpected pending broker server requests")
	}

	// Await shutdowns

	stopTest()
	brokerListener.Close()

	err = testGroup.Wait()
	if err != nil {
		return errors.Trace(err)
	}

	// TODO: check that elapsed time is consistent with rate limit (+/-)

	// Check if STUN server replay callbacks were triggered
	if atomic.LoadInt32(&stunServerAddressSucceededCount) < 1 {
		return errors.TraceNew("unexpected STUN server succeeded count")
	}
	if atomic.LoadInt32(&stunServerAddressFailedCount) > 0 {
		return errors.TraceNew("unexpected STUN server failed count")
	}

	// Check if RoundTripper server replay callbacks were triggered
	if atomic.LoadInt32(&roundTripperSucceededCount) < 1 {
		return errors.TraceNew("unexpected round tripper succeeded count")
	}
	if atomic.LoadInt32(&roundTripperFailedCount) > 0 {
		return errors.TraceNew("unexpected round tripper failed count")
	}

	return nil
}

func runHTTPServer(listener net.Listener, broker *Broker) error {

	httpServer := &http.Server{
		ReadTimeout:  BrokerReadTimeout,
		WriteTimeout: BrokerWriteTimeout,
		IdleTimeout:  BrokerIdleTimeout,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			// For this test, clients set the path to "/client" and proxies
			// set the path to "/proxy" and we use that to create stub GeoIP
			// data to pass the not-same-ASN condition.
			var geoIPData common.GeoIPData
			geoIPData.ASN = r.URL.Path

			// Not an actual HTTP header in this test.
			transportSecret := broker.config.TransportSecret

			requestPayload, err := ioutil.ReadAll(
				http.MaxBytesReader(w, r.Body, BrokerMaxRequestBodySize))
			if err != nil {
				fmt.Printf("runHTTPServer ioutil.ReadAll failed: %v\n", err)
				http.Error(w, "", http.StatusNotFound)
				return
			}
			clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)
			responsePayload, err := broker.HandleSessionPacket(
				r.Context(),
				transportSecret,
				clientIP,
				geoIPData,
				requestPayload)
			if err != nil {
				fmt.Printf("runHTTPServer HandleSessionPacket failed: %v", err)
				http.Error(w, "", http.StatusNotFound)
				return
			}
			w.WriteHeader(http.StatusOK)
			w.Write(responsePayload)
		}),
	}

	certificate, privateKey, err := common.GenerateWebServerCertificate("www.example.com")
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
				IdleConnTimeout:     BrokerIdleTimeout,
				TLSHandshakeTimeout: 1 * time.Second,
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
		},
		endpointAddr: endpointAddr,
		path:         path,
	}
}

func (r *httpRoundTripper) RoundTrip(
	ctx context.Context, requestPayload []byte) ([]byte, error) {

	url := fmt.Sprintf("https://%s/%s", r.endpointAddr, r.path)

	request, err := http.NewRequestWithContext(
		ctx, "POST", url, bytes.NewReader(requestPayload))
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
