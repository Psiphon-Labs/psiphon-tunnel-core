/*
 * Copyright (c) 2017, Psiphon Inc.
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
	crypto_rand "crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/inproxy"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/monotime"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/parameters"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/tactics"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/transforms"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

var KB = 1024
var MB = KB * KB

func TestCachedResponse(t *testing.T) {

	rand.Seed(time.Now().Unix())

	testCases := []struct {
		concurrentResponses int
		responseSize        int
		bufferSize          int
		extendedBufferSize  int
		extendedBufferCount int
		extendedBufferLimit int
		minBytesPerWrite    int
		maxBytesPerWrite    int
		copyPosition        int
		expectedSuccess     bool
	}{
		{1, 16, 16, 0, 0, -1, 1, 1, 0, true},

		{1, 31, 16, 0, 0, -1, 1, 1, 15, true},

		{1, 16, 2, 2, 7, -1, 1, 1, 0, true},

		{1, 31, 15, 3, 5, -1, 1, 1, 1, true},

		{1, 16, 16, 0, 0, -1, 1, 1, 16, true},

		{1, 64*KB + 1, 64 * KB, 64 * KB, 1, -1, 1, 1 * KB, 64 * KB, true},

		{1, 10 * MB, 64 * KB, 64 * KB, 158, -1, 1, 32 * KB, 0, false},

		{1, 10 * MB, 64 * KB, 64 * KB, 159, -1, 1, 32 * KB, 0, true},

		{1, 10 * MB, 64 * KB, 64 * KB, 160, -1, 1, 32 * KB, 0, true},

		{1, 128 * KB, 64 * KB, 0, 0, -1, 1, 1 * KB, 64 * KB, true},

		{1, 128 * KB, 64 * KB, 0, 0, -1, 1, 1 * KB, 63 * KB, false},

		{1, 200 * KB, 64 * KB, 0, 0, -1, 1, 1 * KB, 136 * KB, true},

		{10, 10 * MB, 64 * KB, 64 * KB, 1589, -1, 1, 32 * KB, 0, false},

		{10, 10 * MB, 64 * KB, 64 * KB, 1590, -1, 1, 32 * KB, 0, true},

		{10, 10 * MB, 64 * KB, 64 * KB, 1590, 32, 1, 32 * KB, 0, false},
	}

	for _, testCase := range testCases {
		description := fmt.Sprintf("test case: %+v", testCase)
		t.Run(description, func(t *testing.T) {

			limit := testCase.extendedBufferCount
			if testCase.extendedBufferLimit != -1 {
				limit = testCase.extendedBufferLimit
			}

			pool := NewCachedResponseBufferPool(
				testCase.extendedBufferSize, testCase.extendedBufferCount, limit)

			responses := make([]*CachedResponse, testCase.concurrentResponses)
			for i := 0; i < testCase.concurrentResponses; i++ {
				responses[i] = NewCachedResponse(testCase.bufferSize, pool)
			}

			// Repeats exercise CachedResponse.Reset() and CachedResponseBufferPool replacement
			for repeat := 0; repeat < 2; repeat++ {

				t.Logf("repeat %d", repeat)

				responseData := make([]byte, testCase.responseSize)
				_, _ = rand.Read(responseData)

				waitGroup := new(sync.WaitGroup)

				// Goroutines exercise concurrent access to CachedResponseBufferPool
				for _, response := range responses {
					waitGroup.Add(1)
					go func(response *CachedResponse) {
						defer waitGroup.Done()

						remainingSize := testCase.responseSize
						for remainingSize > 0 {

							writeSize := testCase.minBytesPerWrite
							writeSize += rand.Intn(testCase.maxBytesPerWrite - testCase.minBytesPerWrite + 1)
							if writeSize > remainingSize {
								writeSize = remainingSize
							}

							offset := len(responseData) - remainingSize
							response.Write(responseData[offset : offset+writeSize])
							remainingSize -= writeSize
						}
					}(response)
				}

				waitGroup.Wait()

				atLeastOneFailure := false

				for i, response := range responses {

					cachedResponseData := new(bytes.Buffer)

					n, err := response.CopyFromPosition(testCase.copyPosition, cachedResponseData)

					if testCase.expectedSuccess {
						if err != nil {
							t.Fatalf("CopyFromPosition unexpectedly failed for response %d: %s", i, err)
						}
						if n != cachedResponseData.Len() || n > response.Available() {
							t.Fatalf("cached response size mismatch for response %d", i)
						}
						if !bytes.Equal(responseData[testCase.copyPosition:], cachedResponseData.Bytes()) {
							t.Fatalf("cached response data mismatch for response %d", i)
						}
					} else {
						atLeastOneFailure = true
					}
				}

				if !testCase.expectedSuccess && !atLeastOneFailure {
					t.Fatalf("CopyFromPosition unexpectedly succeeded for all responses")
				}

				for _, response := range responses {
					response.Reset()
				}
			}
		})
	}
}

func TestMeekResiliency(t *testing.T) {
	testMeekResiliency(t, nil, false, false)
}

func TestMeekResiliencyWithPayloadPadding(t *testing.T) {
	testMeekResiliency(t, nil, false, true)
}

func TestMeekHTTPNormalizerResiliency(t *testing.T) {
	testMeekHTTPNormalizerResiliency(t, false)
}

func TestMeekHTTPNormalizerResiliencyWithPayloadPadding(t *testing.T) {
	testMeekHTTPNormalizerResiliency(t, true)
}

func testMeekHTTPNormalizerResiliency(
	t *testing.T,
	enablePayloadPadding bool) {

	seed, err := prng.NewSeed()
	if err != nil {
		t.Fatalf("prng.NewSeed failed %v", err)
	}

	spec := &transforms.HTTPTransformerParameters{
		ProtocolTransformName: "spec1",
		ProtocolTransformSpec: transforms.Spec{{"Host: example.com\r\n", ""}},
		ProtocolTransformSeed: seed,
	}

	testMeekResiliency(t, spec, true, enablePayloadPadding)
}

func testMeekResiliency(
	t *testing.T,
	spec *transforms.HTTPTransformerParameters,
	useHTTPNormalizer bool,
	enablePayloadPadding bool) {

	totalSize := 5 * MB

	upstreamData := make([]byte, totalSize)
	_, _ = rand.Read(upstreamData)

	downstreamData := make([]byte, totalSize)
	_, _ = rand.Read(downstreamData)

	minWrite, maxWrite := 1, 128*KB
	minRead, maxRead := 1, 128*KB
	minWait, maxWait := 1*time.Millisecond, 500*time.Millisecond

	sendFunc := func(name string, conn net.Conn, data []byte) {
		for sent := 0; sent < len(data); {
			wait := minWait + time.Duration(rand.Int63n(int64(maxWait-minWait)+1))
			time.Sleep(wait)
			writeLen := minWrite + rand.Intn(maxWrite-minWrite+1)
			writeLen = min(writeLen, len(data)-sent)
			_, err := conn.Write(data[sent : sent+writeLen])
			if err != nil {
				t.Errorf("conn.Write failed: %s", err)
				return
			}
			sent += writeLen
			fmt.Printf("%s sent %d/%d...\n", name, sent, len(data))
		}
		fmt.Printf("%s send complete\n", name)
	}

	recvFunc := func(name string, conn net.Conn, expectedData []byte) {
		data := make([]byte, len(expectedData))
		for received := 0; received < len(data); {
			wait := minWait + time.Duration(rand.Int63n(int64(maxWait-minWait)+1))
			time.Sleep(wait)
			readLen := minRead + rand.Intn(maxRead-minRead+1)
			readLen = min(readLen, len(data)-received)
			n, err := conn.Read(data[received : received+readLen])
			if err != nil {
				t.Errorf("conn.Read failed: %s", err)
				return
			}
			received += n
			if !bytes.Equal(data[0:received], expectedData[0:received]) {
				fmt.Printf("%s data check has failed...\n", name)
				additionalInfo := ""
				index := bytes.Index(expectedData, data[received-n:received])
				if index != -1 {
					// Helpful for debugging missing or repeated data...
					additionalInfo = fmt.Sprintf(
						" (last read of %d appears at %d)", n, index)
				}
				t.Errorf("%s got unexpected data with %d/%d%s",
					name, received, len(expectedData), additionalInfo)
				return
			}
			fmt.Printf("%s received %d/%d...\n", name, received, len(expectedData))
		}
		fmt.Printf("%s receive complete\n", name)
	}

	// Run meek server

	rawMeekCookieEncryptionPublicKey, rawMeekCookieEncryptionPrivateKey, err := box.GenerateKey(crypto_rand.Reader)
	if err != nil {
		t.Fatalf("box.GenerateKey failed: %s", err)
	}
	meekCookieEncryptionPublicKey := base64.StdEncoding.EncodeToString(rawMeekCookieEncryptionPublicKey[:])
	meekCookieEncryptionPrivateKey := base64.StdEncoding.EncodeToString(rawMeekCookieEncryptionPrivateKey[:])
	meekObfuscatedKey := prng.HexString(SSH_OBFUSCATED_KEY_BYTE_LENGTH)

	mockSupport := &SupportServices{
		Config: &Config{
			MeekObfuscatedKey:              meekObfuscatedKey,
			MeekCookieEncryptionPrivateKey: meekCookieEncryptionPrivateKey,
			TunnelProtocolPorts: map[string]int{
				protocol.TUNNEL_PROTOCOL_UNFRONTED_MEEK: 0,
			},
			runningProtocols: []string{protocol.TUNNEL_PROTOCOL_UNFRONTED_MEEK},

			// Default MeekCachedResponsePoolBufferSize, 64K, may be
			// insufficient for total downstream. Leave private pool at
			// default size but add sufficiently large shared buffers.
			MeekCachedResponsePoolBufferSize: totalSize,
		},
		TrafficRulesSet: &TrafficRulesSet{},
	}
	mockSupport.GeoIPService, _ = NewGeoIPService([]string{})

	// MeekServer requires a wired-up ServerTacticsParametersCache for
	// meek payload padding. The default parameter values are used.

	tacticsConfigFilename := filepath.Join(testDataDirName, "tactics_config.json")

	tacticsConfigJSON := `
    {
      "DefaultTactics" : {
        "TTL" : "60s",
        "Probability" : 1.0,
        "Parameters" : {
        }
      }
    }
    `
	err = ioutil.WriteFile(tacticsConfigFilename, []byte(tacticsConfigJSON), 0600)
	if err != nil {
		t.Fatalf("error paving tactics config file: %s", err)
	}

	tacticsRequestPublicKey, tacticsRequestPrivateKey, tacticsRequestObfuscatedKey, err :=
		tactics.GenerateKeys()
	if err != nil {
		t.Fatalf("error generating tactics keys: %s", err)
	}

	tacticsServer, err := tactics.NewServer(
		nil, nil, nil,
		tacticsConfigFilename,
		tacticsRequestPublicKey,
		tacticsRequestPrivateKey,
		tacticsRequestObfuscatedKey)
	if err != nil {
		t.Fatalf("tactics.NewServer failed: %s", err)
	}

	mockSupport.TacticsServer = tacticsServer
	mockSupport.ServerTacticsParametersCache = NewServerTacticsParametersCache(mockSupport)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen failed: %s", err)
	}
	defer listener.Close()

	serverAddress := listener.Addr().String()

	relayWaitGroup := new(sync.WaitGroup)

	var serverClientConn atomic.Value

	clientHandler := func(conn net.Conn, _ *additionalTransportData) {
		serverClientConn.Store(conn)
		name := "server"
		relayWaitGroup.Add(1)
		go func() {
			defer relayWaitGroup.Done()
			sendFunc(name, conn, downstreamData)
		}()
		relayWaitGroup.Add(1)
		go func() {
			defer relayWaitGroup.Done()
			recvFunc(name, conn, upstreamData)
		}()
	}

	stopBroadcast := make(chan struct{})

	useTLS := false
	isFronted := false
	useObfuscatedSessionTickets := false

	server, err := NewMeekServer(
		mockSupport,
		listener,
		protocol.TUNNEL_PROTOCOL_UNFRONTED_MEEK,
		0,
		useTLS,
		isFronted,
		useObfuscatedSessionTickets,
		useHTTPNormalizer,
		clientHandler,
		stopBroadcast)
	if err != nil {
		t.Fatalf("NewMeekServer failed: %s", err)
	}

	serverWaitGroup := new(sync.WaitGroup)

	serverWaitGroup.Add(1)
	go func() {
		defer serverWaitGroup.Done()
		err := server.Run()
		select {
		case <-stopBroadcast:
			return
		default:
		}
		if err != nil {
			t.Errorf("MeekServer.Run failed: %s", err)
		}
	}()

	// Run meek client

	dialConfig := &psiphon.DialConfig{
		DeviceBinder: new(fileDescriptorInterruptor),
		ResolveIP: func(_ context.Context, host string) ([]net.IP, error) {
			return []net.IP{net.ParseIP(host)}, nil
		},
	}

	params, err := parameters.NewParameters(nil)
	if err != nil {
		t.Fatalf("NewParameters failed: %s", err)
	}

	meekObfuscatorPaddingSeed, err := prng.NewSeed()
	if err != nil {
		t.Fatalf("prng.NewSeed failed: %s", err)
	}
	meekConfig := &psiphon.MeekConfig{
		Parameters:                    params,
		DialAddress:                   serverAddress,
		UseHTTPS:                      useTLS,
		UseObfuscatedSessionTickets:   useObfuscatedSessionTickets,
		HostHeader:                    "example.com",
		MeekCookieEncryptionPublicKey: meekCookieEncryptionPublicKey,
		MeekObfuscatedKey:             meekObfuscatedKey,
		MeekObfuscatorPaddingSeed:     meekObfuscatorPaddingSeed,
		ClientTunnelProtocol:          protocol.TUNNEL_PROTOCOL_UNFRONTED_MEEK,
		HTTPTransformerParameters:     spec,
	}

	if enablePayloadPadding {

		p, err := mockSupport.ServerTacticsParametersCache.Get(GeoIPData{})
		if err != nil {
			t.Fatalf("ServerTacticsParametersCache.Get failed: %s", err)
		}

		meekConfig.EnablePayloadPadding = true
		meekConfig.PayloadPaddingOmitProbability =
			p.Float(parameters.MeekPayloadPaddingClientOmitProbability)
		meekConfig.PayloadPaddingMinSize =
			p.Int(parameters.MeekPayloadPaddingClientMinSize)
		meekConfig.PayloadPaddingMaxSize =
			p.Int(parameters.MeekPayloadPaddingClientMaxSize)
	}

	ctx, cancelFunc := context.WithTimeout(
		context.Background(), time.Second*5)
	defer cancelFunc()

	clientConn, err := psiphon.DialMeek(ctx, meekConfig, dialConfig)
	if err != nil {
		t.Fatalf("psiphon.DialMeek failed: %s", err)
	}

	// Relay data through meek while interrupting underlying TCP connections

	name := "client"
	relayWaitGroup.Add(1)
	go func() {
		defer relayWaitGroup.Done()
		sendFunc(name, clientConn, upstreamData)
	}()

	relayWaitGroup.Add(1)
	go func() {
		defer relayWaitGroup.Done()
		recvFunc(name, clientConn, downstreamData)
	}()

	relayWaitGroup.Wait()

	// Check for multiple underlying connections

	metrics := serverClientConn.Load().(common.MetricsSource).GetMetrics()
	count := metrics["meek_underlying_connection_count"].(int64)
	if count <= 1 {
		t.Fatalf("unexpected meek_underlying_connection_count: %d", count)
	}

	// Graceful shutdown

	clientConn.Close()

	listener.Close()
	close(stopBroadcast)

	// This wait will hang if shutdown is broken, and the test will ultimately panic
	serverWaitGroup.Wait()
}

type fileDescriptorInterruptor struct {
}

func (interruptor *fileDescriptorInterruptor) BindToDevice(fileDescriptor int) (string, error) {
	fdDup, err := syscall.Dup(fileDescriptor)
	if err != nil {
		return "", err
	}
	minAfter := 500 * time.Millisecond
	maxAfter := 1 * time.Second
	after := minAfter + time.Duration(rand.Int63n(int64(maxAfter-minAfter)+1))
	time.AfterFunc(after, func() {
		syscall.Shutdown(fdDup, syscall.SHUT_RDWR)
		syscall.Close(fdDup)
		fmt.Printf("interrupted TCP connection\n")
	})
	return "", nil
}

func TestMeekServer(t *testing.T) {
	runTestMeekAccessControl(t, false, false, false)
}

func TestMeekBrokerHTTP2MaxConcurrentStreams(t *testing.T) {
	// Use net/http's default setting for comparison, and reuse its test TLS
	// certificate for the MeekServer listeners.
	defaultServer := httptest.NewUnstartedServer(nil)
	defaultServer.EnableHTTP2 = true
	defaultServer.StartTLS()
	defer defaultServer.Close()
	defaultMaxStreams := readHTTP2MaxConcurrentStreams(t, defaultServer.Listener.Addr().String())

	for _, testCase := range []struct {
		name       string
		broker     bool
		configured int
		expected   uint32
	}{
		{"broker_default", true, 0, 1500},
		{"broker_override", true, 2400, 2400},
		{"broker_minimum", true, 1, 1},
		{"non_broker_default", false, 0, defaultMaxStreams},
		{"non_broker_override_ignored", false, 2400, defaultMaxStreams},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			stopBroadcast := make(chan struct{})
			server := &MeekServer{
				support: &SupportServices{Config: &Config{
					InproxyBrokerHTTP2MaxConcurrentStreams: testCase.configured,
				}},
				listener:            listener,
				stdTLSConfig:        defaultServer.TLS.Clone(),
				maxSessionStaleness: MEEK_DEFAULT_MAX_SESSION_STALENESS,
				openConns:           common.NewConns[net.Conn](),
				stopBroadcast:       stopBroadcast,
			}
			if testCase.broker {
				privateKey, err := inproxy.GenerateSessionPrivateKey()
				if err != nil {
					t.Fatal(err)
				}
				server.inproxyBroker, err = inproxy.NewBroker(&inproxy.BrokerConfig{
					Logger:                           CommonLogger(log),
					PrivateKey:                       privateKey,
					CommonCompartmentIDs:             []inproxy.ID{{1}},
					ObfuscationAntiReplayHistorySize: -1,
				})
				if err != nil {
					t.Fatal(err)
				}
			}

			runDone := make(chan error, 1)
			go func() { runDone <- server.Run() }()
			defer func() {
				close(stopBroadcast)
				listener.Close()
				select {
				case err := <-runDone:
					if err != nil {
						t.Errorf("MeekServer.Run failed: %v", err)
					}
				case <-time.After(5 * time.Second):
					t.Error("MeekServer.Run did not stop")
				}
			}()

			if actual := readHTTP2MaxConcurrentStreams(t, listener.Addr().String()); actual != testCase.expected {
				t.Fatalf("advertised max concurrent streams = %d; want %d", actual, testCase.expected)
			}
		})
	}
}

// Read the actual HTTP/2 SETTINGS frame to check the net/http configuration
// used by MeekServer on a listener with standard TLS and HTTP/2 enabled.
func readHTTP2MaxConcurrentStreams(t *testing.T, address string) uint32 {
	t.Helper()

	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 5 * time.Second}, "tcp", address,
		&tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if conn.ConnectionState().NegotiatedProtocol != "h2" {
		t.Fatal("HTTP/2 was not negotiated")
	}
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(conn, http2.ClientPreface); err != nil {
		t.Fatal(err)
	}
	framer := http2.NewFramer(conn, conn)
	if err := framer.WriteSettings(); err != nil {
		t.Fatal(err)
	}
	frame, err := framer.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	settings, ok := frame.(*http2.SettingsFrame)
	if !ok {
		t.Fatalf("expected SETTINGS frame, got %T", frame)
	}
	maxStreams, ok := settings.Value(http2.SettingMaxConcurrentStreams)
	if !ok {
		t.Fatal("missing SETTINGS_MAX_CONCURRENT_STREAMS")
	}
	return maxStreams
}

func TestMeekRateLimiter(t *testing.T) {
	runTestMeekAccessControl(t, true, false, false)
}

func TestMeekRestrictFrontingProviders(t *testing.T) {
	runTestMeekAccessControl(t, false, true, false)
}

func TestMeekMissingRequiredHeaders(t *testing.T) {
	runTestMeekAccessControl(t, false, false, true)
}

func TestMeekSessionDeleteInterruptsReads(t *testing.T) {
	for _, useHTTP2 := range []bool{false, true} {
		name := "HTTP1"
		if useHTTP2 {
			name = "HTTP2"
		}
		t.Run(name, func(t *testing.T) {
			server, httpServer, connections := newMeekSessionTestHTTPServer(t, useHTTP2)
			session := newMeekSessionTestSession(server, "stalled")
			if _, err := session.cachedResponse.Write(make([]byte, 2*MEEK_DEFAULT_RESPONSE_BUFFER_LENGTH)); err != nil {
				t.Fatal(err)
			}
			if len(server.bufferPool.buffers) == cap(server.bufferPool.buffers) {
				t.Fatal("test did not borrow a response buffer")
			}

			reading := make(chan struct{})
			handlerDone := make(chan struct{})
			httpServer.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/stalled" {
					r.Body = &meekSessionTestRequestBody{ReadCloser: r.Body, reading: reading}
					defer close(handlerDone)
					if (r.ProtoMajor == 2) != useHTTP2 {
						t.Errorf("unexpected protocol: %s", r.Proto)
					}
				}
				server.ServeHTTP(w, r)
			})
			httpServer.StartTLS()
			client := httpServer.Client()
			client.Timeout = time.Minute
			client.Transport.(*http.Transport).MaxConnsPerHost = 1
			t.Cleanup(client.CloseIdleConnections)

			reader, writer := io.Pipe()
			t.Cleanup(func() { writer.Close() })
			request, err := http.NewRequest(http.MethodPost, httpServer.URL+"/stalled", reader)
			if err != nil {
				t.Fatal(err)
			}
			request.AddCookie(&http.Cookie{Name: "session", Value: "stalled"})
			requestDone := make(chan struct{})
			go func() {
				defer close(requestDone)
				response, err := client.Do(request)
				if err == nil {
					response.Body.Close()
				}
			}()
			if _, err := writer.Write([]byte{1}); err != nil {
				t.Fatal(err)
			}
			waitForMeekSessionTest(t, reading, "request body read")

			reapMeekSessionTestSession(t, server, session, "stalled")
			waitForMeekSessionTest(t, handlerDone, "request handler")
			writer.Close()
			waitForMeekSessionTest(t, requestDone, "client request")

			if useHTTP2 {
				healthy := newMeekSessionTestSession(server, "healthy")
				t.Cleanup(func() { healthy.clientConn.Close() })
				writeDone := make(chan struct{})
				var writeErr error
				go func() {
					defer close(writeDone)
					_, writeErr = healthy.clientConn.Write([]byte("ok"))
				}()
				request, err := http.NewRequest(http.MethodPost, httpServer.URL+"/healthy", nil)
				if err != nil {
					t.Fatal(err)
				}
				request.AddCookie(&http.Cookie{Name: "session", Value: "healthy"})
				response, err := client.Do(request)
				if err != nil {
					t.Fatal(err)
				}
				data, err := io.ReadAll(response.Body)
				response.Body.Close()
				if err != nil || string(data) != "ok" {
					t.Fatalf("healthy response: %q, %v", data, err)
				}
				waitForMeekSessionTest(t, writeDone, "healthy session write")
				if writeErr != nil {
					t.Fatal(writeErr)
				}
				if connections.Load() != 1 {
					t.Fatal("HTTP/2 connection was replaced")
				}
			}
		})
	}
}

func TestMeekSessionDeleteInterruptsWrites(t *testing.T) {
	server, httpServer, connections := newMeekSessionTestHTTPServer(t, true)
	session := newMeekSessionTestSession(server, "stalled")
	t.Cleanup(func() { session.clientConn.Close() })
	handlerDone := make(chan struct{})
	httpServer.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/stalled" {
			defer close(handlerDone)
		}
		server.ServeHTTP(w, r)
	})
	httpServer.StartTLS()
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 5 * time.Second}, "tcp", httpServer.Listener.Addr().String(),
		&tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	if conn.ConnectionState().NegotiatedProtocol != "h2" {
		t.Fatal("HTTP/2 was not negotiated")
	}
	if err := conn.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(conn, http2.ClientPreface); err != nil {
		t.Fatal(err)
	}
	framer := http2.NewFramer(conn, conn)
	// Block DATA writes while allowing the response headers through.
	if err := framer.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 0}); err != nil {
		t.Fatal(err)
	}
	writeMeekSessionTestHTTP2Request(t, framer, 1, "stalled")
	writeDone := make(chan struct{})
	go func() {
		defer close(writeDone)
		session.clientConn.Write(make([]byte, MEEK_MAX_REQUEST_PAYLOAD_LENGTH))
	}()
	for {
		frame := readMeekSessionTestHTTP2Frame(t, framer)
		if headers, ok := frame.(*http2.HeadersFrame); ok && headers.StreamID == 1 {
			if headers.StreamEnded() {
				t.Fatal("response finished before blocking on flow control")
			}
			break
		}
	}
	select {
	case <-handlerDone:
		t.Fatal("handler finished despite the zero stream window")
	default:
	}

	reapMeekSessionTestSession(t, server, session, "stalled")
	waitForMeekSessionTest(t, handlerDone, "request handler")
	waitForMeekSessionTest(t, writeDone, "session write")

	healthy := newMeekSessionTestSession(server, "healthy")
	t.Cleanup(func() { healthy.clientConn.Close() })
	healthyDone := make(chan struct{})
	var healthyErr error
	go func() {
		defer close(healthyDone)
		_, healthyErr = healthy.clientConn.Write([]byte("ok"))
	}()
	writeMeekSessionTestHTTP2Request(t, framer, 3, "healthy")
	if err := framer.WriteWindowUpdate(3, 65535); err != nil {
		t.Fatal(err)
	}
	var response []byte
	for {
		frame := readMeekSessionTestHTTP2Frame(t, framer)
		if reset, ok := frame.(*http2.RSTStreamFrame); ok && reset.StreamID == 3 {
			t.Fatalf("healthy stream reset: %v", reset.ErrCode)
		}
		if data, ok := frame.(*http2.DataFrame); ok && data.StreamID == 3 {
			response = append(response, data.Data()...)
			if data.StreamEnded() {
				break
			}
		}
	}
	if string(response) != "ok" || connections.Load() != 1 {
		t.Fatalf("healthy response: %q, connections: %d", response, connections.Load())
	}
	waitForMeekSessionTest(t, healthyDone, "healthy session write")
	if healthyErr != nil {
		t.Fatal(healthyErr)
	}
}

func TestMeekSessionDeleteIdlePreservesHTTP1Connection(t *testing.T) {
	server, httpServer, connections := newMeekSessionTestHTTPServer(t, false)
	// Keep the handler waiting in pumpWrites after its first write.
	server.extendedTurnAroundTimeout = time.Minute
	session := newMeekSessionTestSession(server, "idle")
	httpServer.StartTLS()
	client := httpServer.Client()
	client.Timeout = time.Minute
	client.Transport.(*http.Transport).MaxConnsPerHost = 1
	t.Cleanup(client.CloseIdleConnections)

	post := func(id string) (string, error) {
		request, err := http.NewRequest(http.MethodPost, httpServer.URL+"/"+id, nil)
		if err != nil {
			return "", err
		}
		request.AddCookie(&http.Cookie{Name: "session", Value: id})
		response, err := client.Do(request)
		if err != nil {
			return "", err
		}
		defer response.Body.Close()
		data, err := io.ReadAll(response.Body)
		return string(data), err
	}

	idleDone := make(chan struct{})
	var idleData string
	var idleErr error
	go func() {
		defer close(idleDone)
		idleData, idleErr = post("idle")
	}()
	// Write returns once the handler has written the payload and is back
	// waiting in pumpWrites, outside of HTTP I/O.
	if _, err := session.clientConn.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	reapMeekSessionTestSession(t, server, session, "idle")
	waitForMeekSessionTest(t, idleDone, "idle request")
	if idleErr != nil || idleData != "x" {
		t.Fatalf("idle response: %q, %v", idleData, idleErr)
	}

	healthy := newMeekSessionTestSession(server, "healthy")
	t.Cleanup(func() { healthy.clientConn.Close() })
	go func() {
		healthy.clientConn.Write([]byte("ok"))
		healthy.clientConn.Close()
	}()
	data, err := post("healthy")
	if err != nil || data != "ok" {
		t.Fatalf("healthy response: %q, %v", data, err)
	}
	if connections.Load() != 1 {
		t.Fatal("HTTP/1 connection was replaced")
	}
}

func TestMeekSessionRequestLifecycle(t *testing.T) {
	for _, timing := range []string{
		"before_registration", "idle", "during_return", "after_return", "with_lock",
		"with_lock_before_return"} {
		t.Run(timing, func(t *testing.T) {
			server := newMeekSessionTestServer()
			session := newMeekSessionTestSession(server, "session")
			writer := &meekSessionTestResponseWriter{ResponseRecorder: httptest.NewRecorder()}
			session.lock.Lock()
			switch timing {
			case "before_registration":
				done := make(chan struct{})
				go func() { session.delete(false); close(done) }()
				waitForMeekSessionTest(t, session.clientConn.closeBroadcast, "connection close")
				if session.startRequest(writer, nil) {
					t.Error("request started after deletion began")
					session.finishRequest()
				}
				session.lock.Unlock()
				waitForMeekSessionTest(t, done, "deletion")

			case "idle":
				if !session.startRequest(writer, nil) {
					t.Fatal("request rejected")
				}
				done := make(chan struct{})
				go func() { session.delete(false); close(done) }()
				waitForMeekSessionTest(t, session.clientConn.closeBroadcast, "connection close")
				if session.startIO() {
					t.Error("I/O started after deletion began")
					session.finishIO()
				}
				session.finishRequest()
				writer.returned.Store(true)
				session.lock.Unlock()
				waitForMeekSessionTest(t, done, "deletion")

			case "during_return":
				writer.deadlineStarted = make(chan struct{})
				writer.releaseDeadline = make(chan struct{})
				if !session.startRequest(writer, nil) || !session.startIO() {
					t.Fatal("request rejected")
				}
				deleted := make(chan struct{})
				go func() { session.delete(false); close(deleted) }()
				waitForMeekSessionTest(t, writer.deadlineStarted, "deadline call")
				if session.requestMutex.TryLock() {
					session.requestMutex.Unlock()
					t.Error("request mutex not held during interruption")
				}
				returned := make(chan struct{})
				go func() {
					session.finishIO()
					session.finishRequest()
					writer.returned.Store(true)
					session.lock.Unlock()
					close(returned)
				}()
				close(writer.releaseDeadline)
				waitForMeekSessionTest(t, returned, "handler return")
				waitForMeekSessionTest(t, deleted, "deletion")
				if writer.deadlines.Load() != 2 {
					t.Error("read and write deadlines were not both set")
				}

			case "after_return", "with_lock":
				if !session.startRequest(writer, nil) {
					t.Fatal("request rejected")
				}
				if timing == "with_lock" {
					session.delete(true)
				}
				session.finishRequest()
				writer.returned.Store(true)
				session.lock.Unlock()
				session.delete(false)

			case "with_lock_before_return":
				// The handler deleted the session and has not yet returned,
				// so its response writer is still registered. The reaper
				// must not interrupt the handler's pending error response.
				if !session.startRequest(writer, nil) {
					t.Fatal("request rejected")
				}
				session.delete(true)
				// Release the lock so that delete(false) completes; its
				// interrupt decision is made before it waits for the lock.
				session.lock.Unlock()
				session.delete(false)
				session.finishRequest()
				writer.returned.Store(true)
			}
			if writer.lateDeadline.Load() {
				t.Error("deadline set after handler return")
			}
			if timing != "during_return" && writer.deadlines.Load() != 0 {
				t.Error("unexpected deadline call")
			}
		})
	}
}

func runTestMeekAccessControl(t *testing.T, rateLimit, restrictProvider, missingRequiredHeaders bool) {

	attempts := 10

	allowedConnections := 5

	if !rateLimit {
		allowedConnections = 10
	}

	if restrictProvider {
		allowedConnections = 0
	}

	if missingRequiredHeaders {
		allowedConnections = 0
	}

	// Configure tactics

	frontingProviderID := prng.HexString(8)

	tacticsConfigJSONFormat := `
    {
      "RequestPublicKey" : "%s",
      "RequestPrivateKey" : "%s",
      "RequestObfuscatedKey" : "%s",
      "DefaultTactics" : {
        "TTL" : "60s",
        "Probability" : 1.0,
        "Parameters" : {
          "RestrictFrontingProviderIDs" : ["%s"],
          "RestrictFrontingProviderIDsServerProbability" : 1.0
        }
      }
    }
    `

	tacticsRequestPublicKey, tacticsRequestPrivateKey, tacticsRequestObfuscatedKey, err :=
		tactics.GenerateKeys()
	if err != nil {
		t.Fatalf("error generating tactics keys: %s", err)
	}

	restrictFrontingProviderID := ""

	if restrictProvider {
		restrictFrontingProviderID = frontingProviderID
	}

	tacticsConfigJSON := fmt.Sprintf(
		tacticsConfigJSONFormat,
		tacticsRequestPublicKey, tacticsRequestPrivateKey, tacticsRequestObfuscatedKey,
		restrictFrontingProviderID)

	tacticsConfigFilename := filepath.Join(testDataDirName, "tactics_config.json")

	err = ioutil.WriteFile(tacticsConfigFilename, []byte(tacticsConfigJSON), 0600)
	if err != nil {
		t.Fatalf("error paving tactics config file: %s", err)
	}

	// Run meek server

	rawMeekCookieEncryptionPublicKey, rawMeekCookieEncryptionPrivateKey, err := box.GenerateKey(crypto_rand.Reader)
	if err != nil {
		t.Fatalf("box.GenerateKey failed: %s", err)
	}
	meekCookieEncryptionPublicKey := base64.StdEncoding.EncodeToString(rawMeekCookieEncryptionPublicKey[:])
	meekCookieEncryptionPrivateKey := base64.StdEncoding.EncodeToString(rawMeekCookieEncryptionPrivateKey[:])
	meekObfuscatedKey := prng.HexString(SSH_OBFUSCATED_KEY_BYTE_LENGTH)

	tunnelProtocol := protocol.TUNNEL_PROTOCOL_FRONTED_MEEK

	meekRateLimiterTunnelProtocols := []string{tunnelProtocol}
	if !rateLimit {
		meekRateLimiterTunnelProtocols = []string{protocol.TUNNEL_PROTOCOL_FRONTED_MEEK}
	}

	requiredHeaderName := "X-Psiphon-Required-Header"
	requiredHeaderValue := prng.Base64String(32)

	mockSupport := &SupportServices{
		Config: &Config{
			MeekObfuscatedKey:              meekObfuscatedKey,
			MeekCookieEncryptionPrivateKey: meekCookieEncryptionPrivateKey,
			MeekRequiredHeaders:            map[string]string{requiredHeaderName: requiredHeaderValue},
			TunnelProtocolPorts:            map[string]int{tunnelProtocol: 0},
			frontingProviderID:             frontingProviderID,
		},
		TrafficRulesSet: &TrafficRulesSet{
			MeekRateLimiterHistorySize:                   allowedConnections,
			MeekRateLimiterThresholdSeconds:              attempts,
			MeekRateLimiterTunnelProtocols:               meekRateLimiterTunnelProtocols,
			MeekRateLimiterGarbageCollectionTriggerCount: 1,
			MeekRateLimiterReapHistoryFrequencySeconds:   1,
		},
	}
	mockSupport.GeoIPService, _ = NewGeoIPService([]string{})

	tacticsServer, err := tactics.NewServer(nil, nil, nil, tacticsConfigFilename, "", "", "")
	if err != nil {
		t.Fatalf("tactics.NewServer failed: %s", err)
	}

	mockSupport.TacticsServer = tacticsServer
	mockSupport.ServerTacticsParametersCache = NewServerTacticsParametersCache(mockSupport)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen failed: %s", err)
	}
	defer listener.Close()

	serverAddress := listener.Addr().String()

	stopBroadcast := make(chan struct{})

	useTLS := false
	isFronted := false
	useObfuscatedSessionTickets := false
	useHTTPNormalizer := false

	server, err := NewMeekServer(
		mockSupport,
		listener,
		tunnelProtocol,
		0,
		useTLS,
		isFronted,
		useObfuscatedSessionTickets,
		useHTTPNormalizer,
		func(conn net.Conn, _ *additionalTransportData) {
			go func() {
				for {
					buffer := make([]byte, 1)
					n, err := conn.Read(buffer)
					if err == nil && n == 1 {
						_, err = conn.Write(buffer)
					}
					if err != nil {
						conn.Close()
						break
					}
				}
			}()
		},
		stopBroadcast)
	if err != nil {
		t.Fatalf("NewMeekServer failed: %s", err)
	}

	serverWaitGroup := new(sync.WaitGroup)

	serverWaitGroup.Add(1)
	go func() {
		defer serverWaitGroup.Done()
		err := server.Run()
		select {
		case <-stopBroadcast:
			return
		default:
		}
		if err != nil {
			t.Errorf("MeekServer.Run failed: %s", err)
		}
	}()

	// Run meek clients:
	// For 10 attempts, connect once per second vs. rate limit of 5-per-10 seconds,
	// so about half of the connections should be rejected by the rate limiter.

	totalConnections := 0
	totalFailures := 0

	for i := 0; i < attempts; i++ {

		dialConfig := &psiphon.DialConfig{
			ResolveIP: func(_ context.Context, host string) ([]net.IP, error) {
				return []net.IP{net.ParseIP(host)}, nil
			},
		}

		if !missingRequiredHeaders {
			headers := make(http.Header)
			headers.Add(requiredHeaderName, requiredHeaderValue)
			dialConfig.CustomHeaders = headers
		}

		params, err := parameters.NewParameters(nil)
		if err != nil {
			t.Fatalf("NewParameters failed: %s", err)
		}

		meekObfuscatorPaddingSeed, err := prng.NewSeed()
		if err != nil {
			t.Fatalf("prng.NewSeed failed: %s", err)
		}

		meekConfig := &psiphon.MeekConfig{
			Parameters:                    params,
			DialAddress:                   serverAddress,
			HostHeader:                    "example.com",
			MeekCookieEncryptionPublicKey: meekCookieEncryptionPublicKey,
			MeekObfuscatedKey:             meekObfuscatedKey,
			MeekObfuscatorPaddingSeed:     meekObfuscatorPaddingSeed,
		}

		ctx, cancelFunc := context.WithTimeout(
			context.Background(), 500*time.Millisecond)
		defer cancelFunc()

		clientConn, err := psiphon.DialMeek(ctx, meekConfig, dialConfig)

		if err == nil {
			_, err = clientConn.Write([]byte{0})
		}
		if err == nil {
			buffer := make([]byte, 1)
			_, err = clientConn.Read(buffer)
		}

		if clientConn != nil {
			clientConn.Close()
		}

		if err != nil {
			totalFailures += 1
		} else {
			totalConnections += 1
		}

		if i < attempts-1 {
			time.Sleep(1 * time.Second)
		}
	}

	if totalConnections != allowedConnections ||
		totalFailures != attempts-totalConnections {

		t.Fatalf(
			"Unexpected results: %d connections, %d failures, %d allowed",
			totalConnections, totalFailures, allowedConnections)
	}

	// Graceful shutdown

	listener.Close()
	close(stopBroadcast)

	// This wait will hang if shutdown is broken, and the test will ultimately panic
	serverWaitGroup.Wait()
}

func newMeekSessionTestServer() *MeekServer {
	return &MeekServer{
		support:                         &SupportServices{Config: &Config{}},
		isFronted:                       true,
		sessions:                        make(map[string]*meekSession),
		bufferPool:                      NewCachedResponseBufferPool(MEEK_DEFAULT_POOL_BUFFER_LENGTH, 2, 2),
		maxSessionStaleness:             time.Minute,
		turnAroundTimeout:               time.Minute,
		skipExtendedTurnAroundThreshold: MEEK_DEFAULT_SKIP_EXTENDED_TURN_AROUND_THRESHOLD,
	}
}

func newMeekSessionTestHTTPServer(t *testing.T, useHTTP2 bool) (*MeekServer, *httptest.Server, *atomic.Int32) {
	t.Helper()
	server := newMeekSessionTestServer()
	httpServer := httptest.NewUnstartedServer(server)
	httpServer.EnableHTTP2 = useHTTP2
	httpServer.Config.ReadTimeout = time.Minute
	httpServer.Config.WriteTimeout = time.Minute
	connections := new(atomic.Int32)
	httpServer.Config.ConnContext = func(ctx context.Context, conn net.Conn) context.Context {
		connections.Add(1)
		return context.WithValue(ctx, meekNetConnContextKey, conn)
	}
	t.Cleanup(func() {
		httpServer.CloseClientConnections()
		httpServer.Close()
	})
	return server, httpServer, connections
}

func newMeekSessionTestSession(server *MeekServer, id string) *meekSession {
	session := &meekSession{
		meekProtocolVersion: MEEK_PROTOCOL_VERSION_2,
		cachedResponse:      NewCachedResponse(MEEK_DEFAULT_RESPONSE_BUFFER_LENGTH, server.bufferPool),
	}
	session.clientConn = newMeekConn(server, session, nil, &net.TCPAddr{}, MEEK_PROTOCOL_VERSION_2)
	session.touch()
	server.sessionsLock.Lock()
	server.sessions[id] = session
	server.sessionsLock.Unlock()
	return session
}

func waitForMeekSessionTest(t *testing.T, done <-chan struct{}, operation string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", operation)
	}
}

func reapMeekSessionTestSession(t *testing.T, server *MeekServer, session *meekSession, id string) {
	t.Helper()
	session.lastActivity.Store(int64(monotime.Now()) - int64(server.maxSessionStaleness+time.Second))
	done := make(chan struct{})
	go func() {
		server.deleteExpiredSessions()
		close(done)
	}()
	waitForMeekSessionTest(t, done, "session reaping")
	server.sessionsLock.RLock()
	_, present := server.sessions[id]
	server.sessionsLock.RUnlock()
	if present {
		t.Fatal("expired session was not removed")
	}
	if len(server.bufferPool.buffers) != cap(server.bufferPool.buffers) {
		t.Fatal("response buffers were not returned to the pool")
	}
}

type meekSessionTestRequestBody struct {
	io.ReadCloser
	reading chan struct{}
	reads   atomic.Int32
}

// Read signals on entry to the second Read. The first Read returns the byte
// the client has already sent; the second blocks awaiting more.
func (body *meekSessionTestRequestBody) Read(p []byte) (int, error) {
	if body.reads.Add(1) == 2 {
		close(body.reading)
	}
	return body.ReadCloser.Read(p)
}

type meekSessionTestResponseWriter struct {
	*httptest.ResponseRecorder
	deadlineStarted chan struct{}
	releaseDeadline chan struct{}
	returned        atomic.Bool
	lateDeadline    atomic.Bool
	deadlines       atomic.Int32
}

func (writer *meekSessionTestResponseWriter) SetReadDeadline(time.Time) error {
	writer.deadlines.Add(1)
	if writer.returned.Load() {
		writer.lateDeadline.Store(true)
	}
	if writer.deadlineStarted != nil {
		close(writer.deadlineStarted)
		<-writer.releaseDeadline
	}
	return nil
}

func (writer *meekSessionTestResponseWriter) SetWriteDeadline(time.Time) error {
	writer.deadlines.Add(1)
	if writer.returned.Load() {
		writer.lateDeadline.Store(true)
	}
	return nil
}

func writeMeekSessionTestHTTP2Request(t *testing.T, framer *http2.Framer, streamID uint32, id string) {
	t.Helper()
	var buffer bytes.Buffer
	encoder := hpack.NewEncoder(&buffer)
	encoder.SetMaxDynamicTableSize(0)
	for _, field := range []hpack.HeaderField{
		{Name: ":method", Value: http.MethodPost},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "example.com"},
		{Name: ":path", Value: "/" + id},
		{Name: "cookie", Value: "session=" + id},
	} {
		if err := encoder.WriteField(field); err != nil {
			t.Fatal(err)
		}
	}
	if err := framer.WriteHeaders(http2.HeadersFrameParam{
		StreamID: streamID, BlockFragment: buffer.Bytes(), EndHeaders: true, EndStream: true,
	}); err != nil {
		t.Fatal(err)
	}
}

func readMeekSessionTestHTTP2Frame(t *testing.T, framer *http2.Framer) http2.Frame {
	t.Helper()
	for {
		frame, err := framer.ReadFrame()
		if err != nil {
			t.Fatal(err)
		}
		switch frame := frame.(type) {
		case *http2.SettingsFrame:
			if !frame.IsAck() {
				if err := framer.WriteSettingsAck(); err != nil {
					t.Fatal(err)
				}
			}
			continue
		case *http2.GoAwayFrame:
			t.Fatalf("HTTP/2 connection closed: %v", frame.ErrCode)
		}
		return frame
	}
}
