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
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/parameters"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/tactics"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/transforms"
	"golang.org/x/crypto/nacl/box"
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

func TestMeekRateLimiter(t *testing.T) {
	runTestMeekAccessControl(t, true, false, false)
}

func TestMeekRestrictFrontingProviders(t *testing.T) {
	runTestMeekAccessControl(t, false, true, false)
}

func TestMeekMissingRequiredHeaders(t *testing.T) {
	runTestMeekAccessControl(t, false, false, true)
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
