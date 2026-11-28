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

package psiphon

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	psiphontls "github.com/Psiphon-Labs/psiphon-tls"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/inproxy"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/light"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/obfuscator"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/parameters"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/push"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/quic"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/tactics"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/tlsdialer"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/transforms"
	utls "github.com/Psiphon-Labs/utls"
)

func TestControllerLightFallbackProxy(t *testing.T) {
	if err := runTestControllerLightFallbackProxy(
		false, light.LIGHT_PROTOCOL_TLS); err != nil {

		t.Fatal(err.Error())
	}
}

func TestControllerLightFallbackProxyQUIC(t *testing.T) {
	if !quic.Enabled() {
		t.Skip("QUIC is not enabled")
	}
	if err := runTestControllerLightFallbackProxy(
		false, light.LIGHT_PROTOCOL_QUIC); err != nil {

		t.Fatal(err.Error())
	}
}

func TestControllerImportPushPayloadLightFallbackProxyDial(t *testing.T) {
	if err := runTestControllerLightFallbackProxy(
		true, light.LIGHT_PROTOCOL_TLS); err != nil {

		t.Fatal(err.Error())
	}
}

func TestLightFallbackProxyUpstreamProxy(t *testing.T) {
	for _, upstreamProxyURL := range []string{"", "http://127.0.0.1:8080", "socks5://127.0.0.1:1080"} {
		for _, protocols := range [][]string{
			{light.LIGHT_PROTOCOL_TLS},
			{light.LIGHT_PROTOCOL_QUIC},
			{light.LIGHT_PROTOCOL_TLS, light.LIGHT_PROTOCOL_QUIC},
		} {
			t.Run(fmt.Sprintf("%s/%s", upstreamProxyURL, strings.Join(protocols, "+")), func(t *testing.T) {
				entry := &light.SignedProxyEntry{ProxyEntry: light.ProxyEntry{
					ProxyID:        base64.RawStdEncoding.EncodeToString(prng.Bytes(32)),
					ObfuscationKey: prng.Bytes(32),
					VerifyPin:      prng.Bytes(32),
					TTLSeconds:     3600,
				}}
				for _, proxyProtocol := range protocols {
					entry.ProxyEntry.DialAddresses = append(entry.ProxyEntry.DialAddresses, light.ProxyAddress{
						IPAddress: "127.0.0.1", Port: 443, Protocol: proxyProtocol,
					})
				}
				encodedEntry, err := protocol.CBOREncoding.Marshal(entry)
				if err != nil {
					t.Fatal(err)
				}

				expectTLS := slices.Contains(protocols, light.LIGHT_PROTOCOL_TLS)
				expectQUIC := slices.Contains(protocols, light.LIGHT_PROTOCOL_QUIC) &&
					quic.Enabled() && upstreamProxyURL == ""
				client, err := makeLightProxyClient(
					&Config{SponsorId: "0000000000000000", SessionID: "0000000000000000"},
					&DialConfig{UpstreamProxyURL: upstreamProxyURL},
					nil, nil, false, encodedEntry, 0)
				if !expectTLS && !expectQUIC {
					if err == nil || !strings.Contains(err.Error(), "no supported proxy protocols") {
						t.Fatalf("expected unsupported proxy protocols, got %v", err)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				if client.SupportsProtocol(light.LIGHT_PROTOCOL_TLS) != expectTLS ||
					client.SupportsProtocol(light.LIGHT_PROTOCOL_QUIC) != expectQUIC {
					t.Fatal("unexpected supported proxy protocols")
				}
				if upstreamProxyURL != "" && client.SelectProtocol() != light.LIGHT_PROTOCOL_TLS {
					t.Fatal("upstream proxy bypassed by protocol selection")
				}
			})
		}
	}
}

func runTestControllerLightFallbackProxy(
	importPushPayload bool,
	proxyProtocol string) (retErr error) {

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	dataRoot, err := ioutil.TempDir("", "psiphon-controller-light-proxy-test")
	if err != nil {
		return errors.Trace(err)
	}
	defer os.RemoveAll(dataRoot)

	webServerAddress, shutdownWebServer, err := startLightTestWebServer(ctx)
	if err != nil {
		return errors.Trace(err)
	}
	defer shutdownWebServer()

	lightProxyEntry, shutdownLightProxy, err := startLightTestProxy(
		ctx, webServerAddress, proxyProtocol)
	if err != nil {
		return errors.Trace(err)
	}
	defer func() {
		if err := shutdownLightProxy(); err != nil && retErr == nil {
			retErr = errors.Trace(err)
		}
	}()
	const lightProxyEntryTracker = 0x0102030405060708

	var obfuscationKey, publicKey, privateKey string
	if importPushPayload {
		obfuscationKey, publicKey, privateKey, err = push.GenerateKeys()
		if err != nil {
			return errors.Trace(err)
		}
	}

	targetServerEntry, err := makeUnreachableTargetServerEntry()
	if err != nil {
		return errors.Trace(err)
	}

	establishTunnelTimeoutSeconds := 0

	config := &Config{
		DataRootDirectory:             dataRoot,
		PropagationChannelId:          "0000000000000000",
		SponsorId:                     "0000000000000000",
		DisableLocalSocksProxy:        true,
		TargetServerEntry:             targetServerEntry,
		EstablishTunnelTimeoutSeconds: &establishTunnelTimeoutSeconds,
		EnableLightProxyFallback:      true,
		LightProxyLimitDestinationAddresses: []string{
			webServerAddress,
		},
	}
	if importPushPayload {
		config.PushPayloadObfuscationKey = obfuscationKey
		config.PushPayloadSignaturePublicKey = publicKey
	} else {
		config.LightProxyEntry = lightProxyEntry
		config.LightProxyEntryTracker = lightProxyEntryTracker
	}

	err = config.Commit(false)
	if err != nil {
		return errors.Trace(err)
	}

	expectedClientEvents := []string{"test-event-1", "test-event-2", "test-event-1"}
	err = config.SetParameters("", false, map[string]interface{}{
		parameters.PsiphonAPIClientEventReportLimit:             len(expectedClientEvents),
		parameters.QUICDisableClientPathMTUDiscoveryProbability: 1.0,
		parameters.ObfuscatedQUICNonceTransformProbability:      1.0,
		parameters.ObfuscatedQUICNonceTransformSpecs:            transforms.Specs{"spec": transforms.Spec{{"", ""}}},
		parameters.ObfuscatedQUICNonceTransformScopedSpecNames:  transforms.ScopedSpecNames{"": {"spec"}},
	})
	if err != nil {
		return errors.Trace(err)
	}

	if err := OpenDataStore(config); err != nil {
		return errors.Trace(err)
	}
	defer CloseDataStore()

	httpProxyPort := make(chan int, 1)
	lightProxyAvailable := make(chan struct{}, 1)
	unexpectedTunnel := make(chan struct{}, 1)

	err = SetNoticeWriter(NewNoticeReceiver(func(notice []byte) {
		noticeType, payload, err := GetNotice(notice)
		if err != nil {
			return
		}

		switch noticeType {
		case "ListeningHttpProxyPort":
			select {
			case httpProxyPort <- int(payload["port"].(float64)):
			default:
			}
		case "LightProxyAvailable":
			select {
			case lightProxyAvailable <- struct{}{}:
			default:
			}
		case "Tunnels":
			if int(payload["count"].(float64)) > 0 {
				select {
				case unexpectedTunnel <- struct{}{}:
				default:
				}
			}
		}
	}))
	if err != nil {
		return errors.Trace(err)
	}
	defer ResetNoticeWriter()

	controller, err := NewController(config)
	if err != nil {
		return errors.Trace(err)
	}

	runCtx, stopController := context.WithCancel(ctx)
	controllerDone := make(chan struct{})
	go func() {
		defer close(controllerDone)
		controller.Run(runCtx)
	}()

	defer func() {
		stopController()
		select {
		case <-controllerDone:
		case <-time.After(10 * time.Second):
			if retErr == nil {
				retErr = errors.TraceNew("controller shutdown timeout exceeded")
			}
		}
	}()

	localProxyPort := 0
	select {
	case localProxyPort = <-httpProxyPort:
	case <-ctx.Done():
		return errors.Trace(ctx.Err())
	}

	if importPushPayload {
		maker, err := push.NewPushPayloadMaker(
			obfuscationKey, publicKey, privateKey)
		if err != nil {
			return errors.Trace(err)
		}

		result, err := maker.MakePushPayloads(
			0,
			0,
			1*time.Hour,
			nil,
			push.PinnedEntries{
				FallbackLightProxyEntries: []*push.LightProxyEntry{{
					ProxyEntry:        lightProxyEntry,
					ProxyEntryTracker: lightProxyEntryTracker,
				}},
			},
			0,
		)
		if err != nil {
			return errors.Trace(err)
		}
		if len(result.Payloads) != 1 {
			return errors.TraceNew("unexpected push payload count")
		}

		if !controller.ImportPushPayload(result.Payloads[0]) {
			return errors.TraceNew("push payload import failed")
		}
	}

	select {
	case <-lightProxyAvailable:
	case <-ctx.Done():
		return errors.Trace(ctx.Err())
	}

	// No events are attributed before the first light proxy dial.
	controller.RecordClientEvent("before-light-proxy-dial")
	controller.clientEventMutex.Lock()
	queuedClientEventCount := len(controller.lightFallbackProxyClientEvents)
	controller.clientEventMutex.Unlock()
	if queuedClientEventCount != 0 {
		return errors.TraceNew("unexpected client events before light proxy dial")
	}

	if importPushPayload {
		storedLightProxy := LoadLightFallbackProxy()
		if storedLightProxy == nil {
			return errors.TraceNew("missing stored light proxy")
		}
		if !bytes.Equal(storedLightProxy.LightProxyEntry, lightProxyEntry) ||
			storedLightProxy.LightProxyEntryTracker != lightProxyEntryTracker {

			return errors.TraceNew("unexpected stored light proxy")
		}
	}

	// Allow for known race condition described in NewHttpProxy().
	time.Sleep(1 * time.Second)

	err = doHTTPSWebServerFetch(ctx, localProxyPort, webServerAddress)
	if err != nil {
		return errors.Trace(err)
	}

	dialParams := config.GetLightFallbackDialParameters()
	if !dialParams.isReplay() || dialParams.Protocol != proxyProtocol {
		return errors.TraceNew(
			"unexpected light proxy replay parameters")
	}
	if proxyProtocol == light.LIGHT_PROTOCOL_QUIC &&
		(!dialParams.QUICDisablePathMTUDiscovery ||
			(dialParams.ObfuscatedQUICNonceTransformerParameters != nil) !=
				protocol.QUICVersionIsObfuscated(dialParams.QUICVersion)) {

		return errors.TraceNew("unexpected Light QUIC tactics selection")
	}

	err = doHTTPSWebServerFetches(ctx, localProxyPort, webServerAddress)
	if err != nil {
		return errors.Trace(err)
	}

	for _, event := range expectedClientEvents {
		controller.RecordClientEvent(event)
	}

	// Events beyond the report limit are dropped.
	controller.RecordClientEvent("test-event-3")
	controller.RecordClientEvent("test-event-4")

	controller.clientEventMutex.Lock()
	clientEvents := slices.Clone(controller.lightFallbackProxyClientEvents)
	controller.clientEventMutex.Unlock()
	if !slices.Equal(clientEvents, expectedClientEvents) {
		return errors.Tracef("unexpected light proxy client events: %v", clientEvents)
	}

	select {
	case <-unexpectedTunnel:
		return errors.TraceNew("unexpected tunnel establishment")
	default:
	}

	return nil
}

func startLightTestWebServer(ctx context.Context) (string, func(), error) {

	certificate, privateKey, _, err := common.GenerateWebServerCertificate("localhost")
	if err != nil {
		return "", nil, errors.Trace(err)
	}

	tlsCertificate, err := tls.X509KeyPair([]byte(certificate), []byte(privateKey))
	if err != nil {
		return "", nil, errors.Trace(err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, errors.Trace(err)
	}

	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Length", strconv.Itoa(len(body)))
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(body)
		}),
	}

	tlsListener := tls.NewListener(listener, &tls.Config{
		Certificates: []tls.Certificate{tlsCertificate},
		MinVersion:   tls.VersionTLS12,
	})

	go func() {
		_ = server.Serve(tlsListener)
	}()

	shutdown := func() {
		shutdownCtx, cancel := context.WithTimeout(ctx, 1*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}

	return listener.Addr().String(), shutdown, nil
}

func startLightTestProxy(
	ctx context.Context,
	allowedWebServerAddress string,
	proxyProtocol string) ([]byte, func() error, error) {

	proxyListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, nil, errors.Trace(err)
	}
	proxyPort := proxyListener.Addr().(*net.TCPAddr).Port

	err = proxyListener.Close()
	if err != nil {
		return nil, nil, errors.Trace(err)
	}

	// Exercise the dual dialer.
	dialAddresses := []light.ProxyAddress{
		{IPAddress: "127.0.0.1", Port: proxyPort, Protocol: proxyProtocol},
		{IPAddress: "::1", Port: proxyPort, Protocol: proxyProtocol},
	}

	proxyConfig, proxyEntry, err := light.Generate(
		prng.HexString(8),
		nil,
		dialAddresses,
		"example.org",
		"",
		0.5,
		protocol.TLS_PROFILE_CHROME_133,
		0.5,
		0,
		0,
		0,
		0,
		0,
		[]string{allowedWebServerAddress},
		nil,
		nil,
		nil,
		allowedWebServerAddress,
		"",
		"")
	if err != nil {
		return nil, nil, errors.Trace(err)
	}

	proxyConfig.AllowBogons = true

	receiver := newTestLightProxyEventReceiver()
	proxy, err := light.NewProxy(
		proxyConfig,
		func(string) common.GeoIPData { return common.GeoIPData{} },
		receiver)
	if err != nil {
		return nil, nil, errors.Trace(err)
	}

	proxyCtx, stopProxy := context.WithCancel(ctx)
	proxyDone := make(chan error, 1)
	go func() {
		proxyDone <- proxy.Run(proxyCtx)
	}()

	shutdown := func() error {
		stopProxy()
		select {
		case err := <-proxyDone:
			return errors.Trace(err)
		case <-time.After(10 * time.Second):
			return errors.TraceNew("light proxy shutdown timeout exceeded")
		}
	}

	select {
	case <-receiver.listening:
	case err := <-proxyDone:
		stopProxy()
		if err == nil {
			err = errors.TraceNew("light proxy stopped before listening")
		}
		return nil, nil, errors.Trace(err)
	case <-ctx.Done():
		if err := shutdown(); err != nil {
			return nil, nil, errors.Trace(err)
		}
		return nil, nil, errors.Trace(ctx.Err())
	}

	return proxyEntry, shutdown, nil
}

func makeUnreachableTargetServerEntry() (string, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", errors.Trace(err)
	}
	addr := listener.Addr().String()

	err = listener.Close()
	if err != nil {
		return "", errors.Trace(err)
	}

	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", errors.Trace(err)
	}

	sshPort, err := strconv.Atoi(port)
	if err != nil {
		return "", errors.Trace(err)
	}

	serverEntry := &protocol.ServerEntry{
		IpAddress:        host,
		WebServerPort:    "0",
		SshPort:          sshPort,
		SshUsername:      "unused",
		SshPassword:      "unused",
		SshHostKey:       base64.StdEncoding.EncodeToString([]byte("unused")),
		SshObfuscatedKey: prng.HexString(32),
		Capabilities: []string{
			protocol.GetCapability(protocol.TUNNEL_PROTOCOL_SSH),
			protocol.CAPABILITY_SSH_API_REQUESTS,
		},
		Region:               "US",
		ConfigurationVersion: 1,
	}

	encodedServerEntry, err := protocol.EncodeServerEntry(serverEntry)
	if err != nil {
		return "", errors.Trace(err)
	}

	return encodedServerEntry, nil
}

func doHTTPSWebServerFetches(
	ctx context.Context,
	localProxyPort int,
	webServerAddress string) error {

	const fetches = 10

	errs := make(chan error, fetches)
	for range fetches {
		go func() {
			errs <- doHTTPSWebServerFetch(ctx, localProxyPort, webServerAddress)
		}()
	}

	for range fetches {
		err := <-errs
		if err != nil {
			return errors.Trace(err)
		}
	}

	return nil
}

func doHTTPSWebServerFetch(
	ctx context.Context,
	localProxyPort int,
	webServerAddress string) error {

	proxyURL, err := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", localProxyPort))
	if err != nil {
		return errors.Trace(err)
	}

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
			DisableKeepAlives: false,
		},
		Timeout: 10 * time.Second,
	}
	defer client.CloseIdleConnections()

	payload := prng.Bytes(prng.Range(1<<20, 1<<21))
	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		fmt.Sprintf("https://%s/", webServerAddress),
		bytes.NewReader(payload))
	if err != nil {
		return errors.Trace(err)
	}

	response, err := client.Do(request)
	if err != nil {
		return errors.Trace(err)
	}
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return errors.Trace(err)
	}

	if response.StatusCode != http.StatusOK || !bytes.Equal(body, payload) {
		return errors.TraceNew("unexpected echo response")
	}

	return nil
}

type testLightProxyEventReceiver struct {
	listening chan struct{}
}

func newTestLightProxyEventReceiver() *testLightProxyEventReceiver {
	return &testLightProxyEventReceiver{
		listening: make(chan struct{}),
	}
}

func (receiver *testLightProxyEventReceiver) Listening(address, ingressProtocol string) {
	fmt.Printf("[Listening] %s %s\n", address, ingressProtocol)
}

func (receiver *testLightProxyEventReceiver) Started() {
	fmt.Printf("[Started]\n")
	close(receiver.listening)
}

func (r *testLightProxyEventReceiver) Paused() {
	fmt.Printf("[Paused]\n")
}

func (r *testLightProxyEventReceiver) Resumed() {
	fmt.Printf("[Resumed]\n")
}

func (r *testLightProxyEventReceiver) Accepted() {
	fmt.Printf("[Accepted]\n")
}

func (r *testLightProxyEventReceiver) Rejected() {
	fmt.Printf("[Rejected]\n")
}

func (receiver *testLightProxyEventReceiver) Activity(
	stats *light.ActivityStats) {
}

func (receiver *testLightProxyEventReceiver) Connection(
	stats *light.ConnectionStats) {

	fmt.Printf("[Connection] failure: %v\n", stats.Failure)
}

func (receiver *testLightProxyEventReceiver) IrregularConnection(
	_ string, _ common.GeoIPData, irregularity string) {

	fmt.Printf("[IrregularConnection] %s\n", irregularity)
}

func (receiver *testLightProxyEventReceiver) DebugLog(_ string, message string) {
}

func (receiver *testLightProxyEventReceiver) InfoLog(_ string, message string) {
	fmt.Printf("[InfoLog] %s\n", message)
}

func (receiver *testLightProxyEventReceiver) WarningLog(_ string, message string) {
	fmt.Printf("[WarningLog] %s\n", message)
}

func (receiver *testLightProxyEventReceiver) ErrorLog(_ string, message string) {
	fmt.Printf("[ErrorLog] %s\n", message)
}

func TestControllerImportPushPayloadLightFallbackProxy(t *testing.T) {

	dataRoot, err := ioutil.TempDir("", "psiphon-controller-push-light-proxy-test")
	if err != nil {
		t.Fatal(errors.Trace(err))
	}
	defer os.RemoveAll(dataRoot)

	const lightProxyEntryTTL = 1 * time.Hour

	_, lightProxyEntry, err := light.Generate(
		prng.HexString(8),
		nil,
		[]light.ProxyAddress{
			{IPAddress: "127.0.0.1", Port: 1, Protocol: light.LIGHT_PROTOCOL_TLS},
		},
		"example.org",
		"",
		0.0,
		"",
		0.0,
		0,
		0,
		0,
		0,
		lightProxyEntryTTL,
		[]string{"example.com:443"},
		nil,
		nil,
		nil,
		"example.com:443",
		"",
		"")
	if err != nil {
		t.Fatal(errors.Trace(err))
	}
	_, lightProxyEntry2, err := light.Generate(
		prng.HexString(8),
		nil,
		[]light.ProxyAddress{
			{IPAddress: "127.0.0.1", Port: 2, Protocol: light.LIGHT_PROTOCOL_TLS},
		},
		"example.org",
		"",
		0.0,
		"",
		0.0,
		0,
		0,
		0,
		0,
		lightProxyEntryTTL,
		[]string{"example.com:443"},
		nil,
		nil,
		nil,
		"example.com:443",
		"",
		"")
	if err != nil {
		t.Fatal(errors.Trace(err))
	}

	obfuscationKey, publicKey, privateKey, err := push.GenerateKeys()
	if err != nil {
		t.Fatal(errors.Trace(err))
	}

	config := &Config{
		DataRootDirectory:             dataRoot,
		PropagationChannelId:          "0000000000000000",
		SponsorId:                     "0000000000000000",
		DisableLocalSocksProxy:        true,
		EnableLightProxyFallback:      true,
		PushPayloadObfuscationKey:     obfuscationKey,
		PushPayloadSignaturePublicKey: publicKey,
	}

	err = config.Commit(false)
	if err != nil {
		t.Fatal(errors.Trace(err))
	}

	if err := OpenDataStore(config); err != nil {
		t.Fatal(errors.Trace(err))
	}
	defer CloseDataStore()

	controller, err := NewController(config)
	if err != nil {
		t.Fatal(errors.Trace(err))
	}

	maker, err := push.NewPushPayloadMaker(
		obfuscationKey, publicKey, privateKey)
	if err != nil {
		t.Fatal(errors.Trace(err))
	}

	const lightProxyEntryTracker = 0x0102030405060708
	const lightProxyEntryTracker2 = 0x1112131415161718
	result, err := maker.MakePushPayloads(
		0,
		0,
		1*time.Hour,
		nil,
		push.PinnedEntries{
			FallbackLightProxyEntries: []*push.LightProxyEntry{{
				ProxyEntry:        lightProxyEntry,
				ProxyEntryTracker: lightProxyEntryTracker,
			}, {
				ProxyEntry:        lightProxyEntry2,
				ProxyEntryTracker: lightProxyEntryTracker2,
			}},
		},
		0,
	)
	if err != nil {
		t.Fatal(errors.Trace(err))
	}
	if len(result.Payloads) != 1 {
		t.Fatal("unexpected push payload count")
	}

	if !controller.ImportPushPayload(result.Payloads[0]) {
		t.Fatal("push payload import failed")
	}

	storedLightProxy := LoadLightFallbackProxy()
	if storedLightProxy == nil {
		t.Fatal("missing stored light proxy")
	}
	if (!bytes.Equal(storedLightProxy.LightProxyEntry, lightProxyEntry) ||
		storedLightProxy.LightProxyEntryTracker != lightProxyEntryTracker) &&
		(!bytes.Equal(storedLightProxy.LightProxyEntry, lightProxyEntry2) ||
			storedLightProxy.LightProxyEntryTracker != lightProxyEntryTracker2) {

		t.Fatal("unexpected stored light proxy")
	}
	if storedLightProxy.Expires.IsZero() ||
		!storedLightProxy.Expires.After(time.Now().UTC()) {
		t.Fatal("unexpected stored light proxy expiry")
	}

	lightProxyClient := controller.config.GetLightFallbackProxyClient()
	if lightProxyClient == nil {
		t.Fatal("missing initialized light proxy client")
	}

	expiredLightProxy, err := json.Marshal(
		&StoredLightProxyEntry{
			LightProxyEntry:        storedLightProxy.LightProxyEntry,
			LightProxyEntryTracker: storedLightProxy.LightProxyEntryTracker,
			Expires:                time.Now().UTC().Add(-1 * time.Second),
		})
	if err != nil {
		t.Fatal(errors.Trace(err))
	}
	err = SetKeyValue(datastoreStoredLightFallbackProxyKey, string(expiredLightProxy))
	if err != nil {
		t.Fatal(errors.Trace(err))
	}

	lightProxy := LoadLightFallbackProxy()
	if lightProxy != nil {
		t.Fatal("expired light proxy loaded")
	}

	lightProxyValue, err := GetKeyValue(datastoreStoredLightFallbackProxyKey)
	if err != nil {
		t.Fatal(errors.Trace(err))
	}
	if lightProxyValue != "" {
		t.Fatal("expired light proxy not deleted")
	}
}

func TestControllerImportPushPayloadLightFallbackProxyStoreFailure(t *testing.T) {

	dataRoot, err := ioutil.TempDir("", "psiphon-controller-push-light-proxy-store-failure-test")
	if err != nil {
		t.Fatal(errors.Trace(err))
	}
	defer os.RemoveAll(dataRoot)

	_, lightProxyEntry, err := light.Generate(
		prng.HexString(8),
		nil,
		[]light.ProxyAddress{
			{IPAddress: "127.0.0.1", Port: 1, Protocol: light.LIGHT_PROTOCOL_TLS},
		},
		"example.org",
		"",
		0.0,
		"",
		0.0,
		0,
		0,
		0,
		0,
		0,
		[]string{"example.com:443"},
		nil,
		nil,
		nil,
		"example.com:443",
		"",
		"")
	if err != nil {
		t.Fatal(errors.Trace(err))
	}

	obfuscationKey, publicKey, privateKey, err := push.GenerateKeys()
	if err != nil {
		t.Fatal(errors.Trace(err))
	}

	config := &Config{
		DataRootDirectory:             dataRoot,
		PropagationChannelId:          "0000000000000000",
		SponsorId:                     "0000000000000000",
		DisableLocalSocksProxy:        true,
		EnableLightProxyFallback:      true,
		PushPayloadObfuscationKey:     obfuscationKey,
		PushPayloadSignaturePublicKey: publicKey,
	}

	err = config.Commit(false)
	if err != nil {
		t.Fatal(errors.Trace(err))
	}

	if err := OpenDataStore(config); err != nil {
		t.Fatal(errors.Trace(err))
	}
	datastoreOpen := true
	defer func() {
		if datastoreOpen {
			CloseDataStore()
		}
	}()

	controller, err := NewController(config)
	if err != nil {
		t.Fatal(errors.Trace(err))
	}

	maker, err := push.NewPushPayloadMaker(
		obfuscationKey, publicKey, privateKey)
	if err != nil {
		t.Fatal(errors.Trace(err))
	}

	result, err := maker.MakePushPayloads(
		0,
		0,
		1*time.Hour,
		nil,
		push.PinnedEntries{
			FallbackLightProxyEntries: []*push.LightProxyEntry{{
				ProxyEntry:        lightProxyEntry,
				ProxyEntryTracker: 0x0102030405060708,
			}},
		},
		0,
	)
	if err != nil {
		t.Fatal(errors.Trace(err))
	}
	if len(result.Payloads) != 1 {
		t.Fatal("unexpected push payload count")
	}

	CloseDataStore()
	datastoreOpen = false

	if controller.ImportPushPayload(result.Payloads[0]) {
		t.Fatal("push payload import succeeded despite light proxy store failure")
	}

	lightProxyClient := controller.config.GetLightFallbackProxyClient()
	if lightProxyClient != nil {
		t.Fatal("light proxy client was initialized despite store failure")
	}
}

func TestControllerImportPushPayloadInvalidLightFallbackProxyNotStored(t *testing.T) {

	dataRoot, err := ioutil.TempDir("", "psiphon-controller-push-invalid-light-proxy-test")
	if err != nil {
		t.Fatal(errors.Trace(err))
	}
	defer os.RemoveAll(dataRoot)

	obfuscationKey, publicKey, privateKey, err := push.GenerateKeys()
	if err != nil {
		t.Fatal(errors.Trace(err))
	}

	config := &Config{
		DataRootDirectory:             dataRoot,
		PropagationChannelId:          "0000000000000000",
		SponsorId:                     "0000000000000000",
		DisableLocalSocksProxy:        true,
		EnableLightProxyFallback:      true,
		PushPayloadObfuscationKey:     obfuscationKey,
		PushPayloadSignaturePublicKey: publicKey,
	}

	err = config.Commit(false)
	if err != nil {
		t.Fatal(errors.Trace(err))
	}

	if err := OpenDataStore(config); err != nil {
		t.Fatal(errors.Trace(err))
	}
	defer CloseDataStore()

	controller, err := NewController(config)
	if err != nil {
		t.Fatal(errors.Trace(err))
	}

	maker, err := push.NewPushPayloadMaker(
		obfuscationKey, publicKey, privateKey)
	if err != nil {
		t.Fatal(errors.Trace(err))
	}

	result, err := maker.MakePushPayloads(
		0,
		0,
		1*time.Hour,
		nil,
		push.PinnedEntries{
			FallbackLightProxyEntries: []*push.LightProxyEntry{{
				ProxyEntry:        []byte("invalid-light-proxy-entry"),
				ProxyEntryTracker: 0x0102030405060708,
			}},
		},
		0,
	)
	if err != nil {
		t.Fatal(errors.Trace(err))
	}
	if len(result.Payloads) != 1 {
		t.Fatal("unexpected push payload count")
	}

	if controller.ImportPushPayload(result.Payloads[0]) {
		t.Fatal("invalid light proxy push payload import succeeded")
	}

	if storedLightProxy := LoadLightFallbackProxy(); storedLightProxy != nil {
		t.Fatal("invalid light proxy was stored")
	}

	lightProxyClient := controller.config.GetLightFallbackProxyClient()
	if lightProxyClient != nil {
		t.Fatal("invalid light proxy client was initialized")
	}
}

func TestLightProxyTLSDialer(t *testing.T) {
	if err := runTestLightProxyTLSDialer(); err != nil {
		t.Fatal(err)
	}
}

func runTestLightProxyTLSDialer() error {

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)

	certificate, privateKey, verifyPin, err :=
		common.GenerateWebServerCertificate("localhost")
	if err != nil {
		cancel()
		return errors.Trace(err)
	}
	tlsCertificate, err := tls.X509KeyPair(
		[]byte(certificate), []byte(privateKey))
	if err != nil {
		cancel()
		return errors.Trace(err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		cancel()
		return errors.Trace(err)
	}

	type serverResult struct {
		exporter []byte
		err      error
	}
	serverResults := make(chan serverResult, 3)
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		serverConfig := &tls.Config{
			Certificates: []tls.Certificate{tlsCertificate},
			MinVersion:   tls.VersionTLS13,
		}
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			tlsConn := tls.Server(conn, serverConfig)
			err = tlsConn.HandshakeContext(ctx)
			var exporter []byte
			if err == nil {
				state := tlsConn.ConnectionState()
				exporter, err = state.ExportKeyingMaterial(
					light.TunnelProxyReportExporterLabel,
					nil,
					light.TunnelProxyReportExporterSize)
			}
			tlsConn.Close()
			select {
			case serverResults <- serverResult{
				exporter: exporter,
				err:      err,
			}:
			case <-ctx.Done():
				return
			}
		}
	}()
	defer func() {
		cancel()
		listener.Close()
		<-serverDone
	}()

	params, err := parameters.NewParameters(nil)
	if err != nil {
		return errors.Trace(err)
	}
	sessionCache := utls.NewLRUClientSessionCache(0)
	proxyTLSDialer := makeLightProxyTLSDialer(
		&Config{params: params},
		&DialConfig{
			ResolveIP: func(ctx context.Context, host string) ([]net.IP, error) {
				return net.DefaultResolver.LookupIP(ctx, "ip", host)
			},
		},
		sessionCache)

	dial := func(pin, expectedDidResume string) ([]byte, []byte, time.Time, time.Time, error) {

		conn, exporter, completedTCP, completedTLS, dialErr := proxyTLSDialer(
			ctx,
			listener.Addr().String(),
			protocol.TLS_PROFILE_CHROME_133,
			nil,
			"example.org",
			false,
			0,
			prng.Bytes(obfuscator.TLS_PASSTHROUGH_MESSAGE_SIZE),
			pin)
		if conn != nil {
			defer conn.Close()
		}
		if dialErr != nil && completedTCP.IsZero() {
			return nil, nil, completedTCP, completedTLS, errors.Trace(dialErr)
		}

		if dialErr == nil {
			// Read post-handshake tickets before closing or redialing.
			deadline, _ := ctx.Deadline()
			dialErr = conn.SetReadDeadline(deadline)
			if dialErr == nil {
				_, dialErr = io.Copy(io.Discard, conn)
			}
		}

		var result serverResult
		select {
		case result = <-serverResults:
		case <-ctx.Done():
			return nil, nil, completedTCP, completedTLS, errors.Trace(ctx.Err())
		}

		if dialErr != nil {
			return nil, nil, completedTCP, completedTLS, errors.Trace(dialErr)
		}
		if result.err != nil {
			return nil, nil, completedTCP, completedTLS, errors.Trace(result.err)
		}
		_, ok := sessionCache.Get(
			lightSessionCacheKeyPrefix + listener.Addr().String())
		if !ok {
			return nil, nil, completedTCP, completedTLS, errors.TraceNew("missing session ticket")
		}
		if conn.(common.MetricsSource).GetMetrics()["tls_did_resume"] != expectedDidResume {
			return nil, nil, completedTCP, completedTLS, errors.TraceNew("unexpected TLS resumption")
		}
		return exporter, result.exporter, completedTCP, completedTLS, nil
	}

	// Test: TLS exporter values match at both ends and change on resumption.

	exporter, serverExporter, completedTCP, completedTLS, err := dial(verifyPin, "0")
	if err != nil {
		return errors.Trace(err)
	}
	if completedTCP.IsZero() {
		return errors.TraceNew("missing TCP completion time")
	}
	if completedTLS.IsZero() || completedTLS.Before(completedTCP) {
		return errors.TraceNew("invalid TLS completion time")
	}
	if !bytes.Equal(exporter, serverExporter) {
		return errors.TraceNew("unexpected TLS exporter")
	}

	nextExporter, nextServerExporter, _, _, err := dial(verifyPin, "1")
	if err != nil {
		return errors.Trace(err)
	}
	if !bytes.Equal(nextExporter, nextServerExporter) {
		return errors.TraceNew("unexpected TLS exporter")
	}
	if bytes.Equal(exporter, nextExporter) {
		return errors.TraceNew("reused TLS exporter")
	}

	// Test: an incorrect pin is rejected even with a cached session.

	invalidPin := base64.StdEncoding.EncodeToString(make([]byte, 32))
	_, _, completedTCP, completedTLS, err = dial(invalidPin, "1")
	if err == nil {
		return errors.TraceNew("unexpected success")
	}
	if !strings.Contains(err.Error(), "no pin found") {
		return errors.Trace(err)
	}
	if completedTCP.IsZero() {
		return errors.TraceNew("missing TCP completion time after TLS failure")
	}
	if !completedTLS.IsZero() {
		return errors.TraceNew("unexpected TLS completion time after TLS failure")
	}

	return nil
}

func TestInproxyMustUpgradeLightProtocolSelection(t *testing.T) {
	if !inproxy.Enabled() {
		t.Skip("in-proxy is not enabled")
	}
	config := &Config{
		DataRootDirectory:    t.TempDir(),
		PropagationChannelId: "0",
		SponsorId:            "0000000000000000",
		NetworkID:            "WIFI-test",
	}
	if err := config.Commit(false); err != nil {
		t.Fatal(err)
	}
	if err := OpenDataStore(config); err != nil {
		t.Fatal(err)
	}
	defer CloseDataStore()
	iterator, err := NewCommonLightTunnelProxyEntryIterator(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	inproxyProtocol := protocol.TunnelProtocolPlusInproxyWebRTC(
		protocol.TUNNEL_PROTOCOL_OBFUSCATED_SSH)
	lightProtocol := protocol.TUNNEL_PROTOCOL_LIGHT_TLS_TLS_SSH
	serverEntry := makeMockServerEntries(
		protocol.TUNNEL_PROTOCOL_OBFUSCATED_SSH, "", "", "", 1)[0]
	serverEntry.InproxyOSSHPort = 443
	serverEntry.LightTlsSSHPort = 443
	serverEntry.LightDialAuthorization = []byte{1}
	serverEntry.Capabilities = append(serverEntry.Capabilities,
		protocol.GetCapability(inproxyProtocol), protocol.GetCapability(lightProtocol))
	constraints := &protocolSelectionConstraints{
		config:                                    config,
		lightTunnelProxyEntryIterator:             iterator,
		initialLimitTunnelProtocols:               protocol.TunnelProtocols{inproxyProtocol, lightProtocol},
		initialLimitTunnelProtocolsCandidateCount: 2,
		limitTunnelProtocols:                      protocol.TunnelProtocols{protocol.TUNNEL_PROTOCOL_OBFUSCATED_SSH},
	}
	config.OnInproxyMustUpgrade()
	checkSelection := func(count int, expected string) {
		t.Helper()
		selected, _, ok := constraints.selectProtocol(
			count, false, personalPairingProtocolNone, true, inproxyProtocol, serverEntry)
		if !ok || selected != expected {
			t.Fatalf("candidate %d: selected %q, want %q", count, selected, expected)
		}
	}

	// With no usable Light proxy, the existing initial phase must still
	// advance to the direct protocol despite the in-proxy preference/hint.
	for count := 0; count < 2; count++ {
		checkSelection(count, inproxyProtocol)
	}
	checkSelection(2, protocol.TUNNEL_PROTOCOL_OBFUSCATED_SSH)

	entry, err := protocol.CBOREncoding.Marshal(&light.SignedProxyEntry{
		ProxyEntry: light.ProxyEntry{
			ProxyID: base64.RawStdEncoding.EncodeToString(prng.Bytes(32)),
			DialAddresses: []light.ProxyAddress{
				{IPAddress: "127.0.0.1", Port: 443, Protocol: light.LIGHT_PROTOCOL_TLS},
			},
			ObfuscationKey: prng.Bytes(32),
			VerifyPin:      prng.Bytes(32),
			TTLSeconds:     3600,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := StoreCommonLightTunnelProxyEntry(entry, 0); err != nil {
		t.Fatal(err)
	}
	if err := iterator.Reset(context.Background()); err != nil {
		t.Fatal(err)
	}
	// When Light is available, it replaces in-proxy even during the initial
	// phase, and the normal direct protocol remains available afterward.
	checkSelection(0, lightProtocol)
	checkSelection(2, protocol.TUNNEL_PROTOCOL_OBFUSCATED_SSH)
}

func TestPersonalPairingProtocolSelection(t *testing.T) {
	if !inproxy.Enabled() {
		t.Skip("inproxy is not enabled")
	}

	lightProtocol := protocol.TUNNEL_PROTOCOL_LIGHT_TLS_TLS_SSH
	inproxyProtocol := protocol.TunnelProtocolPlusInproxyWebRTC(
		protocol.TUNNEL_PROTOCOL_SSH)

	config := &Config{
		EnablePersonalLightProxyTunnels:    true,
		InproxyClientPersonalCompartmentID: "personal",
		personalLightProxyEntries: []personalLightProxyEntry{
			{proxyEntryHash: []byte{1}, protocols: []string{light.LIGHT_PROTOCOL_TLS}},
			{proxyEntryHash: []byte{2}, protocols: []string{light.LIGHT_PROTOCOL_TLS}},
		},
	}

	constraints := &protocolSelectionConstraints{
		config:                        config,
		lightTunnelProxyEntryIterator: newPersonalLightProxyEntryIterator(config),
		limitTunnelProtocols: protocol.TunnelProtocols{
			lightProtocol,
			inproxyProtocol,
		},
	}

	newServerEntry := func(tunnelProtocols ...string) *protocol.ServerEntry {
		capabilities := make([]string, len(tunnelProtocols))
		for i, tunnelProtocol := range tunnelProtocols {
			capabilities[i] = protocol.GetCapability(tunnelProtocol)
		}
		return &protocol.ServerEntry{
			IpAddress:              "127.0.0.1",
			InproxySSHPort:         443,
			LightTlsSSHPort:        443,
			Capabilities:           capabilities,
			LightDialAuthorization: []byte{1},
		}
	}

	lightServerEntry := newServerEntry(lightProtocol)
	inproxyServerEntry := newServerEntry(inproxyProtocol)
	dualServerEntry := newServerEntry(lightProtocol, inproxyProtocol)

	selectFamily := func(
		serverEntry *protocol.ServerEntry,
		expected personalPairingProtocolFamily) {

		family := constraints.selectPersonalPairingProtocolFamily(
			0, false, serverEntry)
		if family != expected {
			t.Fatalf("unexpected personal pairing protocol family: %d", family)
		}

		selected, _, ok := constraints.selectProtocol(
			0, false, family, false, "", serverEntry)
		if !ok || !family.matches(selected) {
			t.Fatalf("unexpected selected protocol: %s", selected)
		}
	}

	constraints.nextPersonalPairingProtocolFamily =
		personalPairingProtocolLight
	selectFamily(lightServerEntry, personalPairingProtocolLight)
	selectFamily(dualServerEntry, personalPairingProtocolInproxy)

	constraints.nextPersonalPairingProtocolFamily =
		personalPairingProtocolInproxy
	selectFamily(inproxyServerEntry, personalPairingProtocolInproxy)
	selectFamily(dualServerEntry, personalPairingProtocolLight)

	// Test: personal entries are selected in ordered round robin and loaded by
	// hash.

	entryIterator := constraints.lightTunnelProxyEntryIterator
	for _, expected := range [][]byte{{1}, {2}, {1}} {
		hash, stored, err := entryIterator.Next(light.LIGHT_PROTOCOL_TLS)
		if err != nil || stored == nil || !bytes.Equal(hash, expected) {
			t.Fatalf("unexpected personal entry selection: %v", err)
		}
	}
	if stored, err := entryIterator.Load([]byte{2}, light.LIGHT_PROTOCOL_TLS); err != nil || stored == nil {
		t.Fatal("failed to load personal entry by hash")
	}
	if stored, err := entryIterator.Load([]byte{2}, light.LIGHT_PROTOCOL_QUIC); err != nil || stored != nil {
		t.Fatal("loaded personal entry for unsupported ingress protocol")
	}
}

func TestPersonalPairingConnectionWorkerPoolSize(t *testing.T) {
	for _, testCase := range []struct {
		name       string
		configJSON string
		tactics    map[string]interface{}
		expected   int
	}{
		{"Default", `{}`, nil, 2},
		{"SharedConfig", `{"PersonalPairingConnectionWorkerPoolSize":5}`, nil, 5},
		{"LegacyConfig", `{"InproxyPersonalPairingConnectionWorkerPoolSize":3}`, nil, 3},
		{"BothConfig", `{"PersonalPairingConnectionWorkerPoolSize":5,"InproxyPersonalPairingConnectionWorkerPoolSize":3}`, nil, 5},
		{"ZeroSharedConfig", `{"PersonalPairingConnectionWorkerPoolSize":0,"InproxyPersonalPairingConnectionWorkerPoolSize":3}`, nil, 3},
		{"InvalidLegacyIgnored", `{"PersonalPairingConnectionWorkerPoolSize":5,"InproxyPersonalPairingConnectionWorkerPoolSize":-1}`, nil, 5},
		{"SharedTactics", `{}`, map[string]interface{}{parameters.PersonalPairingConnectionWorkerPoolSize: 7}, 7},
		{"IgnoredLegacyTactics", `{}`, map[string]interface{}{parameters.InproxyPersonalPairingConnectionWorkerPoolSize: 6}, 2},
		{"BothTactics", `{}`, map[string]interface{}{parameters.PersonalPairingConnectionWorkerPoolSize: 7, parameters.InproxyPersonalPairingConnectionWorkerPoolSize: 6}, 7},
		{"SharedTacticsOverLegacyConfig", `{"InproxyPersonalPairingConnectionWorkerPoolSize":3}`, map[string]interface{}{parameters.PersonalPairingConnectionWorkerPoolSize: 7}, 7},
		{"IgnoredLegacyTacticsOverSharedConfig", `{"PersonalPairingConnectionWorkerPoolSize":5}`, map[string]interface{}{parameters.InproxyPersonalPairingConnectionWorkerPoolSize: 6}, 5},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			for _, mode := range []struct {
				name          string
				enableInproxy bool
				enableLight   bool
			}{
				{"Ordinary", false, false},
				{"InproxyOnly", true, false},
				{"LightOnly", false, true},
				{"Combined", true, true},
			} {
				t.Run(mode.name, func(t *testing.T) {
					config, err := LoadConfig([]byte(testCase.configJSON))
					if err != nil {
						t.Fatal(err)
					}
					config.ConnectionWorkerPoolSize = 9
					config.EnablePersonalLightProxyTunnels = mode.enableLight
					if mode.enableInproxy {
						config.InproxyClientPersonalCompartmentID = "personal"
					}
					config.params, err = parameters.NewParameters(nil)
					if err != nil {
						t.Fatal(err)
					}
					if err := config.SetParameters("", false, testCase.tactics); err != nil {
						t.Fatal(err)
					}

					p := config.GetParameters().Get()
					defer p.Close()
					controller := &Controller{config: config}
					check := func(expected int) {
						t.Helper()
						if actual := controller.getConnectionWorkerPoolSize(p); actual != expected {
							t.Fatalf("got worker pool size %d, expected %d", actual, expected)
						}
					}
					expected := testCase.expected
					if !mode.enableInproxy && !mode.enableLight {
						expected = 9
					}
					check(expected)
					config.ConnectionWorkerPoolMaxSize = 1
					check(1)
					config.ConnectionWorkerPoolMaxSize = 0
					config.TargetServerEntry = "target"
					check(1)
					config.DisableConnectionWorkerPool = true
					check(0)
				})
			}
		})
	}
}

func TestRunningLightProxyConfig(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		change func(*Config)
	}{
		{"UpstreamProxy", func(config *Config) {
			config.UpstreamProxyURL = "http://127.0.0.1:8080"
		}},
		{"MissingDialAuthorizationKey", func(config *Config) {
			config.LightProxyDialAuthorizationPublicKey = ""
		}},
		{"TrustedProxyWithoutSigningKey", func(config *Config) {
			config.ProxySessionPrivateKey = ""
			config.LightProxyTrustedProxyAuthorization =
				base64.StdEncoding.EncodeToString([]byte{1})
		}},
		{"InvalidPersonalCompartmentID", func(config *Config) {
			config.ProxyPersonalCompartmentID = "invalid!"
		}},
		{"ShortPersonalCompartmentID", func(config *Config) {
			config.ProxyPersonalCompartmentID =
				base64.RawStdEncoding.EncodeToString(prng.Bytes(31))
		}},
		{"NoPersonalIDOrCommonCapacity", func(config *Config) {
			config.ProxyPersonalCompartmentID = ""
			maxCommonClients := 0
			config.ProxyMaxCommonClients = &maxCommonClients
		}},
		{"NoPersonalCapacity", func(config *Config) {
			*config.ProxyMaxPersonalClients = 0
			maxCommonClients := 1
			config.ProxyMaxCommonClients = &maxCommonClients
		}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			config := newRunningLightProxyTestConfig(t)
			testCase.change(config)
			if err := config.Commit(false); err == nil {
				t.Fatal("unexpected Commit success")
			}
		})
	}

	t.Run("CommonOnly", func(t *testing.T) {
		config := newRunningLightProxyTestConfig(t)
		config.ProxyPersonalCompartmentID = ""
		*config.ProxyMaxPersonalClients = 0
		maxCommonClients := 1
		config.ProxyMaxCommonClients = &maxCommonClients
		if err := config.Commit(false); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("Disabled", func(t *testing.T) {
		config := newRunningLightProxyTestConfig(t)
		config.EnableRunningLightProxy = false
		config.UpstreamProxyURL = "http://127.0.0.1:8080"
		config.LightProxyDialAuthorizationPublicKey = "invalid"
		if err := config.Commit(false); err != nil {
			t.Fatal(err)
		}
		controller, err := NewController(config)
		if err != nil {
			t.Fatal(err)
		}
		if err := controller.StartLightProxy(nil); err == nil {
			t.Fatal("unexpected StartLightProxy success")
		}
		if err := controller.StopLightProxy(); err == nil {
			t.Fatal("unexpected StopLightProxy success")
		}
	})

	for _, useDeprecatedFields := range []bool{false, true} {
		t.Run(fmt.Sprintf("Deprecated=%t", useDeprecatedFields), func(t *testing.T) {
			config := newRunningLightProxyTestConfig(t)
			expectedPrivateKey := config.ProxySessionPrivateKey
			expectedPersonalCompartmentID := config.ProxyPersonalCompartmentID

			limits, err := common.NewProxyLimits(&common.ProxyLimitsConfig{
				MaxCommonClients:   1,
				MaxPersonalClients: 2,
			})
			if err != nil {
				t.Fatal(err)
			}

			if useDeprecatedFields {
				config.InproxyProxyLimits = limits
				config.InproxyProxySessionPrivateKey = expectedPrivateKey
				config.ProxySessionPrivateKey = ""
				config.InproxyProxyPersonalCompartmentID = expectedPersonalCompartmentID
				config.ProxyPersonalCompartmentID = ""
			} else {
				config.ProxyLimits = limits
				config.InproxyProxySessionPrivateKey = "invalid"
				config.InproxyProxyPersonalCompartmentID = "invalid"
				config.InproxyProxyLimits, err =
					common.NewProxyLimits(&common.ProxyLimitsConfig{
						MaxCommonClients: 1,
					})
				if err != nil {
					t.Fatal(err)
				}
			}

			if err := config.Commit(false); err != nil {
				t.Fatal(err)
			}
			if config.ProxyLimits != limits ||
				config.ProxySessionPrivateKey != expectedPrivateKey ||
				config.ProxyPersonalCompartmentID != expectedPersonalCompartmentID {

				t.Fatal("unexpected proxy limits or identity")
			}
		})
	}

	personalCompartmentID := prng.Bytes(32)
	for _, testCase := range []struct {
		name          string
		compartmentID []byte
		expectedError string
	}{
		{"MissingEntryID", nil, "requires a personal compartment ID"},
		{"InvalidEntryID", prng.Bytes(31), "invalid personal compartment ID"},
		{"SelfPairing", personalCompartmentID, "invalid overlapping personal compartment IDs"},
		{"DistinctPersonalEntry", prng.Bytes(32), ""},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			config := newRunningLightProxyTestConfig(t)
			config.DisableTunnels = false
			config.EnablePersonalLightProxyTunnels = true
			config.ProxyPersonalCompartmentID =
				base64.RawStdEncoding.EncodeToString(personalCompartmentID)
			entry, err := protocol.CBOREncoding.Marshal(&light.SignedProxyEntry{
				ProxyEntry: light.ProxyEntry{
					ProxyID:               base64.RawStdEncoding.EncodeToString(prng.Bytes(32)),
					DialAddresses:         config.LightProxyDialAddresses,
					ObfuscationKey:        prng.Bytes(32),
					VerifyPin:             prng.Bytes(32),
					PersonalCompartmentID: testCase.compartmentID,
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			config.PersonalLightProxyEntries = [][]byte{entry}
			err = config.Commit(false)
			if testCase.expectedError == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), testCase.expectedError) {
				t.Fatalf("expected %q, got %v", testCase.expectedError, err)
			}
		})
	}
}

func TestControllerLightProxyLifecycle(t *testing.T) {
	emitDiagnostics := GetEmitDiagnosticNotices()
	emitNetworkParameters := GetEmitNetworkParameters()
	SetEmitDiagnosticNotices(true, false)
	defer SetEmitDiagnosticNotices(emitDiagnostics, emitNetworkParameters)

	for _, earlyReturn := range []bool{false, true} {
		t.Run(fmt.Sprintf("EarlyReturn=%t", earlyReturn), func(t *testing.T) {
			config := newRunningLightProxyTestConfig(t)
			var lookedUpGeoIP atomic.Bool
			config.LightProxyLookupGeoIP = func(string) common.GeoIPData {
				lookedUpGeoIP.Store(true)
				return common.GeoIPData{}
			}
			if earlyReturn {
				config.ListenInterface = "missing-light-test-interface"
				config.ProxySessionPrivateKey = ""
			} else {
				config.InproxyEnableProxy = inproxy.Enabled()
				// Start before port mapping has discovered public addresses.
				config.LightProxyDialAddresses = nil
			}
			if err := config.Commit(false); err != nil {
				t.Fatal(err)
			}
			controller, err := NewController(config)
			if err != nil {
				t.Fatal(err)
			}

			type notice struct {
				name string
				data map[string]interface{}
				err  error
			}
			notices := make(chan notice, 32)
			accepted := make(chan struct{}, 1)
			idle := make(chan struct{}, 1)
			stoppedResults := make(chan chan error, 1)
			err = SetNoticeWriter(NewNoticeReceiver(func(encoded []byte) {
				name, data, err := GetNotice(encoded)
				if name == "LightProxyStopped" {
					select {
					case result := <-stoppedResults:
						if len(result) != 1 {
							err = errors.TraceNew("proxy result not ready before stopped notice")
						}
					default:
					}
				}
				if err != nil {
					notices <- notice{err: err}
					return
				}
				switch name {
				case "LightProxyAllowed", "LightProxyDisallowed",
					"LightProxyListening", "LightProxyStarted",
					"LightProxyStopped", "LightProxyListenError",
					"InproxyProxyStopped", "Error", "Exiting":

					notices <- notice{name: name, data: data}
				case "LightProxyTotalActivity":
					if data["currentConnectionCount"] == float64(0) {
						select {
						case idle <- struct{}{}:
						default:
						}
					}
					if data["currentConnectionCount"] == float64(1) {
						select {
						case accepted <- struct{}{}:
						default:
						}
					}
				}
			}))
			if err != nil {
				t.Fatal(err)
			}
			defer ResetNoticeWriter()
			defer controller.StopLightProxy()

			waitNotice := func(expected string) map[string]interface{} {
				t.Helper()
				select {
				case notice := <-notices:
					if notice.err != nil {
						t.Fatal(notice.err)
					}
					if notice.name != expected {
						t.Fatalf("got %s, expected %s", notice.name, expected)
					}
					return notice.data
				case <-time.After(5 * time.Second):
					t.Fatalf("timeout awaiting %s", expected)
					return nil
				}
			}
			readListening := func() []light.ProxyAddress {
				t.Helper()
				addresses := make(
					[]light.ProxyAddress, len(config.LightProxyListenAddresses))
				for i := range addresses {
					data := waitNotice("LightProxyListening")
					host, portString, err := net.SplitHostPort(data["address"].(string))
					if err != nil {
						t.Fatal(err)
					}
					port, err := strconv.Atoi(portString)
					if err != nil || port <= 0 || host != "127.0.0.1" {
						t.Fatal("unexpected bound address")
					}
					proxyProtocol := data["protocol"].(string)
					if proxyProtocol != config.LightProxyListenAddresses[i].Protocol {
						t.Fatal("unexpected listener protocol")
					}
					addresses[i] = light.ProxyAddress{
						IPAddress: host,
						Port:      port,
						Protocol:  proxyProtocol,
					}
				}
				waitNotice("LightProxyStarted")
				return addresses
			}

			// Test: StartLightProxy requires Controller.Run.

			if err := controller.StartLightProxy(nil); err == nil {
				t.Fatal("unexpected start before Controller.Run")
			}

			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan struct{})
			go func() {
				defer close(done)
				controller.Run(ctx)
			}()
			defer func() {
				cancel()
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Error("controller shutdown timeout exceeded")
				}
			}()

			checkExited := func() {
				t.Helper()
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Fatal("Controller.Run did not exit")
				}
				if !earlyReturn {
					waitNotice("LightProxyStopped")
				}
				waitNotice("Exiting")
				if err := controller.StartLightProxy(nil); err == nil {
					t.Fatal("unexpected start after Controller.Run exited")
				}
				if err := controller.StopLightProxy(); err != nil {
					t.Fatal(err)
				}
				select {
				case notice := <-notices:
					t.Fatalf("unexpected notice: %s", notice.name)
				default:
				}
			}

			if earlyReturn {
				failure := waitNotice("Error")
				if !strings.Contains(
					failure["message"].(string), "error getting listener IP") {

					t.Fatal("unexpected Controller.Run failure")
				}
				checkExited()
				return
			}

			waitNotice("LightProxyAllowed")
			if config.InproxyEnableProxy {
				failure := waitNotice("InproxyProxyStopped")
				if failure["reason"] != "no_broker_specs" {
					t.Fatal("unexpected in-proxy startup failure")
				}
				controller.runWaitGroup.Wait()
				if controller.runCtx.Err() != nil {
					t.Fatal("missing broker specs stopped Light hosting")
				}
			}

			// Test: tactics reject Light proxy startup before binding listeners.

			setAllowed := func(allowed bool) {
				t.Helper()
				if err := config.SetParameters("", false, map[string]interface{}{
					parameters.LightTunnelAllowProxy: allowed,
				}); err != nil {
					t.Fatal(err)
				}
			}
			setAllowed(false)
			waitNotice("LightProxyDisallowed")
			if err := controller.StartLightProxy(nil); err == nil {
				t.Fatal("unexpected start while Light hosting is disabled")
			}
			setAllowed(true)
			waitNotice("LightProxyAllowed")

			// Test: concurrent starts and stops.

			results := make(chan error, 2)
			waitResult := func() error {
				t.Helper()
				select {
				case err := <-results:
					return err
				case <-time.After(5 * time.Second):
					t.Fatal("timeout awaiting lifecycle call")
					return nil
				}
			}
			for i := 0; i < 2; i++ {
				go func() { results <- controller.StartLightProxy(nil) }()
			}
			successes := 0
			for i := 0; i < 2; i++ {
				if waitResult() == nil {
					successes++
				}
			}
			if successes != 1 {
				t.Fatalf("unexpected successful starts: %d", successes)
			}
			addresses := readListening()

			// Test: tactics stop the proxy once; restarting does not require
			// calling StopLightProxy.

			stoppedResults <- controller.lightProxyResult
			setAllowed(false)
			waitNotice("LightProxyDisallowed")
			waitNotice("LightProxyStopped")
			setAllowed(false)
			select {
			case notice := <-notices:
				t.Fatalf("unexpected repeated notice: %s", notice.name)
			default:
			}
			setAllowed(true)
			waitNotice("LightProxyAllowed")
			if err := controller.StartLightProxy(addresses); err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(addresses, readListening()) {
				t.Fatal("restart did not reuse the requested endpoints")
			}

			for i := 0; i < 2; i++ {
				go func() { results <- controller.StopLightProxy() }()
			}
			for i := 0; i < 2; i++ {
				if err := waitResult(); err != nil {
					t.Fatal(err)
				}
			}
			waitNotice("LightProxyStopped")

			// Test: partial bind failure releases the earlier listener.

			var occupied io.Closer
			if addresses[1].Protocol == light.LIGHT_PROTOCOL_QUIC {
				occupied, err = net.ListenPacket("udp4", addresses[1].String())
			} else {
				occupied, err = net.Listen("tcp4", addresses[1].String())
			}
			if err != nil {
				t.Fatal(err)
			}
			defer occupied.Close()

			if err := controller.StartLightProxy(addresses); err == nil {
				t.Fatal("unexpected startup success with occupied endpoint")
			}
			failure := waitNotice("LightProxyListenError")
			if failure["listenAddress"] != addresses[1].String() {
				t.Fatal("listen error did not identify the failed endpoint")
			}
			waitNotice("LightProxyStopped")

			if err := occupied.Close(); err != nil {
				t.Fatal(err)
			}
			if err := controller.StartLightProxy(addresses); err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(addresses, readListening()) {
				t.Fatal("restart did not reuse the requested endpoints")
			}

			// Test: network changes close connections while listeners keep running.

			for i := 0; i < 2; i++ {
				conn, err := net.DialTimeout(
					"tcp", addresses[0].String(), 5*time.Second)
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				select {
				case <-accepted:
				case <-time.After(5 * time.Second):
					t.Fatal("timeout awaiting accepted connection")
				}

				select {
				case <-idle:
				default:
				}
				controller.NetworkChanged()

				if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
					t.Fatal(err)
				}
				var buffer [1]byte
				if _, err := conn.Read(buffer[:]); err == nil {
					t.Fatal("accepted connection remained open")
				} else if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					t.Fatal("accepted connection was not closed by network change")
				}
				conn.Close()
				select {
				case <-idle:
				case <-time.After(5 * time.Second):
					t.Fatal("timeout awaiting closed connection accounting")
				}
			}
			if !lookedUpGeoIP.Load() {
				t.Fatal("GeoIP lookup was not used")
			}

			// Test: Controller.Run cleanup interrupts an incomplete ingress handshake.

			conn, err := net.DialTimeout(
				"tcp", addresses[0].String(), 5*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			select {
			case <-accepted:
			case <-time.After(5 * time.Second):
				t.Fatal("timeout awaiting accepted connection")
			}

			cancel()
			checkExited()

			if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			var buffer [1]byte
			if _, err := conn.Read(buffer[:]); err == nil {
				t.Fatal("accepted connection remained open")
			} else if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				t.Fatal("accepted connection was not closed by shutdown")
			}
		})
	}
}

func TestControllerInproxyDisallow(t *testing.T) {
	if !inproxy.Enabled() {
		t.Skip("in-proxy is not enabled")
	}

	for _, startup := range []bool{true, false} {
		for _, disableTunnels := range []bool{true, false} {
			for _, hostedLight := range []bool{true, false} {
				name := fmt.Sprintf("Startup=%t/DisableTunnels=%t/HostedLight=%t",
					startup, disableTunnels, hostedLight)
				t.Run(name, func(t *testing.T) {
					config := newRunningLightProxyTestConfig(t)
					config.InproxyEnableProxy = true
					config.InproxySkipAwaitFullyConnected = true
					config.DisableTunnels = disableTunnels
					config.DisableTactics = startup
					config.EnableRunningLightProxy = hostedLight
					config.LightProxyDialAddresses = config.LightProxyDialAddresses[:1]
					config.LightProxyListenAddresses = config.LightProxyListenAddresses[:1]
					if err := config.Commit(false); err != nil {
						t.Fatal(err)
					}
					controller, err := NewController(config)
					if err != nil {
						t.Fatal(err)
					}
					controller.runCtx, controller.stopRunning = context.WithCancel(context.Background())
					defer controller.stopRunning()
					defer controller.currentNetworkCancelFunc(nil)

					err = config.SetParameters("initial", false, map[string]interface{}{
						parameters.InproxyAllowProxy:     !startup,
						parameters.LightTunnelAllowProxy: true,
					})
					if err != nil {
						t.Fatal(err)
					}

					listening := make(chan string, 1)
					var stoppedNotice map[string]interface{}
					err = SetNoticeWriter(NewNoticeReceiver(func(encoded []byte) {
						noticeType, data, err := GetNotice(encoded)
						if err == nil && noticeType == "InproxyProxyStopped" {
							stoppedNotice = data
						}
						if err == nil && noticeType == "LightProxyListening" {
							address, _ := data["address"].(string)
							listening <- address
						}
					}))
					if err != nil {
						t.Fatal(err)
					}
					defer ResetNoticeWriter()

					var listenAddress string
					if hostedLight {
						defer controller.StopLightProxy()
						if err := controller.StartLightProxy(nil); err != nil {
							t.Fatal(err)
						}
						select {
						case listenAddress = <-listening:
						default:
							t.Fatal("missing Light listener address")
						}
					}

					proxyCtx, stopProxy := context.WithCancel(controller.runCtx)
					defer stopProxy()
					if startup {
						controller.runWaitGroup.Add(1)
						controller.runInproxyProxy()
						controller.runWaitGroup.Wait()
					} else {
						encodedTactics, err := json.Marshal(&tactics.Tactics{
							TTL:         "1h",
							Probability: 1,
							Parameters: map[string]interface{}{
								parameters.InproxyAllowProxy:     false,
								parameters.LightTunnelAllowProxy: true,
							},
						})
						if err != nil {
							t.Fatal(err)
						}
						payload, err := json.Marshal(&tactics.Payload{
							Tag:     "disallowed",
							Tactics: encodedTactics,
						})
						if err != nil {
							t.Fatal(err)
						}
						if !controller.inproxyHandleProxyTacticsPayload(
							stopProxy, config.GetNetworkID(), false, payload) {

							t.Fatal("broker tactics were not applied")
						}
						if got := proxyCtx.Err() != nil; got != disableTunnels {
							t.Fatalf("in-proxy cancelled = %t, want %t", got, disableTunnels)
						}
					}

					wantControllerStopped := disableTunnels && !hostedLight
					if startup && (stoppedNotice == nil ||
						stoppedNotice["reason"] != "not_allowed") {

						t.Fatalf("unexpected stopped notice: %v", stoppedNotice)
					}
					if got := controller.runCtx.Err() != nil; got != wantControllerStopped {
						t.Fatalf("Controller stopped = %t, want %t", got, wantControllerStopped)
					}
					if hostedLight {
						conn, err := net.DialTimeout("tcp", listenAddress, time.Second)
						if err != nil {
							t.Fatalf("hosted Light listener is unavailable: %v", err)
						}
						conn.Close()
					}
				})
			}
		}
	}
}

func TestControllerInproxyNetworkWaitCancellation(t *testing.T) {
	checker := &inproxyBlockedNetworkChecker{checked: make(chan struct{}, 1)}
	controller := &Controller{
		config: &Config{
			ProxyPersonalCompartmentID: "test",
			NetworkConnectivityChecker: checker,
		},
	}
	controller.runCtx, controller.stopRunning = context.WithCancel(context.Background())
	defer controller.stopRunning()
	proxyCtx, stopProxy := context.WithCancel(controller.runCtx)
	defer stopProxy()

	done := make(chan bool, 1)
	go func() {
		done <- controller.inproxyWaitForNetworkConnectivity(proxyCtx)
	}()

	select {
	case <-checker.checked:
	case <-time.After(5 * time.Second):
		t.Fatal("network connectivity wait did not start")
	}
	stopProxy()
	select {
	case connected := <-done:
		if connected {
			t.Fatal("cancelled network wait reported connectivity")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("in-proxy cancellation did not interrupt network connectivity wait")
	}
	if controller.runCtx.Err() != nil {
		t.Fatal("in-proxy cancellation stopped the Controller")
	}
}

type inproxyBlockedNetworkChecker struct {
	checked chan struct{}
}

func (checker *inproxyBlockedNetworkChecker) HasNetworkConnectivity() int {
	select {
	case checker.checked <- struct{}{}:
	default:
	}
	return 0
}

func newRunningLightProxyTestConfig(t *testing.T) *Config {
	t.Helper()

	certificate, privateKey, _, err :=
		common.GenerateWebServerCertificate("localhost")
	if err != nil {
		t.Fatal(err)
	}
	publicKey, _, err := protocol.NewServerEntrySignatureKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	proxyPrivateKey, err := inproxy.GenerateSessionPrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	dialAddresses := []light.ProxyAddress{
		{IPAddress: "127.0.0.1", Port: 443, Protocol: light.LIGHT_PROTOCOL_TLS},
		{IPAddress: "127.0.0.1", Port: 444, Protocol: light.LIGHT_PROTOCOL_TLS},
	}
	if quic.Enabled() {
		dialAddresses[1].Protocol = light.LIGHT_PROTOCOL_QUIC
	}
	listenAddresses := slices.Clone(dialAddresses)
	for i := range listenAddresses {
		listenAddresses[i].Port = 0
	}
	maxPersonalClients := 2

	return &Config{
		DataRootDirectory:                    t.TempDir(),
		PropagationChannelId:                 "0000000000000000",
		SponsorId:                            "0000000000000000",
		ClientPlatform:                       "Windows",
		ClientVersion:                        "1",
		DisableTunnels:                       true,
		DisableTactics:                       true,
		DisableRemoteServerListFetcher:       true,
		DisableDSLFetcher:                    true,
		EnableRunningLightProxy:              true,
		ProxySessionPrivateKey:               proxyPrivateKey.String(),
		ProxyMaxPersonalClients:              &maxPersonalClients,
		ProxyPersonalCompartmentID:           base64.RawStdEncoding.EncodeToString(prng.Bytes(32)),
		LightProxyDialAddresses:              dialAddresses,
		LightProxyListenAddresses:            listenAddresses,
		LightProxyObfuscationKey:             prng.HexString(32),
		LightProxyTLSCertificate:             certificate,
		LightProxyTLSPrivateKey:              privateKey,
		LightProxyPassthroughAddress:         "127.0.0.1:1",
		LightProxyDialAuthorizationPublicKey: publicKey,
	}
}

type testLightProxyEntryIterator struct {
	lightTunnelProxyEntryIterator
	next func(string) ([]byte, *StoredLightProxyEntry, error)
}

func (s testLightProxyEntryIterator) Next(
	ingressProtocol string) ([]byte, *StoredLightProxyEntry, error) {
	return s.next(ingressProtocol)
}

func TestLightTunnelDialParametersAndReplay(t *testing.T) {
	if err := SetNoticeWriter(io.Discard); err != nil {
		t.Fatal(err)
	}
	defer ResetNoticeWriter()

	type testCase struct {
		tunnelProtocol string
		common         bool
	}
	var testCases []testCase
	for _, tunnelProtocol := range protocol.LightTunnelProtocols {
		for _, common := range []bool{false, true} {
			testCases = append(testCases, testCase{tunnelProtocol, common})
		}
	}
	for _, testCase := range testCases {
		tunnelProtocol := testCase.tunnelProtocol
		t.Run(fmt.Sprintf("%s/Common=%t", tunnelProtocol, testCase.common), func(t *testing.T) {
			ingressQUIC := protocol.TunnelProtocolUsesLightQUICIngress(tunnelProtocol)
			egressQUIC := protocol.TunnelProtocolUsesLightQUICEgress(tunnelProtocol)
			if ingressQUIC && !quic.Enabled() {
				t.Skip("QUIC is not enabled")
			}
			ingressProtocol := light.LIGHT_PROTOCOL_TLS
			if ingressQUIC {
				ingressProtocol = light.LIGHT_PROTOCOL_QUIC
			}
			personalCompartmentID := prng.Bytes(32)
			if testCase.common {
				personalCompartmentID = nil
			}
			signedEntry := &light.SignedProxyEntry{
				ProxyEntry: light.ProxyEntry{
					ProxyID: base64.RawStdEncoding.EncodeToString(prng.Bytes(32)),
					DialAddresses: []light.ProxyAddress{
						{IPAddress: "127.0.0.1", Port: 443, Protocol: ingressProtocol},
						{IPAddress: "::1", Port: 443, Protocol: ingressProtocol},
					},
					ObfuscationKey:                   prng.Bytes(32),
					VerifyPin:                        prng.Bytes(32),
					RecommendedTLSProfile:            protocol.TLS_PROFILE_CHROME_133,
					RecommendedTLSProfileProbability: 1,
					RecommendedSNI:                   "recommended.example.org",
					RecommendedSNIProbability:        1,
					PersonalCompartmentID:            personalCompartmentID,
					TTLSeconds:                       3600,
				},
			}
			entry, err := protocol.CBOREncoding.Marshal(signedEntry)
			if err != nil {
				t.Fatal(err)
			}
			config := &Config{
				DataRootDirectory:               t.TempDir(),
				PropagationChannelId:            "0",
				SponsorId:                       "0000000000000000",
				NetworkID:                       "WIFI-test",
				EnablePersonalLightProxyTunnels: !testCase.common,
				EnableLightProxyFallback:        testCase.common,
			}
			if testCase.common {
				config.FallbackLightProxyEntry = entry
				config.FallbackLightProxyEntryTracker = 2
			} else {
				config.PersonalLightProxyEntries = [][]byte{entry}
			}
			if err := config.Commit(false); err != nil {
				t.Fatal(err)
			}
			if err := OpenDataStore(config); err != nil {
				t.Fatal(err)
			}
			defer CloseDataStore()
			controller, err := NewController(config)
			if err != nil {
				t.Fatal(err)
			}
			resolver := NewResolver(config, config.deviceBinder())
			defer resolver.Stop()
			config.SetResolver(resolver)

			fallbackClient := config.GetLightFallbackProxyClient()
			if (fallbackClient != nil) != testCase.common {
				t.Fatal("unexpected shared fallback client")
			}
			if testCase.common {
				if err := StoreCommonLightTunnelProxyEntry(entry, 1); err != nil {
					t.Fatal(err)
				}
			}
			iterator, err := NewCommonLightTunnelProxyEntryIterator(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			var entryIterator lightTunnelProxyEntryIterator = iterator
			if !testCase.common {
				entryIterator = newPersonalLightProxyEntryIterator(config)
			}
			constraints := &protocolSelectionConstraints{
				config:                        config,
				limitTunnelProtocols:          protocol.TunnelProtocols{tunnelProtocol},
				replayCandidateCount:          -1,
				lightTunnelProxyEntryIterator: entryIterator,
			}
			canReplay := func(serverEntry *protocol.ServerEntry, p string) bool {
				return constraints.canReplay(0, false, true, serverEntry, p)
			}

			serverEntry := makeMockServerEntries(tunnelProtocol, "CA", "", "", 1)[0]
			serverEntry.LightDialAuthorization = []byte{1}
			serverEntry.LightTlsSSHPort = 443
			serverEntry.LightQuicSSHPort = 443
			serverEntry.LimitQUICVersions = protocol.QUICVersions{protocol.QUIC_VERSION_OBFUSCATED_V1}
			selectProtocol := func(*protocol.ServerEntry, bool, string) (string, bool) {
				return tunnelProtocol, true
			}
			cacheKeys := []string{
				lightSessionCacheKeyPrefix + "127.0.0.1:443",
				lightSessionCacheKeyPrefix + "[::1]:443",
			}
			// A session for the same address that is not a Light session,
			// such as from a fronted dial, is not cleared.
			cacheKeys = append(cacheKeys, "127.0.0.1:443", "unrelated:443")
			seedSessions := func() {
				for _, key := range cacheKeys {
					controller.tlsClientSessionCache.Put(key, &utls.ClientSessionState{})
					controller.quicTLSClientSessionCache.Put(key, &psiphontls.ClientSessionState{})
				}
			}
			checkSessions := func(retained bool) {
				t.Helper()
				for _, key := range cacheKeys {
					tlsSession, _ := controller.tlsClientSessionCache.Get(key)
					quicSession, _ := controller.quicTLSClientSessionCache.Get(key)
					isLight := strings.HasPrefix(key, lightSessionCacheKeyPrefix)
					wantTLS := retained || ingressQUIC || !isLight
					wantQUIC := retained || !ingressQUIC || !isLight
					if (tlsSession != nil) != wantTLS || (quicSession != nil) != wantQUIC {
						t.Fatalf("unexpected session cache state for %s", key)
					}
				}
			}
			makeParams := func() *DialParameters {
				t.Helper()
				dialParams, err := MakeDialParameters(
					config, nil, controller.quicTLSClientSessionCache, controller.tlsClientSessionCache, nil, nil,
					canReplay, selectProtocol, entryIterator, serverEntry, nil, nil, false, 0)
				if err != nil || dialParams == nil {
					t.Fatalf("MakeDialParameters: %v", err)
				}
				return dialParams
			}
			values := map[string]interface{}{
				parameters.LimitTLSProfiles:                             protocol.TLSProfiles{protocol.TLS_PROFILE_CHROME_133, protocol.TLS_PROFILE_RANDOMIZED},
				parameters.SelectRandomizedTLSProfileProbability:        1.0,
				parameters.LimitQUICVersions:                            protocol.QUICVersions{protocol.QUIC_VERSION_V1},
				parameters.QUICDisableClientPathMTUDiscoveryProbability: 1.0,
				parameters.ObfuscatedQUICNonceTransformProbability:      1.0,
				parameters.ObfuscatedQUICNonceTransformSpecs:            transforms.Specs{"spec": transforms.Spec{{"", ""}}},
				parameters.ObfuscatedQUICNonceTransformScopedSpecNames:  transforms.ScopedSpecNames{"": {"spec"}},
				parameters.CustomHostNameRegexes:                        []string{`stock\.example\.org`},
				parameters.CustomHostNameProbability:                    1.0,
				parameters.LightTunnelEgressLimitTLSProfiles:            protocol.TLSProfiles{protocol.TLS_PROFILE_RANDOMIZED},
				parameters.LightTunnelEgressLimitQUICVersions:           protocol.QUICVersions{protocol.QUIC_VERSION_OBFUSCATED_V1},
				parameters.LightTunnelEgressCustomHostNameRegexes:       []string{`egress\.example\.org`},
				parameters.LightTunnelEgressCustomHostNameProbability:   1.0,
				parameters.LightTunnelTLSFragmentClientHelloProbability: 1.0,
				parameters.LightTunnelTLSPaddingProbability:             1.0,
				parameters.LightTunnelMinTLSPadding:                     64,
				parameters.LightTunnelMaxTLSPadding:                     64,
			}
			revision := 0
			apply := func() {
				t.Helper()

				// Test: tactics updates leave existing constraint snapshots unchanged.

				previousConstraints := *constraints
				previousProtocols := previousConstraints.serverSupportedProtocols(
					previousConstraints.limitTunnelProtocols, false, serverEntry)
				revision++
				if err := config.SetParameters(strconv.Itoa(revision), false, values); err != nil {
					t.Fatal(err)
				}
				p := config.GetParameters().Get()
				constraints.initializeLightQUICLimits(p)
				p.Close()
				if !reflect.DeepEqual(previousProtocols,
					previousConstraints.serverSupportedProtocols(
						previousConstraints.limitTunnelProtocols, false, serverEntry)) {

					t.Fatal("tactics changed the previous constraint snapshot")
				}
			}
			seeds := func(p *DialParameters) []*prng.Seed {
				var nonceSeed *prng.Seed
				if p.LightObfuscatedQUICNonceTransformerParameters != nil {
					nonceSeed = p.LightObfuscatedQUICNonceTransformerParameters.TransformSeed
				}
				return []*prng.Seed{
					p.LightRandomizedTLSProfileSeed, p.LightEgressRandomizedTLSProfileSeed,
					p.LightQUICDialRootObfuscationSeed, p.LightEgressQUICDialRootObfuscationSeed,
					nonceSeed,
				}
			}
			apply()

			// Test: split tunneling excludes fresh and replay Light candidates.

			for _, ownRegion := range []bool{false, true} {
				config.SplitTunnelOwnRegion = ownRegion
				config.SplitTunnelRegions = nil
				if !ownRegion {
					config.SplitTunnelRegions = []string{"CA"}
				}
				_, _, selected := constraints.selectProtocol(
					0, false, personalPairingProtocolNone, false, "", serverEntry)
				if selected || canReplay(serverEntry, tunnelProtocol) {
					t.Fatal("accepted Light candidate with split tunneling")
				}
			}
			config.SplitTunnelOwnRegion = false
			config.SplitTunnelRegions = nil

			// Test: missing authorization and invalid ports reject fresh and replay candidates.

			candidate := *serverEntry
			candidate.LightDialAuthorization = nil
			_, _, selected := constraints.selectProtocol(
				0, false, personalPairingProtocolNone, false, "", &candidate)
			if selected || canReplay(&candidate, tunnelProtocol) {
				t.Fatal("accepted candidate without Light dial authorization")
			}
			for _, port := range []int{-1, 0, 65536} {
				candidate = *serverEntry
				if egressQUIC {
					candidate.LightQuicSSHPort = port
				} else {
					candidate.LightTlsSSHPort = port
				}
				_, _, selected = constraints.selectProtocol(
					0, false, personalPairingProtocolNone, false, "", &candidate)
				if selected || canReplay(&candidate, tunnelProtocol) {
					t.Fatalf("accepted candidate with invalid Light port %d", port)
				}
			}

			// Test: candidate filtering keeps ingress and egress QUIC limits separate.

			for _, serverQUICVersion := range []string{
				protocol.QUIC_VERSION_OBFUSCATED_V1,
				protocol.QUIC_VERSION_V1,
				protocol.QUIC_VERSION_GQUIC43,
			} {
				candidate := *serverEntry
				candidate.LimitQUICVersions = []string{serverQUICVersion}
				_, _, selected := constraints.selectProtocol(
					0, false, personalPairingProtocolNone, false, "", &candidate)
				expected := !egressQUIC || serverQUICVersion == protocol.QUIC_VERSION_OBFUSCATED_V1
				if selected != expected || canReplay(&candidate, tunnelProtocol) != expected {
					t.Fatalf("unexpected candidate filtering for server QUIC version %s", serverQUICVersion)
				}
			}

			// Test: ingress QUIC limits reject candidates before version selection
			// only when applied with probability 1.

			if ingressQUIC && quic.GQUICEnabled() {
				values[parameters.LightTunnelIngressLimitQUICVersions] =
					protocol.QUICVersions{protocol.QUIC_VERSION_GQUIC43}
				for _, probability := range []float64{1, 0.5, 0} {
					values[parameters.LimitQUICVersionsProbability] = probability
					apply()
					_, _, selected := constraints.selectProtocol(
						0, false, personalPairingProtocolNone, false, "", serverEntry)
					expected := probability < 1
					if selected != expected || canReplay(serverEntry, tunnelProtocol) != expected {
						t.Fatalf("unexpected candidate filtering with ingress limit probability %v", probability)
					}
				}
				delete(values, parameters.LightTunnelIngressLimitQUICVersions)
				delete(values, parameters.LimitQUICVersionsProbability)
				apply()
			}

			// Test: fresh dials and failures clear only this proxy's ingress sessions
			// for the selected transport.

			seedSessions()
			dialParams := makeParams()
			checkSessions(false)
			seedSessions()
			dialParams.Failed(config, errors.TraceNew("test"))
			checkSessions(false)

			// Test: ingress uses shared tactics, egress uses separate tactics, and
			// tunnel dials ignore proxy entry recommendations.

			if dialParams.LightSNI != "stock.example.org" || dialParams.LightEgressSNI != "egress.example.org" {
				t.Fatal("unexpected SNI selection")
			}
			if ingressQUIC {
				if dialParams.LightQUICVersion != protocol.QUIC_VERSION_V1 {
					t.Fatal("server-entry QUIC limit affected ingress")
				}
				if !dialParams.LightQUICDisablePathMTUDiscovery ||
					dialParams.LightObfuscatedQUICNonceTransformerParameters != nil {

					t.Fatal("unexpected ingress QUIC tactics selection")
				}
			} else if dialParams.LightTLSProfile != protocol.TLS_PROFILE_RANDOMIZED ||
				!dialParams.LightTLSFragmentClientHello || dialParams.LightTLSPadding != 64 {
				t.Fatal("unexpected ingress TLS selection")
			}
			if egressQUIC {
				if dialParams.LightEgressQUICVersion != protocol.QUIC_VERSION_OBFUSCATED_V1 {
					t.Fatal("unexpected egress QUIC selection")
				}
			} else if dialParams.LightEgressTLSProfile != protocol.TLS_PROFILE_RANDOMIZED {
				t.Fatal("unexpected egress TLS selection")
			}
			if testCase.common && !ingressQUIC {
				fallback, err := makeLightFallbackDialParameters(config, fallbackClient)
				if err != nil {
					t.Fatal(err)
				}
				if fallback.SNI != "recommended.example.org" || fallback.TLSProfile != protocol.TLS_PROFILE_CHROME_133 {
					t.Fatal("fallback did not honor entry recommendations")
				}
			}

			// Test: restrictive tactics may require matching or empty SNIs.

			for _, sni := range []string{"same.example.org", ""} {
				regexes := []string{regexp.QuoteMeta(sni)}
				values[parameters.LightTunnelIngressCustomHostNameRegexes] = regexes
				values[parameters.LightTunnelEgressCustomHostNameRegexes] = regexes
				apply()
				next := makeParams()
				if next.LightSNI != sni || next.LightEgressSNI != sni {
					t.Fatalf("unexpected SNI selection for %q", sni)
				}
			}
			values[parameters.LightTunnelEgressCustomHostNameRegexes] = []string{`egress\.example\.org`}

			// Test: explicit ingress overrides and persisted replay of both hops.

			values[parameters.LimitTLSProfiles] = protocol.TLSProfiles{protocol.TLS_PROFILE_CHROME_133}
			values[parameters.LightTunnelIngressLimitTLSProfiles] = protocol.TLSProfiles{protocol.TLS_PROFILE_RANDOMIZED}
			values[parameters.LightTunnelIngressLimitQUICVersions] = protocol.QUICVersions{protocol.QUIC_VERSION_OBFUSCATED_V1}
			values[parameters.LightTunnelIngressCustomHostNameRegexes] = []string{`override\.example\.org`}
			apply()
			dialParams = makeParams()
			if dialParams.LightSNI != "override.example.org" ||
				(!ingressQUIC && dialParams.LightTLSProfile != protocol.TLS_PROFILE_RANDOMIZED) ||
				(ingressQUIC && dialParams.LightQUICVersion != protocol.QUIC_VERSION_OBFUSCATED_V1) {
				t.Fatal("ingress override not selected")
			}
			if ingressQUIC && dialParams.LightObfuscatedQUICNonceTransformerParameters == nil {
				t.Fatal("missing ingress QUIC nonce transform")
			}
			dialParams.Succeeded()
			savedEntryIterator := entryIterator
			entryIterator = testLightProxyEntryIterator{entryIterator, func(string) ([]byte, *StoredLightProxyEntry, error) {
				return nil, nil, errors.TraceNew("replay selected an entry")
			}}
			seedSessions()
			replayed := makeParams()
			entryIterator = savedEntryIterator
			checkSessions(true)
			if !replayed.IsReplay || !reflect.DeepEqual(dialParams.GetLightTunnelMetrics(), replayed.GetLightTunnelMetrics()) ||
				dialParams.LightQUICDisablePathMTUDiscovery != replayed.LightQUICDisablePathMTUDiscovery ||
				!reflect.DeepEqual(dialParams.LightObfuscatedQUICNonceTransformerParameters, replayed.LightObfuscatedQUICNonceTransformerParameters) ||
				!reflect.DeepEqual(seeds(dialParams), seeds(replayed)) {
				t.Fatal("Light dial parameters were not replayed")
			}

			if !bytes.Equal(dialParams.ProxyEntryHash, replayed.ProxyEntryHash) {
				t.Fatal("replay changed the entry")
			}
			entryHash := sha256.Sum256(entry)
			if !bytes.Equal(dialParams.ProxyEntryHash, entryHash[:]) {
				t.Fatal("dial did not retain its entry hash")
			}

			var group sync.WaitGroup
			clients := make([]*light.Client, 4)
			for i := range clients {
				group.Add(1)
				go func() {
					defer group.Done()
					params, err := MakeDialParameters(
						config, nil, nil, nil, nil, nil,
						canReplay, selectProtocol, entryIterator, serverEntry, nil, nil, false, 0)
					if err != nil || params == nil || !params.IsReplay ||
						!bytes.Equal(params.ProxyEntryHash, dialParams.ProxyEntryHash) {

						t.Errorf("concurrent Light replay failed: %v", err)
						return
					}
					clients[i] = params.lightProxyClient
				}()
			}
			group.Wait()
			seen := map[*light.Client]bool{fallbackClient: true}
			clients = append(clients, dialParams.lightProxyClient, replayed.lightProxyClient)
			for _, client := range clients {
				if client == nil || seen[client] {
					t.Fatal("concurrent Light dials shared a client")
				}
				seen[client] = true
			}
			if config.GetLightFallbackProxyClient() != fallbackClient {
				t.Fatal("tunnel dial replaced the shared fallback client")
			}

			// Test: handshake and failed-tunnel stats identify the selected proxy.

			expectedTracker := strconv.FormatInt(LightProxyEntryTrackerPersonalPairing, 10)
			if testCase.common {
				expectedTracker = "1"
			}
			apiParams := getBaseAPIParameters(baseParametersAll, nil, false, config, dialParams)
			packedPayload, err := protocol.MakePackedAPIParametersRequestPayload(
				common.APIParameters{
					"light_proxy_id":            apiParams["light_proxy_id"],
					"light_proxy_entry_tracker": apiParams["light_proxy_entry_tracker"],
				})
			if err != nil {
				t.Fatal(err)
			}
			apiParams, isPacked, err := protocol.GetPackedAPIParametersRequestPayload(packedPayload)
			if err != nil || !isPacked {
				t.Fatalf("invalid packed handshake parameters: %v", err)
			}
			if apiParams["light_proxy_id"] != signedEntry.ProxyEntry.ProxyID {
				t.Fatal("tunnel handshake proxy ID does not match selected entry")
			}
			if apiParams["light_proxy_entry_tracker"] != expectedTracker {
				t.Fatal("tunnel handshake entry tracker does not match selected entry")
			}
			values[parameters.RecordFailedTunnelPersistentStatsProbability] = 1.0
			values[parameters.ReplayIgnoreChangedConfigStateProbability] = 1.0
			apply()
			if err := RecordFailedTunnelStat(config, dialParams, nil, 0, 0, errors.TraceNew("test")); err != nil {
				t.Fatal(err)
			}
			stats, _, err := TakeOutUnreportedPersistentStats(config, 0)
			if err != nil || len(stats[datastorePersistentStatTypeFailedTunnel]) != 1 {
				t.Fatalf("missing failed-tunnel stat: %v", err)
			}
			var failedParams common.APIParameters
			if err := json.Unmarshal(stats[datastorePersistentStatTypeFailedTunnel][0], &failedParams); err != nil {
				t.Fatal(err)
			}
			if failedParams["light_proxy_id"] != signedEntry.ProxyEntry.ProxyID ||
				failedParams["light_proxy_entry_tracker"] != expectedTracker {

				t.Fatal("failed-tunnel proxy metrics do not match selected entry")
			}

			// Test: replay controls refresh only the applicable transport seeds.

			for _, parameter := range []string{
				parameters.ReplayTLSProfile, parameters.ReplayQUICVersion, parameters.ReplayObfuscatedQUIC,
				parameters.ReplayObfuscatedQUICNonceTransformer,
			} {
				values[parameter] = false
				apply()
				next := makeParams()
				if !next.IsReplay || !reflect.DeepEqual(dialParams.GetLightTunnelMetrics(), next.GetLightTunnelMetrics()) {
					t.Fatal("unexpected replay selection")
				}
				refresh := []bool{
					parameter == parameters.ReplayTLSProfile && !ingressQUIC,
					parameter == parameters.ReplayTLSProfile && !egressQUIC,
					(parameter == parameters.ReplayQUICVersion || parameter == parameters.ReplayObfuscatedQUIC) && ingressQUIC,
					(parameter == parameters.ReplayQUICVersion || parameter == parameters.ReplayObfuscatedQUIC) && egressQUIC,
					(parameter == parameters.ReplayQUICVersion || parameter == parameters.ReplayObfuscatedQUICNonceTransformer) && ingressQUIC,
				}
				for i, seed := range seeds(next) {
					if reflect.DeepEqual(seed, seeds(dialParams)[i]) == refresh[i] {
						t.Fatalf("%s: unexpected seed refresh at index %d", parameter, i)
					}
				}
				next.Succeeded()
				dialParams = next
				values[parameter] = true
			}

			// Test: disabling hostname and TLS ClientHello fragmentation replay
			// applies current tactics.

			values[parameters.ReplayHostname] = false
			values[parameters.ReplayTLSFragmentClientHello] = false
			values[parameters.LightTunnelIngressCustomHostNameRegexes] = []string{`fresh-ingress\.example\.org`}
			values[parameters.LightTunnelEgressCustomHostNameRegexes] = []string{`fresh-egress\.example\.org`}
			values[parameters.LightTunnelTLSFragmentClientHelloProbability] = 0.0
			apply()
			next := makeParams()
			if !next.IsReplay || next.LightSNI != "fresh-ingress.example.org" ||
				next.LightEgressSNI != "fresh-egress.example.org" ||
				next.LightTLSFragmentClientHello || !reflect.DeepEqual(seeds(dialParams), seeds(next)) {
				t.Fatal("unexpected hostname or fragmentation replay")
			}
			dialParams = next
			values[parameters.ReplayHostname] = true
			values[parameters.ReplayTLSFragmentClientHello] = true

			if !ingressQUIC {
				// Test: TLS padding is capped, and ClientHello fragmentation is disabled
				// when the replayed SNI is empty or an IP address.

				values[parameters.ReplayObfuscatorPadding] = false
				values[parameters.LightTunnelMinTLSPadding] = tlsdialer.MaxTLSPadding + 1
				values[parameters.LightTunnelMaxTLSPadding] = tlsdialer.MaxTLSPadding + 1
				for _, sni := range []string{"", "192.0.2.1"} {
					dialParams.LightSNI = sni
					dialParams.LightTLSFragmentClientHello = true
					dialParams.Succeeded()
					apply()
					dialParams = makeParams()
					if !dialParams.IsReplay || dialParams.LightTLSFragmentClientHello ||
						dialParams.LightTLSPadding != tlsdialer.MaxTLSPadding {
						t.Fatal("padding cap or fragmentation guard failed")
					}
				}
			}
			if ingressQUIC {
				// Test: switching from obfuscated QUIC to QUICv1 clears nonce transforms
				// and applies the current path MTU discovery tactic.

				values[parameters.ReplayQUICVersion] = false
				values[parameters.LightTunnelIngressLimitQUICVersions] = protocol.QUICVersions{protocol.QUIC_VERSION_V1}
				values[parameters.QUICDisableClientPathMTUDiscoveryProbability] = 0.0
				apply()
				dialParams = makeParams()
				if dialParams.LightQUICDisablePathMTUDiscovery ||
					dialParams.LightObfuscatedQUICNonceTransformerParameters != nil {

					t.Fatal("stale ingress QUIC tactics selection")
				}
			}
			if testCase.common {
				// Test: replay uses the updated proxy entry tracker.

				if err := StoreCommonLightTunnelProxyEntry(entry, 3); err != nil {
					t.Fatal(err)
				}
				dialParams.Succeeded()
				dialParams = makeParams()
				if !dialParams.IsReplay || dialParams.LightProxyEntryTracker != 3 {
					t.Fatal("replay did not use the updated entry tracker")
				}

				// Test: if the saved proxy entry is missing, expired, or corrupt, use
				// fresh dial parameters for its replacement.

				for _, invalidation := range []string{"missing", "expired", "corrupt"} {
					oldHash := dialParams.ProxyEntryHash
					signedEntry.ProxyEntry.DialAddresses[0].Port++
					replacement, err := protocol.CBOREncoding.Marshal(signedEntry)
					if err != nil {
						t.Fatal(err)
					}
					if err := StoreCommonLightTunnelProxyEntry(replacement, 2); err != nil {
						t.Fatal(err)
					}
					switch invalidation {
					case "missing":
						err = deleteBucketValue(datastoreCommonLightTunnelProxyEntriesBucket, oldHash)
					case "expired":
						setCommonLightTunnelProxyEntryExpiry(t, oldHash, time.Now().Add(-time.Hour))
					case "corrupt":
						err = setBucketValue(datastoreCommonLightTunnelProxyEntriesBucket, oldHash, []byte("invalid"))
					}
					if err != nil {
						t.Fatal(err)
					}
					dialParams.Succeeded()
					replacementHash := sha256.Sum256(replacement)
					// Select only the replacement after replay rejects the old version.
					entryIterator = testLightProxyEntryIterator{iterator, func(ingress string) ([]byte, *StoredLightProxyEntry, error) {
						stored, err := LoadCommonLightTunnelProxyEntry(replacementHash[:], ingress)
						return replacementHash[:], stored, err
					}}
					dialParams = makeParams()
					if dialParams.IsReplay || !bytes.Equal(dialParams.ProxyEntryHash, replacementHash[:]) ||
						dialParams.LightProxyID != signedEntry.ProxyEntry.ProxyID ||
						dialParams.LightProxyEntryTracker != 2 {

						t.Fatalf("%s: replay substituted another entry version", invalidation)
					}
				}
			}

			if egressQUIC {
				// Test: incompatible server and tactics QUIC limits reject the dial.

				values[parameters.ReplayQUICVersion] = false
				values[parameters.LightTunnelEgressLimitQUICVersions] = protocol.QUICVersions{protocol.QUIC_VERSION_V1}
				apply()
				dialParams, err := MakeDialParameters(
					config, nil, nil, nil, nil, nil,
					canReplay, selectProtocol, entryIterator, serverEntry, nil, nil, false, 0)
				if err != nil || dialParams != nil {
					t.Fatalf("unexpected dial with incompatible egress QUIC limits: %v", err)
				}
			}
		})
	}
}

func TestLightProxyActivity(t *testing.T) {
	emitDiagnostics := GetEmitDiagnosticNotices()
	emitNetworkParameters := GetEmitNetworkParameters()
	SetEmitDiagnosticNotices(true, false)
	defer SetEmitDiagnosticNotices(emitDiagnostics, emitNetworkParameters)

	for _, emitActivity := range []bool{false, true} {
		t.Run(fmt.Sprintf("EmitActivity=%t", emitActivity), func(t *testing.T) {
			params, err := parameters.NewParameters(nil)
			if err != nil {
				t.Fatal(err)
			}
			config := &Config{params: params, EmitLightProxyActivity: emitActivity}
			setPeriod := func(period string) {
				t.Helper()
				if _, err := params.Set("", 0, map[string]interface{}{
					parameters.LightTunnelProxyTotalActivityNoticePeriod: period,
				}); err != nil {
					t.Fatal(err)
				}
			}
			type notice struct {
				name string
				data map[string]interface{}
			}
			var notices []notice
			if err := SetNoticeWriter(NewNoticeReceiver(func(encoded []byte) {
				name, data, err := GetNotice(encoded)
				if err != nil {
					t.Error(err)
					return
				}
				notices = append(notices, notice{name, data})
			})); err != nil {
				t.Fatal(err)
			}
			defer ResetNoticeWriter()
			check := func(want []string) {
				t.Helper()
				var names []string
				for _, notice := range notices {
					names = append(names, notice.name)
				}
				if !slices.Equal(names, want) {
					t.Fatalf("notices: got %v, expected %v", names, want)
				}
				notices = nil
			}
			activityNotices := func(total bool) []string {
				var names []string
				if emitActivity {
					names = append(names, "LightProxyActivity")
				}
				if total {
					names = append(names, "LightProxyTotalActivity")
				}
				return names
			}
			setPeriod("1h")
			receiver := newLightProxyEventReceiver(config)
			for _, emitDiagnostics := range []bool{false, true} {
				SetEmitDiagnosticNotices(emitDiagnostics, false)
				receiver.Connection(&light.ConnectionStats{BytesRead: 1, BytesWritten: 2})
				check(nil)
				receiver.Connection(&light.ConnectionStats{
					ProxyCompletedLightHeader: time.Now(),
					BytesRead:                 1, BytesWritten: 2,
				})
				receiver.IrregularConnection("", common.GeoIPData{}, "test irregularity")
				if emitDiagnostics {
					check([]string{"Info", "Warning"})
				} else {
					check(nil)
				}
			}
			receiver.Activity(&light.ActivityStats{CurrentConnectionCount: 1, BytesUp: 10, BytesDown: 20})
			check(activityNotices(true))
			receiver.Activity(&light.ActivityStats{CurrentConnectionCount: 1})
			check(nil)

			// Kind and region changes must be reported even with unchanged aggregate counts.
			receiver.Activity(&light.ActivityStats{
				CurrentConnectionCount: 1,
				PersonalRegionActivity: map[string]light.RegionActivitySnapshot{
					"None": {BytesUp: 10, BytesDown: 20, ConnectedClients: 1},
				},
			})
			for _, notice := range notices {
				regions, ok := notice.data["personalRegionActivity"].(map[string]interface{})
				if !ok {
					t.Fatal("missing personal region activity")
				}
				activity, ok := regions["None"].(map[string]interface{})
				if !ok || activity["bytesUp"] != float64(10) ||
					activity["bytesDown"] != float64(20) ||
					activity["connectedClients"] != float64(1) {
					t.Fatal("incorrect None bucket notice")
				}
			}
			check(activityNotices(false))
			receiver.Activity(&light.ActivityStats{
				CurrentConnectionCount: 1,
				PersonalRegionActivity: map[string]light.RegionActivitySnapshot{
					"None": {ConnectedClients: 1},
				},
			})
			check(nil)
			// Region bytes can arrive after their aggregate count was reported.
			receiver.Activity(&light.ActivityStats{
				CurrentConnectionCount: 1,
				PersonalRegionActivity: map[string]light.RegionActivitySnapshot{
					"None": {BytesUp: 1, ConnectedClients: 1},
				},
			})
			check(activityNotices(false))
			receiver.Activity(&light.ActivityStats{
				CurrentConnectionCount: 1,
				CommonRegionActivity: map[string]light.RegionActivitySnapshot{
					"None": {ConnectedClients: 1},
				},
			})
			check(activityNotices(false))
			receiver.Activity(&light.ActivityStats{
				CurrentConnectionCount: 1,
				CommonRegionActivity: map[string]light.RegionActivitySnapshot{
					"CA": {ConnectedClients: 1},
				},
			})
			check(activityNotices(false))
			receiver.Activity(&light.ActivityStats{CurrentConnectionCount: 1})
			check(activityNotices(false))
			if len(receiver.lastPersonalRegionActivity) != 0 ||
				len(receiver.lastCommonRegionActivity) != 0 {
				t.Fatal("expired region snapshots were retained")
			}

			receiver.lastActivityNotice = time.Now().Add(-2 * time.Second)
			receiver.Activity(&light.ActivityStats{CurrentConnectionCount: 1, BytesUp: 1})
			check(activityNotices(false))
			setPeriod("1s")
			receiver.Activity(&light.ActivityStats{CurrentConnectionCount: 1})
			check([]string{"LightProxyTotalActivity"})
			receiver.Activity(&light.ActivityStats{})
			check(activityNotices(true))

			receiver.Stopped()
			if len(notices) != 2 || notices[0].data["totalBytesUp"] != float64(11) ||
				notices[0].data["totalBytesDown"] != float64(20) ||
				notices[0].data["currentConnectionCount"] != float64(0) {
				t.Fatal("incorrect final activity totals")
			}
			_, personalRegions := notices[0].data["personalRegionActivity"]
			_, commonRegions := notices[0].data["commonRegionActivity"]
			if personalRegions || commonRegions {
				t.Fatal("total activity must not include region snapshots")
			}
			check([]string{"LightProxyTotalActivity", "LightProxyStopped"})
			newLightProxyEventReceiver(config).Stopped()
			if len(notices) != 2 || notices[0].data["totalBytesUp"] != float64(0) ||
				notices[0].data["totalBytesDown"] != float64(0) {
				t.Fatal("activity totals did not reset for a new run")
			}
			check([]string{"LightProxyTotalActivity", "LightProxyStopped"})

			SetEmitDiagnosticNotices(false, false)
			newLightProxyEventReceiver(config).Activity(&light.ActivityStats{BytesUp: 1})
			check(activityNotices(false))
			SetEmitDiagnosticNotices(true, false)
		})
	}
}

func TestCommonLightTunnelProxyEntries(t *testing.T) {
	if err := SetNoticeWriter(io.Discard); err != nil {
		t.Fatal(err)
	}
	defer ResetNoticeWriter()

	signedEntry := &light.SignedProxyEntry{ProxyEntry: light.ProxyEntry{
		ProxyID: base64.RawStdEncoding.EncodeToString(prng.Bytes(32)),
		DialAddresses: []light.ProxyAddress{
			{IPAddress: "127.0.0.1", Port: 443, Protocol: light.LIGHT_PROTOCOL_TLS},
		},
		ObfuscationKey: prng.Bytes(32),
		VerifyPin:      prng.Bytes(32),
		TTLSeconds:     3600,
	}}
	encode := func() []byte {
		t.Helper()
		encoded, err := protocol.CBOREncoding.Marshal(signedEntry)
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	}
	tlsEntry := encode()
	tlsHash := sha256.Sum256(tlsEntry)
	config := &Config{
		DataRootDirectory:        t.TempDir(),
		PropagationChannelId:     "0",
		SponsorId:                "0000000000000000",
		NetworkID:                "WIFI-test",
		EnableLightProxyFallback: true,
		LightProxyEntry:          tlsEntry,
	}
	if err := config.Commit(false); err != nil {
		t.Fatal(err)
	}
	if err := OpenDataStore(config); err != nil {
		t.Fatal(err)
	}
	defer CloseDataStore()
	if _, err := NewController(config); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	iterator, err := NewCommonLightTunnelProxyEntryIterator(ctx)
	if err != nil {
		t.Fatal(err)
	}
	constraints := &protocolSelectionConstraints{
		config:                        config,
		lightTunnelProxyEntryIterator: iterator,
	}

	// Test: common Light tunnel selection ignores the configured fallback entry.

	if constraints.supportsLightProtocol(light.LIGHT_PROTOCOL_TLS) {
		t.Fatal("fallback entry used for common tunnels")
	}
	if iterator.imports.Load() != datastoreCommonLightTunnelProxyEntriesImports.Load() {
		t.Fatal("constructor did not capture imports")
	}

	// Test: malformed entries, personal entries, and zero or negative TTLs are rejected.

	if err := StoreCommonLightTunnelProxyEntry([]byte("invalid"), 0); err == nil {
		t.Fatal("accepted malformed entry")
	}
	signedEntry.ProxyEntry.PersonalCompartmentID = prng.Bytes(32)
	if err := StoreCommonLightTunnelProxyEntry(encode(), 0); err == nil {
		t.Fatal("accepted personal entry")
	}
	signedEntry.ProxyEntry.PersonalCompartmentID = nil
	for _, ttl := range []int64{0, -1} {
		signedEntry.ProxyEntry.TTLSeconds = ttl
		if err := StoreCommonLightTunnelProxyEntry(encode(), 0); err == nil {
			t.Fatalf("accepted TTL %d", ttl)
		}
	}
	signedEntry.ProxyEntry.TTLSeconds = 3600
	if iterator.imports.Load() != datastoreCommonLightTunnelProxyEntriesImports.Load() {
		t.Fatal("failed imports advanced the import count")
	}

	// Test: identical imports refresh one record; changed versions coexist.

	if err := StoreCommonLightTunnelProxyEntry(tlsEntry, 1); err != nil {
		t.Fatal(err)
	}
	setCommonLightTunnelProxyEntryExpiry(t, tlsHash[:], time.Now().Add(-time.Hour))
	if err := StoreCommonLightTunnelProxyEntry(tlsEntry, 2); err != nil {
		t.Fatal(err)
	}
	stored, err := LoadCommonLightTunnelProxyEntry(tlsHash[:], light.LIGHT_PROTOCOL_TLS)
	if err != nil || stored == nil || stored.LightProxyEntryTracker != 2 ||
		!stored.Expires.After(time.Now()) || !bytes.Equal(stored.LightProxyEntry, tlsEntry) {

		t.Fatalf("reimport lost refreshed entry: %v", err)
	}
	loadedAgain, err := LoadCommonLightTunnelProxyEntry(tlsHash[:], light.LIGHT_PROTOCOL_TLS)
	if err != nil || loadedAgain == nil || !loadedAgain.Expires.Equal(stored.Expires) {
		t.Fatalf("load renewed expiry: %v", err)
	}
	signedEntry.ProxyEntry.DialAddresses = append(signedEntry.ProxyEntry.DialAddresses,
		light.ProxyAddress{IPAddress: "127.0.0.1", Port: 443, Protocol: light.LIGHT_PROTOCOL_QUIC})
	quicEntry := encode()
	quicHash := sha256.Sum256(quicEntry)
	if err := StoreCommonLightTunnelProxyEntry(quicEntry, 3); err != nil {
		t.Fatal(err)
	}
	if constraints.supportsLightProtocol(light.LIGHT_PROTOCOL_TLS) {
		t.Fatal("new entry appeared in an existing empty snapshot")
	}
	if iterator.imports.Load() == datastoreCommonLightTunnelProxyEntriesImports.Load() {
		t.Fatal("imports did not signal a refresh")
	}
	if err := iterator.Reset(ctx); err != nil {
		t.Fatal(err)
	}
	if iterator.imports.Load() != datastoreCommonLightTunnelProxyEntriesImports.Load() {
		t.Fatal("reset did not capture imports")
	}
	for _, ingress := range []string{light.LIGHT_PROTOCOL_TLS, light.LIGHT_PROTOCOL_QUIC} {
		if !constraints.supportsLightProtocol(ingress) {
			t.Fatalf("common entry did not make %s eligible", ingress)
		}
	}
	if len(iterator.proxyEntryHashes[light.LIGHT_PROTOCOL_TLS]) != 2 ||
		len(iterator.proxyEntryHashes[light.LIGHT_PROTOCOL_QUIC]) != 1 ||
		iterator.indexes[light.LIGHT_PROTOCOL_TLS] != 0 ||
		iterator.indexes[light.LIGHT_PROTOCOL_QUIC] != 0 {

		t.Fatal("unexpected snapshot or consuming availability check")
	}
	constraints.lightTunnelProxyEntryIterator = nil
	if constraints.supportsLightProtocol(light.LIGHT_PROTOCOL_TLS) {
		t.Fatal("missing entry entryIterator made Light eligible")
	}
	constraints.lightTunnelProxyEntryIterator = iterator

	// Test: concurrent workers and resets preserve transport filtering.

	var group sync.WaitGroup
	for i := 0; i < 4; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			ingress := light.LIGHT_PROTOCOL_TLS
			if i%2 != 0 {
				ingress = light.LIGHT_PROTOCOL_QUIC
			}
			for j := 0; j < 10; j++ {
				hash, stored, err := iterator.Next(ingress)
				validHash := bytes.Equal(hash, quicHash[:]) ||
					(ingress == light.LIGHT_PROTOCOL_TLS && bytes.Equal(hash, tlsHash[:]))
				if err != nil || stored == nil || !validHash {
					t.Errorf("incorrect %s iterator selection: %v", ingress, err)
					return
				}
				if err := iterator.Reset(ctx); err != nil {
					t.Error(err)
					return
				}
			}
		}()
	}
	group.Wait()

	// Test: loads skip expired entries; Reset prunes them and their index entries.

	setCommonLightTunnelProxyEntryExpiry(t, tlsHash[:], time.Now().Add(-time.Hour))
	if stored, err := LoadCommonLightTunnelProxyEntry(tlsHash[:], light.LIGHT_PROTOCOL_TLS); err != nil || stored != nil {
		t.Fatalf("loaded expired entry: %v", err)
	}
	if value, err := copyBucketValue(datastoreCommonLightTunnelProxyEntriesBucket, tlsHash[:]); err != nil || value == nil {
		t.Fatalf("load deleted expired entry: %v", err)
	}
	if err := iterator.Reset(ctx); err != nil {
		t.Fatal(err)
	}
	if value, err := copyBucketValue(datastoreCommonLightTunnelProxyEntryIndexBuckets[light.LIGHT_PROTOCOL_TLS], tlsHash[:]); err != nil || value != nil {
		t.Fatalf("expired index entry was not deleted: %v", err)
	}
	for i := 0; i < 2; i++ {
		if hash, stored, err := iterator.Next(light.LIGHT_PROTOCOL_TLS); err != nil ||
			stored == nil || !bytes.Equal(hash, quicHash[:]) {

			t.Fatalf("expired entry prevented selecting a live entry: %v", err)
		}
	}
	if value, err := copyBucketValue(datastoreCommonLightTunnelProxyEntriesBucket, tlsHash[:]); err != nil || value != nil {
		t.Fatalf("expired entry was not deleted: %v", err)
	}
	if hash, stored, err := iterator.Next(light.LIGHT_PROTOCOL_QUIC); err != nil ||
		stored == nil || !bytes.Equal(hash, quicHash[:]) {

		t.Fatalf("live entry hidden by expired entry: %v", err)
	}

	// Test: corrupt records are skipped without deletion, then pruned on expiry.

	value, err := copyBucketValue(datastoreCommonLightTunnelProxyEntriesBucket, quicHash[:])
	if err != nil {
		t.Fatal(err)
	}
	for _, invalidValue := range [][]byte{[]byte("invalid"), value} {
		if err := StoreCommonLightTunnelProxyEntry(tlsEntry, 1); err != nil {
			t.Fatal(err)
		}
		if err := setBucketValue(datastoreCommonLightTunnelProxyEntriesBucket, tlsHash[:], invalidValue); err != nil {
			t.Fatal(err)
		}
		if err := iterator.Reset(ctx); err != nil {
			t.Fatal(err)
		}
		iterator.proxyEntryHashes[light.LIGHT_PROTOCOL_TLS] = [][]byte{tlsHash[:], quicHash[:]}
		if !iterator.HasNext(light.LIGHT_PROTOCOL_TLS) {
			t.Fatal("invalid entry prevented availability")
		}
		if hash, stored, err := iterator.Next(light.LIGHT_PROTOCOL_TLS); err != nil ||
			stored == nil || !bytes.Equal(hash, quicHash[:]) {

			t.Fatalf("invalid entry prevented selecting a live entry: %v", err)
		}
		if value, err := copyBucketValue(datastoreCommonLightTunnelProxyEntriesBucket, tlsHash[:]); err != nil || !bytes.Equal(value, invalidValue) {
			t.Fatalf("load changed invalid entry: %v", err)
		}
		var expires [8]byte
		binary.LittleEndian.PutUint64(expires[:], uint64(time.Now().Add(-time.Hour).UnixMicro()))
		if err := setBucketValue(datastoreCommonLightTunnelProxyEntryIndexBuckets[light.LIGHT_PROTOCOL_TLS], tlsHash[:], expires[:]); err != nil {
			t.Fatal(err)
		}
		if err := iterator.Reset(ctx); err != nil {
			t.Fatal(err)
		}
		if value, err := copyBucketValue(datastoreCommonLightTunnelProxyEntriesBucket, tlsHash[:]); err != nil || value != nil {
			t.Fatalf("expired corrupt entry was not deleted: %v", err)
		}
	}

	// Test: pruning an entry supporting TLS and QUIC removes its key from both indexes.

	setCommonLightTunnelProxyEntryExpiry(t, quicHash[:], time.Now().Add(-time.Hour))
	if err := iterator.Reset(ctx); err != nil {
		t.Fatal(err)
	}
	for ingress, bucket := range datastoreCommonLightTunnelProxyEntryIndexBuckets {
		if iterator.HasNext(ingress) {
			t.Fatalf("expired entry still available for %s", ingress)
		}
		if value, err := copyBucketValue(bucket, quicHash[:]); err != nil || value != nil {
			t.Fatalf("expired %s index entry was not deleted: %v", ingress, err)
		}
	}

	// Test: malformed TLS index entries are removed without deleting the
	// proxy entry or its valid QUIC index entry.

	if err := StoreCommonLightTunnelProxyEntry(quicEntry, 3); err != nil {
		t.Fatal(err)
	}
	indexBucket := datastoreCommonLightTunnelProxyEntryIndexBuckets[light.LIGHT_PROTOCOL_TLS]
	invalidKey := []byte("invalid")
	var expires [8]byte
	binary.LittleEndian.PutUint64(expires[:], uint64(time.Now().Add(time.Hour).UnixMicro()))
	for _, record := range []struct{ key, value []byte }{
		{invalidKey, expires[:]},
		{quicHash[:], []byte("invalid")},
	} {
		if err := setBucketValue(indexBucket, record.key, record.value); err != nil {
			t.Fatal(err)
		}
	}
	if err := iterator.Reset(ctx); err != nil {
		t.Fatal(err)
	}
	for _, key := range [][]byte{invalidKey, quicHash[:]} {
		if value, err := copyBucketValue(indexBucket, key); err != nil || value != nil {
			t.Fatalf("malformed index was not deleted: %v", err)
		}
	}
	if hash, stored, err := iterator.Next(light.LIGHT_PROTOCOL_QUIC); err != nil ||
		stored == nil || !bytes.Equal(hash, quicHash[:]) {

		t.Fatalf("malformed index cleanup deleted a live entry: %v", err)
	}
}

func setCommonLightTunnelProxyEntryExpiry(t *testing.T, hash []byte, expires time.Time) {
	t.Helper()
	value, err := copyBucketValue(datastoreCommonLightTunnelProxyEntriesBucket, hash)
	if err != nil {
		t.Fatal(err)
	}
	var stored StoredLightProxyEntry
	if err := json.Unmarshal(value, &stored); err != nil {
		t.Fatal(err)
	}
	stored.Expires = expires
	value, err = json.Marshal(stored)
	if err != nil {
		t.Fatal(err)
	}
	var expiry [8]byte
	binary.LittleEndian.PutUint64(expiry[:], uint64(expires.UnixMicro()))
	err = datastoreUpdate(func(tx *datastoreTx) error {
		if err := tx.bucket(datastoreCommonLightTunnelProxyEntriesBucket).put(hash, value); err != nil {
			return err
		}
		for _, bucket := range datastoreCommonLightTunnelProxyEntryIndexBuckets {
			index := tx.bucket(bucket)
			if index.get(hash) != nil {
				if err := index.put(hash, expiry[:]); err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
