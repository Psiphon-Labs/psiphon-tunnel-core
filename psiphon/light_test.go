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
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/light"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/push"
)

func TestControllerLightProxy(t *testing.T) {
	if err := runTestControllerLightProxy(false); err != nil {
		t.Fatal(err.Error())
	}
}

func TestControllerImportPushPayloadLightProxyDial(t *testing.T) {
	if err := runTestControllerLightProxy(true); err != nil {
		t.Fatal(err.Error())
	}
}

func runTestControllerLightProxy(importPushPayload bool) (retErr error) {
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

	lightProxyEntry, shutdownLightProxy, err := startLightTestProxy(ctx, webServerAddress)
	if err != nil {
		return errors.Trace(err)
	}
	defer shutdownLightProxy()
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
		EnableLightProxy:              true,
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
				LightProxyEntries: []*push.LightProxyEntry{{
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

	if importPushPayload {
		storedLightProxy := LoadLightProxy()
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

	err = doHTTPSWebServerFetches(ctx, localProxyPort, webServerAddress)
	if err != nil {
		return errors.Trace(err)
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
	allowedWebServerAddress string) ([]byte, func(), error) {

	proxyListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, nil, errors.Trace(err)
	}
	proxyAddress := proxyListener.Addr().String()

	err = proxyListener.Close()
	if err != nil {
		return nil, nil, errors.Trace(err)
	}

	// Exercise the dual dialer.
	proxyIPv6Address := net.JoinHostPort(
		"::1",
		strconv.Itoa(proxyListener.Addr().(*net.TCPAddr).Port))

	proxyConfig, proxyEntry, err := light.Generate(
		prng.HexString(8),
		[]string{proxyAddress, proxyIPv6Address},
		proxyAddress,
		proxyIPv6Address,
		"example.org",
		"",
		[]string{allowedWebServerAddress},
		allowedWebServerAddress)
	if err != nil {
		return nil, nil, errors.Trace(err)
	}

	receiver := newTestLightProxyEventReceiver()
	proxy, err := light.NewProxy(
		proxyConfig,
		func(string) common.GeoIPData { return common.GeoIPData{} },
		receiver)
	if err != nil {
		return nil, nil, errors.Trace(err)
	}

	proxyCtx, stopProxy := context.WithCancel(ctx)
	go func() {
		_ = proxy.Run(proxyCtx)
	}()

	select {
	case <-receiver.listening:
	case <-ctx.Done():
		stopProxy()
		return nil, nil, errors.Trace(ctx.Err())
	}

	return proxyEntry, stopProxy, nil
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
		IpAddress:            host,
		WebServerPort:        "0",
		SshPort:              sshPort,
		SshUsername:          "unused",
		SshPassword:          "unused",
		SshHostKey:           base64.StdEncoding.EncodeToString([]byte("unused")),
		Capabilities:         []string{protocol.GetCapability(protocol.TUNNEL_PROTOCOL_SSH)},
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
	listening     chan struct{}
	listeningOnce sync.Once
}

func newTestLightProxyEventReceiver() *testLightProxyEventReceiver {
	return &testLightProxyEventReceiver{
		listening: make(chan struct{}),
	}
}

func (receiver *testLightProxyEventReceiver) Listening(address string) {
	receiver.listeningOnce.Do(func() {
		close(receiver.listening)
	})
	fmt.Printf("[Listening] %s\n", address)
}

func (r *testLightProxyEventReceiver) Paused() {
	fmt.Printf("[Paused]\n")
}

func (r *testLightProxyEventReceiver) Resumed() {
	fmt.Printf("[Resumed]\n")
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

func TestControllerImportPushPayloadLightProxy(t *testing.T) {

	dataRoot, err := ioutil.TempDir("", "psiphon-controller-push-light-proxy-test")
	if err != nil {
		t.Fatal(errors.Trace(err))
	}
	defer os.RemoveAll(dataRoot)

	_, lightProxyEntry, err := light.Generate(
		prng.HexString(8),
		[]string{"127.0.0.1:1"},
		"127.0.0.1:1",
		"",
		"example.org",
		"",
		[]string{"example.com:443"},
		"example.com:443")
	if err != nil {
		t.Fatal(errors.Trace(err))
	}
	_, lightProxyEntry2, err := light.Generate(
		prng.HexString(8),
		[]string{"127.0.0.1:2"},
		"127.0.0.1:2",
		"",
		"example.org",
		"",
		[]string{"example.com:443"},
		"example.com:443")
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
		EnableLightProxy:              true,
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
			LightProxyEntries: []*push.LightProxyEntry{{
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

	storedLightProxy := LoadLightProxy()
	if storedLightProxy == nil {
		t.Fatal("missing stored light proxy")
	}
	if (!bytes.Equal(storedLightProxy.LightProxyEntry, lightProxyEntry) ||
		storedLightProxy.LightProxyEntryTracker != lightProxyEntryTracker) &&
		(!bytes.Equal(storedLightProxy.LightProxyEntry, lightProxyEntry2) ||
			storedLightProxy.LightProxyEntryTracker != lightProxyEntryTracker2) {

		t.Fatal("unexpected stored light proxy")
	}

	lightProxyClient, _ := controller.lightProxyClient.Load().(*light.Client)
	if lightProxyClient == nil {
		t.Fatal("missing initialized light proxy client")
	}
}

func TestControllerImportPushPayloadLightProxyStoreFailure(t *testing.T) {

	dataRoot, err := ioutil.TempDir("", "psiphon-controller-push-light-proxy-store-failure-test")
	if err != nil {
		t.Fatal(errors.Trace(err))
	}
	defer os.RemoveAll(dataRoot)

	_, lightProxyEntry, err := light.Generate(
		prng.HexString(8),
		[]string{"127.0.0.1:1"},
		"127.0.0.1:1",
		"",
		"example.org",
		"",
		[]string{"example.com:443"},
		"example.com:443")
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
		EnableLightProxy:              true,
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
			LightProxyEntries: []*push.LightProxyEntry{{
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

	lightProxyClient, _ := controller.lightProxyClient.Load().(*light.Client)
	if lightProxyClient != nil {
		t.Fatal("light proxy client was initialized despite store failure")
	}
}

func TestControllerImportPushPayloadInvalidLightProxyNotStored(t *testing.T) {

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
		EnableLightProxy:              true,
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
			LightProxyEntries: []*push.LightProxyEntry{{
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

	if storedLightProxy := LoadLightProxy(); storedLightProxy != nil {
		t.Fatal("invalid light proxy was stored")
	}

	lightProxyClient, _ := controller.lightProxyClient.Load().(*light.Client)
	if lightProxyClient != nil {
		t.Fatal("invalid light proxy client was initialized")
	}
}
