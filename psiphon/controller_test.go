/*
 * Copyright (c) 2015, Psiphon Inc.
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
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Psiphon-Inc/goarista/monotime"
	socks "github.com/Psiphon-Inc/goptlib"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/elazarl/goproxy"
)

func TestMain(m *testing.M) {
	flag.Parse()
	os.Remove(DATA_STORE_FILENAME)
	initDisruptor()
	initUpstreamProxy()
	SetEmitDiagnosticNotices(true)
	os.Exit(m.Run())
}

// Test case notes/limitations/dependencies:
//
// * Untunneled upgrade tests must execute before
//   the other tests to ensure no tunnel is established.
//   We need a way to reset the datastore after it's been
//   initialized in order to to clear out its data entries
//   and be able to arbitrarily order the tests.
//
// * The resumable download tests using disruptNetwork
//   depend on the download object being larger than the
//   disruptorMax limits so that the disruptor will actually
//   interrupt the first download attempt. Specifically, the
//   upgrade and remote server list at the URLs specified in
//   controller_test.config.enc.
//
// * The protocol tests assume there is at least one server
//   supporting each protocol in the server list at the URL
//   specified in controller_test.config.enc, and that these
//   servers are not overloaded.
//
// * fetchAndVerifyWebsite depends on the target URL being
//   available and responding.
//

func TestUntunneledUpgradeDownload(t *testing.T) {
	controllerRun(t,
		&controllerRunConfig{
			expectNoServerEntries:    true,
			protocol:                 "",
			clientIsLatestVersion:    false,
			disableUntunneledUpgrade: false,
			disableEstablishing:      true,
			disableApi:               false,
			tunnelPoolSize:           1,
			useUpstreamProxy:         false,
			disruptNetwork:           false,
			useHostNameTransformer:   false,
			runDuration:              0,
		})
}

func TestUntunneledResumableUpgradeDownload(t *testing.T) {
	controllerRun(t,
		&controllerRunConfig{
			expectNoServerEntries:    true,
			protocol:                 "",
			clientIsLatestVersion:    false,
			disableUntunneledUpgrade: false,
			disableEstablishing:      true,
			disableApi:               false,
			tunnelPoolSize:           1,
			useUpstreamProxy:         false,
			disruptNetwork:           true,
			useHostNameTransformer:   false,
			runDuration:              0,
		})
}

func TestUntunneledUpgradeClientIsLatestVersion(t *testing.T) {
	controllerRun(t,
		&controllerRunConfig{
			expectNoServerEntries:    true,
			protocol:                 "",
			clientIsLatestVersion:    true,
			disableUntunneledUpgrade: false,
			disableEstablishing:      true,
			disableApi:               false,
			tunnelPoolSize:           1,
			useUpstreamProxy:         false,
			disruptNetwork:           false,
			useHostNameTransformer:   false,
			runDuration:              0,
		})
}

func TestUntunneledResumableFetchRemoveServerList(t *testing.T) {
	controllerRun(t,
		&controllerRunConfig{
			expectNoServerEntries:    true,
			protocol:                 "",
			clientIsLatestVersion:    true,
			disableUntunneledUpgrade: false,
			disableEstablishing:      false,
			disableApi:               false,
			tunnelPoolSize:           1,
			useUpstreamProxy:         false,
			disruptNetwork:           true,
			useHostNameTransformer:   false,
			runDuration:              0,
		})
}

func TestTunneledUpgradeClientIsLatestVersion(t *testing.T) {
	controllerRun(t,
		&controllerRunConfig{
			expectNoServerEntries:    false,
			protocol:                 "",
			clientIsLatestVersion:    true,
			disableUntunneledUpgrade: true,
			disableEstablishing:      false,
			disableApi:               false,
			tunnelPoolSize:           1,
			useUpstreamProxy:         false,
			disruptNetwork:           false,
			useHostNameTransformer:   false,
			runDuration:              0,
		})
}

func TestImpairedProtocols(t *testing.T) {

	// This test sets a tunnelPoolSize of 40 and runs
	// the session for 1 minute with network disruption
	// on. All 40 tunnels being disrupted every 10
	// seconds (followed by ssh keep alive probe timeout)
	// should be sufficient to trigger at least one
	// impaired protocol classification.

	controllerRun(t,
		&controllerRunConfig{
			expectNoServerEntries:    false,
			protocol:                 "",
			clientIsLatestVersion:    true,
			disableUntunneledUpgrade: true,
			disableEstablishing:      false,
			disableApi:               false,
			tunnelPoolSize:           40,
			useUpstreamProxy:         false,
			disruptNetwork:           true,
			useHostNameTransformer:   false,
			runDuration:              1 * time.Minute,
		})
}

func TestSSH(t *testing.T) {
	controllerRun(t,
		&controllerRunConfig{
			expectNoServerEntries:    false,
			protocol:                 common.TUNNEL_PROTOCOL_SSH,
			clientIsLatestVersion:    false,
			disableUntunneledUpgrade: true,
			disableEstablishing:      false,
			disableApi:               false,
			tunnelPoolSize:           1,
			useUpstreamProxy:         false,
			disruptNetwork:           false,
			useHostNameTransformer:   false,
			runDuration:              0,
		})
}

func TestObfuscatedSSH(t *testing.T) {
	controllerRun(t,
		&controllerRunConfig{
			expectNoServerEntries:    false,
			protocol:                 common.TUNNEL_PROTOCOL_OBFUSCATED_SSH,
			clientIsLatestVersion:    false,
			disableUntunneledUpgrade: true,
			disableEstablishing:      false,
			disableApi:               false,
			tunnelPoolSize:           1,
			useUpstreamProxy:         false,
			disruptNetwork:           false,
			useHostNameTransformer:   false,
			runDuration:              0,
		})
}

func TestUnfrontedMeek(t *testing.T) {
	controllerRun(t,
		&controllerRunConfig{
			expectNoServerEntries:    false,
			protocol:                 common.TUNNEL_PROTOCOL_UNFRONTED_MEEK,
			clientIsLatestVersion:    false,
			disableUntunneledUpgrade: true,
			disableEstablishing:      false,
			disableApi:               false,
			tunnelPoolSize:           1,
			useUpstreamProxy:         false,
			disruptNetwork:           false,
			useHostNameTransformer:   false,
			runDuration:              0,
		})
}

func TestUnfrontedMeekWithTransformer(t *testing.T) {
	controllerRun(t,
		&controllerRunConfig{
			expectNoServerEntries:    false,
			protocol:                 common.TUNNEL_PROTOCOL_UNFRONTED_MEEK,
			clientIsLatestVersion:    true,
			disableUntunneledUpgrade: true,
			disableEstablishing:      false,
			disableApi:               false,
			tunnelPoolSize:           1,
			useUpstreamProxy:         false,
			disruptNetwork:           false,
			useHostNameTransformer:   true,
			runDuration:              0,
		})
}

func TestFrontedMeek(t *testing.T) {
	controllerRun(t,
		&controllerRunConfig{
			expectNoServerEntries:    false,
			protocol:                 common.TUNNEL_PROTOCOL_FRONTED_MEEK,
			clientIsLatestVersion:    false,
			disableUntunneledUpgrade: true,
			disableEstablishing:      false,
			disableApi:               false,
			tunnelPoolSize:           1,
			useUpstreamProxy:         false,
			disruptNetwork:           false,
			useHostNameTransformer:   false,
			runDuration:              0,
		})
}

func TestFrontedMeekWithTransformer(t *testing.T) {
	controllerRun(t,
		&controllerRunConfig{
			expectNoServerEntries:    false,
			protocol:                 common.TUNNEL_PROTOCOL_FRONTED_MEEK,
			clientIsLatestVersion:    true,
			disableUntunneledUpgrade: true,
			disableEstablishing:      false,
			disableApi:               false,
			tunnelPoolSize:           1,
			useUpstreamProxy:         false,
			disruptNetwork:           false,
			useHostNameTransformer:   true,
			runDuration:              0,
		})
}

func TestFrontedMeekHTTP(t *testing.T) {
	controllerRun(t,
		&controllerRunConfig{
			expectNoServerEntries:    false,
			protocol:                 common.TUNNEL_PROTOCOL_FRONTED_MEEK_HTTP,
			clientIsLatestVersion:    true,
			disableUntunneledUpgrade: true,
			disableEstablishing:      false,
			disableApi:               false,
			tunnelPoolSize:           1,
			useUpstreamProxy:         false,
			disruptNetwork:           false,
			useHostNameTransformer:   false,
			runDuration:              0,
		})
}

func TestUnfrontedMeekHTTPS(t *testing.T) {
	controllerRun(t,
		&controllerRunConfig{
			expectNoServerEntries:    false,
			protocol:                 common.TUNNEL_PROTOCOL_UNFRONTED_MEEK_HTTPS,
			clientIsLatestVersion:    false,
			disableUntunneledUpgrade: true,
			disableEstablishing:      false,
			disableApi:               false,
			tunnelPoolSize:           1,
			useUpstreamProxy:         false,
			disruptNetwork:           false,
			useHostNameTransformer:   false,
			runDuration:              0,
		})
}

func TestUnfrontedMeekHTTPSWithTransformer(t *testing.T) {
	controllerRun(t,
		&controllerRunConfig{
			expectNoServerEntries:    false,
			protocol:                 common.TUNNEL_PROTOCOL_UNFRONTED_MEEK_HTTPS,
			clientIsLatestVersion:    true,
			disableUntunneledUpgrade: true,
			disableEstablishing:      false,
			disableApi:               false,
			tunnelPoolSize:           1,
			useUpstreamProxy:         false,
			disruptNetwork:           false,
			useHostNameTransformer:   true,
			runDuration:              0,
		})
}

func TestDisabledApi(t *testing.T) {
	controllerRun(t,
		&controllerRunConfig{
			expectNoServerEntries:    false,
			protocol:                 "",
			clientIsLatestVersion:    true,
			disableUntunneledUpgrade: true,
			disableEstablishing:      false,
			disableApi:               true,
			tunnelPoolSize:           1,
			useUpstreamProxy:         false,
			disruptNetwork:           false,
			useHostNameTransformer:   false,
			runDuration:              0,
		})
}

func TestObfuscatedSSHWithUpstreamProxy(t *testing.T) {
	controllerRun(t,
		&controllerRunConfig{
			expectNoServerEntries:    false,
			protocol:                 common.TUNNEL_PROTOCOL_OBFUSCATED_SSH,
			clientIsLatestVersion:    false,
			disableUntunneledUpgrade: true,
			disableEstablishing:      false,
			disableApi:               false,
			tunnelPoolSize:           1,
			useUpstreamProxy:         true,
			disruptNetwork:           false,
			useHostNameTransformer:   false,
			runDuration:              0,
		})
}

func TestUnfrontedMeekWithUpstreamProxy(t *testing.T) {
	controllerRun(t,
		&controllerRunConfig{
			expectNoServerEntries:    false,
			protocol:                 common.TUNNEL_PROTOCOL_UNFRONTED_MEEK,
			clientIsLatestVersion:    false,
			disableUntunneledUpgrade: true,
			disableEstablishing:      false,
			disableApi:               false,
			tunnelPoolSize:           1,
			useUpstreamProxy:         true,
			disruptNetwork:           false,
			useHostNameTransformer:   false,
			runDuration:              0,
		})
}

func TestUnfrontedMeekHTTPSWithUpstreamProxy(t *testing.T) {
	controllerRun(t,
		&controllerRunConfig{
			expectNoServerEntries:    false,
			protocol:                 common.TUNNEL_PROTOCOL_UNFRONTED_MEEK_HTTPS,
			clientIsLatestVersion:    false,
			disableUntunneledUpgrade: true,
			disableEstablishing:      false,
			disableApi:               false,
			tunnelPoolSize:           1,
			useUpstreamProxy:         true,
			disruptNetwork:           false,
			useHostNameTransformer:   false,
			runDuration:              0,
		})
}

type controllerRunConfig struct {
	expectNoServerEntries    bool
	protocol                 string
	clientIsLatestVersion    bool
	disableUntunneledUpgrade bool
	disableEstablishing      bool
	disableApi               bool
	tunnelPoolSize           int
	useUpstreamProxy         bool
	disruptNetwork           bool
	useHostNameTransformer   bool
	runDuration              time.Duration
}

func controllerRun(t *testing.T, runConfig *controllerRunConfig) {

	configFileContents, err := ioutil.ReadFile("controller_test.config")
	if err != nil {
		// Skip, don't fail, if config file is not present
		t.Skipf("error loading configuration file: %s", err)
	}
	config, err := LoadConfig(configFileContents)
	if err != nil {
		t.Fatalf("error processing configuration file: %s", err)
	}

	if runConfig.clientIsLatestVersion {
		config.ClientVersion = "999999999"
	}

	if runConfig.disableEstablishing {
		// Clear remote server list so tunnel cannot be established.
		// TODO: also delete all server entries in the datastore.
		config.RemoteServerListUrl = ""
	}

	if runConfig.disableApi {
		config.DisableApi = true
	}

	config.TunnelPoolSize = runConfig.tunnelPoolSize

	if runConfig.disableUntunneledUpgrade {
		// Disable untunneled upgrade downloader to ensure tunneled case is tested
		config.UpgradeDownloadClientVersionHeader = ""
	}

	if runConfig.useUpstreamProxy && runConfig.disruptNetwork {
		t.Fatalf("cannot use multiple upstream proxies")
	}
	if runConfig.disruptNetwork {
		config.UpstreamProxyUrl = disruptorProxyURL
	} else if runConfig.useUpstreamProxy {
		config.UpstreamProxyUrl = upstreamProxyURL
		config.UpstreamProxyCustomHeaders = upstreamProxyCustomHeaders
	}

	if runConfig.useHostNameTransformer {
		config.HostNameTransformer = &TestHostNameTransformer{}
	}

	// Override client retry throttle values to speed up automated
	// tests and ensure tests complete within fixed deadlines.
	fetchRemoteServerListRetryPeriodSeconds := 0
	config.FetchRemoteServerListRetryPeriodSeconds = &fetchRemoteServerListRetryPeriodSeconds
	downloadUpgradeRetryPeriodSeconds := 0
	config.DownloadUpgradeRetryPeriodSeconds = &downloadUpgradeRetryPeriodSeconds
	establishTunnelPausePeriodSeconds := 1
	config.EstablishTunnelPausePeriodSeconds = &establishTunnelPausePeriodSeconds

	os.Remove(config.UpgradeDownloadFilename)

	config.TunnelProtocol = runConfig.protocol

	err = InitDataStore(config)
	if err != nil {
		t.Fatalf("error initializing datastore: %s", err)
	}

	serverEntryCount := CountServerEntries("", "")

	if runConfig.expectNoServerEntries && serverEntryCount > 0 {
		// TODO: replace expectNoServerEntries with resetServerEntries
		// so tests can run in arbitrary order
		t.Fatalf("unexpected server entries")
	}

	controller, err := NewController(config)
	if err != nil {
		t.Fatalf("error creating controller: %s", err)
	}

	// Monitor notices for "Tunnels" with count > 1, the
	// indication of tunnel establishment success.
	// Also record the selected HTTP proxy port to use
	// when fetching websites through the tunnel.

	httpProxyPort := 0

	tunnelEstablished := make(chan struct{}, 1)
	upgradeDownloaded := make(chan struct{}, 1)
	remoteServerListDownloaded := make(chan struct{}, 1)
	confirmedLatestVersion := make(chan struct{}, 1)

	var clientUpgradeDownloadedBytesCount int32
	var remoteServerListDownloadedBytesCount int32
	var impairedProtocolCount int32
	var impairedProtocolClassification = struct {
		sync.RWMutex
		classification map[string]int
	}{classification: make(map[string]int)}

	SetNoticeOutput(NewNoticeReceiver(
		func(notice []byte) {
			// TODO: log notices without logging server IPs:
			// fmt.Fprintf(os.Stderr, "%s\n", string(notice))
			noticeType, payload, err := GetNotice(notice)
			if err != nil {
				return
			}
			switch noticeType {

			case "ListeningHttpProxyPort":

				httpProxyPort = int(payload["port"].(float64))

			case "ConnectingServer":

				serverProtocol := payload["protocol"].(string)
				if runConfig.protocol != "" && serverProtocol != runConfig.protocol {
					// TODO: wrong goroutine for t.FatalNow()
					t.Fatalf("wrong protocol selected: %s", serverProtocol)
				}

			case "Tunnels":

				count := int(payload["count"].(float64))
				if count > 0 {
					if runConfig.disableEstablishing {
						// TODO: wrong goroutine for t.FatalNow()
						t.Fatalf("tunnel established unexpectedly")
					} else {
						select {
						case tunnelEstablished <- *new(struct{}):
						default:
						}
					}
				}

			case "ClientUpgradeDownloadedBytes":

				atomic.AddInt32(&clientUpgradeDownloadedBytesCount, 1)
				t.Logf("ClientUpgradeDownloadedBytes: %d", int(payload["bytes"].(float64)))

			case "ClientUpgradeDownloaded":

				select {
				case upgradeDownloaded <- *new(struct{}):
				default:
				}

			case "ClientIsLatestVersion":

				select {
				case confirmedLatestVersion <- *new(struct{}):
				default:
				}

			case "RemoteServerListDownloadedBytes":

				atomic.AddInt32(&remoteServerListDownloadedBytesCount, 1)
				t.Logf("RemoteServerListDownloadedBytes: %d", int(payload["bytes"].(float64)))

			case "RemoteServerListDownloaded":

				select {
				case remoteServerListDownloaded <- *new(struct{}):
				default:
				}

			case "ImpairedProtocolClassification":

				classification := payload["classification"].(map[string]interface{})

				impairedProtocolClassification.Lock()
				impairedProtocolClassification.classification = make(map[string]int)
				for k, v := range classification {
					count := int(v.(float64))
					if count >= IMPAIRED_PROTOCOL_CLASSIFICATION_THRESHOLD {
						atomic.AddInt32(&impairedProtocolCount, 1)
					}
					impairedProtocolClassification.classification[k] = count
				}
				impairedProtocolClassification.Unlock()

			case "ActiveTunnel":

				serverProtocol := payload["protocol"].(string)

				classification := make(map[string]int)
				impairedProtocolClassification.RLock()
				for k, v := range impairedProtocolClassification.classification {
					classification[k] = v
				}
				impairedProtocolClassification.RUnlock()

				count, ok := classification[serverProtocol]
				if ok && count >= IMPAIRED_PROTOCOL_CLASSIFICATION_THRESHOLD {
					// TODO: wrong goroutine for t.FatalNow()
					t.Fatalf("unexpected tunnel using impaired protocol: %s, %+v",
						serverProtocol, classification)
				}

			}
		}))

	// Run controller, which establishes tunnels

	shutdownBroadcast := make(chan struct{})
	controllerWaitGroup := new(sync.WaitGroup)
	controllerWaitGroup.Add(1)
	go func() {
		defer controllerWaitGroup.Done()
		controller.Run(shutdownBroadcast)
	}()

	defer func() {
		// Test: shutdown must complete within 20 seconds

		close(shutdownBroadcast)

		shutdownTimeout := time.NewTimer(20 * time.Second)

		shutdownOk := make(chan struct{}, 1)
		go func() {
			controllerWaitGroup.Wait()
			shutdownOk <- *new(struct{})
		}()

		select {
		case <-shutdownOk:
		case <-shutdownTimeout.C:
			t.Fatalf("controller shutdown timeout exceeded")
		}
	}()

	if !runConfig.disableEstablishing {

		// Test: tunnel must be established within 120 seconds

		establishTimeout := time.NewTimer(120 * time.Second)

		select {
		case <-tunnelEstablished:

		case <-establishTimeout.C:
			t.Fatalf("tunnel establish timeout exceeded")
		}

		// Test: if starting with no server entries, a fetch remote
		// server list must have succeeded. With disruptNetwork, the
		// fetch must have been resumed at least once.

		if serverEntryCount == 0 {
			select {
			case <-remoteServerListDownloaded:
			default:
				t.Fatalf("expected remote server list downloaded")
			}

			if runConfig.disruptNetwork {
				count := atomic.LoadInt32(&remoteServerListDownloadedBytesCount)
				if count <= 1 {
					t.Fatalf("unexpected remote server list download progress: %d", count)
				}
			}
		}

		// Test: fetch website through tunnel

		// Allow for known race condition described in NewHttpProxy():
		time.Sleep(1 * time.Second)

		fetchAndVerifyWebsite(t, httpProxyPort)

		// Test: run for duration, periodically using the tunnel to
		// ensure failed tunnel detection, and ultimately hitting
		// impaired protocol checks.

		startTime := monotime.Now()

		for {

			time.Sleep(1 * time.Second)
			useTunnel(t, httpProxyPort)

			if startTime.Add(runConfig.runDuration).Before(monotime.Now()) {
				break
			}
		}

		// Test: with disruptNetwork, impaired protocols should be exercised

		if runConfig.runDuration > 0 && runConfig.disruptNetwork {
			count := atomic.LoadInt32(&impairedProtocolCount)
			if count <= 0 {
				t.Fatalf("unexpected impaired protocol count: %d", count)
			} else {
				impairedProtocolClassification.RLock()
				t.Logf("impaired protocol classification: %+v",
					impairedProtocolClassification.classification)
				impairedProtocolClassification.RUnlock()
			}
		}
	}

	// Test: upgrade check/download must be downloaded within 180 seconds

	expectUpgrade := !runConfig.disableApi && !runConfig.disableUntunneledUpgrade

	if expectUpgrade {
		upgradeTimeout := time.NewTimer(180 * time.Second)

		select {
		case <-upgradeDownloaded:
			// TODO: verify downloaded file
			if runConfig.clientIsLatestVersion {
				t.Fatalf("upgrade downloaded unexpectedly")
			}

			// Test: with disruptNetwork, must be multiple download progress notices

			if runConfig.disruptNetwork {
				count := atomic.LoadInt32(&clientUpgradeDownloadedBytesCount)
				if count <= 1 {
					t.Fatalf("unexpected upgrade download progress: %d", count)
				}
			}

		case <-confirmedLatestVersion:
			if !runConfig.clientIsLatestVersion {
				t.Fatalf("confirmed latest version unexpectedly")
			}

		case <-upgradeTimeout.C:
			t.Fatalf("upgrade download timeout exceeded")
		}
	}
}

type TestHostNameTransformer struct {
}

func (TestHostNameTransformer) TransformHostName(string) (string, bool) {
	return "example.com", true
}

func fetchAndVerifyWebsite(t *testing.T, httpProxyPort int) {

	testUrl := "https://raw.githubusercontent.com/Psiphon-Labs/psiphon-tunnel-core/master/LICENSE"
	roundTripTimeout := 30 * time.Second
	expectedResponsePrefix := "                    GNU GENERAL PUBLIC LICENSE"
	expectedResponseSize := 35148
	checkResponse := func(responseBody string) bool {
		return strings.HasPrefix(responseBody, expectedResponsePrefix) && len(responseBody) == expectedResponseSize
	}

	// Test: use HTTP proxy

	proxyUrl, err := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", httpProxyPort))
	if err != nil {
		t.Fatalf("error initializing proxied HTTP request: %s", err)
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyUrl),
		},
		Timeout: roundTripTimeout,
	}

	response, err := httpClient.Get(testUrl)
	if err != nil {
		t.Fatalf("error sending proxied HTTP request: %s", err)
	}

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("error reading proxied HTTP response: %s", err)
	}
	response.Body.Close()

	if !checkResponse(string(body)) {
		t.Fatalf("unexpected proxied HTTP response")
	}

	// Test: use direct URL proxy

	httpClient = &http.Client{
		Transport: http.DefaultTransport,
		Timeout:   roundTripTimeout,
	}

	response, err = httpClient.Get(
		fmt.Sprintf("http://127.0.0.1:%d/direct/%s",
			httpProxyPort, url.QueryEscape(testUrl)))
	if err != nil {
		t.Fatalf("error sending direct URL request: %s", err)
	}

	body, err = ioutil.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("error reading direct URL response: %s", err)
	}
	response.Body.Close()

	if !checkResponse(string(body)) {
		t.Fatalf("unexpected direct URL response")
	}

	// Test: use tunneled URL proxy

	response, err = httpClient.Get(
		fmt.Sprintf("http://127.0.0.1:%d/tunneled/%s",
			httpProxyPort, url.QueryEscape(testUrl)))
	if err != nil {
		t.Fatalf("error sending tunneled URL request: %s", err)
	}

	body, err = ioutil.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("error reading tunneled URL response: %s", err)
	}
	response.Body.Close()

	if !checkResponse(string(body)) {
		t.Fatalf("unexpected tunneled URL response")
	}
}

func useTunnel(t *testing.T, httpProxyPort int) {

	// No action on errors as the tunnel is expected to fail sometimes

	testUrl := "https://psiphon3.com"
	roundTripTimeout := 1 * time.Second
	proxyUrl, err := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", httpProxyPort))
	if err != nil {
		return
	}
	httpClient := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyUrl),
		},
		Timeout: roundTripTimeout,
	}
	response, err := httpClient.Get(testUrl)
	if err != nil {
		return
	}
	response.Body.Close()
}

const disruptorProxyAddress = "127.0.0.1:2160"
const disruptorProxyURL = "socks4a://" + disruptorProxyAddress
const disruptorMaxConnectionBytes = 500000
const disruptorMaxConnectionTime = 10 * time.Second

func initDisruptor() {

	go func() {
		listener, err := socks.ListenSocks("tcp", disruptorProxyAddress)
		if err != nil {
			fmt.Errorf("disruptor proxy listen error: %s", err)
			return
		}
		for {
			localConn, err := listener.AcceptSocks()
			if err != nil {
				fmt.Errorf("disruptor proxy accept error: %s", err)
				return
			}
			go func() {
				defer localConn.Close()
				remoteConn, err := net.Dial("tcp", localConn.Req.Target)
				if err != nil {
					fmt.Errorf("disruptor proxy dial error: %s", err)
					return
				}
				defer remoteConn.Close()
				err = localConn.Grant(&net.TCPAddr{IP: net.ParseIP("0.0.0.0"), Port: 0})
				if err != nil {
					fmt.Errorf("disruptor proxy grant error: %s", err)
					return
				}

				// Cut connection after disruptorMaxConnectionTime
				time.AfterFunc(disruptorMaxConnectionTime, func() {
					localConn.Close()
					remoteConn.Close()
				})

				// Relay connection, but only up to disruptorMaxConnectionBytes
				waitGroup := new(sync.WaitGroup)
				waitGroup.Add(1)
				go func() {
					defer waitGroup.Done()
					io.CopyN(localConn, remoteConn, disruptorMaxConnectionBytes)
				}()
				io.CopyN(remoteConn, localConn, disruptorMaxConnectionBytes)
				waitGroup.Wait()
			}()
		}
	}()
}

const upstreamProxyURL = "http://127.0.0.1:2161"

var upstreamProxyCustomHeaders = map[string][]string{"X-Test-Header-Name": []string{"test-header-value1", "test-header-value2"}}

func hasExpectedCustomHeaders(h http.Header) bool {
	for name, values := range upstreamProxyCustomHeaders {
		if h[name] == nil {
			return false
		}
		// Order may not be the same
		for _, value := range values {
			if !common.Contains(h[name], value) {
				return false
			}
		}
	}
	return true
}

func initUpstreamProxy() {
	go func() {
		proxy := goproxy.NewProxyHttpServer()

		proxy.OnRequest().DoFunc(
			func(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
				if !hasExpectedCustomHeaders(r.Header) {
					ctx.Logf("missing expected headers: %+v", ctx.Req.Header)
					return nil, goproxy.NewResponse(r, goproxy.ContentTypeText, http.StatusUnauthorized, "")
				}
				return r, nil
			})

		proxy.OnRequest().HandleConnectFunc(
			func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
				if !hasExpectedCustomHeaders(ctx.Req.Header) {
					ctx.Logf("missing expected headers: %+v", ctx.Req.Header)
					return goproxy.RejectConnect, host
				}
				return goproxy.OkConnect, host
			})

		err := http.ListenAndServe("127.0.0.1:2161", proxy)
		if err != nil {
			fmt.Printf("upstream proxy failed: %s", err)
		}
	}()

	// TODO: wait until listener is active?
}
