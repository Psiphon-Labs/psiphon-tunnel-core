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
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	socks "github.com/Psiphon-Labs/goptlib"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/inproxy"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/quic"
	"github.com/elazarl/goproxy"
	"github.com/elazarl/goproxy/ext/auth"
)

const testClientPlatform = "test_github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon"

func TestMain(m *testing.M) {
	flag.Parse()

	SetEmitDiagnosticNotices(true, true)

	initDisruptor()
	initUpstreamProxy()

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
			expectNoServerEntries: true,
			protocol:              "",
			disableEstablishing:   true,
		})
}

func TestUntunneledResumableUpgradeDownload(t *testing.T) {
	controllerRun(t,
		&controllerRunConfig{
			expectNoServerEntries: true,
			protocol:              "",
			disableEstablishing:   true,
			disruptNetwork:        true,
		})
}

func TestUntunneledUpgradeClientIsLatestVersion(t *testing.T) {
	controllerRun(t,
		&controllerRunConfig{
			expectNoServerEntries: true,
			protocol:              "",
			clientIsLatestVersion: true,
			disableEstablishing:   true,
		})
}

func TestUntunneledResumableFetchRemoteServerList(t *testing.T) {
	controllerRun(t,
		&controllerRunConfig{
			expectNoServerEntries: true,
			protocol:              "",
			clientIsLatestVersion: true,
			disruptNetwork:        true,
		})
}

func TestTunneledUpgradeClientIsLatestVersion(t *testing.T) {
	controllerRun(t,
		&controllerRunConfig{
			protocol:                 "",
			clientIsLatestVersion:    true,
			disableUntunneledUpgrade: true,
		})
}

func TestSSH(t *testing.T) {
	controllerRun(t,
		&controllerRunConfig{
			protocol:                 protocol.TUNNEL_PROTOCOL_SSH,
			disableUntunneledUpgrade: true,
		})
}

func TestObfuscatedSSH(t *testing.T) {
	controllerRun(t,
		&controllerRunConfig{
			protocol:                 protocol.TUNNEL_PROTOCOL_OBFUSCATED_SSH,
			disableUntunneledUpgrade: true,
		})
}

func TestTLSOSSH(t *testing.T) {
	controllerRun(t,
		&controllerRunConfig{
			protocol:                 protocol.TUNNEL_PROTOCOL_TLS_OBFUSCATED_SSH,
			disableUntunneledUpgrade: true,
		})
}

func TestShadowsocks(t *testing.T) {

	t.Skipf("temporarily disabled")

	controllerRun(t,
		&controllerRunConfig{
			protocol:                 protocol.TUNNEL_PROTOCOL_SHADOWSOCKS_OSSH,
			disableUntunneledUpgrade: true,
		})
}

func TestUnfrontedMeek(t *testing.T) {
	controllerRun(t,
		&controllerRunConfig{
			protocol:                 protocol.TUNNEL_PROTOCOL_UNFRONTED_MEEK,
			disableUntunneledUpgrade: true,
		})
}

func TestUnfrontedMeekWithTransformer(t *testing.T) {
	controllerRun(t,
		&controllerRunConfig{
			protocol:                 protocol.TUNNEL_PROTOCOL_UNFRONTED_MEEK,
			disableUntunneledUpgrade: true,
			transformHostNames:       true,
		})
}

func TestFrontedMeek(t *testing.T) {
	controllerRun(t,
		&controllerRunConfig{
			protocol:                 protocol.TUNNEL_PROTOCOL_FRONTED_MEEK,
			disableUntunneledUpgrade: true,
		})
}

func TestFrontedMeekWithTransformer(t *testing.T) {
	controllerRun(t,
		&controllerRunConfig{
			protocol:                 protocol.TUNNEL_PROTOCOL_FRONTED_MEEK,
			disableUntunneledUpgrade: true,
			transformHostNames:       true,
		})
}

func TestFrontedMeekHTTP(t *testing.T) {
	controllerRun(t,
		&controllerRunConfig{
			protocol:                 protocol.TUNNEL_PROTOCOL_FRONTED_MEEK_HTTP,
			disableUntunneledUpgrade: true,
		})
}

func TestUnfrontedMeekHTTPS(t *testing.T) {
	controllerRun(t,
		&controllerRunConfig{
			expectNoServerEntries:    false,
			protocol:                 protocol.TUNNEL_PROTOCOL_UNFRONTED_MEEK_HTTPS,
			disableUntunneledUpgrade: true,
		})
}

func TestUnfrontedMeekHTTPSWithTransformer(t *testing.T) {
	controllerRun(t,
		&controllerRunConfig{
			protocol:              protocol.TUNNEL_PROTOCOL_UNFRONTED_MEEK_HTTPS,
			clientIsLatestVersion: true,
			transformHostNames:    true,
		})
}

func TestDisabledApi(t *testing.T) {
	controllerRun(t,
		&controllerRunConfig{
			protocol:                 "",
			clientIsLatestVersion:    true,
			disableUntunneledUpgrade: true,
			disableApi:               true,
			tunnelPoolSize:           1,
		})
}

func TestObfuscatedSSHWithUpstreamProxy(t *testing.T) {
	controllerRun(t,
		&controllerRunConfig{
			protocol:                 protocol.TUNNEL_PROTOCOL_OBFUSCATED_SSH,
			disableUntunneledUpgrade: true,
			useUpstreamProxy:         true,
		})
}

func TestUnfrontedMeekWithUpstreamProxy(t *testing.T) {
	controllerRun(t,
		&controllerRunConfig{
			protocol:                 protocol.TUNNEL_PROTOCOL_UNFRONTED_MEEK,
			disableUntunneledUpgrade: true,
			useUpstreamProxy:         true,
		})
}

func TestUnfrontedMeekHTTPSWithUpstreamProxy(t *testing.T) {
	controllerRun(t,
		&controllerRunConfig{
			protocol:                 protocol.TUNNEL_PROTOCOL_UNFRONTED_MEEK_HTTPS,
			disableUntunneledUpgrade: true,
			useUpstreamProxy:         true,
		})
}

func TestObfuscatedSSHFragmentor(t *testing.T) {
	controllerRun(t,
		&controllerRunConfig{
			protocol:                 protocol.TUNNEL_PROTOCOL_OBFUSCATED_SSH,
			disableUntunneledUpgrade: true,
			useFragmentor:            true,
		})
}

func TestFrontedMeekFragmentor(t *testing.T) {
	controllerRun(t,
		&controllerRunConfig{
			protocol:                 protocol.TUNNEL_PROTOCOL_FRONTED_MEEK,
			disableUntunneledUpgrade: true,
			useFragmentor:            true,
		})
}

func TestGQUIC(t *testing.T) {
	if !quic.Enabled() {
		t.Skip("QUIC is not enabled")
	}
	if !quic.GQUICEnabled() {
		t.Skip("gQUIC is not enabled")
	}
	controllerRun(t,
		&controllerRunConfig{
			protocol:                 protocol.TUNNEL_PROTOCOL_QUIC_OBFUSCATED_SSH,
			disableUntunneledUpgrade: true,
			quicVersions:             protocol.SupportedGQUICVersions,
		})
}

func TestIETFQUIC(t *testing.T) {
	if !quic.Enabled() {
		t.Skip("QUIC is not enabled")
	}
	controllerRun(t,
		&controllerRunConfig{
			protocol:                 protocol.TUNNEL_PROTOCOL_QUIC_OBFUSCATED_SSH,
			disableUntunneledUpgrade: true,
			quicVersions:             protocol.SupportedQUICv1Versions,
		})
}

func TestFrontedQUIC(t *testing.T) {
	if !quic.Enabled() {
		t.Skip("QUIC is not enabled")
	}
	controllerRun(t,
		&controllerRunConfig{
			protocol:                 protocol.TUNNEL_PROTOCOL_FRONTED_MEEK_QUIC_OBFUSCATED_SSH,
			disableUntunneledUpgrade: true,
		})
}

func TestInproxyOSSH(t *testing.T) {

	if !inproxy.Enabled() {
		t.Skip("In-proxy is not enabled")
	}

	controllerRun(t,
		&controllerRunConfig{
			protocol:                 "INPROXY-WEBRTC-OSSH",
			disableUntunneledUpgrade: true,
			useInproxyDialRateLimit:  true,
		})
}

func TestInproxyQUICOSSH(t *testing.T) {

	if !inproxy.Enabled() {
		t.Skip("In-proxy is not enabled")
	}

	controllerRun(t,
		&controllerRunConfig{
			protocol:                 "INPROXY-WEBRTC-QUIC-OSSH",
			disableUntunneledUpgrade: true,
			useInproxyDialRateLimit:  true,
		})
}

func TestInproxyUnfrontedMeekHTTPS(t *testing.T) {

	if !inproxy.Enabled() {
		t.Skip("In-proxy is not enabled")
	}

	controllerRun(t,
		&controllerRunConfig{
			protocol:                 "INPROXY-WEBRTC-UNFRONTED-MEEK-HTTPS-OSSH",
			disableUntunneledUpgrade: true,
		})
}

func TestInproxyTLSOSSH(t *testing.T) {

	if !inproxy.Enabled() {
		t.Skip("In-proxy is not enabled")
	}

	controllerRun(t,
		&controllerRunConfig{
			protocol:                 "INPROXY-WEBRTC-TLS-OSSH",
			disableUntunneledUpgrade: true,
		})
}

func TestTunnelPool(t *testing.T) {
	controllerRun(t,
		&controllerRunConfig{
			protocol:                 protocol.TUNNEL_PROTOCOL_OBFUSCATED_SSH,
			disableUntunneledUpgrade: true,
			tunnelPoolSize:           2,
		})
}

func TestLegacyAPIEncoding(t *testing.T) {
	controllerRun(t,
		&controllerRunConfig{
			protocol:             protocol.TUNNEL_PROTOCOL_OBFUSCATED_SSH,
			useLegacyAPIEncoding: true,
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
	transformHostNames       bool
	useFragmentor            bool
	useLegacyAPIEncoding     bool
	useInproxyDialRateLimit  bool
	quicVersions             protocol.QUICVersions
}

func controllerRun(t *testing.T, runConfig *controllerRunConfig) {

	testDataDirName, err := ioutil.TempDir("", "psiphon-controller-test")
	if err != nil {
		t.Fatalf("TempDir failed: %s\n", err)
	}
	defer os.RemoveAll(testDataDirName)

	configJSON, err := ioutil.ReadFile("controller_test.config")
	if err != nil {
		// Skip, don't fail, if config file is not present
		t.Skipf("error loading configuration file: %s", err)
	}

	// Note: a successful tactics request may modify config parameters.

	var modifyConfig map[string]interface{}
	err = json.Unmarshal(configJSON, &modifyConfig)
	if err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	modifyConfig["DataRootDirectory"] = testDataDirName

	if runConfig.protocol != "" {
		modifyConfig["DisableTactics"] = true
		modifyConfig["LimitTunnelProtocols"] = protocol.TunnelProtocols{runConfig.protocol}
	}

	modifyConfig["EnableUpgradeDownload"] = true
	modifyConfig["EnableFeedbackUpload"] = false

	// Override client retry throttle values to speed up automated
	// tests and ensure tests complete within fixed deadlines.
	modifyConfig["FetchRemoteServerListRetryPeriodMilliseconds"] = 250
	modifyConfig["FetchUpgradeRetryPeriodMilliseconds"] = 250
	modifyConfig["EstablishTunnelPausePeriodSeconds"] = 1

	if runConfig.disableUntunneledUpgrade {
		// Break untunneled upgrade downloader to ensure tunneled case is tested
		modifyConfig["UpgradeDownloadClientVersionHeader"] = "invalid-value"
	}

	if runConfig.transformHostNames {
		modifyConfig["TransformHostNames"] = "always"
	} else {
		modifyConfig["TransformHostNames"] = "never"
	}

	if runConfig.useFragmentor {
		modifyConfig["UseFragmentor"] = "always"
		modifyConfig["FragmentorLimitProtocols"] = protocol.TunnelProtocols{runConfig.protocol}
		modifyConfig["FragmentorMinTotalBytes"] = 1000
		modifyConfig["FragmentorMaxTotalBytes"] = 2000
		modifyConfig["FragmentorMinWriteBytes"] = 1
		modifyConfig["FragmentorMaxWriteBytes"] = 100
		modifyConfig["FragmentorMinDelayMicroseconds"] = 1000
		modifyConfig["FragmentorMaxDelayMicroseconds"] = 10000
		modifyConfig["ObfuscatedSSHMinPadding"] = 4096
		modifyConfig["ObfuscatedSSHMaxPadding"] = 8192
	}

	if runConfig.useLegacyAPIEncoding {
		modifyConfig["TargetAPIEncoding"] = protocol.PSIPHON_API_ENCODING_JSON
	}

	if runConfig.useInproxyDialRateLimit {
		modifyConfig["InproxyClientDialRateLimitQuantity"] = 2
		modifyConfig["InproxyClientDialRateLimitIntervalMilliseconds"] = 1000
	}

	modifyConfig["LimitQUICVersions"] = runConfig.quicVersions

	// TODO: vary this option
	modifyConfig["CompressTactics"] = false

	configJSON, _ = json.Marshal(modifyConfig)

	// Don't print initial config setup notices
	err = SetNoticeWriter(io.Discard)
	if err != nil {
		t.Fatalf("error setting notice writer: %s", err)
	}
	defer ResetNoticeWriter()

	config, err := LoadConfig(configJSON)
	if err != nil {
		t.Fatalf("error processing configuration file: %s", err)
	}

	if config.ClientPlatform == "" {
		config.ClientPlatform = testClientPlatform
	}

	if runConfig.clientIsLatestVersion {
		config.ClientVersion = "999999999"
	}

	if runConfig.disableEstablishing {
		// Clear remote server list so tunnel cannot be established.
		// TODO: also delete all server entries in the datastore.
		config.DisableRemoteServerListFetcher = true
	}

	if runConfig.disableApi {
		config.DisableApi = true
	}

	config.TunnelPoolSize = runConfig.tunnelPoolSize

	if runConfig.useUpstreamProxy && runConfig.disruptNetwork {
		t.Fatalf("cannot use multiple upstream proxies")
	}
	if runConfig.disruptNetwork {
		config.UpstreamProxyURL = disruptorProxyURL
	} else if runConfig.useUpstreamProxy {
		config.UpstreamProxyURL = upstreamProxyURL
		config.CustomHeaders = upstreamProxyCustomHeaders
	}

	// All config fields should be set before calling Commit.
	err = config.Commit(false)
	if err != nil {
		t.Fatalf("error committing configuration file: %s", err)
	}

	err = OpenDataStore(config)
	if err != nil {
		t.Fatalf("error initializing datastore: %s", err)
	}
	defer CloseDataStore()

	serverEntryCount := CountServerEntries()

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
	candidateServers := make(chan struct{}, 1)
	availableEgressRegions := make(chan struct{}, 1)

	var clientUpgradeDownloadedBytesCount int32
	var remoteServerListDownloadedBytesCount int32

	ResetNoticeWriter()
	err = SetNoticeWriter(NewNoticeReceiver(
		func(notice []byte) {
			// TODO: log notices without logging server IPs:
			//fmt.Fprintf(os.Stderr, "%s\n", string(notice))
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
						case tunnelEstablished <- struct{}{}:
						default:
						}
					}
				}

			case "ClientUpgradeDownloadedBytes":

				atomic.AddInt32(&clientUpgradeDownloadedBytesCount, 1)
				t.Logf("ClientUpgradeDownloadedBytes: %d", int(payload["bytes"].(float64)))

			case "ClientUpgradeDownloaded":

				select {
				case upgradeDownloaded <- struct{}{}:
				default:
				}

			case "ClientIsLatestVersion":

				select {
				case confirmedLatestVersion <- struct{}{}:
				default:
				}

			case "RemoteServerListResourceDownloadedBytes":

				url := payload["url"].(string)
				if url == config.RemoteServerListUrl {
					t.Logf("RemoteServerListResourceDownloadedBytes: %d", int(payload["bytes"].(float64)))
					atomic.AddInt32(&remoteServerListDownloadedBytesCount, 1)
				}

			case "RemoteServerListResourceDownloaded":

				url := payload["url"].(string)
				if url == config.RemoteServerListUrl {
					t.Logf("RemoteServerListResourceDownloaded")
					select {
					case remoteServerListDownloaded <- struct{}{}:
					default:
					}
				}

			case "CandidateServers":

				select {
				case candidateServers <- struct{}{}:
				default:
				}

			case "AvailableEgressRegions":

				select {
				case availableEgressRegions <- struct{}{}:
				default:
				}
			}
		}))
	if err != nil {
		t.Fatalf("error setting notice writer: %s", err)
	}
	defer ResetNoticeWriter()

	// Run controller, which establishes tunnels

	ctx, cancelFunc := context.WithCancel(context.Background())

	controllerWaitGroup := new(sync.WaitGroup)

	controllerWaitGroup.Add(1)
	go func() {
		defer controllerWaitGroup.Done()
		controller.Run(ctx)
	}()

	defer func() {

		// Test: shutdown must complete within 20 seconds

		cancelFunc()

		shutdownTimeout := time.NewTimer(20 * time.Second)

		shutdownOk := make(chan struct{}, 1)
		go func() {
			controllerWaitGroup.Wait()
			shutdownOk <- struct{}{}
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

		// Test: asynchronous server entry scans must complete

		select {
		case <-candidateServers:
		case <-establishTimeout.C:
			t.Fatalf("missing candidate servers notice")
		}

		select {
		case <-availableEgressRegions:
		case <-establishTimeout.C:
			t.Fatalf("missing available egress regions notice")
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

		// Cannot establish port forwards in DisableApi mode
		if !runConfig.disableApi {

			// Test: fetch website through tunnel

			// Allow for known race condition described in NewHttpProxy():
			time.Sleep(1 * time.Second)

			if !runConfig.disruptNetwork {
				fetchAndVerifyWebsite(t, httpProxyPort)
			}
		}
	}

	// Test: upgrade check/download must be downloaded within 240 seconds

	expectUpgrade := !runConfig.disableApi && !runConfig.disableUntunneledUpgrade

	if expectUpgrade {
		upgradeTimeout := time.NewTimer(240 * time.Second)

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

func fetchAndVerifyWebsite(t *testing.T, httpProxyPort int) error {

	testUrl := "https://psiphon.ca"
	roundTripTimeout := 30 * time.Second
	expectedResponseContains := "Psiphon"
	checkResponse := func(responseBody string) bool {
		return strings.Contains(responseBody, expectedResponseContains)
	}

	// Retries are made to compensate for intermittent failures due
	// to external network conditions.
	fetchWithRetries := func(fetchName string, fetchFunc func() error) error {
		retryCount := 6
		retryDelay := 5 * time.Second
		var err error
		for i := 0; i < retryCount; i++ {
			err = fetchFunc()
			if err == nil || i == retryCount-1 {
				break
			}
			time.Sleep(retryDelay)
			t.Logf("retrying %s...", fetchName)
		}
		return err
	}

	// Test: use HTTP proxy

	fetchUsingHTTPProxy := func() error {

		proxyUrl, err := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", httpProxyPort))
		if err != nil {
			return fmt.Errorf("error initializing proxied HTTP request: %s", err)
		}

		httpTransport := &http.Transport{
			Proxy:             http.ProxyURL(proxyUrl),
			DisableKeepAlives: true,
		}

		httpClient := &http.Client{
			Transport: httpTransport,
			Timeout:   roundTripTimeout,
		}

		request, err := http.NewRequest("GET", testUrl, nil)
		if err != nil {
			return fmt.Errorf("error preparing proxied HTTP request: %s", err)
		}

		response, err := httpClient.Do(request)
		if err != nil {
			return fmt.Errorf("error sending proxied HTTP request: %s", err)
		}
		defer response.Body.Close()

		body, err := ioutil.ReadAll(response.Body)
		if err != nil {
			return fmt.Errorf("error reading proxied HTTP response: %s", err)
		}

		if !checkResponse(string(body)) {
			return fmt.Errorf("unexpected proxied HTTP response")
		}

		return nil
	}

	err := fetchWithRetries("proxied HTTP request", fetchUsingHTTPProxy)
	if err != nil {
		return err
	}

	// Delay before requesting from external service again
	time.Sleep(1 * time.Second)

	// Test: use direct URL proxy

	fetchUsingURLProxyDirect := func() error {

		httpTransport := &http.Transport{
			DisableKeepAlives: true,
		}

		httpClient := &http.Client{
			Transport: httpTransport,
			Timeout:   roundTripTimeout,
		}

		request, err := http.NewRequest(
			"GET",
			fmt.Sprintf("http://127.0.0.1:%d/direct/%s",
				httpProxyPort, url.QueryEscape(testUrl)),
			nil)
		if err != nil {
			return fmt.Errorf("error preparing direct URL request: %s", err)
		}

		response, err := httpClient.Do(request)
		if err != nil {
			return fmt.Errorf("error sending direct URL request: %s", err)
		}
		defer response.Body.Close()

		body, err := ioutil.ReadAll(response.Body)
		if err != nil {
			return fmt.Errorf("error reading direct URL response: %s", err)
		}

		if !checkResponse(string(body)) {
			return fmt.Errorf("unexpected direct URL response")
		}

		return nil
	}

	err = fetchWithRetries("direct URL request", fetchUsingURLProxyDirect)
	if err != nil {
		return err
	}

	// Delay before requesting from external service again
	time.Sleep(1 * time.Second)

	// Test: use tunneled URL proxy

	fetchUsingURLProxyTunneled := func() error {

		httpTransport := &http.Transport{
			DisableKeepAlives: true,
		}

		httpClient := &http.Client{
			Transport: httpTransport,
			Timeout:   roundTripTimeout,
		}

		request, err := http.NewRequest(
			"GET",
			fmt.Sprintf("http://127.0.0.1:%d/tunneled/%s",
				httpProxyPort, url.QueryEscape(testUrl)),
			nil)
		if err != nil {
			return fmt.Errorf("error preparing tunneled URL request: %s", err)
		}

		response, err := httpClient.Do(request)
		if err != nil {
			return fmt.Errorf("error sending tunneled URL request: %s", err)
		}
		defer response.Body.Close()

		body, err := ioutil.ReadAll(response.Body)
		if err != nil {
			return fmt.Errorf("error reading tunneled URL response: %s", err)
		}

		if !checkResponse(string(body)) {
			return fmt.Errorf("unexpected tunneled URL response")
		}

		return nil
	}

	err = fetchWithRetries("tunneled URL request", fetchUsingURLProxyTunneled)
	if err != nil {
		return err
	}

	return nil
}

// Note: Valid values for disruptorMaxConnectionBytes depend on the production
// network; for example, the size of the remote server list resource must exceed
// disruptorMaxConnectionBytes or else TestUntunneledResumableFetchRemoteServerList
// will fail since no retries are required. But if disruptorMaxConnectionBytes is
// too small, the test will take longer to run since more retries are necessary.
//
// Tests such as TestUntunneledResumableFetchRemoteServerList could be rewritten to
// use mock components (for example, see TestObfuscatedRemoteServerLists); however
// these test in controller_test serve the dual purpose of ensuring that tunnel
// core works with the production network.
//
// TODO: set disruptorMaxConnectionBytes (and disruptorMaxConnectionTime) dynamically,
// based on current production network configuration?

const disruptorProxyAddress = "127.0.0.1:2160"
const disruptorProxyURL = "socks4a://" + disruptorProxyAddress
const disruptorMaxConnectionBytes = 150000
const disruptorMaxConnectionTime = 10 * time.Second

func initDisruptor() {

	go func() {
		listener, err := socks.ListenSocks("tcp", disruptorProxyAddress)
		if err != nil {
			fmt.Printf("disruptor proxy listen error: %s\n", err)
			return
		}
		for {
			localConn, err := listener.AcceptSocks()
			if err != nil {
				if e, ok := err.(net.Error); ok && e.Temporary() {
					fmt.Printf("disruptor proxy temporary accept error: %s\n", err)
					continue
				}
				fmt.Printf("disruptor proxy accept error: %s\n", err)
				return
			}
			go func() {
				defer localConn.Close()
				remoteConn, err := net.Dial("tcp", localConn.Req.Target)
				if err != nil {
					// TODO: log "err" without logging server IPs
					fmt.Printf("disruptor proxy dial error\n")
					return
				}
				defer remoteConn.Close()
				err = localConn.Grant(&net.TCPAddr{IP: net.ParseIP("0.0.0.0"), Port: 0})
				if err != nil {
					fmt.Printf("disruptor proxy grant error: %s\n", err)
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
					localConn.Close()
					remoteConn.Close()
				}()
				io.CopyN(remoteConn, localConn, disruptorMaxConnectionBytes)
				localConn.Close()
				remoteConn.Close()
				waitGroup.Wait()
			}()
		}
	}()
}

const upstreamProxyURL = "http://testUser:testPassword@127.0.0.1:2161"

var upstreamProxyCustomHeaders = map[string][]string{"X-Test-Header-Name": {"test-header-value1", "test-header-value2"}}

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
		proxy.Logger = log.New(ioutil.Discard, "", 0)

		auth.ProxyBasic(
			proxy,
			"testRealm",
			func(user, passwd string) bool { return user == "testUser" && passwd == "testPassword" })

		proxy.OnRequest().DoFunc(
			func(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
				if !hasExpectedCustomHeaders(r.Header) {
					fmt.Printf("missing expected headers: %+v\n", ctx.Req.Header)
					return nil, goproxy.NewResponse(r, goproxy.ContentTypeText, http.StatusUnauthorized, "")
				}
				return r, nil
			})

		proxy.OnRequest().HandleConnectFunc(
			func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
				if !hasExpectedCustomHeaders(ctx.Req.Header) {
					fmt.Printf("missing expected headers: %+v\n", ctx.Req.Header)
					return goproxy.RejectConnect, host
				}
				return goproxy.OkConnect, host
			})

		err := http.ListenAndServe("127.0.0.1:2161", proxy)
		if err != nil {
			fmt.Printf("upstream proxy failed: %s\n", err)
		}
	}()

	// TODO: wait until listener is active?
}
