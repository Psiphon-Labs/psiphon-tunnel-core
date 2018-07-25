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
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Psiphon-Labs/goarista/monotime"
	socks "github.com/Psiphon-Labs/goptlib"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/parameters"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	"github.com/elazarl/goproxy"
)

var testDataDirName string

func TestMain(m *testing.M) {
	flag.Parse()

	var err error
	testDataDirName, err = ioutil.TempDir("", "psiphon-controller-test")
	if err != nil {
		fmt.Printf("TempDir failed: %s\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(testDataDirName)

	os.Remove(filepath.Join(testDataDirName, DATA_STORE_FILENAME))

	SetEmitDiagnosticNotices(true)

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
			expectNoServerEntries:    true,
			protocol:                 "",
			clientIsLatestVersion:    false,
			disableUntunneledUpgrade: false,
			disableEstablishing:      true,
			disableApi:               false,
			tunnelPoolSize:           1,
			useUpstreamProxy:         false,
			disruptNetwork:           false,
			transformHostNames:       false,
			useFragmentor:            false,
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
			transformHostNames:       false,
			useFragmentor:            false,
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
			transformHostNames:       false,
			useFragmentor:            false,
			runDuration:              0,
		})
}

func TestUntunneledResumableFetchRemoteServerList(t *testing.T) {
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
			transformHostNames:       false,
			useFragmentor:            false,
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
			transformHostNames:       false,
			useFragmentor:            false,
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
			transformHostNames:       false,
			useFragmentor:            false,
			runDuration:              1 * time.Minute,
		})
}

func TestSSH(t *testing.T) {
	controllerRun(t,
		&controllerRunConfig{
			expectNoServerEntries:    false,
			protocol:                 protocol.TUNNEL_PROTOCOL_SSH,
			clientIsLatestVersion:    false,
			disableUntunneledUpgrade: true,
			disableEstablishing:      false,
			disableApi:               false,
			tunnelPoolSize:           1,
			useUpstreamProxy:         false,
			disruptNetwork:           false,
			transformHostNames:       false,
			useFragmentor:            false,
			runDuration:              0,
		})
}

func TestObfuscatedSSH(t *testing.T) {
	controllerRun(t,
		&controllerRunConfig{
			expectNoServerEntries:    false,
			protocol:                 protocol.TUNNEL_PROTOCOL_OBFUSCATED_SSH,
			clientIsLatestVersion:    false,
			disableUntunneledUpgrade: true,
			disableEstablishing:      false,
			disableApi:               false,
			tunnelPoolSize:           1,
			useUpstreamProxy:         false,
			disruptNetwork:           false,
			transformHostNames:       false,
			useFragmentor:            false,
			runDuration:              0,
		})
}

func TestUnfrontedMeek(t *testing.T) {
	controllerRun(t,
		&controllerRunConfig{
			expectNoServerEntries:    false,
			protocol:                 protocol.TUNNEL_PROTOCOL_UNFRONTED_MEEK,
			clientIsLatestVersion:    false,
			disableUntunneledUpgrade: true,
			disableEstablishing:      false,
			disableApi:               false,
			tunnelPoolSize:           1,
			useUpstreamProxy:         false,
			disruptNetwork:           false,
			transformHostNames:       false,
			useFragmentor:            false,
			runDuration:              0,
		})
}

func TestUnfrontedMeekWithTransformer(t *testing.T) {
	controllerRun(t,
		&controllerRunConfig{
			expectNoServerEntries:    false,
			protocol:                 protocol.TUNNEL_PROTOCOL_UNFRONTED_MEEK,
			clientIsLatestVersion:    true,
			disableUntunneledUpgrade: true,
			disableEstablishing:      false,
			disableApi:               false,
			tunnelPoolSize:           1,
			useUpstreamProxy:         false,
			disruptNetwork:           false,
			transformHostNames:       true,
			useFragmentor:            false,
			runDuration:              0,
		})
}

func TestFrontedMeek(t *testing.T) {
	controllerRun(t,
		&controllerRunConfig{
			expectNoServerEntries:    false,
			protocol:                 protocol.TUNNEL_PROTOCOL_FRONTED_MEEK,
			clientIsLatestVersion:    false,
			disableUntunneledUpgrade: true,
			disableEstablishing:      false,
			disableApi:               false,
			tunnelPoolSize:           1,
			useUpstreamProxy:         false,
			disruptNetwork:           false,
			transformHostNames:       false,
			useFragmentor:            false,
			runDuration:              0,
		})
}

func TestFrontedMeekWithTransformer(t *testing.T) {
	controllerRun(t,
		&controllerRunConfig{
			expectNoServerEntries:    false,
			protocol:                 protocol.TUNNEL_PROTOCOL_FRONTED_MEEK,
			clientIsLatestVersion:    true,
			disableUntunneledUpgrade: true,
			disableEstablishing:      false,
			disableApi:               false,
			tunnelPoolSize:           1,
			useUpstreamProxy:         false,
			disruptNetwork:           false,
			transformHostNames:       true,
			useFragmentor:            false,
			runDuration:              0,
		})
}

func TestFrontedMeekHTTP(t *testing.T) {
	controllerRun(t,
		&controllerRunConfig{
			expectNoServerEntries:    false,
			protocol:                 protocol.TUNNEL_PROTOCOL_FRONTED_MEEK_HTTP,
			clientIsLatestVersion:    true,
			disableUntunneledUpgrade: true,
			disableEstablishing:      false,
			disableApi:               false,
			tunnelPoolSize:           1,
			useUpstreamProxy:         false,
			disruptNetwork:           false,
			transformHostNames:       false,
			useFragmentor:            false,
			runDuration:              0,
		})
}

func TestUnfrontedMeekHTTPS(t *testing.T) {
	controllerRun(t,
		&controllerRunConfig{
			expectNoServerEntries:    false,
			protocol:                 protocol.TUNNEL_PROTOCOL_UNFRONTED_MEEK_HTTPS,
			clientIsLatestVersion:    false,
			disableUntunneledUpgrade: true,
			disableEstablishing:      false,
			disableApi:               false,
			tunnelPoolSize:           1,
			useUpstreamProxy:         false,
			disruptNetwork:           false,
			transformHostNames:       false,
			useFragmentor:            false,
			runDuration:              0,
		})
}

func TestUnfrontedMeekHTTPSWithTransformer(t *testing.T) {
	controllerRun(t,
		&controllerRunConfig{
			expectNoServerEntries:    false,
			protocol:                 protocol.TUNNEL_PROTOCOL_UNFRONTED_MEEK_HTTPS,
			clientIsLatestVersion:    true,
			disableUntunneledUpgrade: true,
			disableEstablishing:      false,
			disableApi:               false,
			tunnelPoolSize:           1,
			useUpstreamProxy:         false,
			disruptNetwork:           false,
			transformHostNames:       true,
			useFragmentor:            false,
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
			transformHostNames:       false,
			useFragmentor:            false,
			runDuration:              0,
		})
}

func TestObfuscatedSSHWithUpstreamProxy(t *testing.T) {
	controllerRun(t,
		&controllerRunConfig{
			expectNoServerEntries:    false,
			protocol:                 protocol.TUNNEL_PROTOCOL_OBFUSCATED_SSH,
			clientIsLatestVersion:    false,
			disableUntunneledUpgrade: true,
			disableEstablishing:      false,
			disableApi:               false,
			tunnelPoolSize:           1,
			useUpstreamProxy:         true,
			disruptNetwork:           false,
			transformHostNames:       false,
			useFragmentor:            false,
			runDuration:              0,
		})
}

func TestUnfrontedMeekWithUpstreamProxy(t *testing.T) {
	controllerRun(t,
		&controllerRunConfig{
			expectNoServerEntries:    false,
			protocol:                 protocol.TUNNEL_PROTOCOL_UNFRONTED_MEEK,
			clientIsLatestVersion:    false,
			disableUntunneledUpgrade: true,
			disableEstablishing:      false,
			disableApi:               false,
			tunnelPoolSize:           1,
			useUpstreamProxy:         true,
			disruptNetwork:           false,
			transformHostNames:       false,
			useFragmentor:            false,
			runDuration:              0,
		})
}

func TestUnfrontedMeekHTTPSWithUpstreamProxy(t *testing.T) {
	controllerRun(t,
		&controllerRunConfig{
			expectNoServerEntries:    false,
			protocol:                 protocol.TUNNEL_PROTOCOL_UNFRONTED_MEEK_HTTPS,
			clientIsLatestVersion:    false,
			disableUntunneledUpgrade: true,
			disableEstablishing:      false,
			disableApi:               false,
			tunnelPoolSize:           1,
			useUpstreamProxy:         true,
			disruptNetwork:           false,
			transformHostNames:       false,
			useFragmentor:            false,
			runDuration:              0,
		})
}

func TestObfuscatedSSHFragmentor(t *testing.T) {
	controllerRun(t,
		&controllerRunConfig{
			expectNoServerEntries:    false,
			protocol:                 protocol.TUNNEL_PROTOCOL_OBFUSCATED_SSH,
			clientIsLatestVersion:    false,
			disableUntunneledUpgrade: true,
			disableEstablishing:      false,
			disableApi:               false,
			tunnelPoolSize:           1,
			useUpstreamProxy:         false,
			disruptNetwork:           false,
			transformHostNames:       false,
			useFragmentor:            true,
			runDuration:              0,
		})
}

func TestFrontedMeekFragmentor(t *testing.T) {
	controllerRun(t,
		&controllerRunConfig{
			expectNoServerEntries:    false,
			protocol:                 protocol.TUNNEL_PROTOCOL_FRONTED_MEEK,
			clientIsLatestVersion:    false,
			disableUntunneledUpgrade: true,
			disableEstablishing:      false,
			disableApi:               false,
			tunnelPoolSize:           1,
			useUpstreamProxy:         false,
			disruptNetwork:           false,
			transformHostNames:       false,
			useFragmentor:            true,
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
	transformHostNames       bool
	useFragmentor            bool
	runDuration              time.Duration
}

func controllerRun(t *testing.T, runConfig *controllerRunConfig) {

	configJSON, err := ioutil.ReadFile("controller_test.config")
	if err != nil {
		// Skip, don't fail, if config file is not present
		t.Skipf("error loading configuration file: %s", err)
	}

	// Note: a successful tactics request may modify config parameters.

	// These fields must be filled in before calling LoadConfig
	var modifyConfig map[string]interface{}
	json.Unmarshal(configJSON, &modifyConfig)
	modifyConfig["DataStoreDirectory"] = testDataDirName
	modifyConfig["RemoteServerListDownloadFilename"] = filepath.Join(testDataDirName, "server_list_compressed")
	modifyConfig["UpgradeDownloadFilename"] = filepath.Join(testDataDirName, "upgrade")

	if runConfig.protocol != "" {
		modifyConfig["TunnelProtocols"] = protocol.TunnelProtocols{runConfig.protocol}
	}

	// Override client retry throttle values to speed up automated
	// tests and ensure tests complete within fixed deadlines.
	modifyConfig["FetchRemoteServerListRetryPeriodMilliseconds"] = 250
	modifyConfig["FetchUpgradeRetryPeriodMilliseconds"] = 250
	modifyConfig["EstablishTunnelPausePeriodSeconds"] = 1

	if runConfig.disableUntunneledUpgrade {
		// Disable untunneled upgrade downloader to ensure tunneled case is tested
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

	configJSON, _ = json.Marshal(modifyConfig)

	config, err := LoadConfig(configJSON)
	if err != nil {
		t.Fatalf("error processing configuration file: %s", err)
	}

	// The following config values are not client parameters can be set directly.

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
	err = config.Commit()
	if err != nil {
		t.Fatalf("error committing configuration file: %s", err)
	}

	// Enable tactics requests. This will passively exercise the code
	// paths. server_test runs a more comprehensive test that checks
	// that the tactics request succeeds.
	config.NetworkID = "NETWORK1"

	os.Remove(config.UpgradeDownloadFilename)
	os.Remove(config.RemoteServerListDownloadFilename)

	err = OpenDataStore(config)
	if err != nil {
		t.Fatalf("error initializing datastore: %s", err)
	}
	defer CloseDataStore()

	serverEntryCount := CountServerEntries(config.UseUpstreamProxy(), "", nil)

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

	SetNoticeWriter(NewNoticeReceiver(
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
					case remoteServerListDownloaded <- *new(struct{}):
					default:
					}
				}

			case "ImpairedProtocolClassification":

				classification := payload["classification"].(map[string]interface{})

				impairedProtocolClassification.Lock()
				impairedProtocolClassification.classification = make(map[string]int)
				for k, v := range classification {
					count := int(v.(float64))
					if count >= config.clientParameters.Get().Int(parameters.ImpairedProtocolClassificationThreshold) {
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
				if ok && count >= config.clientParameters.Get().Int(parameters.ImpairedProtocolClassificationThreshold) {

					// TODO: Fix this test case. Use of TunnelPoolSize breaks this
					// case, as many tunnel establishments are occurring in parallel,
					// and it can happen that a protocol is classified as impaired
					// while a tunnel with that protocol is established and set
					// active.

					// *not* t.Fatalf
					t.Logf("unexpected tunnel using impaired protocol: %s, %+v",
						serverProtocol, classification)
				}

			}
		}))

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

		// Cannot establish port forwards in DisableApi mode
		if !runConfig.disableApi {

			// Test: fetch website through tunnel

			// Allow for known race condition described in NewHttpProxy():
			time.Sleep(1 * time.Second)

			if !runConfig.disruptNetwork {
				fetchAndVerifyWebsite(t, httpProxyPort)
			}

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
	}

	// Test: upgrade check/download must be downloaded within 180 seconds

	expectUpgrade := !runConfig.disableApi && !runConfig.disableUntunneledUpgrade

	if expectUpgrade {
		upgradeTimeout := time.NewTimer(120 * time.Second)

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
const disruptorMaxConnectionBytes = 250000
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

const upstreamProxyURL = "http://127.0.0.1:2161"

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
