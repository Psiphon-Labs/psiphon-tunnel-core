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

	socks "github.com/Psiphon-Inc/goptlib"
)

func TestMain(m *testing.M) {
	flag.Parse()
	os.Remove(DATA_STORE_FILENAME)
	initDisruptor()
	setEmitDiagnosticNotices(true)
	os.Exit(m.Run())
}

// Note: untunneled upgrade tests must execute before
// the other tests to ensure no tunnel is established.
// We need a way to reset the datastore after it's been
// initialized in order to to clear out its data entries
// and be able to arbitrarily order the tests.

func TestUntunneledUpgradeDownload(t *testing.T) {
	controllerRun(t,
		&controllerRunConfig{
			protocol:                 "",
			clientIsLatestVersion:    false,
			disableUntunneledUpgrade: false,
			disableEstablishing:      true,
			disruptNetwork:           false,
			useHostNameTransformer:   false,
		})
}

func TestUntunneledResumableUpgradeDownload(t *testing.T) {
	controllerRun(t,
		&controllerRunConfig{
			protocol:                 "",
			clientIsLatestVersion:    false,
			disableUntunneledUpgrade: false,
			disableEstablishing:      true,
			disruptNetwork:           true,
			useHostNameTransformer:   false,
		})
}

func TestUntunneledUpgradeClientIsLatestVersion(t *testing.T) {
	controllerRun(t,
		&controllerRunConfig{
			protocol:                 "",
			clientIsLatestVersion:    true,
			disableUntunneledUpgrade: false,
			disableEstablishing:      true,
			disruptNetwork:           false,
			useHostNameTransformer:   false,
		})
}

func TestTunneledUpgradeClientIsLatestVersion(t *testing.T) {
	controllerRun(t,
		&controllerRunConfig{
			protocol:                 "",
			clientIsLatestVersion:    true,
			disableUntunneledUpgrade: true,
			disableEstablishing:      false,
			disruptNetwork:           false,
			useHostNameTransformer:   false,
		})
}

func TestControllerRunSSH(t *testing.T) {
	controllerRun(t,
		&controllerRunConfig{
			protocol:                 TUNNEL_PROTOCOL_SSH,
			clientIsLatestVersion:    false,
			disableUntunneledUpgrade: true,
			disableEstablishing:      false,
			disruptNetwork:           false,
			useHostNameTransformer:   false,
		})
}

func TestControllerRunObfuscatedSSH(t *testing.T) {
	controllerRun(t,
		&controllerRunConfig{
			protocol:                 TUNNEL_PROTOCOL_OBFUSCATED_SSH,
			clientIsLatestVersion:    false,
			disableUntunneledUpgrade: true,
			disableEstablishing:      false,
			disruptNetwork:           false,
			useHostNameTransformer:   false,
		})
}

func TestControllerRunUnfrontedMeek(t *testing.T) {
	controllerRun(t,
		&controllerRunConfig{
			protocol:                 TUNNEL_PROTOCOL_UNFRONTED_MEEK,
			clientIsLatestVersion:    false,
			disableUntunneledUpgrade: true,
			disableEstablishing:      false,
			disruptNetwork:           false,
			useHostNameTransformer:   false,
		})
}

func TestControllerRunUnfrontedMeekWithTransformer(t *testing.T) {
	controllerRun(t,
		&controllerRunConfig{
			protocol:                 TUNNEL_PROTOCOL_UNFRONTED_MEEK,
			clientIsLatestVersion:    true,
			disableUntunneledUpgrade: true,
			disableEstablishing:      false,
			disruptNetwork:           false,
			useHostNameTransformer:   true,
		})
}

func TestControllerRunFrontedMeek(t *testing.T) {
	controllerRun(t,
		&controllerRunConfig{
			protocol:                 TUNNEL_PROTOCOL_FRONTED_MEEK,
			clientIsLatestVersion:    false,
			disableUntunneledUpgrade: true,
			disableEstablishing:      false,
			disruptNetwork:           false,
			useHostNameTransformer:   false,
		})
}

func TestControllerRunFrontedMeekWithTransformer(t *testing.T) {
	controllerRun(t,
		&controllerRunConfig{
			protocol:                 TUNNEL_PROTOCOL_FRONTED_MEEK,
			clientIsLatestVersion:    true,
			disableUntunneledUpgrade: true,
			disableEstablishing:      false,
			disruptNetwork:           false,
			useHostNameTransformer:   true,
		})
}

func TestControllerFrontedMeekHTTP(t *testing.T) {
	controllerRun(t,
		&controllerRunConfig{
			protocol:                 TUNNEL_PROTOCOL_FRONTED_MEEK_HTTP,
			clientIsLatestVersion:    true,
			disableUntunneledUpgrade: true,
			disableEstablishing:      false,
			disruptNetwork:           false,
			useHostNameTransformer:   false,
		})
}

func TestControllerRunUnfrontedMeekHTTPS(t *testing.T) {
	controllerRun(t,
		&controllerRunConfig{
			protocol:                 TUNNEL_PROTOCOL_UNFRONTED_MEEK_HTTPS,
			clientIsLatestVersion:    false,
			disableUntunneledUpgrade: true,
			disableEstablishing:      false,
			disruptNetwork:           false,
			useHostNameTransformer:   false,
		})
}

func TestControllerRunUnfrontedMeekHTTPSWithTransformer(t *testing.T) {
	controllerRun(t,
		&controllerRunConfig{
			protocol:                 TUNNEL_PROTOCOL_UNFRONTED_MEEK_HTTPS,
			clientIsLatestVersion:    true,
			disableUntunneledUpgrade: true,
			disableEstablishing:      false,
			disruptNetwork:           false,
			useHostNameTransformer:   true,
		})
}

type controllerRunConfig struct {
	protocol                 string
	clientIsLatestVersion    bool
	disableUntunneledUpgrade bool
	disableEstablishing      bool
	disruptNetwork           bool
	useHostNameTransformer   bool
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

	if runConfig.disableUntunneledUpgrade {
		// Disable untunneled upgrade downloader to ensure tunneled case is tested
		config.UpgradeDownloadClientVersionHeader = ""
	}

	if runConfig.disruptNetwork {
		config.UpstreamProxyUrl = disruptorProxyURL
	}

	if runConfig.useHostNameTransformer {
		config.HostNameTransformer = &TestHostNameTransformer{}
	}

	os.Remove(config.UpgradeDownloadFilename)

	config.TunnelProtocol = runConfig.protocol

	err = InitDataStore(config)
	if err != nil {
		t.Fatalf("error initializing datastore: %s", err)
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
	confirmedLatestVersion := make(chan struct{}, 1)

	var clientUpgradeDownloadedBytesCount int32

	SetNoticeOutput(NewNoticeReceiver(
		func(notice []byte) {
			// TODO: log notices without logging server IPs:
			// fmt.Fprintf(os.Stderr, "%s\n", string(notice))
			noticeType, payload, err := GetNotice(notice)
			if err != nil {
				return
			}
			switch noticeType {
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
			case "ListeningHttpProxyPort":
				httpProxyPort = int(payload["port"].(float64))
			case "ConnectingServer":
				serverProtocol := payload["protocol"]
				if runConfig.protocol != "" && serverProtocol != runConfig.protocol {
					// TODO: wrong goroutine for t.FatalNow()
					t.Fatalf("wrong protocol selected: %s", serverProtocol)
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
		// Test: shutdown must complete within 10 seconds

		close(shutdownBroadcast)

		shutdownTimeout := time.NewTimer(10 * time.Second)

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

		// Test: tunnel must be established within 60 seconds

		establishTimeout := time.NewTimer(60 * time.Second)

		select {
		case <-tunnelEstablished:

		case <-establishTimeout.C:
			t.Fatalf("tunnel establish timeout exceeded")
		}

		// Test: fetch website through tunnel

		// Allow for known race condition described in NewHttpProxy():
		time.Sleep(1 * time.Second)
		fetchWebsite(t, httpProxyPort)
	}

	// Test: upgrade check/download must be downloaded within 120 seconds

	upgradeTimeout := time.NewTimer(120 * time.Second)

	select {
	case <-upgradeDownloaded:
		// TODO: verify downloaded file
		if runConfig.clientIsLatestVersion {
			t.Fatalf("upgrade downloaded unexpectedly")
		}

	case <-confirmedLatestVersion:
		if !runConfig.clientIsLatestVersion {
			t.Fatalf("confirmed latest version unexpectedly")
		}

	case <-upgradeTimeout.C:
		t.Fatalf("upgrade download timeout exceeded")
	}

	// Test: with disruptNetwork, must be multiple download progress notices

	if runConfig.disruptNetwork && !runConfig.clientIsLatestVersion {
		count := atomic.LoadInt32(&clientUpgradeDownloadedBytesCount)
		if count <= 1 {
			t.Fatalf("unexpected upgrade download progress: %d", count)
		}
	}
}

type TestHostNameTransformer struct {
}

func (TestHostNameTransformer) TransformHostName(string) (string, bool) {
	return "example.com", true
}

func fetchWebsite(t *testing.T, httpProxyPort int) {

	testUrl := "https://raw.githubusercontent.com/Psiphon-Labs/psiphon-tunnel-core/master/LICENSE"
	roundTripTimeout := 10 * time.Second
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

const disruptorProxyAddress = "127.0.0.1:2160"
const disruptorProxyURL = "socks4a://" + disruptorProxyAddress
const disruptorMaxConnectionBytes = 2000000
const disruptorMaxConnectionTime = 15 * time.Second

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
