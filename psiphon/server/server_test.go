/*
 * Copyright (c) 2016, Psiphon Inc.
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
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon"
)

func TestMain(m *testing.M) {
	flag.Parse()
	os.Remove(psiphon.DATA_STORE_FILENAME)
	psiphon.SetEmitDiagnosticNotices(true)
	os.Exit(m.Run())
}

// Note: not testing fronting meek protocols, which client is
// hard-wired to except running on privileged ports 80 and 443.

func TestSSH(t *testing.T) {
	runServer(t,
		&runServerConfig{
			tunnelProtocol:       "SSH",
			enableSSHAPIRequests: true,
		})
}

func TestOSSH(t *testing.T) {
	runServer(t,
		&runServerConfig{
			tunnelProtocol:       "OSSH",
			enableSSHAPIRequests: true,
		})
}

func TestUnfrontedMeek(t *testing.T) {
	runServer(t,
		&runServerConfig{
			tunnelProtocol:       "UNFRONTED-MEEK-OSSH",
			enableSSHAPIRequests: true,
		})
}

func TestUnfrontedMeekHTTPS(t *testing.T) {
	runServer(t,
		&runServerConfig{
			tunnelProtocol:       "UNFRONTED-MEEK-HTTPS-OSSH",
			enableSSHAPIRequests: true,
		})
}

func TestWebTransportAPIRequests(t *testing.T) {
	runServer(t,
		&runServerConfig{
			tunnelProtocol:       "OSSH",
			enableSSHAPIRequests: false,
		})
}

type runServerConfig struct {
	tunnelProtocol       string
	enableSSHAPIRequests bool
}

func runServer(t *testing.T, runConfig *runServerConfig) {

	// create a server

	serverConfigJSON, _, encodedServerEntry, err := GenerateConfig(
		&GenerateConfigParams{
			ServerIPAddress:      "127.0.0.1",
			EnableSSHAPIRequests: runConfig.enableSSHAPIRequests,
			WebServerPort:        8000,
			TunnelProtocolPorts:  map[string]int{runConfig.tunnelProtocol: 4000},
		})
	if err != nil {
		t.Fatalf("error generating server config: %s", err)
	}

	// customize server config

	psinetFilename, sponsorID, expectedHomepageURL := pavePsinetDatabaseFile(t)

	var serverConfig interface{}
	json.Unmarshal(serverConfigJSON, &serverConfig)
	serverConfig.(map[string]interface{})["GeoIPDatabaseFilename"] = ""
	serverConfig.(map[string]interface{})["PsinetDatabaseFilename"] = psinetFilename
	serverConfig.(map[string]interface{})["TrafficRulesFilename"] = ""
	serverConfigJSON, _ = json.Marshal(serverConfig)

	// run server

	serverWaitGroup := new(sync.WaitGroup)
	serverWaitGroup.Add(1)
	go func() {
		defer serverWaitGroup.Done()
		err := RunServices(serverConfigJSON)
		if err != nil {
			// TODO: wrong goroutine for t.FatalNow()
			t.Fatalf("error running server: %s", err)
		}
	}()
	defer func() {

		// Test: orderly server shutdown

		p, _ := os.FindProcess(os.Getpid())
		p.Signal(os.Interrupt)

		shutdownTimeout := time.NewTimer(5 * time.Second)

		shutdownOk := make(chan struct{}, 1)
		go func() {
			serverWaitGroup.Wait()
			shutdownOk <- *new(struct{})
		}()

		select {
		case <-shutdownOk:
		case <-shutdownTimeout.C:
			t.Fatalf("server shutdown timeout exceeded")
		}
	}()

	// connect to server with client

	// TODO: currently, TargetServerEntry only works with one tunnel
	numTunnels := 1
	localHTTPProxyPort := 8081
	establishTunnelPausePeriodSeconds := 1

	// Note: calling LoadConfig ensures all *int config fields are initialized
	clientConfigJSON := `
    {
        "ClientVersion" : "0",
        "SponsorId" : "0",
        "PropagationChannelId" : "0"
    }`
	clientConfig, _ := psiphon.LoadConfig([]byte(clientConfigJSON))

	clientConfig.SponsorId = sponsorID
	clientConfig.ConnectionWorkerPoolSize = numTunnels
	clientConfig.TunnelPoolSize = numTunnels
	clientConfig.DisableRemoteServerListFetcher = true
	clientConfig.EstablishTunnelPausePeriodSeconds = &establishTunnelPausePeriodSeconds
	clientConfig.TargetServerEntry = string(encodedServerEntry)
	clientConfig.TunnelProtocol = runConfig.tunnelProtocol
	clientConfig.LocalHttpProxyPort = localHTTPProxyPort

	err = psiphon.InitDataStore(clientConfig)
	if err != nil {
		t.Fatalf("error initializing client datastore: %s", err)
	}

	controller, err := psiphon.NewController(clientConfig)
	if err != nil {
		t.Fatalf("error creating client controller: %s", err)
	}

	tunnelsEstablished := make(chan struct{}, 1)
	homepageReceived := make(chan struct{}, 1)

	psiphon.SetNoticeOutput(psiphon.NewNoticeReceiver(
		func(notice []byte) {

			//fmt.Printf("%s\n", string(notice))

			noticeType, payload, err := psiphon.GetNotice(notice)
			if err != nil {
				return
			}

			switch noticeType {
			case "Tunnels":
				count := int(payload["count"].(float64))
				if count >= numTunnels {
					select {
					case tunnelsEstablished <- *new(struct{}):
					default:
					}
				}
			case "Homepage":
				homepageURL := payload["url"].(string)
				if homepageURL != expectedHomepageURL {
					// TODO: wrong goroutine for t.FatalNow()
					t.Fatalf("unexpected homepage: %s", homepageURL)
				}
				select {
				case homepageReceived <- *new(struct{}):
				default:
				}
			}
		}))

	controllerShutdownBroadcast := make(chan struct{})
	controllerWaitGroup := new(sync.WaitGroup)
	controllerWaitGroup.Add(1)
	go func() {
		defer controllerWaitGroup.Done()
		controller.Run(controllerShutdownBroadcast)
	}()
	defer func() {
		close(controllerShutdownBroadcast)

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

	// Test: tunnels must be established, and correct homepage
	// must be received, within 30 seconds

	establishTimeout := time.NewTimer(30 * time.Second)
	select {
	case <-tunnelsEstablished:
	case <-establishTimeout.C:
		t.Fatalf("tunnel establish timeout exceeded")
	}

	select {
	case <-homepageReceived:
	case <-establishTimeout.C:
		t.Fatalf("homepage received timeout exceeded")
	}

	// Test: tunneled web site fetch

	testUrl := "https://psiphon.ca"
	roundTripTimeout := 30 * time.Second

	proxyUrl, err := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", localHTTPProxyPort))
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

	_, err = ioutil.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("error reading proxied HTTP response: %s", err)
	}
	response.Body.Close()
}

func pavePsinetDatabaseFile(t *testing.T) (string, string, string) {

	psinetFilename := "psinet.json"

	sponsorID, _ := psiphon.MakeRandomStringHex(8)

	fakeDomain, _ := psiphon.MakeRandomStringHex(4)
	fakePath, _ := psiphon.MakeRandomStringHex(4)
	expectedHomepageURL := fmt.Sprintf("https://%s.com/%s", fakeDomain, fakePath)

	psinetJSONFormat := `
    {
        "sponsors": {
            "%s": {
                "home_pages": {
                    "None": [
                        {
                            "region": null,
                            "url": "%s"
                        }
                    ]
                }
            }
        }
    }
	`
	psinetJSON := fmt.Sprintf(psinetJSONFormat, sponsorID, expectedHomepageURL)

	err := ioutil.WriteFile(psinetFilename, []byte(psinetJSON), 0600)
	if err != nil {
		t.Fatalf("error paving psinet database: %s", err)
	}

	return psinetFilename, sponsorID, expectedHomepageURL
}
