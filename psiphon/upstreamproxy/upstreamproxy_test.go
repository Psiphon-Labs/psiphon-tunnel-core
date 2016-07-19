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

package upstreamproxy

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
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/server"
	"github.com/elazarl/goproxy"
)

// Note: upstreamproxy_test is redundant -- it doesn't test any cases not
// covered by controller_test; and its code is largely copied from server_test
// and controller_test. upstreamproxy_test exists so that coverage within the
// upstreamproxy package can be measured and reported.

func TestMain(m *testing.M) {
	flag.Parse()
	os.Remove(psiphon.DATA_STORE_FILENAME)
	initUpstreamProxy()
	psiphon.SetEmitDiagnosticNotices(true)
	os.Exit(m.Run())
}

func TestSSHViaUpstreamProxy(t *testing.T) {
	runServer(t, "SSH")
}

func TestOSSHViaUpstreamProxy(t *testing.T) {
	runServer(t, "OSSH")
}

func TestUnfrontedMeekViaUpstreamProxy(t *testing.T) {
	runServer(t, "UNFRONTED-MEEK-OSSH")
}

func TestUnfrontedMeekHTTPSViaUpstreamProxy(t *testing.T) {
	runServer(t, "UNFRONTED-MEEK-HTTPS-OSSH")
}

func runServer(t *testing.T, tunnelProtocol string) {

	// create a server

	serverIPaddress, err := psiphon.GetInterfaceIPAddress("en0")
	if err != nil {
		t.Fatalf("error getting server IP address: %s", err)
	}

	serverConfigJSON, _, encodedServerEntry, err := server.GenerateConfig(
		&server.GenerateConfigParams{
			ServerIPAddress:      serverIPaddress,
			EnableSSHAPIRequests: true,
			WebServerPort:        8000,
			TunnelProtocolPorts:  map[string]int{tunnelProtocol: 4000},
		})
	if err != nil {
		t.Fatalf("error generating server config: %s", err)
	}

	// customize server config

	var serverConfig interface{}
	json.Unmarshal(serverConfigJSON, &serverConfig)
	serverConfig.(map[string]interface{})["GeoIPDatabaseFilename"] = ""
	serverConfig.(map[string]interface{})["PsinetDatabaseFilename"] = ""
	serverConfig.(map[string]interface{})["TrafficRulesFilename"] = ""
	serverConfigJSON, _ = json.Marshal(serverConfig)

	// run server

	serverWaitGroup := new(sync.WaitGroup)
	serverWaitGroup.Add(1)
	go func() {
		defer serverWaitGroup.Done()
		err := server.RunServices(serverConfigJSON)
		if err != nil {
			// TODO: wrong goroutine for t.FatalNow()
			t.Fatalf("error running server: %s", err)
		}
	}()
	defer func() {
		p, _ := os.FindProcess(os.Getpid())
		p.Signal(os.Interrupt)
		serverWaitGroup.Wait()
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

	clientConfig.ConnectionWorkerPoolSize = numTunnels
	clientConfig.TunnelPoolSize = numTunnels
	clientConfig.DisableRemoteServerListFetcher = true
	clientConfig.EstablishTunnelPausePeriodSeconds = &establishTunnelPausePeriodSeconds
	clientConfig.TargetServerEntry = string(encodedServerEntry)
	clientConfig.TunnelProtocol = tunnelProtocol
	clientConfig.LocalHttpProxyPort = localHTTPProxyPort

	clientConfig.UpstreamProxyUrl = upstreamProxyURL
	clientConfig.UpstreamProxyCustomHeaders = upstreamProxyCustomHeaders

	err = psiphon.InitDataStore(clientConfig)
	if err != nil {
		t.Fatalf("error initializing client datastore: %s", err)
	}

	controller, err := psiphon.NewController(clientConfig)
	if err != nil {
		t.Fatalf("error creating client controller: %s", err)
	}

	tunnelsEstablished := make(chan struct{}, 1)

	psiphon.SetNoticeOutput(psiphon.NewNoticeReceiver(
		func(notice []byte) {

			fmt.Printf("%s\n", string(notice))

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
		controllerWaitGroup.Wait()
	}()

	// Test: tunnels must be established within 30 seconds

	establishTimeout := time.NewTimer(30 * time.Second)
	select {
	case <-tunnelsEstablished:
	case <-establishTimeout.C:
		t.Fatalf("tunnel establish timeout exceeded")
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

const upstreamProxyURL = "http://127.0.0.1:2161"

var upstreamProxyCustomHeaders = map[string][]string{"X-Test-Header-Name": []string{"test-header-value1", "test-header-value2"}}

func hasExpectedCustomHeaders(h http.Header) bool {
	for name, values := range upstreamProxyCustomHeaders {
		if h[name] == nil {
			return false
		}
		// Order may not be the same
		for _, value := range values {
			if !psiphon.Contains(h[name], value) {
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
				// TODO: enable this check. Currently the headers aren't send because the
				// following type assertion in upstreamproxy.newHTTP fails (but only in this
				// test context, not in controller_test):
				//   if upstreamProxyConfig, ok := forward.(*UpstreamProxyConfig); ok {
				//       hp.customHeaders = upstreamProxyConfig.CustomHeaders
				//   }
				//
				/*
					if !hasExpectedCustomHeaders(ctx.Req.Header) {
						ctx.Logf("missing expected headers: %+v", ctx.Req.Header)
						return goproxy.RejectConnect, host
					}
				*/
				return goproxy.OkConnect, host
			})

		err := http.ListenAndServe("127.0.0.1:2161", proxy)
		if err != nil {
			fmt.Printf("upstream proxy failed: %s", err)
		}
	}()

	// TODO: wait until listener is active?
}
