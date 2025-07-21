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

package psiphon

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/values"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/server"
	"github.com/elazarl/goproxy"
)

// TODO: test that server receives and records correct user_agent value

func TestOSSHUserAgent(t *testing.T) {
	attemptConnectionsWithUserAgent(t, "OSSH", true)
}

func TestUnfrontedMeekUserAgent(t *testing.T) {
	attemptConnectionsWithUserAgent(t, "UNFRONTED-MEEK-OSSH", false)
}

func TestUnfrontedMeekHTTPSUserAgent(t *testing.T) {
	attemptConnectionsWithUserAgent(t, "UNFRONTED-MEEK-HTTPS-OSSH", true)
}

var mockUserAgents = []string{"UserAgentA", "UserAgentB"}
var userAgentCountsMutex sync.Mutex
var userAgentCounts map[string]int
var initUserAgentCounter sync.Once

func initMockUserAgents() {
	values.SetUserAgentsSpec(values.NewPickOneSpec(mockUserAgents))
}

func resetUserAgentCounts() {
	userAgentCountsMutex.Lock()
	defer userAgentCountsMutex.Unlock()
	userAgentCounts = make(map[string]int)
}

func countHTTPUserAgent(headers http.Header, isCONNECT bool) {
	userAgentCountsMutex.Lock()
	defer userAgentCountsMutex.Unlock()
	if _, ok := headers["User-Agent"]; !ok {
		userAgentCounts["BLANK"]++
	} else if isCONNECT {
		userAgentCounts["CONNECT-"+headers.Get("User-Agent")]++
	} else {
		userAgentCounts[headers.Get("User-Agent")]++
	}
}

func countNoticeUserAgent(userAgent string) {
	userAgentCountsMutex.Lock()
	defer userAgentCountsMutex.Unlock()
	userAgentCounts["NOTICE-"+userAgent]++
}

func checkUserAgentCounts(t *testing.T, isCONNECT bool) {
	userAgentCountsMutex.Lock()
	defer userAgentCountsMutex.Unlock()

	for _, userAgent := range mockUserAgents {

		if isCONNECT {
			if userAgentCounts["CONNECT-"+userAgent] == 0 {
				t.Fatalf("unexpected CONNECT user agent count of 0: %+v", userAgentCounts)
				return
			}
		} else {

			if userAgentCounts[userAgent] == 0 {
				t.Fatalf("unexpected non-CONNECT user agent count of 0: %+v", userAgentCounts)
				return
			}
		}

		if userAgentCounts["NOTICE-"+userAgent] == 0 {
			t.Fatalf("unexpected NOTICE user agent count of 0: %+v", userAgentCounts)
			return
		}
	}

	if userAgentCounts["BLANK"] == 0 {
		t.Fatalf("unexpected BLANK user agent count of 0: %+v", userAgentCounts)
		return
	}

	// TODO: check proportions
	t.Logf("%+v", userAgentCounts)
}

func initUserAgentCounterUpstreamProxy() {
	initUserAgentCounter.Do(func() {
		go func() {
			proxy := goproxy.NewProxyHttpServer()

			proxy.OnRequest().DoFunc(
				func(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
					countHTTPUserAgent(r.Header, false)
					return nil, goproxy.NewResponse(r, goproxy.ContentTypeText, http.StatusUnauthorized, "")
				})

			proxy.OnRequest().HandleConnectFunc(
				func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
					countHTTPUserAgent(ctx.Req.Header, true)
					return goproxy.RejectConnect, host
				})

			err := http.ListenAndServe("127.0.0.1:2163", proxy)
			if err != nil {
				fmt.Printf("upstream proxy failed: %s\n", err)
			}
		}()

		// TODO: more robust wait-until-listening
		time.Sleep(1 * time.Second)
	})
}

func attemptConnectionsWithUserAgent(
	t *testing.T, tunnelProtocol string, isCONNECT bool) {

	testDataDirName, err := ioutil.TempDir("", "psiphon-user-agent-test")
	if err != nil {
		t.Fatalf("TempDir failed: %s\n", err)
	}
	defer os.RemoveAll(testDataDirName)

	initMockUserAgents()
	initUserAgentCounterUpstreamProxy()
	resetUserAgentCounts()

	// create a server entry

	_, _, _, _, encodedServerEntry, err := server.GenerateConfig(
		&server.GenerateConfigParams{
			ServerIPAddress:     "127.0.0.1",
			TunnelProtocolPorts: map[string]int{tunnelProtocol: 4000},
		})
	if err != nil {
		t.Fatalf("error generating server config: %s", err)
	}

	// attempt connections with client

	// Connections are made through a mock upstream proxy that
	// counts user agents. No server is running, and the upstream
	// proxy rejects connections after counting the user agent.

	// Note: calling LoadConfig ensures all *int config fields are initialized
	clientConfigJSON := `
    {
        "ClientPlatform" : "Windows",
        "ClientVersion" : "0",
        "SponsorId" : "0000000000000000",
        "PropagationChannelId" : "0000000000000000",
        "ConnectionWorkerPoolSize" : 1,
        "EstablishTunnelPausePeriodSeconds" : 1,
        "DisableRemoteServerListFetcher" : true,
        "TransformHostNameProbability" : 0.0,
        "UpstreamProxyUrl" : "http://127.0.0.1:2163",
        "UpstreamProxyAllowAllServerEntrySources" : true
    }`
	clientConfig, err := LoadConfig([]byte(clientConfigJSON))
	if err != nil {
		t.Fatalf("error processing configuration file: %s", err)
	}

	clientConfig.TargetServerEntry = string(encodedServerEntry)
	clientConfig.TunnelProtocol = tunnelProtocol
	clientConfig.DataRootDirectory = testDataDirName

	err = clientConfig.Commit(false)
	if err != nil {
		t.Fatalf("error committing configuration file: %s", err)
	}

	err = OpenDataStore(clientConfig)
	if err != nil {
		t.Fatalf("error initializing client datastore: %s", err)
	}
	defer CloseDataStore()

	err = SetNoticeWriter(NewNoticeReceiver(
		func(notice []byte) {
			noticeType, payload, err := GetNotice(notice)
			if err != nil {
				return
			}
			if noticeType == "ConnectingServer" {
				userAgent, ok := payload["userAgent"]
				if ok {
					countNoticeUserAgent(userAgent.(string))
				}
			}
		}))
	if err != nil {
		t.Fatalf("error setting notice writer: %s", err)
	}
	defer ResetNoticeWriter()

	controller, err := NewController(clientConfig)
	if err != nil {
		t.Fatalf("error creating client controller: %s", err)
	}

	ctx, cancelFunc := context.WithCancel(context.Background())

	controllerWaitGroup := new(sync.WaitGroup)

	controllerWaitGroup.Add(1)
	go func() {
		defer controllerWaitGroup.Done()
		controller.Run(ctx)
	}()

	// repeat attempts for long enough to select each user agent

	time.Sleep(30 * time.Second)

	cancelFunc()

	controllerWaitGroup.Wait()

	checkUserAgentCounts(t, isCONNECT)
}
