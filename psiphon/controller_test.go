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
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestControllerRunSSH(t *testing.T) {
	controllerRun(t, TUNNEL_PROTOCOL_SSH)
}

func TestControllerRunObfuscatedSSH(t *testing.T) {
	controllerRun(t, TUNNEL_PROTOCOL_OBFUSCATED_SSH)
}

func TestControllerRunUnfrontedMeek(t *testing.T) {
	controllerRun(t, TUNNEL_PROTOCOL_UNFRONTED_MEEK)
}

func TestControllerRunFrontedMeek(t *testing.T) {
	controllerRun(t, TUNNEL_PROTOCOL_FRONTED_MEEK)
}

func TestControllerRunFrontedMeekHTTP(t *testing.T) {
	controllerRun(t, TUNNEL_PROTOCOL_FRONTED_MEEK_HTTP)
}

func TestControllerRunUnfrontedMeekHTTPS(t *testing.T) {
	controllerRun(t, TUNNEL_PROTOCOL_UNFRONTED_MEEK_HTTPS)
}

func controllerRun(t *testing.T, protocol string) {

	configFileContents, err := ioutil.ReadFile("controller_test.config")
	if err != nil {
		// Skip, don't fail, if config file is not present
		t.Skipf("error loading configuration file: %s", err)
	}
	config, err := LoadConfig(configFileContents)
	if err != nil {
		t.Errorf("error processing configuration file: %s", err)
		t.FailNow()
	}
	config.TunnelProtocol = protocol

	err = InitDataStore(config)
	if err != nil {
		t.Errorf("error initializing datastore: %s", err)
		t.FailNow()
	}

	controller, err := NewController(config)
	if err != nil {
		t.Errorf("error creating controller: %s", err)
		t.FailNow()
	}

	// Monitor notices for "Tunnels" with count > 1, the
	// indication of tunnel establishment success.
	// Also record the selected HTTP proxy port to use
	// when fetching websites through the tunnel.

	httpProxyPort := 0

	tunnelEstablished := make(chan struct{}, 1)
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
					select {
					case tunnelEstablished <- *new(struct{}):
					default:
					}
				}
			case "ListeningHttpProxyPort":
				httpProxyPort = int(payload["port"].(float64))
			case "ConnectingServer":
				serverProtocol := payload["protocol"]
				if serverProtocol != protocol {
					t.Errorf("wrong protocol selected: %s", serverProtocol)
					t.FailNow()
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

	// Test: tunnel must be established within 60 seconds

	establishTimeout := time.NewTimer(60 * time.Second)

	select {
	case <-tunnelEstablished:

		// Allow for known race condition described in NewHttpProxy():
		time.Sleep(1 * time.Second)

		// Test: fetch website through tunnel
		fetchWebsite(t, httpProxyPort)

	case <-establishTimeout.C:
		t.Errorf("tunnel establish timeout exceeded")
		// ...continue with cleanup
	}

	close(shutdownBroadcast)

	// Test: shutdown must complete within 10 seconds

	shutdownTimeout := time.NewTimer(10 * time.Second)

	shutdownOk := make(chan struct{}, 1)
	go func() {
		controllerWaitGroup.Wait()
		shutdownOk <- *new(struct{})
	}()

	select {
	case <-shutdownOk:
	case <-shutdownTimeout.C:
		t.Errorf("controller shutdown timeout exceeded")
	}
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
		t.Errorf("error initializing proxied HTTP request: %s", err)
		t.FailNow()
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyUrl),
		},
		Timeout: roundTripTimeout,
	}

	response, err := httpClient.Get(testUrl)
	if err != nil {
		t.Errorf("error sending proxied HTTP request: %s", err)
		t.FailNow()
	}

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		t.Errorf("error reading proxied HTTP response: %s", err)
		t.FailNow()
	}
	response.Body.Close()

	if !checkResponse(string(body)) {
		t.Errorf("unexpected proxied HTTP response")
		t.FailNow()
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
		t.Errorf("error sending direct URL request: %s", err)
		t.FailNow()
	}

	body, err = ioutil.ReadAll(response.Body)
	if err != nil {
		t.Errorf("error reading direct URL response: %s", err)
		t.FailNow()
	}
	response.Body.Close()

	if !checkResponse(string(body)) {
		t.Errorf("unexpected direct URL response")
		t.FailNow()
	}

	// Test: use tunneled URL proxy

	response, err = httpClient.Get(
		fmt.Sprintf("http://127.0.0.1:%d/tunneled/%s",
			httpProxyPort, url.QueryEscape(testUrl)))
	if err != nil {
		t.Errorf("error sending tunneled URL request: %s", err)
		t.FailNow()
	}

	body, err = ioutil.ReadAll(response.Body)
	if err != nil {
		t.Errorf("error reading tunneled URL response: %s", err)
		t.FailNow()
	}
	response.Body.Close()

	if !checkResponse(string(body)) {
		t.Errorf("unexpected tunneled URL response")
		t.FailNow()
	}
}
