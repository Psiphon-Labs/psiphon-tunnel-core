/*
 * Copyright (c) 2020, Psiphon Inc.
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
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
)

func TestPassthrough(t *testing.T) {
	testPassthrough(t, false)
}

func TestLegacyPassthrough(t *testing.T) {
	testPassthrough(t, true)
}

func testPassthrough(t *testing.T, legacy bool) {

	psiphon.SetEmitDiagnosticNotices(true, true)

	// Run passthrough web server

	webServerCertificate, webServerPrivateKey, _, err := common.GenerateWebServerCertificate("example.org")
	if err != nil {
		t.Fatalf("common.GenerateWebServerCertificate failed: %s", err)
	}

	webListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen failed: %s", err)
	}
	defer webListener.Close()

	webCertificate, err := tls.X509KeyPair(
		[]byte(webServerCertificate),
		[]byte(webServerPrivateKey))
	if err != nil {
		t.Fatalf("tls.X509KeyPair failed: %s", err)
	}

	webListener = tls.NewListener(webListener, &tls.Config{
		Certificates: []tls.Certificate{webCertificate},
	})

	webServerAddress := webListener.Addr().String()

	webResponseBody := []byte(prng.HexString(32))

	webServer := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Write(webResponseBody)
	})

	go func() {
		http.Serve(webListener, webServer)
	}()

	// Run Psiphon server

	tunnelProtocol := protocol.TUNNEL_PROTOCOL_UNFRONTED_MEEK_SESSION_TICKET

	generateConfigParams := &GenerateConfigParams{
		ServerIPAddress:     "127.0.0.1",
		TunnelProtocolPorts: map[string]int{tunnelProtocol: 4000},
		Passthrough:         true,
		LegacyPassthrough:   legacy,
	}

	serverConfigJSON, _, _, _, encodedServerEntry, err := GenerateConfig(generateConfigParams)
	if err != nil {
		t.Fatalf("error generating server config: %s", err)
	}

	var serverConfig map[string]interface{}
	json.Unmarshal(serverConfigJSON, &serverConfig)

	serverConfig["LogFilename"] = filepath.Join(testDataDirName, "psiphond.log")
	serverConfig["LogLevel"] = "debug"
	serverConfig["TunnelProtocolPassthroughAddresses"] = map[string]string{tunnelProtocol: webServerAddress}

	serverConfigJSON, _ = json.Marshal(serverConfig)

	serverWaitGroup := new(sync.WaitGroup)
	serverWaitGroup.Add(1)
	go func() {
		defer serverWaitGroup.Done()
		err := RunServices(serverConfigJSON)
		if err != nil {
			t.Errorf("error running server: %s", err)
		}
	}()

	defer func() {
		p, _ := os.FindProcess(os.Getpid())
		p.Signal(os.Interrupt)
		serverWaitGroup.Wait()
	}()

	// TODO: monitor logs for more robust wait-until-loaded.
	time.Sleep(1 * time.Second)

	// Test: normal client connects successfully

	clientConfigJSON := fmt.Sprintf(`
		    {
		    	"DataRootDirectory" : "%s",
		        "ClientPlatform" : "Windows",
		        "ClientVersion" : "0",
		        "SponsorId" : "0000000000000000",
		        "PropagationChannelId" : "0000000000000000",
		        "TargetServerEntry" : "%s"
		    }`, testDataDirName, string(encodedServerEntry))

	clientConfig, err := psiphon.LoadConfig([]byte(clientConfigJSON))
	if err != nil {
		t.Fatalf("error processing configuration file: %s", err)
	}

	err = clientConfig.Commit(false)
	if err != nil {
		t.Fatalf("error committing configuration file: %s", err)
	}

	err = psiphon.OpenDataStore(clientConfig)
	if err != nil {
		t.Fatalf("error initializing client datastore: %s", err)
	}
	defer psiphon.CloseDataStore()

	controller, err := psiphon.NewController(clientConfig)
	if err != nil {
		t.Fatalf("error creating client controller: %s", err)
	}

	tunnelEstablished := make(chan struct{}, 1)

	err = psiphon.SetNoticeWriter(psiphon.NewNoticeReceiver(
		func(notice []byte) {
			noticeType, payload, err := psiphon.GetNotice(notice)
			if err != nil {
				return
			}
			if noticeType == "Tunnels" {
				count := int(payload["count"].(float64))
				if count >= 1 {
					tunnelEstablished <- struct{}{}
				}
			}
		}))
	if err != nil {
		t.Fatalf("error setting notice writer: %s", err)
	}
	defer psiphon.ResetNoticeWriter()

	ctx, cancelFunc := context.WithCancel(context.Background())
	controllerWaitGroup := new(sync.WaitGroup)
	controllerWaitGroup.Add(1)
	go func() {
		defer controllerWaitGroup.Done()
		controller.Run(ctx)
	}()
	<-tunnelEstablished
	cancelFunc()
	controllerWaitGroup.Wait()

	// Test: passthrough

	// Non-psiphon HTTPS request routed to passthrough web server

	verifiedCertificate := int32(0)

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
					if len(rawCerts) < 1 {
						return errors.New("no certificate to verify")
					}
					if !bytes.Equal(rawCerts[0], []byte(webCertificate.Certificate[0])) {
						return errors.New("unexpected certificate")
					}
					atomic.StoreInt32(&verifiedCertificate, 1)
					return nil
				},
			},
		},
	}

	response, err := httpClient.Get("https://127.0.0.1:4000")
	if err != nil {
		t.Fatalf("http.Get failed: %s", err)
	}
	defer response.Body.Close()

	if atomic.LoadInt32(&verifiedCertificate) != 1 {
		t.Fatalf("certificate not verified")
	}

	if response.StatusCode != http.StatusOK {
		t.Fatalf("unexpected response.StatusCode: %d", response.StatusCode)
	}

	responseBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("ioutil.ReadAll failed: %s", err)
	}

	if !bytes.Equal(responseBody, webResponseBody) {
		t.Fatalf("unexpected responseBody: %s", string(responseBody))
	}
}
