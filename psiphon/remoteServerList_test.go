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

package psiphon

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	socks "github.com/Psiphon-Inc/goptlib"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/osl"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/server"
)

// TODO: TestCommonRemoteServerList (this is currently covered by controller_test.go)

func TestObfuscatedRemoteServerLists(t *testing.T) {

	//
	// create a server
	//

	var err error
	serverIPaddress := ""
	for _, interfaceName := range []string{"eth0", "en0"} {
		serverIPaddress, err = GetInterfaceIPAddress(interfaceName)
		if err == nil {
			break
		}
	}
	if err != nil {
		t.Fatalf("error getting server IP address: %s", err)
	}

	serverConfigJSON, _, encodedServerEntry, err := server.GenerateConfig(
		&server.GenerateConfigParams{
			ServerIPAddress:      serverIPaddress,
			EnableSSHAPIRequests: true,
			WebServerPort:        8000,
			TunnelProtocolPorts:  map[string]int{"OSSH": 4000},
		})
	if err != nil {
		t.Fatalf("error generating server config: %s", err)
	}

	//
	// pave OSLs
	//

	oslConfigJSONTemplate := `
    {
      "Schemes" : [
        {
          "Epoch" : "%s",
          "Regions" : [],
          "PropagationChannelIDs" : ["%s"],
          "MasterKey" : "vwab2WY3eNyMBpyFVPtsivMxF4MOpNHM/T7rHJIXctg=",
          "SeedSpecs" : [
            {
              "ID" : "KuP2V6gLcROIFzb/27fUVu4SxtEfm2omUoISlrWv1mA=",
              "UpstreamSubnets" : ["0.0.0.0/0"],
              "Targets" :
              {
                  "BytesRead" : 1,
                  "BytesWritten" : 1,
                  "PortForwardDurationNanoseconds" : 1
              }
            }
          ],
          "SeedSpecThreshold" : 1,
          "SeedPeriodNanoseconds" : %d,
          "SeedPeriodKeySplits": [
            {
              "Total": 1,
              "Threshold": 1
            }
          ]
        }
      ]
    }`

	now := time.Now().UTC()
	seedPeriod := 24 * time.Hour
	epoch := now.Truncate(seedPeriod)
	epochStr := epoch.Format(time.RFC3339Nano)

	propagationChannelID, _ := common.MakeRandomStringHex(8)

	oslConfigJSON := fmt.Sprintf(
		oslConfigJSONTemplate,
		epochStr,
		propagationChannelID,
		seedPeriod)

	oslConfig, err := osl.LoadConfig([]byte(oslConfigJSON))
	if err != nil {
		t.Fatalf("error loading OSL config: %s", err)
	}

	signingPublicKey, signingPrivateKey, err := common.GenerateAuthenticatedDataPackageKeys()
	if err != nil {
		t.Fatalf("error generating package keys: %s", err)
	}

	paveFiles, err := oslConfig.Pave(
		epoch,
		propagationChannelID,
		signingPublicKey,
		signingPrivateKey,
		[]map[time.Time]string{
			map[time.Time]string{
				epoch: string(encodedServerEntry),
			},
		})
	if err != nil {
		t.Fatalf("error paving OSL files: %s", err)
	}

	//
	// mock seeding SLOKs
	//

	singleton.db = nil
	os.Remove(DATA_STORE_FILENAME)

	err = InitDataStore(&Config{})
	if err != nil {
		t.Fatalf("error initializing client datastore: %s", err)
	}

	seedState := oslConfig.NewClientSeedState("", propagationChannelID, nil)
	seedPortForward := seedState.NewClientSeedPortForward(net.ParseIP("0.0.0.0"))
	seedPortForward.UpdateProgress(1, 1, 1)
	payload := seedState.GetSeedPayload()
	if len(payload.SLOKs) != 1 {
		t.Fatalf("expected 1 SLOKs, got %d", len(payload.SLOKs))
	}

	SetSLOK(payload.SLOKs[0].ID, payload.SLOKs[0].Key)

	//
	// run mock remote server list host
	//

	downloadRoot := "test-data"
	os.MkdirAll(downloadRoot, 0700)

	remoteServerListHostAddress := net.JoinHostPort(serverIPaddress, "8080")

	// The common remote server list fetches will 404
	remoteServerListURL := fmt.Sprintf("http://%s/server_list_compressed", remoteServerListHostAddress)
	remoteServerListDownloadFilename := filepath.Join(downloadRoot, "server_list_compressed")

	obfuscatedServerListRootURL := fmt.Sprintf("http://%s/", remoteServerListHostAddress)
	obfuscatedServerListDownloadDirectory := downloadRoot

	go func() {
		startTime := time.Now()
		serveMux := http.NewServeMux()
		for _, paveFile := range paveFiles {
			file := paveFile
			serveMux.HandleFunc("/"+file.Name, func(w http.ResponseWriter, req *http.Request) {
				md5sum := md5.Sum(file.Contents)
				w.Header().Add("Content-Type", "application/octet-stream")
				w.Header().Add("ETag", hex.EncodeToString(md5sum[:]))
				http.ServeContent(w, req, file.Name, startTime, bytes.NewReader(file.Contents))
			})
		}
		httpServer := &http.Server{
			Addr:    remoteServerListHostAddress,
			Handler: serveMux,
		}
		err := httpServer.ListenAndServe()
		if err != nil {
			// TODO: wrong goroutine for t.FatalNow()
			t.Fatalf("error running remote server list host: %s", err)

		}
	}()

	//
	// run Psiphon server
	//

	go func() {
		err := server.RunServices(serverConfigJSON)
		if err != nil {
			// TODO: wrong goroutine for t.FatalNow()
			t.Fatalf("error running server: %s", err)
		}
	}()

	//
	// disrupt remote server list downloads
	//

	disruptorProxyAddress := "127.0.0.1:2162"
	disruptorProxyURL := "socks4a://" + disruptorProxyAddress

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
				remoteConn, err := net.Dial("tcp", localConn.Req.Target)
				if err != nil {
					fmt.Errorf("disruptor proxy dial error: %s", err)
					return
				}
				err = localConn.Grant(&net.TCPAddr{IP: net.ParseIP("0.0.0.0"), Port: 0})
				if err != nil {
					fmt.Errorf("disruptor proxy grant error: %s", err)
					return
				}

				waitGroup := new(sync.WaitGroup)
				waitGroup.Add(1)
				go func() {
					defer waitGroup.Done()
					io.Copy(remoteConn, localConn)
				}()
				if localConn.Req.Target == remoteServerListHostAddress {
					io.CopyN(localConn, remoteConn, 500)
				} else {
					io.Copy(localConn, remoteConn)
				}
				localConn.Close()
				remoteConn.Close()
				waitGroup.Wait()
			}()
		}
	}()

	//
	// connect to Psiphon server with Psiphon client
	//

	// Note: calling LoadConfig ensures all *int config fields are initialized
	clientConfigJSONTemplate := `
    {
        "ClientPlatform" : "",
        "ClientVersion" : "0",
        "SponsorId" : "0",
        "PropagationChannelId" : "0",
        "ConnectionPoolSize" : 1,
        "EstablishTunnelPausePeriodSeconds" : 1,
        "FetchRemoteServerListRetryPeriodSeconds" : 1,
		"RemoteServerListSignaturePublicKey" : "%s",
		"RemoteServerListUrl" : "%s",
		"RemoteServerListDownloadFilename" : "%s",
		"ObfuscatedServerListRootURL" : "%s",
		"ObfuscatedServerListDownloadDirectory" : "%s",
		"UpstreamProxyUrl" : "%s"
    }`

	clientConfigJSON := fmt.Sprintf(
		clientConfigJSONTemplate,
		signingPublicKey,
		remoteServerListURL,
		remoteServerListDownloadFilename,
		obfuscatedServerListRootURL,
		obfuscatedServerListDownloadDirectory,
		disruptorProxyURL)

	clientConfig, _ := LoadConfig([]byte(clientConfigJSON))

	controller, err := NewController(clientConfig)
	if err != nil {
		t.Fatalf("error creating client controller: %s", err)
	}

	tunnelEstablished := make(chan struct{}, 1)

	SetNoticeOutput(NewNoticeReceiver(
		func(notice []byte) {

			noticeType, payload, err := GetNotice(notice)
			if err != nil {
				return
			}

			printNotice := false

			switch noticeType {
			case "Tunnels":
				printNotice = true
				count := int(payload["count"].(float64))
				if count == 1 {
					tunnelEstablished <- *new(struct{})
				}
			case "RemoteServerListResourceDownloadedBytes":
				// TODO: check for resumed download for each URL
				//url := payload["url"].(string)
				printNotice = true
			case "RemoteServerListResourceDownloaded":
				printNotice = true
			}

			if printNotice {
				fmt.Printf("%s\n", string(notice))
			}
		}))

	go func() {
		controller.Run(make(chan struct{}))
	}()

	establishTimeout := time.NewTimer(30 * time.Second)
	select {
	case <-tunnelEstablished:
	case <-establishTimeout.C:
		t.Fatalf("tunnel establish timeout exceeded")
	}
}
