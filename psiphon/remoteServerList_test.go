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
	"context"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	socks "github.com/Psiphon-Inc/goptlib"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/osl"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/server"
)

// TODO: TestCommonRemoteServerList (this is currently covered by controller_test.go)

func TestObfuscatedRemoteServerLists(t *testing.T) {
	testObfuscatedRemoteServerLists(t, false)
}

func TestObfuscatedRemoteServerListsOmitMD5Sums(t *testing.T) {
	testObfuscatedRemoteServerLists(t, true)
}

func testObfuscatedRemoteServerLists(t *testing.T, omitMD5Sums bool) {

	testDataDirName, err := ioutil.TempDir("", "psiphon-remote-server-list-test")
	if err != nil {
		t.Fatalf("TempDir failed: %s", err)
	}
	defer os.RemoveAll(testDataDirName)

	//
	// create a server
	//

	serverIPAddress := ""
	for _, interfaceName := range []string{"eth0", "en0"} {
		var serverIPv4Address, serverIPv6Address net.IP
		serverIPv4Address, serverIPv6Address, err = common.GetInterfaceIPAddresses(interfaceName)
		if err == nil {
			if serverIPv4Address != nil {
				serverIPAddress = serverIPv4Address.String()
			} else {
				serverIPAddress = serverIPv6Address.String()
			}
			break
		}
	}
	if err != nil {
		t.Fatalf("error getting server IP address: %s", err)
	}

	serverConfigJSON, _, encodedServerEntry, err := server.GenerateConfig(
		&server.GenerateConfigParams{
			ServerIPAddress:      serverIPAddress,
			EnableSSHAPIRequests: true,
			WebServerPort:        8001,
			TunnelProtocolPorts:  map[string]int{"OSSH": 4001},
			LogFilename:          filepath.Join(testDataDirName, "psiphond.log"),
			LogLevel:             "debug",

			// "defer os.RemoveAll" will cause a log write error
			SkipPanickingLogWriter: true,
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

	var omitMD5SumsSchemes []int
	if omitMD5Sums {
		omitMD5SumsSchemes = []int{0}
	}
	omitEmptyOSLsSchemes := []int{0}

	// First Pave() call is to get the OSL ID to pave into

	oslID := ""

	paveFiles, err := oslConfig.Pave(
		epoch,
		propagationChannelID,
		signingPublicKey,
		signingPrivateKey,
		map[string][]string{},
		omitMD5SumsSchemes,
		omitEmptyOSLsSchemes,
		func(logInfo *osl.PaveLogInfo) {
			oslID = logInfo.OSLID
		})
	if err != nil {
		t.Fatalf("error paving OSL files: %s", err)
	}

	paveFiles, err = oslConfig.Pave(
		epoch,
		propagationChannelID,
		signingPublicKey,
		signingPrivateKey,
		map[string][]string{
			oslID: {string(encodedServerEntry)},
		},
		omitMD5SumsSchemes,
		omitEmptyOSLsSchemes,
		nil)
	if err != nil {
		t.Fatalf("error paving OSL files: %s", err)
	}

	//
	// mock seeding SLOKs
	//

	singleton = dataStore{}
	os.Remove(filepath.Join(testDataDirName, DATA_STORE_FILENAME))

	err = InitDataStore(&Config{DataStoreDirectory: testDataDirName})
	if err != nil {
		t.Fatalf("error initializing client datastore: %s", err)
	}

	if CountServerEntries("", "") > 0 {
		t.Fatalf("unexpected server entries")
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

	// Exercise using multiple download URLs

	var remoteServerListListeners [2]net.Listener
	var remoteServerListHostAddresses [2]string

	for i := 0; i < len(remoteServerListListeners); i++ {
		remoteServerListListeners[i], err = net.Listen("tcp", net.JoinHostPort(serverIPAddress, "0"))
		if err != nil {
			t.Fatalf("net.Listen error: %s", err)
		}
		defer remoteServerListListeners[i].Close()
		remoteServerListHostAddresses[i] = remoteServerListListeners[i].Addr().String()
	}

	// The common remote server list fetches will 404
	remoteServerListURL := fmt.Sprintf("http://%s/server_list_compressed", remoteServerListHostAddresses[0])
	remoteServerListDownloadFilename := filepath.Join(testDataDirName, "server_list_compressed")

	obfuscatedServerListRootURLsJSONConfig := "["
	obfuscatedServerListRootURLs := make([]string, len(remoteServerListHostAddresses))
	for i := 0; i < len(remoteServerListHostAddresses); i++ {

		obfuscatedServerListRootURLs[i] = fmt.Sprintf("http://%s/", remoteServerListHostAddresses[i])

		obfuscatedServerListRootURLsJSONConfig += fmt.Sprintf(
			"{\"URL\" : \"%s\"}", base64.StdEncoding.EncodeToString([]byte(obfuscatedServerListRootURLs[i])))
		if i == len(remoteServerListHostAddresses)-1 {
			obfuscatedServerListRootURLsJSONConfig += "]"
		} else {
			obfuscatedServerListRootURLsJSONConfig += ","
		}

		go func(listener net.Listener, remoteServerListHostAddress string) {
			startTime := time.Now()
			serveMux := http.NewServeMux()
			for _, paveFile := range paveFiles {
				file := paveFile
				serveMux.HandleFunc("/"+file.Name, func(w http.ResponseWriter, req *http.Request) {
					md5sum := md5.Sum(file.Contents)
					w.Header().Add("Content-Type", "application/octet-stream")
					w.Header().Add("ETag", fmt.Sprintf("\"%s\"", hex.EncodeToString(md5sum[:])))
					http.ServeContent(w, req, file.Name, startTime, bytes.NewReader(file.Contents))
				})
			}
			httpServer := &http.Server{
				Addr:    remoteServerListHostAddress,
				Handler: serveMux,
			}
			httpServer.Serve(listener)
		}(remoteServerListListeners[i], remoteServerListHostAddresses[i])
	}

	obfuscatedServerListDownloadDirectory := testDataDirName

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

	process, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatalf("os.FindProcess error: %s", err)
	}
	defer process.Signal(syscall.SIGTERM)

	//
	// disrupt remote server list downloads
	//

	disruptorListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen error: %s", err)
	}
	defer disruptorListener.Close()

	disruptorProxyAddress := disruptorListener.Addr().String()
	disruptorProxyURL := "socks4a://" + disruptorProxyAddress

	go func() {
		listener := socks.NewSocksListener(disruptorListener)
		for {
			localConn, err := listener.AcceptSocks()
			if err != nil {
				fmt.Printf("disruptor proxy accept error: %s\n", err)
				return
			}
			go func() {
				remoteConn, err := net.Dial("tcp", localConn.Req.Target)
				if err != nil {
					fmt.Printf("disruptor proxy dial error: %s\n", err)
					return
				}
				err = localConn.Grant(&net.TCPAddr{IP: net.ParseIP("0.0.0.0"), Port: 0})
				if err != nil {
					fmt.Printf("disruptor proxy grant error: %s\n", err)
					return
				}

				waitGroup := new(sync.WaitGroup)
				waitGroup.Add(1)
				go func() {
					defer waitGroup.Done()
					io.Copy(remoteConn, localConn)
				}()
				if common.Contains(remoteServerListHostAddresses[:], localConn.Req.Target) {
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

	SetEmitDiagnosticNotices(true)

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
		"ObfuscatedServerListRootURLs" : %s,
		"ObfuscatedServerListDownloadDirectory" : "%s",
		"UpstreamProxyUrl" : "%s"
    }`

	clientConfigJSON := fmt.Sprintf(
		clientConfigJSONTemplate,
		signingPublicKey,
		remoteServerListURL,
		remoteServerListDownloadFilename,
		obfuscatedServerListRootURLsJSONConfig,
		obfuscatedServerListDownloadDirectory,
		disruptorProxyURL)

	clientConfig, _ := LoadConfig([]byte(clientConfigJSON))

	controller, err := NewController(clientConfig)
	if err != nil {
		t.Fatalf("error creating client controller: %s", err)
	}

	tunnelEstablished := make(chan struct{}, 1)

	SetNoticeWriter(NewNoticeReceiver(
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
				//printNotice = true
				printNotice = false
			case "RemoteServerListResourceDownloaded":
				printNotice = true
			}

			if printNotice {
				fmt.Printf("%s\n", string(notice))
			}
		}))

	ctx, cancelFunc := context.WithCancel(context.Background())
	defer cancelFunc()

	go func() {
		controller.Run(ctx)
	}()

	establishTimeout := time.NewTimer(30 * time.Second)
	select {
	case <-tunnelEstablished:
	case <-establishTimeout.C:
		t.Fatalf("tunnel establish timeout exceeded")
	}

	for _, paveFile := range paveFiles {
		u, _ := url.Parse(obfuscatedServerListRootURLs[0])
		u.Path = path.Join(u.Path, paveFile.Name)
		etag, _ := GetUrlETag(u.String())
		md5sum := md5.Sum(paveFile.Contents)
		if etag != fmt.Sprintf("\"%s\"", hex.EncodeToString(md5sum[:])) {
			t.Fatalf("unexpected ETag for %s", u)
		}
	}
}
