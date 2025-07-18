/*
 * Copyright (c) 2018, Psiphon Inc.
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
	"os"
	"sync"
	"testing"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/parameters"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/server"
)

func TestLimitTunnelProtocols(t *testing.T) {

	testDataDirName, err := ioutil.TempDir("", "psiphon-limit-tunnel-protocols-test")
	if err != nil {
		t.Fatalf("TempDir failed: %s", err)
	}
	defer os.RemoveAll(testDataDirName)

	initialLimitTunnelProtocols := protocol.TunnelProtocols{"OSSH", "UNFRONTED-MEEK-HTTPS-OSSH"}
	initialLimitTunnelProtocolsCandidateCount := 100
	limitTunnelProtocols := protocol.TunnelProtocols{"SSH", "UNFRONTED-MEEK-OSSH"}

	initialConnectingCount := 0
	connectingCount := 0

	err = SetNoticeWriter(NewNoticeReceiver(
		func(notice []byte) {
			noticeType, payload, err := GetNotice(notice)
			if err != nil {
				return
			}

			if noticeType == "ConnectingServer" {

				connectingCount += 1

				protocolField := payload["protocol"]
				protocol := protocolField.(string)

				if common.Contains(initialLimitTunnelProtocols, protocol) {
					initialConnectingCount += 1
				}

				if common.Contains(limitTunnelProtocols, protocol) {
					connectingCount += 1
				}

				// At the end of the InitialLimit phase, the order of
				// ConnectingServer notices isn't strictly synchronized and
				// it's possible for a Limit candidate ConnectingServer notice
				// to arrive before the last InitialLimit notice. So strict
				// checking of notice order is performed only up to 90% of
				// InitialLimitTunnelProtocolsCandidateCount.

				if initialConnectingCount <= (initialLimitTunnelProtocolsCandidateCount*9)/10 {

					var expectedProtocols []string
					if connectingCount <= initialLimitTunnelProtocolsCandidateCount {
						expectedProtocols = initialLimitTunnelProtocols
					} else {
						expectedProtocols = limitTunnelProtocols
					}

					if !common.Contains(expectedProtocols, protocol) {
						t.Fatalf("unexpected protocol: %s (%d %+v)", protocol, connectingCount, expectedProtocols)
					}
				}
			}
		}))
	if err != nil {
		t.Fatalf("error setting notice writer: %s", err)
	}
	defer ResetNoticeWriter()

	clientConfigJSON := `
    {
        "ClientPlatform" : "Windows",
        "ClientVersion" : "0",
        "SponsorId" : "0000000000000000",
        "PropagationChannelId" : "0000000000000000",
        "DisableRemoteServerListFetcher" : true
    }`
	clientConfig, err := LoadConfig([]byte(clientConfigJSON))
	if err != nil {
		t.Fatalf("error processing configuration file: %s", err)
	}

	clientConfig.DataRootDirectory = testDataDirName

	err = clientConfig.Commit(false)
	if err != nil {
		t.Fatalf("error committing configuration file: %s", err)
	}

	applyParameters := make(map[string]interface{})

	applyParameters[parameters.ConnectionWorkerPoolSize] = initialLimitTunnelProtocolsCandidateCount / 2
	applyParameters[parameters.LimitIntensiveConnectionWorkers] = initialLimitTunnelProtocolsCandidateCount / 4
	applyParameters[parameters.TunnelConnectTimeout] = "1s"
	applyParameters[parameters.EstablishTunnelPausePeriod] = "1s"
	applyParameters[parameters.InitialLimitTunnelProtocols] = initialLimitTunnelProtocols
	applyParameters[parameters.InitialLimitTunnelProtocolsCandidateCount] = initialLimitTunnelProtocolsCandidateCount
	applyParameters[parameters.LimitTunnelProtocols] = limitTunnelProtocols

	err = clientConfig.SetParameters("", true, applyParameters)
	if err != nil {
		t.Fatalf("error setting client parameters: %s", err)
	}

	err = OpenDataStore(clientConfig)
	if err != nil {
		t.Fatalf("error initializing client datastore: %s", err)
	}
	defer CloseDataStore()

	if CountServerEntries() > 0 {
		t.Fatalf("unexpected server entries")
	}

	serverEntries := make([]map[string]interface{}, len(protocol.SupportedTunnelProtocols))

	for i, tunnelProtocol := range protocol.SupportedTunnelProtocols {

		_, _, _, _, encodedServerEntry, err := server.GenerateConfig(
			&server.GenerateConfigParams{
				ServerIPAddress:     fmt.Sprintf("0.1.0.0"),
				TunnelProtocolPorts: map[string]int{tunnelProtocol: 4000},
			})
		if err != nil {
			t.Fatalf("error generating server config: %s", err)
		}

		serverEntryFields, err := protocol.DecodeServerEntryFields(
			string(encodedServerEntry),
			common.GetCurrentTimestamp(),
			protocol.SERVER_ENTRY_SOURCE_REMOTE)
		if err != nil {
			t.Fatalf("error decoding server entry: %s", err)
		}

		serverEntries[i] = serverEntryFields
	}

	for i := 0; i < 1000; i++ {

		serverEntryFields := serverEntries[i%len(protocol.SupportedTunnelProtocols)]

		serverEntryFields["ipAddress"] = fmt.Sprintf("0.1.%d.%d", (i>>8)&0xFF, i&0xFF)

		err = StoreServerEntry(serverEntryFields, true)
		if err != nil {
			t.Fatalf("error storing server entry: %s", err)
		}
	}

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

	time.Sleep(10 * time.Second)

	cancelFunc()

	controllerWaitGroup.Wait()

	t.Logf("initial-connecting and connecting count: %d/%d", initialConnectingCount, connectingCount)

	if initialConnectingCount != initialLimitTunnelProtocolsCandidateCount {
		t.Fatalf("unexpected initial-connecting count")
	}

	if connectingCount < 3*initialLimitTunnelProtocolsCandidateCount {
		t.Fatalf("unexpected connecting count")
	}
}
