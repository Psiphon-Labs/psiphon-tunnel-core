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
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/tactics"
)

func TestServerFragmentorReplay(t *testing.T) {
	runServerReplayTests(t, false)
}

func runServerReplayTests(t *testing.T, runPacketManipulation bool) {

	// Do not use OSSH, which has a different fragmentor replay mechanism. Meek
	// has a unique code path for passing around replay parameters and metrics.
	testCases := protocol.TunnelProtocols{
		protocol.TUNNEL_PROTOCOL_SSH,
		protocol.TUNNEL_PROTOCOL_UNFRONTED_MEEK,
	}

	for _, tunnelProtocol := range testCases {
		t.Run(tunnelProtocol, func(t *testing.T) {
			runServerReplayTest(t, runPacketManipulation, tunnelProtocol)
		})
	}
}

func runServerReplayTest(
	t *testing.T,
	runPacketManipulation bool,
	tunnelProtocol string) {

	psiphon.SetEmitDiagnosticNotices(true, true)

	// Configure tactics

	tacticsConfigJSONFormat := `
    {
      "RequestPublicKey" : "%s",
      "RequestPrivateKey" : "%s",
      "RequestObfuscatedKey" : "%s",
      "DefaultTactics" : {
        "TTL" : "60s",
        "Probability" : 1.0,
        "Parameters" : {
          "LimitTunnelProtocols" : ["%s"],
          "FragmentorDownstreamLimitProtocols" : ["%s"],
          "FragmentorDownstreamProbability" : 1.0,
          "FragmentorDownstreamMinTotalBytes" : 10,
          "FragmentorDownstreamMaxTotalBytes" : 10,
          "FragmentorDownstreamMinWriteBytes" : 1,
          "FragmentorDownstreamMaxWriteBytes" : 1,
          "FragmentorDownstreamMinDelay" : "1ms",
          "FragmentorDownstreamMaxDelay" : "1ms",
          "ServerPacketManipulationSpecs" : [{"Name": "test-packetman-spec", "PacketSpecs": [[]]}],
          "ServerPacketManipulationProbability" : 1.0,
          "ServerProtocolPacketManipulations": {"%s" : ["test-packetman-spec"]},
          "ServerReplayPacketManipulation" : true,
          "ServerReplayFragmentor" : true,
          "ServerReplayUnknownGeoIP" : true,
          "ServerReplayTTL" : "5s",
          "ServerReplayTargetWaitDuration" : "200ms",
          "ServerReplayTargetTunnelDuration" : "50ms",
          "ServerReplayTargetUpstreamBytes" : 0,
          "ServerReplayTargetDownstreamBytes" : 0,
          "ServerReplayFailedCountThreshold" : 1,
          "ServerReplayFailedCountThreshold" : 1
        }
      }
    }
    `

	tacticsRequestPublicKey, tacticsRequestPrivateKey, tacticsRequestObfuscatedKey, err :=
		tactics.GenerateKeys()
	if err != nil {
		t.Fatalf("error generating tactics keys: %s", err)
	}

	tacticsConfigJSON := fmt.Sprintf(
		tacticsConfigJSONFormat,
		tacticsRequestPublicKey, tacticsRequestPrivateKey, tacticsRequestObfuscatedKey,
		tunnelProtocol, tunnelProtocol, tunnelProtocol)

	tacticsConfigFilename := filepath.Join(testDataDirName, "tactics_config.json")

	err = ioutil.WriteFile(tacticsConfigFilename, []byte(tacticsConfigJSON), 0600)
	if err != nil {
		t.Fatalf("error paving tactics config file: %s", err)
	}

	// Run Psiphon server

	generateConfigParams := &GenerateConfigParams{
		ServerIPAddress:     "127.0.0.1",
		TunnelProtocolPorts: map[string]int{tunnelProtocol: 4000},
	}

	serverConfigJSON, _, _, _, encodedServerEntry, err := GenerateConfig(generateConfigParams)
	if err != nil {
		t.Fatalf("error generating server config: %s", err)
	}

	var serverConfig map[string]interface{}
	json.Unmarshal(serverConfigJSON, &serverConfig)

	serverConfig["LogFilename"] = filepath.Join(testDataDirName, "psiphond.log")
	serverConfig["LogLevel"] = "debug"
	serverConfig["TacticsConfigFilename"] = tacticsConfigFilename

	// Ensure server_tunnels emit quickly.
	serverConfig["MeekMaxSessionStalenessMilliseconds"] = 500

	if runPacketManipulation {
		serverConfig["RunPacketManipulator"] = true
	}

	serverConfigJSON, _ = json.Marshal(serverConfig)

	serverTunnelLog := make(chan map[string]interface{}, 1)

	setLogCallback(func(log []byte) {
		logFields := make(map[string]interface{})
		err := json.Unmarshal(log, &logFields)
		if err != nil {
			return
		}
		if logFields["event_name"] == nil {
			return
		}
		if logFields["event_name"].(string) == "server_tunnel" {
			select {
			case serverTunnelLog <- logFields:
			default:
			}
		}
	})

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

	checkServerTunnelLog := func(expectReplay bool) {

		// Numbers are float64 due to JSON decoding.
		expectedServerTunnelFields := map[string]interface{}{
			"downstream_bytes_fragmented":       float64(10),
			"downstream_min_bytes_written":      float64(1),
			"downstream_max_bytes_written":      float64(1),
			"downstream_min_delayed":            float64(1000),
			"downstream_max_delayed":            float64(1000),
			"server_replay_fragmentation":       expectReplay,
			"server_replay_packet_manipulation": expectReplay && runPacketManipulation,
		}
		if runPacketManipulation {
			expectedServerTunnelFields["server_packet_manipulation"] = "test-packetman-spec"
		}

		logFields := <-serverTunnelLog

		for name, value := range expectedServerTunnelFields {
			logValue, ok := logFields[name]
			if !ok {
				t.Fatalf("Missing expected server_tunnel field: %s", name)
			}
			if !reflect.DeepEqual(logValue, value) {
				t.Fatalf(
					"Unexpected server_tunnel %s value: got %T(%v); expected %T(%v)",
					name, logValue, logValue, value, value)
			}
		}
	}

	t.Log("first client run; no replay")

	runServerReplayClient(t, encodedServerEntry, true)
	checkServerTunnelLog(false)

	t.Log("second client run; is replay")

	runServerReplayClient(t, encodedServerEntry, true)
	checkServerTunnelLog(true)

	t.Log("TTL expires; no replay")

	// Wait until TTL expires.
	time.Sleep(5100 * time.Millisecond)

	runServerReplayClient(t, encodedServerEntry, true)
	checkServerTunnelLog(false)

	t.Log("failure clears replay; no replay")

	runServerReplayClient(t, encodedServerEntry, true)
	checkServerTunnelLog(true)

	runServerReplayClient(t, encodedServerEntry, false)
	// No server_tunnel for SSH handshake failure.

	// Wait for session to be retired, which will trigger replay failure.
	if protocol.TunnelProtocolUsesMeek(tunnelProtocol) {
		time.Sleep(1000 * time.Millisecond)
	}

	runServerReplayClient(t, encodedServerEntry, true)
	checkServerTunnelLog(false)
}

func runServerReplayClient(
	t *testing.T,
	encodedServerEntry []byte,
	handshakeSuccess bool) {

	if !handshakeSuccess {
		serverEntry, err := protocol.DecodeServerEntry(string(encodedServerEntry), "", "")
		if err != nil {
			t.Fatalf("error decoding server entry: %s", err)
		}
		serverEntry.SshPassword = ""
		encodedServerEntryStr, err := protocol.EncodeServerEntry(serverEntry)
		if err != nil {
			t.Fatalf("error encoding server entry: %s", err)
		}
		encodedServerEntry = []byte(encodedServerEntryStr)
	}

	dataRootDir, err := ioutil.TempDir(testDataDirName, "serverReplayClient")
	if err != nil {
		t.Fatalf("error createing temp dir: %s", err)
	}
	defer os.RemoveAll(dataRootDir)

	clientConfigJSON := fmt.Sprintf(`
    {
        "DataRootDirectory" : "%s",
        "ClientPlatform" : "Windows",
        "ClientVersion" : "0",
        "SponsorId" : "0000000000000000",
        "PropagationChannelId" : "0000000000000000",
        "TargetServerEntry" : "%s"
    }`, dataRootDir, string(encodedServerEntry))

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

	if handshakeSuccess {
		<-tunnelEstablished
	}

	// Meet tunnel duration critera.
	for i := 0; i < 20; i++ {
		time.Sleep(10 * time.Millisecond)
		_, _ = controller.Dial("127.0.0.1:80", nil)
	}

	cancelFunc()
	controllerWaitGroup.Wait()
}
