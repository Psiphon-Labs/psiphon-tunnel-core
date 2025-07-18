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
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
)

func TestDuplicateSessionID(t *testing.T) {

	testDataDirName, err := ioutil.TempDir("", "psiphond-duplicate-session-id-test")
	if err != nil {
		t.Fatalf("TempDir failed: %s", err)
	}
	defer os.RemoveAll(testDataDirName)

	psiphon.SetEmitDiagnosticNotices(true, true)

	// Configure server

	generateConfigParams := &GenerateConfigParams{
		ServerIPAddress:     "127.0.0.1",
		TunnelProtocolPorts: map[string]int{"OSSH": 4000},
	}

	serverConfigJSON, _, _, _, encodedServerEntry, err := GenerateConfig(generateConfigParams)
	if err != nil {
		t.Fatalf("error generating server config: %s", err)
	}

	var serverConfig map[string]interface{}
	json.Unmarshal(serverConfigJSON, &serverConfig)

	serverConfig["LogFilename"] = filepath.Join(testDataDirName, "psiphond.log")
	serverConfig["LogLevel"] = "debug"

	serverConfigJSON, _ = json.Marshal(serverConfig)

	numConcurrentClients := 50

	stoppingEvent := "stopping existing client with duplicate session ID"
	abortingEvent := "aborting new client with duplicate session ID"

	// Sufficiently buffer channel so log callback handler doesn't cause server
	// operations to block while handling concurrent clients.
	duplicateSessionIDEvents := make(chan string, numConcurrentClients)

	setLogCallback(func(log []byte) {
		strLog := string(log)
		var event string
		if strings.Contains(strLog, stoppingEvent) {
			event = stoppingEvent
		} else if strings.Contains(strLog, abortingEvent) {
			event = abortingEvent
		}
		if event != "" {
			select {
			case duplicateSessionIDEvents <- event:
			default:
			}
		}

	})

	// Run server

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

	// Initialize tunnel clients. Bypassing Controller and using Tunnel directly
	// to permit multiple concurrent clients.
	//
	// Limitation: all tunnels still use one singleton datastore and notice
	// handler.

	err = psiphon.SetNoticeWriter(io.Discard)
	if err != nil {
		t.Fatalf("error setting notice writer: %s", err)
	}
	defer psiphon.ResetNoticeWriter()

	clientConfigJSONTemplate := `
    {
        "DataRootDirectory" : "%s",
        "SponsorId" : "0000000000000000",
        "PropagationChannelId" : "0000000000000000",
        "SessionID" : "00000000000000000000000000000000"
    }`

	clientConfigJSON := fmt.Sprintf(
		clientConfigJSONTemplate,
		testDataDirName)

	clientConfig, err := psiphon.LoadConfig([]byte(clientConfigJSON))
	if err != nil {
		t.Fatalf("LoadConfig failed: %s", err)
	}
	err = clientConfig.Commit(false)
	if err != nil {
		t.Fatalf("Commit failed: %s", err)
	}

	resolver := psiphon.NewResolver(clientConfig, true)
	defer resolver.Stop()
	clientConfig.SetResolver(resolver)

	err = psiphon.OpenDataStore(clientConfig)
	if err != nil {
		t.Fatalf("OpenDataStore failed: %s", err)
	}
	defer psiphon.CloseDataStore()

	serverEntry, err := protocol.DecodeServerEntry(
		string(encodedServerEntry),
		common.GetCurrentTimestamp(),
		protocol.SERVER_ENTRY_SOURCE_EMBEDDED)
	if err != nil {
		t.Fatalf("DecodeServerEntry failed: %s", err)
	}

	dialTunnel := func(ctx context.Context) *psiphon.Tunnel {

		dialParams, err := psiphon.MakeDialParameters(
			clientConfig,
			nil,
			nil,
			nil,
			nil,
			func(_ *protocol.ServerEntry, _ string) bool { return false },
			func(_ *protocol.ServerEntry) (string, bool) { return "OSSH", true },
			serverEntry,
			nil,
			nil,
			false,
			0,
			0)
		if err != nil {
			t.Fatalf("MakeDialParameters failed: %s", err)
		}

		tunnel, err := psiphon.ConnectTunnel(
			ctx,
			clientConfig,
			time.Now(),
			dialParams)
		if err != nil {
			t.Fatalf("ConnectTunnel failed: %s", err)
		}

		return tunnel
	}

	handshakeTunnel := func(tunnel *psiphon.Tunnel, expectSuccess bool) {

		_, err = psiphon.NewServerContext(tunnel)

		if expectSuccess && err != nil || (!expectSuccess && err == nil) {
			t.Fatalf("Unexpected handshake result: %s", err)
		}
	}

	ctx, cancelFunc := context.WithCancel(context.Background())
	defer cancelFunc()

	// Test: normal case
	//
	// First tunnel, t1, fully establishes and then is superceded by new tunnel, t2.

	t1 := dialTunnel(ctx)

	handshakeTunnel(t1, true)

	t2 := dialTunnel(ctx)

	expectEvent := <-duplicateSessionIDEvents

	if expectEvent != stoppingEvent {
		t.Fatalf("Unexpected duplicate session ID event")
	}

	handshakeTunnel(t2, true)

	t1.Close(true)
	t2.Close(true)

	// Test: simultaneous/interleaved case
	//
	// First tunnel connects but then tries to handshake after second tunnel has
	// connected.

	t1 = dialTunnel(ctx)

	// TODO: await log confirmation that t1 completed registerEstablishedClient?
	// Otherwise, there's some small chance that t2 is the "first" tunnel and the
	// test could fail (false negative).

	t2 = dialTunnel(ctx)

	expectEvent = <-duplicateSessionIDEvents

	if expectEvent != stoppingEvent {
		t.Fatalf("Unexpected duplicate session ID event")
	}

	handshakeTunnel(t1, false)

	handshakeTunnel(t2, true)

	t1.Close(true)
	t2.Close(true)

	// Test: 50 concurrent clients, all with the same session ID.
	//
	// This should be enough concurrent clients to trigger both the "stopping"
	// and "aborting" duplicate session ID cases.

	tunnels := make([]*psiphon.Tunnel, numConcurrentClients)

	waitGroup := new(sync.WaitGroup)
	for i := 0; i < numConcurrentClients; i++ {
		waitGroup.Add(1)
		go func(i int) {
			defer waitGroup.Done()
			tunnels[i] = dialTunnel(ctx)
		}(i)
	}
	waitGroup.Wait()

	for _, t := range tunnels {
		if t == nil {
			continue
		}
		t.Close(true)
	}

	receivedEvents := make(map[string]int)
	for i := 0; i < numConcurrentClients-1; i++ {
		receivedEvents[<-duplicateSessionIDEvents] += 1
	}

	if receivedEvents[stoppingEvent] < 1 {
		t.Fatalf("No stopping events received")
	}

	if receivedEvents[abortingEvent] < 1 {
		t.Fatalf("No aborting events received")
	}
}
