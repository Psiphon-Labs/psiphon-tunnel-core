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

package memory_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/parameters"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
)

// memory_test is a memory stress test suite that repeatedly reestablishes
// tunnels and restarts the Controller.
//
// runtime.MemStats is used to monitor system memory usage during the test.
//
// These tests are in its own package as its runtime.MemStats checks must not
// be impacted by other test runs. For the same reason, this test doesn't run
// a mock server.
//
// This test is also long-running and _may_ require setting the test flag
// "-timeout" beyond the default of 10 minutes (check the testDuration
// configured below). Update: testDuration is now reduced from 5 to 2 minutes
// since too many iterations -- reconnections -- will impact the ability of
// the client to access the network. Manually adjust testDuration to run a
// tougher stress test.
//
// For the most accurate memory reporting, run each test individually; e.g.,
// go test -run [TestReconnectTunnel|TestRestartController|etc.]

const (
	testModeReconnectTunnel = iota
	testModeRestartController
	testModeReconnectAndRestart
)

func TestReconnectTunnel(t *testing.T) {
	runMemoryTest(t, testModeReconnectTunnel)
}

func TestRestartController(t *testing.T) {
	runMemoryTest(t, testModeRestartController)
}

func TestReconnectAndRestart(t *testing.T) {
	runMemoryTest(t, testModeReconnectAndRestart)
}

func runMemoryTest(t *testing.T, testMode int) {

	testDataDirName, err := ioutil.TempDir("", "psiphon-memory-test")
	if err != nil {
		fmt.Printf("TempDir failed: %s\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(testDataDirName)

	psiphon.SetEmitDiagnosticNotices(true, true)

	configJSON, err := ioutil.ReadFile("../controller_test.config")
	if err != nil {
		// Skip, don't fail, if config file is not present
		t.Skipf("error loading configuration file: %s", err)
	}

	// Most of these fields _must_ be filled in before calling LoadConfig,
	// so that they are correctly set into client parameters.
	var modifyConfig map[string]interface{}
	err = json.Unmarshal(configJSON, &modifyConfig)
	if err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	modifyConfig["ClientVersion"] = "999999999"
	modifyConfig["TunnelPoolSize"] = 1
	modifyConfig["DataRootDirectory"] = testDataDirName
	modifyConfig["FetchRemoteServerListRetryPeriodMilliseconds"] = 250
	modifyConfig["EstablishTunnelPausePeriodSeconds"] = 1
	modifyConfig["ConnectionWorkerPoolSize"] = 10
	modifyConfig["DisableLocalSocksProxy"] = true
	modifyConfig["DisableLocalHTTPProxy"] = true
	modifyConfig["LimitIntensiveConnectionWorkers"] = 2
	modifyConfig["LimitMeekBufferSizes"] = true
	modifyConfig["StaggerConnectionWorkersMilliseconds"] = 100
	modifyConfig["IgnoreHandshakeStatsRegexps"] = true

	configJSON, _ = json.Marshal(modifyConfig)

	config, err := psiphon.LoadConfig(configJSON)
	if err != nil {
		t.Fatalf("error processing configuration file: %s", err)
	}
	err = config.Commit(false)
	if err != nil {
		t.Fatalf("error committing configuration file: %s", err)
	}

	// Don't wait for a tactics request.
	applyParameters := map[string]interface{}{
		parameters.TacticsWaitPeriod: "1ms",
	}
	err = config.SetParameters("", true, applyParameters)
	if err != nil {
		t.Fatalf("SetParameters failed: %s", err)
	}

	err = psiphon.OpenDataStore(config)
	if err != nil {
		t.Fatalf("error initializing datastore: %s", err)
	}
	defer psiphon.CloseDataStore()

	var controller *psiphon.Controller
	var controllerCtx context.Context
	var controllerStopRunning context.CancelFunc
	var controllerWaitGroup *sync.WaitGroup
	restartController := make(chan bool, 1)
	reconnectTunnel := make(chan bool, 1)
	tunnelsEstablished := int32(0)

	postActiveTunnelTerminateDelay := 250 * time.Millisecond
	testDuration := 2 * time.Minute
	memInspectionFrequency := 10 * time.Second
	maxInuseBytes := uint64(10 * 1024 * 1024)

	err = psiphon.SetNoticeWriter(psiphon.NewNoticeReceiver(
		func(notice []byte) {
			noticeType, payload, err := psiphon.GetNotice(notice)
			if err != nil {
				return
			}

			switch noticeType {
			case "Tunnels":
				count := int(payload["count"].(float64))
				if count > 0 {
					atomic.AddInt32(&tunnelsEstablished, 1)

					time.Sleep(postActiveTunnelTerminateDelay)

					doRestartController := (testMode == testModeRestartController)
					if testMode == testModeReconnectAndRestart {
						doRestartController = prng.FlipCoin()
					}
					if doRestartController {
						select {
						case restartController <- true:
						default:
						}
					} else {
						select {
						case reconnectTunnel <- true:
						default:
						}
					}
				}
			case "Info":
				message := payload["message"].(string)
				if strings.Contains(message, "peak concurrent establish tunnels") {
					fmt.Printf("%s, ", message)
				} else if strings.Contains(message, "peak concurrent meek establish tunnels") {
					fmt.Printf("%s\n", message)
				}
			}
		}))
	if err != nil {
		t.Fatalf("error setting notice writer: %s", err)
	}
	defer psiphon.ResetNoticeWriter()

	startController := func() {
		controller, err = psiphon.NewController(config)
		if err != nil {
			t.Fatalf("error creating controller: %s", err)
		}

		controllerCtx, controllerStopRunning = context.WithCancel(context.Background())
		controllerWaitGroup = new(sync.WaitGroup)

		controllerWaitGroup.Add(1)
		go func() {
			defer controllerWaitGroup.Done()
			controller.Run(controllerCtx)
		}()
	}

	stopController := func() {
		controllerStopRunning()
		controllerWaitGroup.Wait()
	}

	testTimer := time.NewTimer(testDuration)
	defer testTimer.Stop()
	memInspectionTicker := time.NewTicker(memInspectionFrequency)
	lastTunnelsEstablished := int32(0)

	startController()

test_loop:
	for {
		select {

		case <-testTimer.C:
			break test_loop

		case <-memInspectionTicker.C:
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			inuseBytes := m.HeapInuse + m.StackInuse + m.MSpanInuse + m.MCacheInuse
			if inuseBytes > maxInuseBytes {
				t.Fatalf("MemStats.*Inuse bytes exceeds limit: %d", inuseBytes)
			} else {
				n := atomic.LoadInt32(&tunnelsEstablished)
				fmt.Printf("Tunnels established: %d, MemStats.*InUse (peak memory in use): %s, MemStats.TotalAlloc (cumulative allocations): %s\n",
					n, common.FormatByteCount(inuseBytes), common.FormatByteCount(m.TotalAlloc))
				if lastTunnelsEstablished-n >= 0 {
					t.Fatalf("expected established tunnels")
				}
				lastTunnelsEstablished = n
			}

		case <-reconnectTunnel:
			controller.TerminateNextActiveTunnel()

		case <-restartController:
			stopController()
			startController()
		}
	}

	stopController()
}
