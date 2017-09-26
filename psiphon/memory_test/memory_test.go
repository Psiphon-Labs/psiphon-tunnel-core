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
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon"
)

// TestMemoryUsage is a memory stress test that repeatedly
// establishes a tunnel, immediately terminates it, and
// start reestablishing.
//
// runtime.MemStats is used to monitor system memory usage
// during the test.
//
// This test is in its own package as its runtime.MemStats
// checks must not be impacted by other test runs; this
// test is also long-running.

func TestMemoryUsage(t *testing.T) {

	testDataDirName, err := ioutil.TempDir("", "psiphon-memory-test")
	if err != nil {
		fmt.Printf("TempDir failed: %s\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(testDataDirName)
	os.Remove(filepath.Join(testDataDirName, psiphon.DATA_STORE_FILENAME))

	psiphon.SetEmitDiagnosticNotices(true)

	configJSON, err := ioutil.ReadFile("../controller_test.config")
	if err != nil {
		// Skip, don't fail, if config file is not present
		t.Skipf("error loading configuration file: %s", err)
	}

	// These fields must be filled in before calling LoadConfig
	var modifyConfig map[string]interface{}
	json.Unmarshal(configJSON, &modifyConfig)
	modifyConfig["DataStoreDirectory"] = testDataDirName
	modifyConfig["RemoteServerListDownloadFilename"] = filepath.Join(testDataDirName, "server_list_compressed")
	modifyConfig["UpgradeDownloadFilename"] = filepath.Join(testDataDirName, "upgrade")
	configJSON, _ = json.Marshal(modifyConfig)

	config, err := psiphon.LoadConfig(configJSON)
	if err != nil {
		t.Fatalf("error processing configuration file: %s", err)
	}

	postActiveTunnelTerminateDelay := 250 * time.Millisecond
	testDuration := 5 * time.Minute
	memInspectionFrequency := 10 * time.Second
	maxSysMemory := uint64(10 * 1024 * 1024)

	config.ClientVersion = "999999999"
	config.TunnelPoolSize = 1
	fetchRemoteServerListRetryPeriodSeconds := 0
	config.FetchRemoteServerListRetryPeriodSeconds = &fetchRemoteServerListRetryPeriodSeconds
	establishTunnelPausePeriodSeconds := 1
	config.EstablishTunnelPausePeriodSeconds = &establishTunnelPausePeriodSeconds
	config.TunnelProtocol = ""
	config.DisableLocalSocksProxy = true
	config.DisableLocalHTTPProxy = true
	config.ConnectionWorkerPoolSize = 10
	config.LimitMeekConnectionWorkers = 5
	config.LimitMeekBufferSizes = true
	config.StaggerConnectionWorkersMilliseconds = 100
	config.IgnoreHandshakeStatsRegexps = true

	err = psiphon.InitDataStore(config)
	if err != nil {
		t.Fatalf("error initializing datastore: %s", err)
	}

	var controller *psiphon.Controller
	tunnelsEstablished := int32(0)

	psiphon.SetNoticeOutput(psiphon.NewNoticeReceiver(
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
					go controller.TerminateNextActiveTunnel()
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

	controller, err = psiphon.NewController(config)
	if err != nil {
		t.Fatalf("error creating controller: %s", err)
	}

	shutdownBroadcast := make(chan struct{})
	controllerWaitGroup := new(sync.WaitGroup)
	controllerWaitGroup.Add(1)
	go func() {
		defer controllerWaitGroup.Done()
		controller.Run(shutdownBroadcast)
	}()

	testTimer := time.NewTimer(testDuration)
	memInspectionTicker := time.NewTicker(memInspectionFrequency)

	lastTunnelsEstablished := int32(0)
test_loop:
	for {
		select {
		case <-testTimer.C:
			break test_loop
		case <-memInspectionTicker.C:
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			if m.Sys > maxSysMemory {
				t.Fatalf("sys memory exceeds limit: %d", m.Sys)
			} else {
				n := atomic.LoadInt32(&tunnelsEstablished)
				fmt.Printf("Tunnels established: %d, MemStats.Sys (peak system memory used): %s, MemStats.TotalAlloc (cumulative allocations): %s\n",
					n, psiphon.FormatByteCount(m.Sys), psiphon.FormatByteCount(m.TotalAlloc))
				if lastTunnelsEstablished-n >= 0 {
					t.Fatalf("expected established tunnels")
				}
				lastTunnelsEstablished = n
			}
		}
	}

	close(shutdownBroadcast)
	controllerWaitGroup.Wait()
}
