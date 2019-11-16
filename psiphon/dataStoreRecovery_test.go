// +build !BADGER_DB,!FILES_DB

/*
 * Copyright (c) 2019, Psiphon Inc.
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
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
)

func TestBoltResiliency(t *testing.T) {

	testDataDirName, err := ioutil.TempDir("", "psiphon-bolt-recovery-test")
	if err != nil {
		t.Fatalf("TempDir failed: %s", err)
	}
	defer os.RemoveAll(testDataDirName)

	SetEmitDiagnosticNotices(true, true)

	clientConfigJSONTemplate := `
    {
        "DataRootDirectory" : "%s",
        "ClientPlatform" : "",
        "ClientVersion" : "0",
        "SponsorId" : "0",
        "PropagationChannelId" : "0",
        "ConnectionPoolSize" : 10,
        "EstablishTunnelTimeoutSeconds" : 1,
        "EstablishTunnelPausePeriodSeconds" : 1
    }`

	clientConfigJSON := fmt.Sprintf(
		clientConfigJSONTemplate,
		testDataDirName)

	clientConfig, err := LoadConfig([]byte(clientConfigJSON))
	if err != nil {
		t.Fatalf("LoadConfig failed: %s", err)
	}
	err = clientConfig.Commit()
	if err != nil {
		t.Fatalf("Commit failed: %s", err)
	}

	serverEntryCount := 100

	noticeCandidateServers := make(chan struct{}, 1)
	noticeExiting := make(chan struct{}, 1)
	noticeResetDatastore := make(chan struct{}, 1)
	noticeDatastoreFailed := make(chan struct{}, 1)

	SetNoticeWriter(NewNoticeReceiver(
		func(notice []byte) {

			noticeType, payload, err := GetNotice(notice)
			if err != nil {
				return
			}

			printNotice := false

			switch noticeType {
			case "CandidateServers":
				count := int(payload["count"].(float64))
				if count != serverEntryCount {
					t.Fatalf("unexpected server entry count: %d", count)
				}
				select {
				case noticeCandidateServers <- *new(struct{}):
				default:
				}
			case "Exiting":
				select {
				case noticeExiting <- *new(struct{}):
				default:
				}
			case "Alert":
				message := payload["message"].(string)
				var channel chan struct{}
				if strings.Contains(message, "tryDatastoreOpenDB: reset") {
					channel = noticeResetDatastore
				} else if strings.Contains(message, "datastore has failed") {
					channel = noticeDatastoreFailed
				}
				if channel != nil {
					select {
					case channel <- *new(struct{}):
					default:
					}
				}
			}

			if printNotice {
				fmt.Printf("%s\n", string(notice))
			}
		}))

	drainNoticeChannel := func(channel chan struct{}) {
		for {
			select {
			case channel <- *new(struct{}):
			default:
				return
			}
		}
	}

	drainNoticeChannels := func() {
		drainNoticeChannel(noticeCandidateServers)
		drainNoticeChannel(noticeExiting)
		drainNoticeChannel(noticeResetDatastore)
		drainNoticeChannel(noticeDatastoreFailed)
	}

	// Paving sufficient server entries, then truncating the datastore file to
	// remove some server entry data, then iterating over all server entries (to
	// produce the CandidateServers output) triggers datastore corruption
	// detection and, at start up, reset/recovery.

	paveServerEntries := func() {
		for i := 0; i < serverEntryCount; i++ {

			n := 16
			fields := make(protocol.ServerEntryFields)
			fields["ipAddress"] = fmt.Sprintf("127.0.0.%d", i+1)
			fields["sshPort"] = 2222
			fields["sshUsername"] = prng.HexString(n)
			fields["sshPassword"] = prng.HexString(n)
			fields["sshHostKey"] = prng.HexString(n)
			fields["capabilities"] = []string{"SSH", "ssh-api-requests"}
			fields["region"] = "US"
			fields["configurationVersion"] = 1

			fields.SetLocalSource(protocol.SERVER_ENTRY_SOURCE_EMBEDDED)
			fields.SetLocalTimestamp(
				common.TruncateTimestampToHour(common.GetCurrentTimestamp()))

			err = StoreServerEntry(fields, true)
			if err != nil {
				t.Fatalf("StoreServerEntry failed: %s", err)
			}
		}
	}

	startController := func() func() {
		controller, err := NewController(clientConfig)
		if err != nil {
			t.Fatalf("NewController failed: %s", err)
		}
		ctx, cancelFunc := context.WithCancel(context.Background())
		controllerWaitGroup := new(sync.WaitGroup)
		controllerWaitGroup.Add(1)
		go func() {
			defer controllerWaitGroup.Done()
			controller.Run(ctx)
		}()
		return func() {
			cancelFunc()
			controllerWaitGroup.Wait()
		}
	}

	truncateDataStore := func() {
		filename := filepath.Join(testDataDirName, "datastore", "psiphon.boltdb")
		configFile, err := os.OpenFile(filename, os.O_RDWR, 0666)
		if err != nil {
			t.Fatalf("OpenFile failed: %s", err)
		}
		defer configFile.Close()
		fileInfo, err := configFile.Stat()
		if err != nil {
			t.Fatalf("Stat failed: %s", err)
		}
		err = configFile.Truncate(fileInfo.Size() / 4)
		if err != nil {
			t.Fatalf("Truncate failed: %s", err)
		}
		err = configFile.Sync()
		if err != nil {
			t.Fatalf("Sync failed: %s", err)
		}
	}

	// Populate datastore with 100 server entries.

	err = OpenDataStore(clientConfig)
	if err != nil {
		t.Fatalf("OpenDataStore failed: %s", err)
	}
	defer CloseDataStore()

	paveServerEntries()

	stopController := startController()

	<-noticeCandidateServers

	stopController()

	CloseDataStore()

	drainNoticeChannels()

	// Truncate datastore file before running controller; expect a datastore
	// "reset" notice on OpenDataStore.

	t.Logf("test: recover from datastore corrupted before opening")

	truncateDataStore()

	err = OpenDataStore(clientConfig)
	if err != nil {
		t.Fatalf("OpenDataStore failed: %s", err)
	}
	defer CloseDataStore()

	<-noticeResetDatastore

	paveServerEntries()

	// Truncate datastore while running the controller. First, complete one
	// successful data scan (CandidateServers). The next scan should trigger a
	// datastore "failed" notice.

	t.Logf("test: detect corrupt datastore while running")

	stopController = startController()

	<-noticeCandidateServers

	truncateDataStore()

	<-noticeDatastoreFailed

	<-noticeExiting

	stopController()

	CloseDataStore()

	drainNoticeChannels()

	// Restart successfully after previous failure shutdown.

	t.Logf("test: after restart, recover from datastore corrupted while running")

	err = OpenDataStore(clientConfig)
	if err != nil {
		t.Fatalf("OpenDataStore failed: %s", err)
	}
	defer CloseDataStore()

	<-noticeResetDatastore

	paveServerEntries()

	stopController = startController()

	<-noticeCandidateServers

	stopController()

	CloseDataStore()
}
