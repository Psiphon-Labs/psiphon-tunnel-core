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

package psiphon

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	utls "github.com/Psiphon-Labs/utls"
)

func TestStandAloneGetTactics(t *testing.T) {

	testDataDirName, err := ioutil.TempDir("", "psiphon-tactics-test")
	if err != nil {
		t.Fatalf("TempDir failed: %s\n", err)
	}
	defer os.RemoveAll(testDataDirName)

	configJSON, err := ioutil.ReadFile("controller_test.config")
	if err != nil {
		// Skip, don't fail, if config file is not present
		t.Skipf("error loading configuration file: %s", err)
	}

	var modifyConfig map[string]interface{}
	err = json.Unmarshal(configJSON, &modifyConfig)
	if err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	modifyConfig["DataRootDirectory"] = testDataDirName

	configJSON, _ = json.Marshal(modifyConfig)

	config, err := LoadConfig(configJSON)
	if err != nil {
		t.Fatalf("error processing configuration file: %s", err)
	}

	if config.ClientPlatform == "" {
		config.ClientPlatform = testClientPlatform
	}

	err = config.Commit(false)
	if err != nil {
		t.Fatalf("error committing configuration file: %s", err)
	}

	resolver := NewResolver(config, true)
	defer resolver.Stop()
	config.SetResolver(resolver)

	gotTactics := int32(0)

	SetNoticeWriter(NewNoticeReceiver(
		func(notice []byte) {
			noticeType, _, err := GetNotice(notice)
			if err != nil {
				return
			}
			switch noticeType {
			case "RequestedTactics":
				atomic.StoreInt32(&gotTactics, 1)
			}
		}))

	ctx, cancelFunc := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelFunc()

	err = OpenDataStore(config)
	if err != nil {
		t.Fatalf("error committing initializing datastore: %s", err)
	}

	untunneledDialConfig := &DialConfig{
		ResolveIP: func(ctx context.Context, hostname string) ([]net.IP, error) {
			IPs, err := UntunneledResolveIP(
				ctx, config, resolver, hostname, "")
			if err != nil {
				return nil, errors.Trace(err)
			}
			return IPs, nil
		},
		UpstreamProxyURL: config.UpstreamProxyURL,
	}

	tlsCache := utls.NewLRUClientSessionCache(0)

	err = FetchCommonRemoteServerList(ctx, config, 0, nil, untunneledDialConfig, tlsCache)
	if err != nil {
		t.Fatalf("error fetching remote server list: %s", err)
	}

	// Close the datastore to exercise the OpenDatastore/CloseDatastore
	// operations in GetTactics.
	CloseDataStore()

	GetTactics(ctx, config, true)

	if atomic.LoadInt32(&gotTactics) != 1 {
		t.Fatalf("failed to get tactics")
	}
}
