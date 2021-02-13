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

package clientlib

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"os"
	"testing"
	"time"
)

func TestStartTunnel(t *testing.T) {
	// TODO: More comprehensive tests. This is only a smoke test.

	clientPlatform := "clientlib_test.go"
	networkID := "UNKNOWN"
	timeout := 60
	quickTimeout := 1

	configJSON, err := ioutil.ReadFile("../../psiphon/controller_test.config")
	if err != nil {
		// Skip, don't fail, if config file is not present
		t.Skipf("error loading configuration file: %s", err)
	}

	// Initialize a fresh datastore and create a modified config which cannot
	// connect without known servers, to be used in timeout cases.

	testDataDirName, err := ioutil.TempDir("", "psiphon-clientlib-test")
	if err != nil {
		t.Fatalf("ioutil.TempDir failed: %v", err)
	}
	defer os.RemoveAll(testDataDirName)

	var config map[string]interface{}
	err = json.Unmarshal(configJSON, &config)
	if err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}
	config["DisableRemoteServerListFetcher"] = true
	configJSONNoFetcher, err := json.Marshal(config)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	type args struct {
		ctxTimeout              time.Duration
		configJSON              []byte
		embeddedServerEntryList string
		params                  Parameters
		paramsDelta             ParametersDelta
		noticeReceiver          func(NoticeEvent)
	}
	tests := []struct {
		name        string
		args        args
		wantTunnel  bool
		expectedErr error
	}{
		{
			name: "Failure: context timeout",
			args: args{
				ctxTimeout:              10 * time.Millisecond,
				configJSON:              configJSONNoFetcher,
				embeddedServerEntryList: "",
				params: Parameters{
					DataRootDirectory:             &testDataDirName,
					ClientPlatform:                &clientPlatform,
					NetworkID:                     &networkID,
					EstablishTunnelTimeoutSeconds: &timeout,
				},
				paramsDelta:    nil,
				noticeReceiver: nil,
			},
			wantTunnel:  false,
			expectedErr: ErrTimeout,
		},
		{
			name: "Failure: config timeout",
			args: args{
				ctxTimeout:              0,
				configJSON:              configJSONNoFetcher,
				embeddedServerEntryList: "",
				params: Parameters{
					DataRootDirectory:             &testDataDirName,
					ClientPlatform:                &clientPlatform,
					NetworkID:                     &networkID,
					EstablishTunnelTimeoutSeconds: &quickTimeout,
				},
				paramsDelta:    nil,
				noticeReceiver: nil,
			},
			wantTunnel:  false,
			expectedErr: ErrTimeout,
		},
		{
			name: "Success: simple",
			args: args{
				ctxTimeout:              0,
				configJSON:              configJSON,
				embeddedServerEntryList: "",
				params: Parameters{
					DataRootDirectory:             &testDataDirName,
					ClientPlatform:                &clientPlatform,
					NetworkID:                     &networkID,
					EstablishTunnelTimeoutSeconds: &timeout,
				},
				paramsDelta:    nil,
				noticeReceiver: nil,
			},
			wantTunnel:  true,
			expectedErr: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			ctx := context.Background()
			var cancelFunc context.CancelFunc
			if tt.args.ctxTimeout > 0 {
				ctx, cancelFunc = context.WithTimeout(ctx, tt.args.ctxTimeout)
			}

			tunnel, err := StartTunnel(
				ctx,
				tt.args.configJSON,
				tt.args.embeddedServerEntryList,
				tt.args.params,
				tt.args.paramsDelta,
				tt.args.noticeReceiver)

			gotTunnel := (tunnel != nil)

			if cancelFunc != nil {
				cancelFunc()
			}

			if tunnel != nil {
				tunnel.Stop()
			}

			if gotTunnel != tt.wantTunnel {
				t.Errorf("StartTunnel() gotTunnel = %v, wantTunnel %v", err, tt.wantTunnel)
			}

			if err != tt.expectedErr {
				t.Fatalf("StartTunnel() error = %v, expectedErr %v", err, tt.expectedErr)
				return
			}

		})
	}
}
