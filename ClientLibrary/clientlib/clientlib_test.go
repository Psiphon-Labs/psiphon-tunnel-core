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
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"testing"
	"time"
)

var testDataDirName string

func TestMain(m *testing.M) {
	flag.Parse()

	var err error
	testDataDirName, err = ioutil.TempDir("", "psiphon-clientlib-test")
	if err != nil {
		fmt.Printf("TempDir failed: %s\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(testDataDirName)

	os.Exit(m.Run())
}

func getConfigJSON(t *testing.T) []byte {
	configJSON, err := ioutil.ReadFile("../../psiphon/controller_test.config")
	if err != nil {
		// Skip, don't fail, if config file is not present
		t.Skipf("error loading configuration file: %s", err)
	}

	return configJSON
}

func TestStartTunnel(t *testing.T) {
	// TODO: More comprehensive tests. This is only a smoke test.

	configJSON := getConfigJSON(t)
	clientPlatform := "clientlib_test.go"
	networkID := "UNKNOWN"
	timeout := 60

	// Cancels the context after a duration. Pass 0 for no cancel.
	// (Note that cancelling causes an error, not a timeout.)
	contextGetter := func(cancelAfter time.Duration) func() context.Context {
		return func() context.Context {
			if cancelAfter == 0 {
				return context.Background()
			}

			ctx, ctxCancel := context.WithCancel(context.Background())
			go func() {
				time.Sleep(cancelAfter)
				ctxCancel()
			}()
			return ctx
		}
	}

	type args struct {
		ctxGetter               func() context.Context
		configJSON              []byte
		embeddedServerEntryList string
		params                  Parameters
		paramsDelta             ParametersDelta
		noticeReceiver          func(NoticeEvent)
	}
	tests := []struct {
		name       string
		args       args
		wantTunnel bool
		wantErr    bool
	}{
		{
			name: "Success: simple",
			args: args{
				ctxGetter:               contextGetter(0),
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
			wantTunnel: true,
			wantErr:    false,
		},
		{
			name: "Failure: timeout",
			args: args{
				ctxGetter:               contextGetter(10 * time.Millisecond),
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
			wantTunnel: false,
			wantErr:    true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotTunnel, err := StartTunnel(tt.args.ctxGetter(),
				tt.args.configJSON, tt.args.embeddedServerEntryList,
				tt.args.params, tt.args.paramsDelta, tt.args.noticeReceiver)
			if (err != nil) != tt.wantErr {
				t.Fatalf("StartTunnel() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if (gotTunnel != nil) != tt.wantTunnel {
				t.Errorf("StartTunnel() gotTunnel = %v, wantTunnel %v", err, tt.wantTunnel)
			}

			if gotTunnel != nil {
				gotTunnel.Stop()
			}
		})
	}
}
