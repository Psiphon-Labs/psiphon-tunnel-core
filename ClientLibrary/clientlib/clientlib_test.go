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
	trueVal := true

	configJSON, err := os.ReadFile("../../psiphon/controller_test.config")
	if err != nil {
		// Skip, don't fail, if config file is not present
		t.Skipf("error loading configuration file: %s", err)
	}

	// Initialize a fresh datastore and create a modified config which cannot
	// connect without known servers, to be used in timeout cases.

	testDataDirName, err := os.MkdirTemp("", "psiphon-clientlib-test")
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
		{
			name: "Success: disable SOCKS proxy",
			args: args{
				ctxTimeout:              0,
				configJSON:              configJSON,
				embeddedServerEntryList: "",
				params: Parameters{
					DataRootDirectory:             &testDataDirName,
					ClientPlatform:                &clientPlatform,
					NetworkID:                     &networkID,
					EstablishTunnelTimeoutSeconds: &timeout,
					DisableLocalSocksProxy:        &trueVal,
				},
				paramsDelta:    nil,
				noticeReceiver: nil,
			},
			wantTunnel:  true,
			expectedErr: nil,
		},
		{
			name: "Success: disable HTTP proxy",
			args: args{
				ctxTimeout:              0,
				configJSON:              configJSON,
				embeddedServerEntryList: "",
				params: Parameters{
					DataRootDirectory:             &testDataDirName,
					ClientPlatform:                &clientPlatform,
					NetworkID:                     &networkID,
					EstablishTunnelTimeoutSeconds: &timeout,
					DisableLocalHTTPProxy:         &trueVal,
				},
				paramsDelta:    nil,
				noticeReceiver: nil,
			},
			wantTunnel:  true,
			expectedErr: nil,
		},
		{
			name: "Success: disable SOCKS and HTTP proxies",
			args: args{
				ctxTimeout:              0,
				configJSON:              configJSON,
				embeddedServerEntryList: "",
				params: Parameters{
					DataRootDirectory:             &testDataDirName,
					ClientPlatform:                &clientPlatform,
					NetworkID:                     &networkID,
					EstablishTunnelTimeoutSeconds: &timeout,
					DisableLocalSocksProxy:        &trueVal,
					DisableLocalHTTPProxy:         &trueVal,
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

			if tunnel == nil {
				return
			}

			if tt.args.params.DisableLocalSocksProxy != nil && *tt.args.params.DisableLocalSocksProxy {
				if tunnel.SOCKSProxyPort != 0 {
					t.Fatalf("should not have started SOCKS proxy")
				}
			} else {
				if tunnel.SOCKSProxyPort == 0 {
					t.Fatalf("failed to start SOCKS proxy")
				}
			}

			if tt.args.params.DisableLocalHTTPProxy != nil && *tt.args.params.DisableLocalHTTPProxy {
				if tunnel.HTTPProxyPort != 0 {
					t.Fatalf("should not have started HTTP proxy")
				}
			} else {
				if tunnel.HTTPProxyPort == 0 {
					t.Fatalf("failed to start HTTP proxy")
				}
			}
		})
	}
}

func TestMultipleStartTunnel(t *testing.T) {
	configJSON, err := os.ReadFile("../../psiphon/controller_test.config")
	if err != nil {
		// What to do if config file is not present?
		t.Skipf("error loading configuration file: %s", err)
	}

	testDataDirName, err := os.MkdirTemp("", "psiphon-clientlib-test")
	if err != nil {
		t.Fatalf("ioutil.TempDir failed: %v", err)
	}
	defer os.RemoveAll(testDataDirName)

	ctx := context.Background()

	tunnel1, err := StartTunnel(
		ctx,
		configJSON,
		"",
		Parameters{DataRootDirectory: &testDataDirName},
		nil,
		nil)

	if err != nil {
		t.Fatalf("first StartTunnel() error = %v", err)
	}

	// We have not stopped the tunnel, so a second StartTunnel() should fail
	_, err = StartTunnel(
		ctx,
		configJSON,
		"",
		Parameters{DataRootDirectory: &testDataDirName},
		nil,
		nil)

	if err != errMultipleStart {
		t.Fatalf("second StartTunnel() should have failed with errMultipleStart; got %v", err)
	}

	// Stop the tunnel and try again
	tunnel1.Stop()
	tunnel3, err := StartTunnel(
		ctx,
		configJSON,
		"",
		Parameters{DataRootDirectory: &testDataDirName},
		nil,
		nil)

	if err != nil {
		t.Fatalf("third StartTunnel() error = %v", err)
	}

	// Stop the tunnel so it doesn't interfere with other tests
	tunnel3.Stop()
}

func TestPsiphonTunnel_Dial(t *testing.T) {
	trueVal := true
	configJSON, err := os.ReadFile("../../psiphon/controller_test.config")
	if err != nil {
		// Skip, don't fail, if config file is not present
		t.Skipf("error loading configuration file: %s", err)
	}

	testDataDirName, err := os.MkdirTemp("", "psiphon-clientlib-test")
	if err != nil {
		t.Fatalf("ioutil.TempDir failed: %v", err)
	}
	defer os.RemoveAll(testDataDirName)

	type args struct {
		remoteAddr string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name:    "Success: example.com",
			args:    args{remoteAddr: "example.com:443"},
			wantErr: false,
		},
		{
			name:    "Failure: invalid address",
			args:    args{remoteAddr: "example.com:99999"},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tunnel, err := StartTunnel(
				context.Background(),
				configJSON,
				"",
				Parameters{
					DataRootDirectory: &testDataDirName,
					// Don't need local proxies for dial tests
					// (and this is likely the configuration that will be used by consumers of the library who utilitize Dial).
					DisableLocalSocksProxy: &trueVal,
					DisableLocalHTTPProxy:  &trueVal,
				},
				nil,
				nil)
			if err != nil {
				t.Fatalf("StartTunnel() error = %v", err)
			}
			defer tunnel.Stop()

			conn, err := tunnel.Dial(tt.args.remoteAddr)
			if (err != nil) != tt.wantErr {
				t.Fatalf("PsiphonTunnel.Dial() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr != (conn == nil) {
				t.Fatalf("PsiphonTunnel.Dial() conn = %v, wantConn %v", conn, !tt.wantErr)
			}
		})
	}
}
