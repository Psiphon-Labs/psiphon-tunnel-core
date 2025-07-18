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
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon"
)

func setupConfig(t *testing.T, disableFetcher bool) []byte {
	configJSON, err := os.ReadFile("../../psiphon/controller_test.config")
	if err != nil {
		// What to do if config file is not present?
		t.Skipf("error loading configuration file: %s", err)
	}

	var config map[string]interface{}
	err = json.Unmarshal(configJSON, &config)
	if err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	if disableFetcher {
		config["DisableRemoteServerListFetcher"] = true
	}

	configJSON, err = json.Marshal(config)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	return configJSON
}

func TestStartTunnel(t *testing.T) {
	// TODO: More comprehensive tests. This is only a smoke test.

	configJSON := setupConfig(t, false)
	configJSONNoFetcher := setupConfig(t, true)

	clientPlatform := "clientlib_test.go"
	networkID := "UNKNOWN"
	timeout := 60
	quickTimeout := 1
	trueVal := true

	// Initialize a fresh datastore and create a modified config which cannot
	// connect without known servers, to be used in timeout cases.

	testDataDirName, err := os.MkdirTemp("", "psiphon-clientlib-test")
	if err != nil {
		t.Fatalf("ioutil.TempDir failed: %v", err)
	}
	defer os.RemoveAll(testDataDirName)

	paramsDeltaErr := func(err error) bool {
		return strings.Contains(err.Error(), "SetParameters failed for delta")
	}
	timeoutErr := func(err error) bool {
		return errors.Is(err, ErrTimeout)
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
		expectedErr func(error) bool
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
			expectedErr: timeoutErr,
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
			expectedErr: timeoutErr,
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
		{
			name: "Success: good ParametersDelta",
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
				paramsDelta:    ParametersDelta{"NetworkLatencyMultiplierMin": 1},
				noticeReceiver: nil,
			},
			wantTunnel:  true,
			expectedErr: nil,
		},
		{
			name: "Failure: bad ParametersDelta",
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
				paramsDelta:    ParametersDelta{"invalidParam": 1},
				noticeReceiver: nil,
			},
			wantTunnel:  false,
			expectedErr: paramsDeltaErr,
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

			if tt.expectedErr == nil {
				if err != nil {
					t.Fatalf("StartTunnel() returned unexpected error: %v", err)
				}
			} else if !tt.expectedErr(err) {
				t.Fatalf("StartTunnel() error: %v", err)
				return
			}

			if err != nil {
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
	configJSON := setupConfig(t, false)
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
	configJSON := setupConfig(t, false)
	trueVal := true

	testDataDirName, err := os.MkdirTemp("", "psiphon-clientlib-test")
	if err != nil {
		t.Fatalf("ioutil.TempDir failed: %v", err)
	}
	defer os.RemoveAll(testDataDirName)

	type args struct {
		remoteAddr string
	}
	tests := []struct {
		name          string
		args          args
		wantErr       bool
		tunnelStopped bool
	}{
		{
			name:    "Success: psiphon.ca",
			args:    args{remoteAddr: "psiphon.ca:443"},
			wantErr: false,
		},
		{
			name:    "Failure: invalid address",
			args:    args{remoteAddr: "psiphon.ca:99999"},
			wantErr: true,
		},
		{
			name:          "Failure: tunnel not started",
			args:          args{remoteAddr: "psiphon.ca:443"},
			wantErr:       true,
			tunnelStopped: true,
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

			if tt.tunnelStopped {
				tunnel.Stop()
			}

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

// We had a problem where config-related notices were being printed to stderr before we
// set the NoticeWriter. We want to make sure that no longer happens.
func TestStartTunnelNoOutput(t *testing.T) {
	// Before starting the tunnel, set up a notice receiver. If it receives anything at
	// all, that means that it would have been printed to stderr.
	err := psiphon.SetNoticeWriter(psiphon.NewNoticeReceiver(
		func(notice []byte) {
			t.Fatalf("Received notice: %v", string(notice))
		}))
	if err != nil {
		t.Fatalf("psiphon.SetNoticeWriter failed: %v", err)
	}
	defer psiphon.ResetNoticeWriter()

	configJSON := setupConfig(t, false)

	testDataDirName, err := os.MkdirTemp("", "psiphon-clientlib-test")
	if err != nil {
		t.Fatalf("ioutil.TempDir failed: %v", err)
	}
	defer os.RemoveAll(testDataDirName)

	psiphon.ResetNoticeWriter()

	ctx := context.Background()

	tunnel, err := StartTunnel(
		ctx,
		configJSON,
		"",
		Parameters{DataRootDirectory: &testDataDirName},
		nil,
		nil)

	if err != nil {
		t.Fatalf("StartTunnel() error = %v", err)
	}
	tunnel.Stop()
}

// We had a problem where a very early error could result in `started` being set to true
// and not be set back to false, preventing StartTunnel from being re-callable.
func TestStartTunnelReentry(t *testing.T) {
	testDataDirName, err := os.MkdirTemp("", "psiphon-clientlib-test")
	if err != nil {
		t.Fatalf("ioutil.TempDir failed: %v", err)
	}
	defer os.RemoveAll(testDataDirName)

	configJSON := []byte("BAD CONFIG JSON")

	ctx := context.Background()

	_, err = StartTunnel(
		ctx,
		configJSON,
		"",
		Parameters{DataRootDirectory: &testDataDirName},
		nil,
		nil)

	if err == nil {
		t.Fatalf("expected config error")
	}

	// Call again with a good config. Should work.
	configJSON = setupConfig(t, false)

	tunnel, err := StartTunnel(
		ctx,
		configJSON,
		"",
		Parameters{DataRootDirectory: &testDataDirName},
		nil,
		nil)

	if err != nil {
		t.Fatalf("StartTunnel() error = %v", err)
	}
	tunnel.Stop()
}
