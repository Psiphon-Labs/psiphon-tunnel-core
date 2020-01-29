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
	std_errors "errors"
	"fmt"
	"path/filepath"
	"sync"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
)

// Parameters provide an easier way to modify the tunnel config at runtime.
type Parameters struct {
	// Used as the directory for the datastore, remote server list, and obfuscasted
	// server list.
	// Empty string means the default will be used (current working directory).
	// nil means the values in the config file will be used.
	// Optional, but strongly recommended.
	DataRootDirectory *string

	// Overrides config.ClientPlatform. See config.go for details.
	// nil means the value in the config file will be used.
	// Optional, but strongly recommended.
	ClientPlatform *string

	// Overrides config.NetworkID. For details see:
	// https://godoc.org/github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon#NetworkIDGetter
	// nil means the value in the config file will be used. (If not set in the config,
	// an error will result.)
	// Empty string will produce an error.
	// Optional, but strongly recommended.
	NetworkID *string

	// Overrides config.EstablishTunnelTimeoutSeconds. See config.go for details.
	// nil means the EstablishTunnelTimeoutSeconds value in the config file will be used.
	// If there's no such value in the config file, the default will be used.
	// Zero means there will be no timeout.
	// Optional.
	EstablishTunnelTimeoutSeconds *int

	// EmitDiagnosticNoticesToFile indicates whether to use the rotating log file
	// facility to record diagnostic notices instead of sending diagnostic
	// notices to noticeReceiver. Has no effect unless the tunnel
	// config.EmitDiagnosticNotices flag is set.
	EmitDiagnosticNoticesToFiles bool
}

// PsiphonTunnel is the tunnel object. It can be used for stopping the tunnel and
// retrieving proxy ports.
type PsiphonTunnel struct {
	controllerWaitGroup sync.WaitGroup
	stopController      context.CancelFunc

	// The port on which the HTTP proxy is running
	HTTPProxyPort int
	// The port on which the SOCKS proxy is running
	SOCKSProxyPort int
}

// ClientParametersDelta allows for fine-grained modification of parameters.ClientParameters.
// NOTE: Ordinary users of this library should never need this.
type ClientParametersDelta map[string]interface{}

// NoticeEvent represents the notices emitted by tunnel core. It will be passed to
// noticeReceiver, if supplied.
// NOTE: Ordinary users of this library should never need this.
type NoticeEvent struct {
	Data      map[string]interface{} `json:"data"`
	Type      string                 `json:"noticeType"`
	Timestamp string                 `json:"timestamp"`
}

// ErrTimeout is returned when the tunnel establishment attempt fails due to timeout
var ErrTimeout = std_errors.New("clientlib: tunnel establishment timeout")

// StartTunnel establishes a Psiphon tunnel. It returns an error if the establishment
// was not successful. If the returned error is nil, the returned tunnel can be used
// to find out the proxy ports and subsequently stop the tunnel.
//
// ctx may be cancelable, if the caller wants to be able to interrupt the establishment
// attempt, or context.Background().
//
// configJSON will be passed to psiphon.LoadConfig to configure the tunnel. Required.
//
// embeddedServerEntryList is the encoded embedded server entry list. It is optional.
//
// params are config values that typically need to be overridden at runtime.
//
// paramsDelta contains changes that will be applied to the ClientParameters.
// NOTE: Ordinary users of this library should never need this and should pass nil.
//
// noticeReceiver, if non-nil, will be called for each notice emitted by tunnel core.
// NOTE: Ordinary users of this library should never need this and should pass nil.
func StartTunnel(ctx context.Context,
	configJSON []byte, embeddedServerEntryList string,
	params Parameters, paramsDelta ClientParametersDelta,
	noticeReceiver func(NoticeEvent)) (tunnel *PsiphonTunnel, err error) {

	config, err := psiphon.LoadConfig(configJSON)
	if err != nil {
		return nil, errors.TraceMsg(err, "failed to load config file")
	}

	// Use params.DataRootDirectory to set related config values.
	if params.DataRootDirectory != nil {
		config.DataRootDirectory = *params.DataRootDirectory

		// Migrate old fields
		config.MigrateDataStoreDirectory = *params.DataRootDirectory
		config.MigrateObfuscatedServerListDownloadDirectory = *params.DataRootDirectory
		config.MigrateRemoteServerListDownloadFilename = filepath.Join(*params.DataRootDirectory, "server_list_compressed")
	}

	if params.NetworkID != nil {
		config.NetworkID = *params.NetworkID
	}

	if params.ClientPlatform != nil {
		config.ClientPlatform = *params.ClientPlatform
	} // else use the value in config

	if params.EstablishTunnelTimeoutSeconds != nil {
		config.EstablishTunnelTimeoutSeconds = params.EstablishTunnelTimeoutSeconds
	} // else use the value in config

	if config.UseNoticeFiles == nil && config.EmitDiagnosticNotices && params.EmitDiagnosticNoticesToFiles {
		config.UseNoticeFiles = &psiphon.UseNoticeFiles{
			RotatingFileSize:      0,
			RotatingSyncFrequency: 0,
		}
	} // else use the value in the config

	// config.Commit must be called before calling config.SetClientParameters
	// or attempting to connect.
	err = config.Commit(true)
	if err != nil {
		return nil, errors.TraceMsg(err, "config.Commit failed")
	}

	// If supplied, apply the client parameters delta
	if len(paramsDelta) > 0 {
		err = config.SetClientParameters("", false, paramsDelta)
		if err != nil {
			return nil, errors.TraceMsg(
				err, fmt.Sprintf("SetClientParameters failed for delta: %v", paramsDelta))
		}
	}

	err = psiphon.OpenDataStore(config)
	if err != nil {
		return nil, errors.TraceMsg(err, "failed to open data store")
	}
	// Make sure we close the datastore in case of error
	defer func() {
		if err != nil {
			psiphon.CloseDataStore()
		}
	}()

	// Store embedded server entries
	serverEntries, err := protocol.DecodeServerEntryList(
		embeddedServerEntryList,
		common.TruncateTimestampToHour(common.GetCurrentTimestamp()),
		protocol.SERVER_ENTRY_SOURCE_EMBEDDED)
	if err != nil {
		return nil, errors.TraceMsg(err, "failed to decode server entry list")
	}

	err = psiphon.StoreServerEntries(config, serverEntries, false)
	if err != nil {
		return nil, errors.TraceMsg(err, "failed to store server entries")
	}

	// Will receive a value when the tunnel has successfully connected.
	connected := make(chan struct{})
	// Will receive a value if the tunnel times out trying to connect.
	timedOut := make(chan struct{})
	// Will receive a value if an error occurs during the connection sequence.
	errored := make(chan error)

	// Create the tunnel object
	tunnel = new(PsiphonTunnel)

	// Set up notice handling
	psiphon.SetNoticeWriter(psiphon.NewNoticeReceiver(
		func(notice []byte) {
			var event NoticeEvent
			err := json.Unmarshal(notice, &event)
			if err != nil {
				// This is unexpected and probably indicates something fatal has occurred.
				// We'll interpret it as a connection error and abort.
				err = errors.TraceMsg(err, "failed to unmarshal notice JSON")
				select {
				case errored <- err:
				default:
				}
				return
			}

			if event.Type == "ListeningHttpProxyPort" {
				port := event.Data["port"].(float64)
				tunnel.HTTPProxyPort = int(port)
			} else if event.Type == "ListeningSocksProxyPort" {
				port := event.Data["port"].(float64)
				tunnel.SOCKSProxyPort = int(port)
			} else if event.Type == "EstablishTunnelTimeout" {
				select {
				case timedOut <- struct{}{}:
				default:
				}
			} else if event.Type == "Tunnels" {
				count := event.Data["count"].(float64)
				if count > 0 {
					select {
					case connected <- struct{}{}:
					default:
					}
				}
			}

			// Some users of this package may need to add special processing of notices.
			// If the caller has requested it, we'll pass on the notices.
			if noticeReceiver != nil {
				noticeReceiver(event)
			}
		}))

	// Create the Psiphon controller
	controller, err := psiphon.NewController(config)
	if err != nil {
		return nil, errors.TraceMsg(err, "psiphon.NewController failed")
	}

	// Create a cancelable context that will be used for stopping the tunnel
	var controllerCtx context.Context
	controllerCtx, tunnel.stopController = context.WithCancel(ctx)

	// Begin tunnel connection
	tunnel.controllerWaitGroup.Add(1)
	go func() {
		defer tunnel.controllerWaitGroup.Done()

		// Start the tunnel. Only returns on error (or internal timeout).
		controller.Run(controllerCtx)

		select {
		case errored <- errors.TraceNew("controller.Run exited unexpectedly"):
		default:
		}
	}()

	// Wait for an active tunnel, timeout, or error
	select {
	case <-connected:
		return tunnel, nil
	case <-timedOut:
		tunnel.Stop()
		return nil, ErrTimeout
	case err := <-errored:
		tunnel.Stop()
		return nil, errors.TraceMsg(err, "tunnel start produced error")
	}
}

// Stop stops/disconnects/shuts down the tunnel. It is safe to call when not connected.
func (tunnel *PsiphonTunnel) Stop() {
	if tunnel.stopController != nil {
		tunnel.stopController()
	}

	tunnel.controllerWaitGroup.Wait()

	psiphon.CloseDataStore()
}
