/*
 * Copyright (c) 2015, Psiphon Inc.
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

package psi

// This package is a shim between Java and the "psiphon" package. Due to limitations
// on what Go types may be exposed (http://godoc.org/golang.org/x/mobile/cmd/gobind),
// a psiphon.Controller cannot be directly used by Java. This shim exposes a trivial
// Start/Stop interface on top of a single Controller instance.

import (
	"fmt"
	"sync"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
)

type PsiphonProvider interface {
	Notice(noticeJSON string)
	HasNetworkConnectivity() int
	BindToDevice(fileDescriptor int) error
	GetPrimaryDnsServer() string
	GetSecondaryDnsServer() string
}

var controllerMutex sync.Mutex
var controller *psiphon.Controller
var shutdownBroadcast chan struct{}
var controllerWaitGroup *sync.WaitGroup

func Start(
	configJson, embeddedServerEntryList string,
	provider PsiphonProvider,
	useDeviceBinder bool) error {

	controllerMutex.Lock()
	defer controllerMutex.Unlock()

	if controller != nil {
		return fmt.Errorf("already started")
	}

	config, err := psiphon.LoadConfig([]byte(configJson))
	if err != nil {
		return fmt.Errorf("error loading configuration file: %s", err)
	}
	config.NetworkConnectivityChecker = provider

	if useDeviceBinder {
		config.DeviceBinder = provider
		config.DnsServerGetter = provider
	}

	psiphon.SetNoticeOutput(psiphon.NewNoticeReceiver(
		func(notice []byte) {
			provider.Notice(string(notice))
		}))

	psiphon.NoticeBuildInfo()

	// TODO: should following errors be Notices?

	err = psiphon.InitDataStore(config)
	if err != nil {
		return fmt.Errorf("error initializing datastore: %s", err)
	}

	serverEntries, err := psiphon.DecodeAndValidateServerEntryList(
		embeddedServerEntryList,
		common.GetCurrentTimestamp(),
		common.SERVER_ENTRY_SOURCE_EMBEDDED)
	if err != nil {
		return fmt.Errorf("error decoding embedded server entry list: %s", err)
	}
	err = psiphon.StoreServerEntries(serverEntries, false)
	if err != nil {
		return fmt.Errorf("error storing embedded server entry list: %s", err)
	}

	controller, err = psiphon.NewController(config)
	if err != nil {
		return fmt.Errorf("error initializing controller: %s", err)
	}

	shutdownBroadcast = make(chan struct{})
	controllerWaitGroup = new(sync.WaitGroup)
	controllerWaitGroup.Add(1)
	go func() {
		defer controllerWaitGroup.Done()
		controller.Run(shutdownBroadcast)
	}()

	return nil
}

func Stop() {

	controllerMutex.Lock()
	defer controllerMutex.Unlock()

	if controller != nil {
		close(shutdownBroadcast)
		controllerWaitGroup.Wait()
		controller = nil
		shutdownBroadcast = nil
		controllerWaitGroup = nil
	}
}

// This is a passthrough to Controller.SetClientVerificationPayloadForActiveTunnels.
// Note: should only be called after Start() and before Stop(); otherwise,
// will silently take no action.
func SetClientVerificationPayload(clientVerificationPayload string) {

	controllerMutex.Lock()
	defer controllerMutex.Unlock()

	if controller != nil {
		controller.SetClientVerificationPayloadForActiveTunnels(clientVerificationPayload)
	}
}

// Encrypt and upload feedback.
func SendFeedback(configJson, diagnosticsJson, b64EncodedPublicKey, uploadServer, uploadPath, uploadServerHeaders string) {
	err := psiphon.SendFeedback(configJson, diagnosticsJson, b64EncodedPublicKey, uploadServer, uploadPath, uploadServerHeaders)
	if err != nil {
		psiphon.NoticeAlert("failed to upload feedback: %s", err)
	} else {
		psiphon.NoticeInfo("feedback uploaded successfully")
	}
}
