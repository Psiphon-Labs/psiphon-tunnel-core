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
)

type PsiphonProvider interface {
	Notice(noticeJSON string)
	HasNetworkConnectivity() int
	BindToDevice(fileDescriptor int) error
	GetDnsServer() string
}

var controller *psiphon.Controller
var shutdownBroadcast chan struct{}
var controllerWaitGroup *sync.WaitGroup

func Start(
	configJson, embeddedServerEntryList string,
	provider PsiphonProvider,
	useDeviceBinder bool) error {

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

	// TODO: should following errors be Notices?

	err = psiphon.InitDataStore(config)
	if err != nil {
		return fmt.Errorf("error initializing datastore: %s", err)
	}

	// If specified, the embedded server list is loaded and stored. When there
	// are no server candidates at all, we wait for this import to complete
	// before starting the Psiphon controller. Otherwise, we import while
	// concurrently starting the controller to minimize delay before attempting
	// to connect to existing candidate servers.
	// If the import fails, an error notice is emitted, but the controller is
	// still started: either existing candidate servers may suffice, or the
	// remote server list fetch may obtain candidate servers.
	// TODO: duplicates logic in psiphonClient.go -- refactor?
	if embeddedServerEntryList != "" {
		embeddedServerListWaitGroup := new(sync.WaitGroup)
		embeddedServerListWaitGroup.Add(1)
		go func() {
			defer embeddedServerListWaitGroup.Done()
			// TODO: stream embedded server list data?
			serverEntries, err := psiphon.DecodeAndValidateServerEntryList(embeddedServerEntryList)
			if err != nil {
				psiphon.NoticeError("error decoding embedded server entry list file: %s", err)
				return
			}
			// Since embedded server list entries may become stale, they will not
			// overwrite existing stored entries for the same server.
			err = psiphon.StoreServerEntries(serverEntries, false)
			if err != nil {
				psiphon.NoticeError("error storing embedded server entry list data: %s", err)
				return
			}
		}()

		if psiphon.CountServerEntries(config.EgressRegion, config.TunnelProtocol) == 0 {
			embeddedServerListWaitGroup.Wait()
		} else {
			defer embeddedServerListWaitGroup.Wait()
		}
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
	if controller != nil {
		close(shutdownBroadcast)
		controllerWaitGroup.Wait()
		controller = nil
		shutdownBroadcast = nil
		controllerWaitGroup = nil
	}
}
