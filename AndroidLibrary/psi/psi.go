/*
 * Copyright (c) 2014, Psiphon Inc.
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
	"log"
	"sync"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon"
)

type PsiphonProvider interface {
	Notice(message string)

	// TODO: return 'error'; at the moment gobind doesn't
	// work with interface function return values.
	BindToDevice(fileDescriptor int)
}

type logRelay struct {
	provider PsiphonProvider
}

func (lr *logRelay) Write(p []byte) (n int, err error) {
	// TODO: buffer incomplete lines
	lr.provider.Notice(string(p))
	return len(p), nil
}

var controller *psiphon.Controller
var shutdownBroadcast chan struct{}
var controllerWaitGroup *sync.WaitGroup

func Start(configJson string, provider PsiphonProvider) error {

	if controller != nil {
		return fmt.Errorf("already started")
	}

	config, err := psiphon.LoadConfig([]byte(configJson))
	if err != nil {
		return fmt.Errorf("error loading configuration file: %s", err)
	}

	err = psiphon.InitDataStore(config.DataStoreFilename)
	if err != nil {
		return fmt.Errorf("error initializing datastore: %s", err)
	}

	log.SetOutput(&logRelay{provider: provider})

	config.BindToDeviceProvider = provider

	controller = psiphon.NewController(config)
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
