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
	psiphon "github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon"
	"log"
	"sync"
)

type Listener interface {
	Message(message string)
}

type logRelay struct {
	listener Listener
}

func (lr *logRelay) Write(p []byte) (n int, err error) {
	// TODO: buffer incomplete lines
	lr.listener.Message(string(p))
	return len(p), nil
}

var controller *psiphon.Controller
var shutdownBroadcast chan struct{}
var controllerWaitGroup *sync.WaitGroup

func Start(configJson string, listener Listener) error {

	if controller != nil {
		return fmt.Errorf("already started")
	}

	config, err := psiphon.LoadConfig([]byte(configJson))
	if err != nil {
		return fmt.Errorf("error loading configuration file: %s", err)
	}

	log.SetOutput(&logRelay{listener: listener})

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
