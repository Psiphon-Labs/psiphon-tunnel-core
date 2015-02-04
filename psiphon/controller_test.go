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

package psiphon

import (
	"io/ioutil"
	"sync"
	"testing"
	"time"
)

func TestControllerRunSSH(t *testing.T) {
	controllerRun(t, TUNNEL_PROTOCOL_SSH)
}

func TestControllerRunObfuscatedSSH(t *testing.T) {
	controllerRun(t, TUNNEL_PROTOCOL_OBFUSCATED_SSH)
}

func TestControllerRunUnfrontedMeek(t *testing.T) {
	controllerRun(t, TUNNEL_PROTOCOL_UNFRONTED_MEEK)
}

func TestControllerRunFrontedMeek(t *testing.T) {
	controllerRun(t, TUNNEL_PROTOCOL_FRONTED_MEEK)
}

func controllerRun(t *testing.T, protocol string) {

	configFileContents, err := ioutil.ReadFile("controller_test.config")
	if err != nil {
		// Skip, don't fail, if config file is not present
		t.Skipf("error loading configuration file: %s", err)
	}
	config, err := LoadConfig(configFileContents)
	if err != nil {
		t.Errorf("error processing configuration file: %s", err)
		t.FailNow()
	}
	config.TunnelProtocol = protocol

	err = InitDataStore(config)
	if err != nil {
		t.Errorf("error initializing datastore: %s", err)
		t.FailNow()
	}

	controller, err := NewController(config)
	if err != nil {
		t.Errorf("error creating controller: %s", err)
		t.FailNow()
	}

	// Monitor notices for "Tunnels" with count > 1, the
	// indication of tunnel establishment success

	tunnelEstablished := make(chan struct{}, 1)
	SetNoticeOutput(NewNoticeReceiver(
		func(notice []byte) {
			// TODO: log notices without logging server IPs:
			// fmt.Fprintf(os.Stderr, "%s\n", string(notice))
			count, ok := GetNoticeTunnels(notice)
			if ok && count > 0 {
				select {
				case tunnelEstablished <- *new(struct{}):
				default:
				}
			}
		}))

	// Run controller, which establishes tunnels

	shutdownBroadcast := make(chan struct{})
	controllerWaitGroup := new(sync.WaitGroup)
	controllerWaitGroup.Add(1)
	go func() {
		defer controllerWaitGroup.Done()
		controller.Run(shutdownBroadcast)
	}()

	// Test: tunnel must be established within 60 seconds

	establishTimeout := time.NewTimer(60 * time.Second)

	select {
	case <-tunnelEstablished:
	case <-establishTimeout.C:
		t.Errorf("tunnel establish timeout exceeded")
	}

	close(shutdownBroadcast)

	// Test: shutdown must complete within 10 seconds

	shutdownTimeout := time.NewTimer(10 * time.Second)

	shutdownOk := make(chan struct{}, 1)
	go func() {
		controllerWaitGroup.Wait()
		shutdownOk <- *new(struct{})
	}()

	select {
	case <-shutdownOk:
	case <-shutdownTimeout.C:
		t.Errorf("controller shutdown timeout exceeded")
	}
}
