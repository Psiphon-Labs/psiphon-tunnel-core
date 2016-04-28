/*
 * Copyright (c) 2016, Psiphon Inc.
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

// Package psiphon/server implements the core tunnel functionality of a Psiphon server.
// The main function is RunServices, which runs one or all of a Psiphon API web server,
// a tunneling SSH server, and an Obfuscated SSH protocol server. The server configuration
// is created by the GenerateConfig function.
package server

import (
	"os"
	"os/signal"
	"sync"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon"
)

// RunServices initializes support functions including logging, GeoIP service, and
// redis connection pooling; and then starts the server components and runs them
// until os.Interrupt or os.Kill signals are received. The config determines
// which components are run.
func RunServices(encodedConfigs [][]byte) error {

	config, err := LoadConfig(encodedConfigs)
	if err != nil {
		log.WithContextFields(LogFields{"error": err}).Error("load config failed")
		return psiphon.ContextError(err)
	}

	err = InitLogging(config)
	if err != nil {
		log.WithContextFields(LogFields{"error": err}).Error("init logging failed")
		return psiphon.ContextError(err)
	}

	err = InitGeoIP(config)
	if err != nil {
		log.WithContextFields(LogFields{"error": err}).Error("init GeoIP failed")
		return psiphon.ContextError(err)
	}

	if config.UseRedis() {
		err = InitRedis(config)
		if err != nil {
			log.WithContextFields(LogFields{"error": err}).Error("init redis failed")
			return psiphon.ContextError(err)
		}
	}

	waitGroup := new(sync.WaitGroup)
	shutdownBroadcast := make(chan struct{})
	errors := make(chan error)

	if config.RunWebServer() {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			err := RunWebServer(config, shutdownBroadcast)
			select {
			case errors <- err:
			default:
			}
		}()
	}

	if config.RunSSHServer() {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			err := RunSSHServer(config, shutdownBroadcast)
			select {
			case errors <- err:
			default:
			}
		}()
	}

	if config.RunObfuscatedSSHServer() {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			err := RunObfuscatedSSHServer(config, shutdownBroadcast)
			select {
			case errors <- err:
			default:
			}
		}()
	}

	// An OS signal triggers an orderly shutdown
	systemStopSignal := make(chan os.Signal, 1)
	signal.Notify(systemStopSignal, os.Interrupt, os.Kill)

	err = nil

	select {
	case <-systemStopSignal:
		log.WithContext().Info("shutdown by system")
	case err = <-errors:
		log.WithContextFields(LogFields{"error": err}).Error("service failed")
	}

	close(shutdownBroadcast)
	waitGroup.Wait()

	return err
}
