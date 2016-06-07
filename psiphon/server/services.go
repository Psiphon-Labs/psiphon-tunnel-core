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
	"runtime"
	"sync"
	"syscall"
	"time"

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

	tunnelServer, err := NewTunnelServer(config, shutdownBroadcast)
	if err != nil {
		log.WithContextFields(LogFields{"error": err}).Error("init tunnel server failed")
		return psiphon.ContextError(err)
	}

	if config.RunLoadMonitor() {
		waitGroup.Add(1)
		go func() {
			waitGroup.Done()
			ticker := time.NewTicker(time.Duration(config.LoadMonitorPeriodSeconds) * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-shutdownBroadcast:
					return
				case <-ticker.C:
					logLoad(tunnelServer)
				}
			}
		}()
	}

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

	// The tunnel server is always run; it launches multiple
	// listeners, depending on which tunnel protocols are enabled.
	waitGroup.Add(1)
	go func() {
		defer waitGroup.Done()
		err := tunnelServer.Run()
		select {
		case errors <- err:
		default:
		}
	}()

	// An OS signal triggers an orderly shutdown
	systemStopSignal := make(chan os.Signal, 1)
	signal.Notify(systemStopSignal, os.Interrupt, os.Kill)

	// SIGUSR1 triggers a load log
	logLoadSignal := make(chan os.Signal, 1)
	signal.Notify(logLoadSignal, syscall.SIGUSR1)

	err = nil

loop:
	for {
		select {
		case <-logLoadSignal:
			logLoad(tunnelServer)
		case <-systemStopSignal:
			log.WithContext().Info("shutdown by system")
			break loop
		case err = <-errors:
			log.WithContextFields(LogFields{"error": err}).Error("service failed")
			break loop
		}
	}

	close(shutdownBroadcast)
	waitGroup.Wait()

	return err
}

func logLoad(server *TunnelServer) {

	// golang runtime stats
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	fields := LogFields{
		"NumGoroutine":        runtime.NumGoroutine(),
		"MemStats.Alloc":      memStats.Alloc,
		"MemStats.TotalAlloc": memStats.TotalAlloc,
		"MemStats.Sys":        memStats.Sys,
	}

	// tunnel server stats
	for tunnelProtocol, stats := range server.GetLoadStats() {
		for stat, value := range stats {
			fields[tunnelProtocol+"."+stat] = value
		}
	}

	log.WithContextFields(fields).Info("load")
}
