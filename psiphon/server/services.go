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

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/server/psinet"
)

// RunServices initializes support functions including logging and GeoIP services;
// and then starts the server components and runs them until os.Interrupt or
// os.Kill signals are received. The config determines which components are run.
func RunServices(configJSON []byte) error {

	config, err := LoadConfig(configJSON)
	if err != nil {
		log.WithContextFields(LogFields{"error": err}).Error("load config failed")
		return common.ContextError(err)
	}

	err = InitLogging(config)
	if err != nil {
		log.WithContextFields(LogFields{"error": err}).Error("init logging failed")
		return common.ContextError(err)
	}

	supportServices, err := NewSupportServices(config)
	if err != nil {
		log.WithContextFields(LogFields{"error": err}).Error("init support services failed")
		return common.ContextError(err)
	}

	log.WithContextFields(*common.GetBuildInfo().ToMap()).Info("startup")

	waitGroup := new(sync.WaitGroup)
	shutdownBroadcast := make(chan struct{})
	errors := make(chan error)

	tunnelServer, err := NewTunnelServer(supportServices, shutdownBroadcast)
	if err != nil {
		log.WithContextFields(LogFields{"error": err}).Error("init tunnel server failed")
		return common.ContextError(err)
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
					logServerLoad(tunnelServer)
				}
			}
		}()
	}

	if config.RunWebServer() {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			err := RunWebServer(supportServices, shutdownBroadcast)
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

	// SIGUSR1 triggers a reload of support services
	reloadSupportServicesSignal := make(chan os.Signal, 1)
	signal.Notify(reloadSupportServicesSignal, syscall.SIGUSR1)

	// SIGUSR2 triggers an immediate load log
	logServerLoadSignal := make(chan os.Signal, 1)
	signal.Notify(logServerLoadSignal, syscall.SIGUSR2)

	err = nil

loop:
	for {
		select {
		case <-reloadSupportServicesSignal:
			supportServices.Reload()
		case <-logServerLoadSignal:
			logServerLoad(tunnelServer)
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

func logServerLoad(server *TunnelServer) {

	// golang runtime stats
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	fields := LogFields{
		"BuildRev":     common.GetBuildInfo().BuildRev,
		"NumGoroutine": runtime.NumGoroutine(),
		"MemStats": map[string]interface{}{
			"Alloc":         memStats.Alloc,
			"TotalAlloc":    memStats.TotalAlloc,
			"Sys":           memStats.Sys,
			"PauseTotalNs":  memStats.PauseTotalNs,
			"PauseNs":       memStats.PauseNs,
			"NumGC":         memStats.NumGC,
			"GCCPUFraction": memStats.GCCPUFraction,
		},
	}

	// tunnel server stats
	for tunnelProtocol, stats := range server.GetLoadStats() {
		tempMap := make(map[string]interface{})
		for stat, value := range stats {
			tempMap[stat] = value
		}

		fields[tunnelProtocol] = tempMap
	}

	log.WithContextFields(fields).Info("load")
}

// SupportServices carries common and shared data components
// across different server components. SupportServices implements a
// hot reload of traffic rules, psinet database, and geo IP database
// components, which allows these data components to be refreshed
// without restarting the server process.
type SupportServices struct {
	Config          *Config
	TrafficRulesSet *TrafficRulesSet
	PsinetDatabase  *psinet.Database
	GeoIPService    *GeoIPService
	DNSResolver     *DNSResolver
}

// NewSupportServices initializes a new SupportServices.
func NewSupportServices(config *Config) (*SupportServices, error) {
	trafficRulesSet, err := NewTrafficRulesSet(config.TrafficRulesFilename)
	if err != nil {
		return nil, common.ContextError(err)
	}

	psinetDatabase, err := psinet.NewDatabase(config.PsinetDatabaseFilename)
	if err != nil {
		return nil, common.ContextError(err)
	}

	geoIPService, err := NewGeoIPService(
		config.GeoIPDatabaseFilenames, config.DiscoveryValueHMACKey)
	if err != nil {
		return nil, common.ContextError(err)
	}

	dnsResolver, err := NewDNSResolver(config.DNSResolverIPAddress)
	if err != nil {
		return nil, common.ContextError(err)
	}

	return &SupportServices{
		Config:          config,
		TrafficRulesSet: trafficRulesSet,
		PsinetDatabase:  psinetDatabase,
		GeoIPService:    geoIPService,
		DNSResolver:     dnsResolver,
	}, nil
}

// Reload reinitializes traffic rules, psinet database, and geo IP database
// components. If any component fails to reload, an error is logged and
// Reload proceeds, using the previous state of the component.
//
// Limitation: reload of traffic rules currently doesn't apply to existing,
// established clients.
func (support *SupportServices) Reload() {

	reloaders := append(
		[]common.Reloader{support.TrafficRulesSet, support.PsinetDatabase},
		support.GeoIPService.Reloaders()...)

	for _, reloader := range reloaders {

		if !reloader.WillReload() {
			// Skip logging
			continue
		}

		// "reloaded" flag indicates if file was actually reloaded or ignored
		reloaded, err := reloader.Reload()
		if err != nil {
			log.WithContextFields(
				LogFields{
					"reloader": reloader.LogDescription(),
					"error":    err}).Error("reload failed")
			// Keep running with previous state
		} else {
			log.WithContextFields(
				LogFields{
					"reloader": reloader.LogDescription(),
					"reloaded": reloaded}).Info("reload success")
		}
	}
}
