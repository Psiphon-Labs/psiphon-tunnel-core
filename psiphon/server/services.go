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
	"math/rand"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"sync"
	"syscall"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/osl"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/server/psinet"
)

// RunServices initializes support functions including logging and GeoIP services;
// and then starts the server components and runs them until os.Interrupt or
// os.Kill signals are received. The config determines which components are run.
func RunServices(configJSON []byte) error {

	rand.Seed(int64(time.Now().Nanosecond()))

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

	supportServices.TunnelServer = tunnelServer

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

	// Shutdown doesn't wait for the outputProcessProfiles goroutine
	// to complete, as it may be sleeping while running a "block" or
	// CPU profile.
	signalProcessProfiles := make(chan struct{}, 1)
	go func() {
		for {
			select {
			case <-signalProcessProfiles:
				outputProcessProfiles(supportServices.Config)
			case <-shutdownBroadcast:
				return
			}
		}
	}()

	// In addition to the actual signal handling here, there is
	// a list of signals that need to be passed through panicwrap
	// in 'github.com/Psiphon-Labs/psiphon-tunnel-core/Server/main.go'
	// where 'panicwrap.Wrap' is called. The handled signals below, and the
	// list there must be kept in sync to ensure proper signal handling

	// An OS signal triggers an orderly shutdown
	systemStopSignal := make(chan os.Signal, 1)
	signal.Notify(systemStopSignal, os.Interrupt, os.Kill, syscall.SIGTERM)

	// SIGUSR1 triggers a reload of support services
	reloadSupportServicesSignal := make(chan os.Signal, 1)
	signal.Notify(reloadSupportServicesSignal, syscall.SIGUSR1)

	// SIGUSR2 triggers an immediate load log and optional process profile output
	logServerLoadSignal := make(chan os.Signal, 1)
	signal.Notify(logServerLoadSignal, syscall.SIGUSR2)

	// SIGTSTP triggers tunnelServer to stop establishing new tunnels
	stopEstablishingTunnelsSignal := make(chan os.Signal, 1)
	signal.Notify(stopEstablishingTunnelsSignal, syscall.SIGTSTP)

	// SIGCONT triggers tunnelServer to resume establishing new tunnels
	resumeEstablishingTunnelsSignal := make(chan os.Signal, 1)
	signal.Notify(resumeEstablishingTunnelsSignal, syscall.SIGCONT)

	err = nil

loop:
	for {
		select {
		case <-stopEstablishingTunnelsSignal:
			tunnelServer.SetEstablishTunnels(false)

		case <-resumeEstablishingTunnelsSignal:
			tunnelServer.SetEstablishTunnels(true)

		case <-reloadSupportServicesSignal:
			supportServices.Reload()

		case <-logServerLoadSignal:
			// Signal profiles writes first to ensure some diagnostics are
			// available in case logServerLoad hangs (which has happened
			// in the past due to a deadlock bug).
			select {
			case signalProcessProfiles <- *new(struct{}):
			default:
			}
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

func outputProcessProfiles(config *Config) {

	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	log.WithContextFields(
		LogFields{
			"num_goroutine":   runtime.NumGoroutine(),
			"alloc":           memStats.Alloc,
			"total_alloc":     memStats.TotalAlloc,
			"sys":             memStats.Sys,
			"pause_total_ns":  memStats.PauseTotalNs,
			"pause_ns":        memStats.PauseNs,
			"num_gc":          memStats.NumGC,
			"gc_cpu_fraction": memStats.GCCPUFraction,
		}).Info("runtime_stats")

	if config.ProcessProfileOutputDirectory != "" {

		openProfileFile := func(profileName string) *os.File {
			fileName := filepath.Join(
				config.ProcessProfileOutputDirectory, profileName+".profile")
			file, err := os.OpenFile(
				fileName, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0666)
			if err != nil {
				log.WithContextFields(
					LogFields{
						"error":    err,
						"fileName": fileName}).Error("open profile file failed")
				return nil
			}
			return file
		}

		writeProfile := func(profileName string) {

			file := openProfileFile(profileName)
			if file == nil {
				return
			}
			err := pprof.Lookup(profileName).WriteTo(file, 1)
			file.Close()
			if err != nil {
				log.WithContextFields(
					LogFields{
						"error":       err,
						"profileName": profileName}).Error("write profile failed")
			}
		}

		// TODO: capture https://golang.org/pkg/runtime/debug/#WriteHeapDump?
		// May not be useful in its current state, as per:
		// https://groups.google.com/forum/#!topic/golang-dev/cYAkuU45Qyw

		// Write goroutine, heap, and threadcreate profiles
		// https://golang.org/pkg/runtime/pprof/#Profile
		writeProfile("goroutine")
		writeProfile("heap")
		writeProfile("threadcreate")

		// Write block profile (after sampling)
		// https://golang.org/pkg/runtime/pprof/#Profile

		if config.ProcessBlockProfileDurationSeconds > 0 {
			log.WithContext().Info("start block profiling")
			runtime.SetBlockProfileRate(1)
			time.Sleep(
				time.Duration(config.ProcessBlockProfileDurationSeconds) * time.Second)
			runtime.SetBlockProfileRate(0)
			log.WithContext().Info("end block profiling")
			writeProfile("block")
		}

		// Write CPU profile (after sampling)
		// https://golang.org/pkg/runtime/pprof/#StartCPUProfile

		if config.ProcessCPUProfileDurationSeconds > 0 {
			file := openProfileFile("cpu")
			if file != nil {
				log.WithContext().Info("start cpu profiling")
				err := pprof.StartCPUProfile(file)
				if err != nil {
					log.WithContextFields(
						LogFields{"error": err}).Error("StartCPUProfile failed")
				} else {
					time.Sleep(time.Duration(
						config.ProcessCPUProfileDurationSeconds) * time.Second)
					pprof.StopCPUProfile()
					log.WithContext().Info("end cpu profiling")
				}
				file.Close()
			}
		}
	}
}

func logServerLoad(server *TunnelServer) {

	protocolStats, regionStats := server.GetLoadStats()

	serverLoad := LogFields{
		"event_name": "server_load",
	}
	for protocol, stats := range protocolStats {
		serverLoad[protocol] = stats
	}
	serverLoad["establish_tunnels"] = server.GetEstablishTunnels()

	log.LogRawFieldsWithTimestamp(serverLoad)

	for protocol, regions := range regionStats {
		for region, stats := range regions {

			serverRegionLoad := LogFields{
				"event_name": "server_region_load",
				"protocol":   protocol,
				"region":     region,
			}

			for name, value := range stats {
				serverRegionLoad[name] = value
			}

			log.LogRawFieldsWithTimestamp(serverRegionLoad)
		}
	}
}

// SupportServices carries common and shared data components
// across different server components. SupportServices implements a
// hot reload of traffic rules, psinet database, and geo IP database
// components, which allows these data components to be refreshed
// without restarting the server process.
type SupportServices struct {
	Config          *Config
	TrafficRulesSet *TrafficRulesSet
	OSLConfig       *osl.Config
	PsinetDatabase  *psinet.Database
	GeoIPService    *GeoIPService
	DNSResolver     *DNSResolver
	TunnelServer    *TunnelServer
}

// NewSupportServices initializes a new SupportServices.
func NewSupportServices(config *Config) (*SupportServices, error) {

	trafficRulesSet, err := NewTrafficRulesSet(config.TrafficRulesFilename)
	if err != nil {
		return nil, common.ContextError(err)
	}

	oslConfig, err := osl.NewConfig(config.OSLConfigFilename)
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
		OSLConfig:       oslConfig,
		PsinetDatabase:  psinetDatabase,
		GeoIPService:    geoIPService,
		DNSResolver:     dnsResolver,
	}, nil
}

// Reload reinitializes traffic rules, psinet database, and geo IP database
// components. If any component fails to reload, an error is logged and
// Reload proceeds, using the previous state of the component.
func (support *SupportServices) Reload() {

	reloaders := append(
		[]common.Reloader{
			support.TrafficRulesSet,
			support.OSLConfig,
			support.PsinetDatabase},
		support.GeoIPService.Reloaders()...)

	// Take these actions only after the corresponding Reloader has reloaded.
	// In both the traffic rules and OSL cases, there is some impact from state
	// reset, so the reset should be avoided where possible.
	reloadPostActions := map[common.Reloader]func(){
		support.TrafficRulesSet: func() { support.TunnelServer.ResetAllClientTrafficRules() },
		support.OSLConfig:       func() { support.TunnelServer.ResetAllClientOSLConfigs() },
	}

	for _, reloader := range reloaders {

		if !reloader.WillReload() {
			// Skip logging
			continue
		}

		// "reloaded" flag indicates if file was actually reloaded or ignored
		reloaded, err := reloader.Reload()

		if reloaded {
			if action, ok := reloadPostActions[reloader]; ok {
				action()
			}
		}

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
