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

// Package server implements the core tunnel functionality of a Psiphon server.
// The main function is RunServices, which runs one or all of a Psiphon API web server,
// a tunneling SSH server, and an Obfuscated SSH protocol server. The server configuration
// is created by the GenerateConfig function.
package server

import (
	"fmt"
	"math/rand"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/buildinfo"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/osl"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/tactics"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/tun"
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
		return errors.Trace(err)
	}

	err = InitLogging(config)
	if err != nil {
		log.WithContextFields(LogFields{"error": err}).Error("init logging failed")
		return errors.Trace(err)
	}

	supportServices, err := NewSupportServices(config)
	if err != nil {
		log.WithContextFields(LogFields{"error": err}).Error("init support services failed")
		return errors.Trace(err)
	}

	log.WithContextFields(*buildinfo.GetBuildInfo().ToMap()).Info("startup")

	waitGroup := new(sync.WaitGroup)
	shutdownBroadcast := make(chan struct{})
	errorChannel := make(chan error)

	tunnelServer, err := NewTunnelServer(supportServices, shutdownBroadcast)
	if err != nil {
		log.WithContextFields(LogFields{"error": err}).Error("init tunnel server failed")
		return errors.Trace(err)
	}

	supportServices.TunnelServer = tunnelServer

	if config.RunPacketTunnel {

		packetTunnelServer, err := tun.NewServer(&tun.ServerConfig{
			Logger:                      CommonLogger(log),
			SudoNetworkConfigCommands:   config.PacketTunnelSudoNetworkConfigCommands,
			GetDNSResolverIPv4Addresses: supportServices.DNSResolver.GetAllIPv4,
			GetDNSResolverIPv6Addresses: supportServices.DNSResolver.GetAllIPv6,
			EgressInterface:             config.PacketTunnelEgressInterface,
			DownstreamPacketQueueSize:   config.PacketTunnelDownstreamPacketQueueSize,
			SessionIdleExpirySeconds:    config.PacketTunnelSessionIdleExpirySeconds,
		})
		if err != nil {
			log.WithContextFields(LogFields{"error": err}).Error("init packet tunnel failed")
			return errors.Trace(err)
		}

		supportServices.PacketTunnelServer = packetTunnelServer
	}

	// After this point, errors should be delivered to the errors channel and
	// orderly shutdown should flow through to the end of the function to ensure
	// all workers are synchronously stopped.

	if config.RunPacketTunnel {
		supportServices.PacketTunnelServer.Start()
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			<-shutdownBroadcast
			supportServices.PacketTunnelServer.Stop()
		}()
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

	if config.RunPeriodicGarbageCollection() {
		waitGroup.Add(1)
		go func() {
			waitGroup.Done()
			ticker := time.NewTicker(time.Duration(config.PeriodicGarbageCollectionSeconds) * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-shutdownBroadcast:
					return
				case <-ticker.C:
					runtime.GC()
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
			case errorChannel <- err:
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
		case errorChannel <- err:
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
				outputProcessProfiles(supportServices.Config, "")
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

		case err = <-errorChannel:
			log.WithContextFields(LogFields{"error": err}).Error("service failed")
			break loop
		}
	}

	// During any delayed or hung shutdown, periodically dump profiles to help
	// diagnose the cause.
	signalProfileDumperStop := make(chan struct{}, 1)
	go func() {
		tickSeconds := 10
		ticker := time.NewTicker(time.Duration(tickSeconds) * time.Second)
		defer ticker.Stop()
		for i := tickSeconds; i <= 60; i += tickSeconds {
			select {
			case <-signalProfileDumperStop:
				return
			case <-ticker.C:
				filenameSuffix := fmt.Sprintf("delayed_shutdown_%ds", i)
				outputProcessProfiles(supportServices.Config, filenameSuffix)
			}
		}
	}()

	close(shutdownBroadcast)
	waitGroup.Wait()

	close(signalProfileDumperStop)

	return err
}

func getRuntimeMetrics() LogFields {

	numGoroutine := runtime.NumGoroutine()

	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	lastGC := ""
	if memStats.LastGC > 0 {
		lastGC = time.Unix(0, int64(memStats.LastGC)).UTC().Format(time.RFC3339)
	}

	return LogFields{
		"num_goroutine": numGoroutine,
		"heap_alloc":    memStats.HeapAlloc,
		"heap_sys":      memStats.HeapSys,
		"heap_idle":     memStats.HeapIdle,
		"heap_inuse":    memStats.HeapInuse,
		"heap_released": memStats.HeapReleased,
		"heap_objects":  memStats.HeapObjects,
		"num_gc":        memStats.NumGC,
		"num_forced_gc": memStats.NumForcedGC,
		"last_gc":       lastGC,
	}
}

func outputProcessProfiles(config *Config, filenameSuffix string) {

	log.WithContextFields(getRuntimeMetrics()).Info("runtime_metrics")

	if config.ProcessProfileOutputDirectory != "" {
		common.WriteRuntimeProfiles(
			CommonLogger(log),
			config.ProcessProfileOutputDirectory,
			filenameSuffix,
			config.ProcessBlockProfileDurationSeconds,
			config.ProcessCPUProfileDurationSeconds)
	}
}

func logServerLoad(server *TunnelServer) {

	protocolStats, regionStats := server.GetLoadStats()

	serverLoad := getRuntimeMetrics()

	serverLoad["event_name"] = "server_load"

	serverLoad["establish_tunnels"] = server.GetEstablishTunnels()

	for protocol, stats := range protocolStats {
		serverLoad[protocol] = stats
	}

	log.LogRawFieldsWithTimestamp(serverLoad)

	for region, regionProtocolStats := range regionStats {

		serverLoad := LogFields{
			"event_name": "server_load",
			"region":     region,
		}

		for protocol, stats := range regionProtocolStats {
			serverLoad[protocol] = stats
		}

		log.LogRawFieldsWithTimestamp(serverLoad)
	}
}

// SupportServices carries common and shared data components
// across different server components. SupportServices implements a
// hot reload of traffic rules, psinet database, and geo IP database
// components, which allows these data components to be refreshed
// without restarting the server process.
type SupportServices struct {
	Config             *Config
	TrafficRulesSet    *TrafficRulesSet
	OSLConfig          *osl.Config
	PsinetDatabase     *psinet.Database
	GeoIPService       *GeoIPService
	DNSResolver        *DNSResolver
	TunnelServer       *TunnelServer
	PacketTunnelServer *tun.Server
	TacticsServer      *tactics.Server
	Blocklist          *Blocklist
}

// NewSupportServices initializes a new SupportServices.
func NewSupportServices(config *Config) (*SupportServices, error) {

	trafficRulesSet, err := NewTrafficRulesSet(config.TrafficRulesFilename)
	if err != nil {
		return nil, errors.Trace(err)
	}

	oslConfig, err := osl.NewConfig(config.OSLConfigFilename)
	if err != nil {
		return nil, errors.Trace(err)
	}

	psinetDatabase, err := psinet.NewDatabase(config.PsinetDatabaseFilename)
	if err != nil {
		return nil, errors.Trace(err)
	}

	geoIPService, err := NewGeoIPService(
		config.GeoIPDatabaseFilenames, config.DiscoveryValueHMACKey)
	if err != nil {
		return nil, errors.Trace(err)
	}

	dnsResolver, err := NewDNSResolver(config.DNSResolverIPAddress)
	if err != nil {
		return nil, errors.Trace(err)
	}

	blocklist, err := NewBlocklist(config.BlocklistFilename)
	if err != nil {
		return nil, errors.Trace(err)
	}

	tacticsServer, err := tactics.NewServer(
		CommonLogger(log),
		getTacticsAPIParameterLogFieldFormatter(),
		getTacticsAPIParameterValidator(config),
		config.TacticsConfigFilename)
	if err != nil {
		return nil, errors.Trace(err)
	}

	return &SupportServices{
		Config:          config,
		TrafficRulesSet: trafficRulesSet,
		OSLConfig:       oslConfig,
		PsinetDatabase:  psinetDatabase,
		GeoIPService:    geoIPService,
		DNSResolver:     dnsResolver,
		TacticsServer:   tacticsServer,
		Blocklist:       blocklist,
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
			support.PsinetDatabase,
			support.TacticsServer,
			support.Blocklist},
		support.GeoIPService.Reloaders()...)

	// Note: established clients aren't notified when tactics change after a
	// reload; new tactics will be obtained on the next client handshake or
	// tactics request.

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
