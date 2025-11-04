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
	"context"
	"fmt"
	"math/rand"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"sync"
	"syscall"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/buildinfo"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/dsl"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/osl"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/packetman"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/tactics"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/tun"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/server/psinet"
	"github.com/shirou/gopsutil/v4/cpu"
)

// RunServices initializes support functions including logging and GeoIP services;
// and then starts the server components and runs them until os.Interrupt or
// os.Kill signals are received. The config determines which components are run.
func RunServices(configJSON []byte) (retErr error) {

	loggingInitialized := false

	defer func() {
		if retErr != nil && loggingInitialized {
			log.WithTraceFields(LogFields{"error": retErr}).Error("RunServices failed")
		}
	}()

	rand.Seed(int64(time.Now().Nanosecond()))

	config, err := LoadConfig(configJSON)
	if err != nil {
		return errors.Trace(err)
	}

	err = InitLogging(config)
	if err != nil {
		return errors.Trace(err)
	}

	loggingInitialized = true

	if ShouldLogProtobuf() {
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), config.metricWriterShutdownDelay)
			defer cancel()

			metricSocketWriter.Stop(ctx)
		}()
	}

	err = addHostConfig(config)
	if err != nil {
		return errors.Trace(err)
	}
	defer func() {
		err := removeHostConfig(config)
		if err != nil {
			log.WithTraceFields(LogFields{"error": retErr}).Error("removeHostConfig failed")
		}
	}()

	support, err := NewSupportServices(config)
	if err != nil {
		return errors.Trace(err)
	}

	startupFields := buildinfo.GetBuildInfo().ToMap()
	startupFields["GODEBUG"] = os.Getenv("GODEBUG")
	log.WithTraceFields(startupFields).Info("startup")

	waitGroup := new(sync.WaitGroup)
	shutdownBroadcast := make(chan struct{})
	errorChannel := make(chan error, 1)

	tunnelServer, err := NewTunnelServer(support, shutdownBroadcast)
	if err != nil {
		return errors.Trace(err)
	}

	support.TunnelServer = tunnelServer

	if config.RunPacketTunnel {

		packetTunnelServer, err := tun.NewServer(&tun.ServerConfig{
			Logger:                      CommonLogger(log),
			SudoNetworkConfigCommands:   config.PacketTunnelSudoNetworkConfigCommands,
			GetDNSResolverIPv4Addresses: support.DNSResolver.GetAllIPv4,
			GetDNSResolverIPv6Addresses: support.DNSResolver.GetAllIPv6,
			EnableDNSFlowTracking:       config.PacketTunnelEnableDNSFlowTracking,
			EgressInterface:             config.PacketTunnelEgressInterface,
			DownstreamPacketQueueSize:   config.PacketTunnelDownstreamPacketQueueSize,
			SessionIdleExpirySeconds:    config.PacketTunnelSessionIdleExpirySeconds,
			AllowBogons:                 config.AllowBogons,
		})
		if err != nil {
			return errors.Trace(err)
		}

		support.PacketTunnelServer = packetTunnelServer
	}

	if config.RunPacketManipulator {

		packetManipulatorConfig, err := makePacketManipulatorConfig(support)
		if err != nil {
			return errors.Trace(err)
		}

		packetManipulator, err := packetman.NewManipulator(packetManipulatorConfig)
		if err != nil {
			return errors.Trace(err)
		}

		support.PacketManipulator = packetManipulator
	}

	if config.DSLRelayServiceAddress != "" {
		support.dslRelay, err = dsl.NewRelay(&dsl.RelayConfig{
			Logger:                        CommonLogger(log),
			CACertificatesFilename:        config.DSLRelayCACertificatesFilename,
			HostCertificateFilename:       config.DSLRelayHostCertificateFilename,
			HostKeyFilename:               config.DSLRelayHostKeyFilename,
			GetServiceAddress:             dslMakeGetServiceAddress(support),
			HostID:                        config.HostID,
			APIParameterValidator:         getDSLAPIParameterValidator(config),
			APIParameterLogFieldFormatter: getDSLAPIParameterLogFieldFormatter(),
		})
		if err != nil {
			return errors.Trace(err)
		}

		err := dslReloadRelayTactics(support)
		if err != nil {
			return errors.Trace(err)
		}
	}

	support.discovery = makeDiscovery(support)

	// After this point, errors should be delivered to the errors channel and
	// orderly shutdown should flow through to the end of the function to ensure
	// all workers are synchronously stopped.

	if config.RunPacketTunnel {
		support.PacketTunnelServer.Start()
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			<-shutdownBroadcast
			support.PacketTunnelServer.Stop()
		}()
	}

	if config.RunPacketManipulator {
		err := support.PacketManipulator.Start()
		if err != nil {
			select {
			case errorChannel <- err:
			default:
			}
		} else {
			waitGroup.Add(1)
			go func() {
				defer waitGroup.Done()
				<-shutdownBroadcast
				support.PacketManipulator.Stop()
			}()
		}
	}

	err = support.discovery.Start()
	if err != nil {
		select {
		case errorChannel <- err:
		default:
		}
	} else {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			<-shutdownBroadcast
			support.discovery.Stop()
		}()
	}

	if config.RunLoadMonitor() {
		waitGroup.Add(1)
		go func() {
			waitGroup.Done()
			ticker := time.NewTicker(time.Duration(config.LoadMonitorPeriodSeconds) * time.Second)
			defer ticker.Stop()

			logNetworkBytes := true
			logCPU := true

			previousNetworkBytesReceived, previousNetworkBytesSent, err := getNetworkBytesTransferred()
			if err != nil {
				log.WithTraceFields(LogFields{"error": errors.Trace(err)}).Error(
					"failed to get initial network bytes transferred")

				// If getNetworkBytesTransferred fails, stop logging network
				// bytes for the lifetime of this process, in case there's a
				// persistent issue with /proc/net/dev data.

				logNetworkBytes = false
			}

			// Establish initial previous CPU stats. The previous CPU stats
			// are stored internally by gopsutil/cpu.
			_, err = getCPUPercent()
			if err != nil {
				log.WithTraceFields(LogFields{"error": errors.Trace(err)}).Error(
					"failed to get initial CPU percent")

				logCPU = false
			}

			for {
				select {
				case <-shutdownBroadcast:
					return
				case <-ticker.C:

					var networkBytesReceived, networkBytesSent int64
					if logNetworkBytes {
						currentNetworkBytesReceived, currentNetworkBytesSent, err := getNetworkBytesTransferred()
						if err != nil {
							log.WithTraceFields(LogFields{"error": errors.Trace(err)}).Error(
								"failed to get current network bytes transferred")
							logNetworkBytes = false

						} else {
							networkBytesReceived = currentNetworkBytesReceived - previousNetworkBytesReceived
							networkBytesSent = currentNetworkBytesSent - previousNetworkBytesSent

							previousNetworkBytesReceived, previousNetworkBytesSent =
								currentNetworkBytesReceived, currentNetworkBytesSent
						}
					}

					var CPUPercent float64
					if logCPU {
						recentCPUPercent, err := getCPUPercent()
						if err != nil {
							log.WithTraceFields(LogFields{"error": errors.Trace(err)}).Error(
								"failed to get recent CPU percent")
							logCPU = false

						} else {
							CPUPercent = recentCPUPercent
						}
					}

					// In the rare case that /proc/net/dev rx or tx counters
					// wrap around or are reset, networkBytesReceived or
					// networkBytesSent may be < 0. logServerLoad will not
					// log these negative values.

					logServerLoad(
						support, logNetworkBytes, networkBytesReceived, networkBytesSent, logCPU, CPUPercent)
				}
			}
		}()
	}

	if config.RunPeriodicGarbageCollection() {
		waitGroup.Add(1)
		go func() {
			waitGroup.Done()
			ticker := time.NewTicker(config.periodicGarbageCollection)
			defer ticker.Stop()
			for {
				select {
				case <-shutdownBroadcast:
					return
				case <-ticker.C:
					debug.FreeOSMemory()
				}
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
				outputProcessProfiles(support.Config, "")
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
	signal.Notify(systemStopSignal, os.Interrupt, syscall.SIGTERM)

	// SIGUSR1 triggers a reload of support services
	reloadSupportServicesSignal := makeSIGUSR1Channel()

	// SIGUSR2 triggers an immediate load log and optional process profile output
	logServerLoadSignal := makeSIGUSR2Channel()

	// SIGTSTP triggers tunnelServer to stop establishing new tunnels. The
	// in-proxy broker, if running, may also stop enqueueing announces or
	// offers.
	stopEstablishingTunnelsSignal := makeSIGTSTPChannel()

	// SIGCONT triggers tunnelServer to resume establishing new tunnels. The
	// in-proxy broker, if running, will resume enqueueing all announces and
	// offers.
	resumeEstablishingTunnelsSignal := makeSIGCONTChannel()

	err = nil

loop:
	for {
		select {
		case <-stopEstablishingTunnelsSignal:
			tunnelServer.SetEstablishTunnels(false)

			// Dump profiles when entering the load limiting state with an
			// unexpectedly low established client count, as determined by
			// DumpProfilesOnStopEstablishTunnels.
			if config.DumpProfilesOnStopEstablishTunnels(
				tunnelServer.GetEstablishedClientCount()) {

				// Run the profile dump in a goroutine and don't block this loop. Shutdown
				// doesn't wait for any running outputProcessProfiles to complete.
				go func() {
					outputProcessProfiles(support.Config, "stop_establish_tunnels")
				}()
			}

		case <-resumeEstablishingTunnelsSignal:
			tunnelServer.SetEstablishTunnels(true)

		case <-reloadSupportServicesSignal:
			support.Reload()

		case <-logServerLoadSignal:
			// Signal profiles writes first to ensure some diagnostics are
			// available in case logServerLoad hangs (which has happened
			// in the past due to a deadlock bug).
			select {
			case signalProcessProfiles <- struct{}{}:
			default:
			}
			logServerLoad(support, false, 0, 0, false, 0)

		case <-systemStopSignal:
			log.WithTrace().Info("shutdown by system")
			break loop

		case err = <-errorChannel:
			break loop
		}
	}

	// During any delayed or hung shutdown, periodically dump profiles to help
	// diagnose the cause. Shutdown doesn't wait for any running
	// outputProcessProfiles to complete.
	//
	// Wait 10 seconds before the first profile dump, and at least 10
	// seconds between profile dumps (longer when
	// ProcessCPUProfileDurationSeconds is set).
	signalProfileDumperStop := make(chan struct{})
	shutdownStartTime := time.Now()
	go func() {
		for i := 0; i < 3; i++ {
			timer := time.NewTimer(10 * time.Second)
			select {
			case <-signalProfileDumperStop:
				timer.Stop()
				return
			case <-timer.C:
			}
			filenameSuffix := fmt.Sprintf(
				"delayed_shutdown_%ds",
				time.Since(shutdownStartTime)/time.Second)
			outputProcessProfiles(support.Config, filenameSuffix)

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

	log.WithTraceFields(getRuntimeMetrics()).Info("runtime_metrics")

	if config.ProcessProfileOutputDirectory != "" {
		common.WriteRuntimeProfiles(
			CommonLogger(log),
			config.ProcessProfileOutputDirectory,
			filenameSuffix,
			config.ProcessBlockProfileDurationSeconds,
			config.ProcessCPUProfileDurationSeconds)
	}
}

// getCPUPercent returns the overall system CPU percent (not the percent used
// by this process), across all cores.
func getCPUPercent() (float64, error) {
	values, err := cpu.Percent(0, false)
	if err != nil {
		return 0, errors.Trace(err)
	}
	if len(values) != 1 {
		return 0, errors.TraceNew("unexpected cpu.Percent return value")
	}
	return values[0], nil
}

func logServerLoad(
	support *SupportServices,
	logNetworkBytes bool,
	networkBytesReceived int64,
	networkBytesSent int64,
	logCPU bool,
	CPUPercent float64) {

	serverLoad := getRuntimeMetrics()

	serverLoad["event_name"] = "server_load"

	if logNetworkBytes {

		// Negative values, which may occur due to counter wrap arounds, are
		// omitted.

		if networkBytesReceived >= 0 {
			serverLoad["network_bytes_received"] = networkBytesReceived
		}
		if networkBytesSent >= 0 {
			serverLoad["network_bytes_sent"] = networkBytesSent
		}
	}

	if logCPU {
		serverLoad["cpu_percent"] = CPUPercent
	}

	establishTunnels, establishLimitedCount :=
		support.TunnelServer.GetEstablishTunnelsMetrics()
	serverLoad["establish_tunnels"] = establishTunnels
	serverLoad["establish_tunnels_limited_count"] = establishLimitedCount

	serverLoad.Add(support.ReplayCache.GetMetrics())

	serverLoad.Add(support.ServerTacticsParametersCache.GetMetrics())

	upstreamStats, protocolStats, regionStats :=
		support.TunnelServer.GetLoadStats()

	for name, value := range upstreamStats {
		serverLoad[name] = value
	}

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

func logIrregularTunnel(
	support *SupportServices,
	listenerTunnelProtocol string,
	listenerPort int,
	peerIP string,
	tunnelError error,
	logFields LogFields) {

	if logFields == nil {
		logFields = make(LogFields)
	}

	logFields["event_name"] = "irregular_tunnel"
	logFields["listener_protocol"] = listenerTunnelProtocol
	logFields["listener_port_number"] = listenerPort
	logFields["tunnel_error"] = tunnelError.Error()

	// Note: logging with the "client_" prefix for legacy compatibility; it
	// would be more correct to use the prefix "peer_".
	support.GeoIPService.Lookup(peerIP).SetClientLogFields(logFields)

	log.LogRawFieldsWithTimestamp(logFields)
}

// SupportServices carries common and shared data components
// across different server components. SupportServices implements a
// hot reload of traffic rules, psinet database, and geo IP database
// components, which allows these data components to be refreshed
// without restarting the server process.
type SupportServices struct {
	// TODO: make all fields non-exported, none are accessed outside
	// of this package.
	Config                       *Config
	TrafficRulesSet              *TrafficRulesSet
	OSLConfig                    *osl.Config
	PsinetDatabase               *psinet.Database
	GeoIPService                 *GeoIPService
	DNSResolver                  *DNSResolver
	TunnelServer                 *TunnelServer
	PacketTunnelServer           *tun.Server
	TacticsServer                *tactics.Server
	Blocklist                    *Blocklist
	PacketManipulator            *packetman.Manipulator
	ReplayCache                  *ReplayCache
	ServerTacticsParametersCache *ServerTacticsParametersCache
	dslRelay                     *dsl.Relay
	discovery                    *Discovery
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

	geoIPService, err := NewGeoIPService(config.GeoIPDatabaseFilenames)
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
		config.TacticsConfigFilename,
		config.TacticsRequestPublicKey,
		config.TacticsRequestPrivateKey,
		config.TacticsRequestObfuscatedKey)
	if err != nil {
		return nil, errors.Trace(err)
	}

	support := &SupportServices{
		Config:          config,
		TrafficRulesSet: trafficRulesSet,
		OSLConfig:       oslConfig,
		PsinetDatabase:  psinetDatabase,
		GeoIPService:    geoIPService,
		DNSResolver:     dnsResolver,
		TacticsServer:   tacticsServer,
		Blocklist:       blocklist,
	}

	support.ReplayCache = NewReplayCache(support)

	support.ServerTacticsParametersCache =
		NewServerTacticsParametersCache(support)

	return support, nil
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

	if support.dslRelay != nil {
		reloaders = append(reloaders, support.dslRelay)
	}

	reloadDiscovery := func(reloadedTactics bool) {
		err := support.discovery.reload(reloadedTactics)
		if err != nil {
			log.WithTraceFields(
				LogFields{"error": errors.Trace(err)}).Warning(
				"failed to reload discovery")
			return
		}
	}

	// Note: established clients aren't notified when tactics change after a
	// reload; new tactics will be obtained on the next client handshake or
	// tactics request.

	reloadTactics := func() {

		// Don't use stale tactics.
		support.ReplayCache.Flush()
		support.ServerTacticsParametersCache.Flush()

		err := support.TunnelServer.ReloadTactics()
		if err != nil {
			log.WithTraceFields(
				LogFields{"error": errors.Trace(err)}).Warning(
				"failed to reload tunnel server tactics")
		}

		if support.Config.RunPacketManipulator {
			err := reloadPacketManipulationSpecs(support)
			if err != nil {
				log.WithTraceFields(
					LogFields{"error": errors.Trace(err)}).Warning(
					"failed to reload packet manipulation specs")
			}
		}

		reloadDiscovery(true)

		if support.dslRelay != nil {
			err := dslReloadRelayTactics(support)
			if err != nil {
				log.WithTraceFields(
					LogFields{"error": errors.Trace(err)}).Warning(
					"failed to reload DSL relay tactics")
			}

		}
	}

	// Take these actions only after the corresponding Reloader has reloaded.
	// In both the traffic rules and OSL cases, there is some impact from state
	// reset, so the reset should be avoided where possible.
	//
	// Note: if both tactics and psinet are reloaded at the same time and
	// the discovery strategy tactic has changed, then discovery will be reloaded
	// twice.
	reloadPostActions := map[common.Reloader]func(){
		support.TrafficRulesSet: func() { support.TunnelServer.ResetAllClientTrafficRules() },
		support.OSLConfig:       func() { support.TunnelServer.ResetAllClientOSLConfigs() },
		support.TacticsServer:   reloadTactics,
		support.PsinetDatabase:  func() { reloadDiscovery(false) },
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
			log.WithTraceFields(
				LogFields{
					"reloader": reloader.ReloadLogDescription(),
					"error":    err}).Error("reload failed")
			// Keep running with previous state
		} else {
			log.WithTraceFields(
				LogFields{
					"reloader": reloader.ReloadLogDescription(),
					"reloaded": reloaded}).Info("reload success")
		}
	}
}
