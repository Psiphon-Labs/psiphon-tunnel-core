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

// Package psiphon implements the core tunnel functionality of a Psiphon client.
// The main function is RunForever, which runs a Controller that obtains lists of
// servers, establishes tunnel connections, and runs local proxies through which
// tunneled traffic may be sent.
package psiphon

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"runtime"
	"runtime/pprof"
	"sync"
	"sync/atomic"
	"time"

	tls "github.com/Psiphon-Labs/psiphon-tls"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/inproxy"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/parameters"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/resolver"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/tactics"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/tun"
	utls "github.com/Psiphon-Labs/utls"
	"github.com/axiomhq/hyperloglog"
	lrucache "github.com/cognusion/go-cache-lru"
	"github.com/fxamacker/cbor/v2"
	"golang.org/x/time/rate"
)

// Controller is a tunnel lifecycle coordinator. It manages lists of servers to
// connect to; establishes and monitors tunnels; and runs local proxies which
// route traffic through the tunnels.
type Controller struct {
	config                                  *Config
	runCtx                                  context.Context
	stopRunning                             context.CancelFunc
	runWaitGroup                            *sync.WaitGroup
	connectedTunnels                        chan *Tunnel
	failedTunnels                           chan *Tunnel
	tunnelMutex                             sync.Mutex
	establishedOnce                         bool
	tunnelPoolSize                          int
	tunnels                                 []*Tunnel
	nextTunnel                              int
	isEstablishing                          bool
	establishStartTime                      time.Time
	protocolSelectionConstraints            *protocolSelectionConstraints
	concurrentEstablishTunnelsMutex         sync.Mutex
	establishConnectTunnelCount             int
	concurrentEstablishTunnels              int
	concurrentIntensiveEstablishTunnels     int
	peakConcurrentEstablishTunnels          int
	peakConcurrentIntensiveEstablishTunnels int
	establishInproxyForceSelectionCount     int
	establishCtx                            context.Context
	stopEstablish                           context.CancelFunc
	establishWaitGroup                      *sync.WaitGroup
	establishedTunnelsCount                 int32
	candidateServerEntries                  chan *candidateServerEntry
	untunneledDialConfig                    *DialConfig
	untunneledSplitTunnelClassifications    *lrucache.Cache
	signalFetchCommonRemoteServerList       chan struct{}
	signalFetchObfuscatedServerLists        chan struct{}
	signalUntunneledDSLFetch                chan struct{}
	signalTunneledDSLFetch                  chan struct{}
	signalDownloadUpgrade                   chan string
	signalReportServerEntries               chan *serverEntriesReportRequest
	signalReportConnected                   chan struct{}
	signalRestartEstablishing               chan struct{}
	serverAffinityDoneBroadcast             chan struct{}
	packetTunnelClient                      *tun.Client
	packetTunnelTransport                   *PacketTunnelTransport
	staggerMutex                            sync.Mutex
	resolver                                *resolver.Resolver
	steeringIPCache                         *lrucache.Cache
	tlsClientSessionCache                   utls.ClientSessionCache
	quicTLSClientSessionCache               tls.ClientSessionCache
	inproxyProxyBrokerClientManager         *InproxyBrokerClientManager
	inproxyClientBrokerClientManager        *InproxyBrokerClientManager
	inproxyNATStateManager                  *InproxyNATStateManager
	inproxyHandleTacticsMutex               sync.Mutex
	inproxyLastStoredTactics                time.Time
	establishSignalForceTacticsFetch        chan struct{}
	inproxyClientDialRateLimiter            *rate.Limiter

	serverEntryIterationMetricsMutex                    sync.Mutex
	serverEntryIterationUniqueCandidates                *hyperloglog.Sketch
	serverEntryIterationFirstFrontedMeekCandidateNumber int
	serverEntryIterationMovedToFrontCount               int

	currentNetworkMutex      sync.Mutex
	currentNetworkCtx        context.Context
	currentNetworkCancelFunc context.CancelFunc
}

// NewController initializes a new controller.
func NewController(config *Config) (controller *Controller, err error) {

	if !config.IsCommitted() {
		return nil, errors.TraceNew("uncommitted config")
	}

	// Needed by regen, at least
	rand.Seed(int64(time.Now().Nanosecond()))

	applyClientAPILevel(config)

	// The session ID for the Psiphon server API is used across all
	// tunnels established by the controller.
	NoticeSessionId(config.SessionID)

	if !config.DisableTactics {
		// Attempt to apply any valid, local stored tactics. The pre-done context
		// ensures no tactics request is attempted now.
		doneContext, cancelFunc := context.WithCancel(context.Background())
		cancelFunc()
		GetTactics(doneContext, config, true)
	}

	p := config.GetParameters().Get()
	splitTunnelClassificationTTL :=
		p.Duration(parameters.SplitTunnelClassificationTTL)
	splitTunnelClassificationMaxEntries :=
		p.Int(parameters.SplitTunnelClassificationMaxEntries)
	steeringIPCacheTTL := p.Duration(parameters.SteeringIPCacheTTL)
	steeringIPCacheMaxEntries := p.Int(parameters.SteeringIPCacheMaxEntries)

	controller = &Controller{
		config:       config,
		runWaitGroup: new(sync.WaitGroup),
		// connectedTunnels and failedTunnels buffer sizes are large enough to
		// receive full pools of tunnels without blocking. Senders should not block.
		connectedTunnels: make(chan *Tunnel, MAX_TUNNEL_POOL_SIZE),
		failedTunnels:    make(chan *Tunnel, MAX_TUNNEL_POOL_SIZE),
		tunnelPoolSize:   TUNNEL_POOL_SIZE,
		tunnels:          make([]*Tunnel, 0),
		establishedOnce:  false,
		isEstablishing:   false,

		untunneledSplitTunnelClassifications: lrucache.NewWithLRU(
			splitTunnelClassificationTTL,
			1*time.Minute,
			splitTunnelClassificationMaxEntries),

		// TODO: Add a buffer of 1 so we don't miss a signal while receiver is
		// starting? Trade-off is potential back-to-back fetch remotes. As-is,
		// establish will eventually signal another fetch remote.
		signalFetchCommonRemoteServerList: make(chan struct{}),
		signalFetchObfuscatedServerLists:  make(chan struct{}),
		signalUntunneledDSLFetch:          make(chan struct{}),
		signalTunneledDSLFetch:            make(chan struct{}),
		signalDownloadUpgrade:             make(chan string),
		signalReportConnected:             make(chan struct{}),

		// Using a buffer of 1 to ensure there's no race between the first signal
		// sent and a channel receiver initializing; a side effect is that this
		// allows 1 additional scan to enqueue while a scan is in progress, possibly
		// resulting in one unnecessary scan.
		signalReportServerEntries: make(chan *serverEntriesReportRequest, 1),

		// signalRestartEstablishing has a buffer of 1 to ensure sending the
		// signal doesn't block and receiving won't miss a signal.
		signalRestartEstablishing: make(chan struct{}, 1),

		steeringIPCache: lrucache.NewWithLRU(
			steeringIPCacheTTL,
			1*time.Minute,
			steeringIPCacheMaxEntries),

		tlsClientSessionCache:     utls.NewLRUClientSessionCache(0),
		quicTLSClientSessionCache: tls.NewLRUClientSessionCache(0),
	}

	// Initialize the current network context. This context represents the
	// lifetime of the host's current active network interface. When
	// Controller.NetworkChanged is called (by the Android and iOS platform
	// code), the previous current network interface is considered to be no
	// longer active and the corresponding current network context is canceled.
	// Components may use currentNetworkCtx to cancel and close old network
	// connections and quickly initiate new connections when the active
	// interface changes.

	controller.currentNetworkCtx, controller.currentNetworkCancelFunc =
		context.WithCancel(context.Background())

	// Initialize untunneledDialConfig, used by untunneled dials including
	// remote server list and upgrade downloads.
	controller.untunneledDialConfig = &DialConfig{
		UpstreamProxyURL: controller.config.UpstreamProxyURL,
		CustomHeaders:    controller.config.CustomHeaders,
		DeviceBinder:     controller.config.deviceBinder,
		IPv6Synthesizer:  controller.config.IPv6Synthesizer,
		ResolveIP: func(ctx context.Context, hostname string) ([]net.IP, error) {
			// Note: when domain fronting would be used for untunneled dials a
			// copy of untunneledDialConfig should be used instead, which
			// redefines ResolveIP such that the corresponding fronting
			// provider ID is passed into UntunneledResolveIP to enable the use
			// of pre-resolved IPs.
			IPs, err := UntunneledResolveIP(
				ctx, controller.config, controller.resolver, hostname, "")
			if err != nil {
				return nil, errors.Trace(err)
			}
			return IPs, nil
		},
		TrustedCACertificatesFilename: controller.config.TrustedCACertificatesFilename,
	}

	if config.PacketTunnelTunFileDescriptor > 0 {

		// Run a packet tunnel client. The lifetime of the tun.Client is the
		// lifetime of the Controller, so it exists across tunnel establishments
		// and reestablishments. The PacketTunnelTransport provides a layer
		// that presents a continuosuly existing transport to the tun.Client;
		// it's set to use new SSH channels after new SSH tunnel establishes.

		packetTunnelTransport := NewPacketTunnelTransport()

		packetTunnelClient, err := tun.NewClient(&tun.ClientConfig{
			Logger:                    NoticeCommonLogger(false),
			TunFileDescriptor:         config.PacketTunnelTunFileDescriptor,
			TransparentDNSIPv4Address: config.PacketTunnelTransparentDNSIPv4Address,
			TransparentDNSIPv6Address: config.PacketTunnelTransparentDNSIPv6Address,
			Transport:                 packetTunnelTransport,
		})
		if err != nil {
			return nil, errors.Trace(err)
		}

		controller.packetTunnelClient = packetTunnelClient
		controller.packetTunnelTransport = packetTunnelTransport
	}

	// Initialize shared in-proxy broker clients to be used for all in-proxy
	// client dials and in-proxy proxy operations.
	//
	// Using shared broker connections minimizes the overhead of establishing
	// broker connections at the start of an in-proxy dial or operation. By
	// design, established broker connections will be retained for up to the
	// entire lifetime of the controller run, so past the end of client
	// tunnel establishment.
	//
	// No network operations are performed by NewInproxyBrokerClientManager or
	// NewInproxyNATStateManager; each manager operates on demand, when
	// in-proxy dials or operations are invoked.
	//
	// The controller run may include client tunnel establishment, in-proxy
	// proxy operations, or both.
	//
	// Due to the inproxy.InitiatorSessions.NewRoundTrip waitToShareSession
	// application-level round trip limitation, there is one broker client
	// manager for each of the client and proxy cases, so that neither
	// initially blocks while trying to share the others session.
	//
	// One NAT state manager is shared between both the in-proxy client and
	// proxy. While each may have different network discovery policies, any
	// discovered network state is valid and useful for both consumers.

	// Both broker client and NAT state managers may require resets and update
	// when tactics change.
	var tacticAppliedReceivers []TacticsAppliedReceiver

	isProxy := false
	controller.inproxyClientBrokerClientManager = NewInproxyBrokerClientManager(config, isProxy, controller.tlsClientSessionCache)
	tacticAppliedReceivers = append(tacticAppliedReceivers, controller.inproxyClientBrokerClientManager)
	controller.inproxyNATStateManager = NewInproxyNATStateManager(config)
	tacticAppliedReceivers = append(tacticAppliedReceivers, controller.inproxyNATStateManager)

	if config.InproxyEnableProxy {
		isProxy = true
		controller.inproxyProxyBrokerClientManager = NewInproxyBrokerClientManager(config, isProxy, controller.tlsClientSessionCache)
		tacticAppliedReceivers = append(tacticAppliedReceivers, controller.inproxyProxyBrokerClientManager)
	}

	controller.config.SetTacticsAppliedReceivers(tacticAppliedReceivers)
	controller.config.SetSignalComponentFailure(controller.SignalComponentFailure)
	controller.config.SetServerEntryIterationMetricsUpdater(controller.updateServerEntryIterationResetMetrics)

	return controller, nil
}

// Run executes the controller. Run exits if a controller
// component fails or the parent context is canceled.
func (controller *Controller) Run(ctx context.Context) {

	if controller.config.LimitCPUThreads {
		runtime.GOMAXPROCS(1)
	}

	pprofRun()

	// Ensure fresh repetitive notice state for each run, so the
	// client will always get an AvailableEgressRegions notice,
	// an initial instance of any repetitive error notice, etc.
	ResetRepetitiveNotices()

	runCtx, stopRunning := context.WithCancel(ctx)
	defer stopRunning()

	controller.runCtx = runCtx
	controller.stopRunning = stopRunning

	// Start components

	// Initialize a single resolver to be used by all dials. Sharing a single
	// resolver ensures cached results are shared, and that network state
	// query overhead is amortized over all dials. Multiple dials can resolve
	// domain concurrently.
	//
	// config.SetResolver makes this resolver available to MakeDialParameters.
	controller.resolver = NewResolver(controller.config, true)
	defer controller.resolver.Stop()
	controller.config.SetResolver(controller.resolver)

	// Maintain a cache of steering IPs to be applied to dials. A steering IP
	// is an alternate dial IP; for example, steering IPs may be specified by
	// a CDN service and used to load balance CDN traffic.
	controller.steeringIPCache.Flush()

	// TODO: IPv6 support
	var listenIP string
	if controller.config.ListenInterface == "" {
		listenIP = "127.0.0.1"
	} else if controller.config.ListenInterface == "any" {
		listenIP = "0.0.0.0"
	} else {
		IPv4Address, _, err := common.GetInterfaceIPAddresses(controller.config.ListenInterface)
		if err == nil && IPv4Address == nil {
			err = fmt.Errorf("no IPv4 address for interface %s", controller.config.ListenInterface)
		}
		if err != nil {
			NoticeError("error getting listener IP: %v", errors.Trace(err))
			return
		}
		listenIP = IPv4Address.String()
	}

	// The controller run may include client tunnel establishment, in-proxy
	// proxy operations, or both. Local tactics are shared between both modes
	// and both modes can fetch tactics.
	//
	// Limitation: the upgrade downloader is not enabled when client tunnel
	// establishment is disabled; upgrade version information is not
	// currently distributed to in-proxy proxies

	if !controller.config.DisableTunnels {

		if !controller.config.DisableLocalSocksProxy {
			socksProxy, err := NewSocksProxy(controller.config, controller, listenIP)
			if err != nil {
				NoticeError("error initializing local SOCKS proxy: %v", errors.Trace(err))
				return
			}
			defer socksProxy.Close()
		}

		if !controller.config.DisableLocalHTTPProxy {
			httpProxy, err := NewHttpProxy(controller.config, controller, listenIP)
			if err != nil {
				NoticeError("error initializing local HTTP proxy: %v", errors.Trace(err))
				return
			}
			defer httpProxy.Close()
		}

		if controller.config.EnableUpgradeDownload {
			controller.runWaitGroup.Add(1)
			go controller.upgradeDownloader()
		}

		controller.runWaitGroup.Add(1)
		go controller.serverEntriesReporter()

		controller.runWaitGroup.Add(1)
		go controller.connectedReporter()

		controller.runWaitGroup.Add(1)
		go controller.establishTunnelWatcher()

		controller.runWaitGroup.Add(1)
		go controller.runTunnels()

		if controller.packetTunnelClient != nil {
			controller.packetTunnelClient.Start()
		}
	}

	if !controller.config.DisableRemoteServerListFetcher {

		if controller.config.RemoteServerListURLs != nil {
			controller.runWaitGroup.Add(1)
			go controller.remoteServerListFetcher(
				"common",
				FetchCommonRemoteServerList,
				controller.signalFetchCommonRemoteServerList)
		}

		if controller.config.ObfuscatedServerListRootURLs != nil {
			controller.runWaitGroup.Add(1)
			go controller.remoteServerListFetcher(
				"obfuscated",
				FetchObfuscatedServerLists,
				controller.signalFetchObfuscatedServerLists)
		}
	}

	if !controller.config.DisableDSLFetcher {

		controller.runWaitGroup.Add(1)
		go func() {
			defer controller.runWaitGroup.Done()
			runUntunneledDSLFetcher(
				controller.runCtx,
				controller.config,
				controller.inproxyClientBrokerClientManager,
				controller.signalUntunneledDSLFetch)
		}()

		controller.runWaitGroup.Add(1)
		go func() {
			defer controller.runWaitGroup.Done()
			runTunneledDSLFetcher(
				controller.runCtx,
				controller.config,
				controller.getNextActiveTunnel,
				controller.signalTunneledDSLFetch)
		}()
	}

	if controller.config.InproxyEnableProxy {
		controller.runWaitGroup.Add(1)
		go controller.runInproxyProxy()
	}

	// Wait while running

	<-controller.runCtx.Done()
	NoticeInfo("controller stopped")

	// To assist with diagnosing unexpected shutdown hangs, log a goroutine
	// profile if the wait operation runs over a deadline. This diagnostic
	// goroutine is intentially not awaited on.
	signalDoneShutdown := make(chan struct{})
	go func() {
		deadlineSeconds := 60
		if controller.config.ShutdownGoroutineProfileDeadlineSeconds != nil {
			deadlineSeconds = *controller.config.ShutdownGoroutineProfileDeadlineSeconds
		}
		if deadlineSeconds == 0 {
			return
		}
		timer := time.NewTimer(time.Duration(deadlineSeconds) * time.Second)
		defer timer.Stop()
		select {
		case <-signalDoneShutdown:
			return
		case <-timer.C:
		}
		pprof.Lookup("goroutine").WriteTo(
			NewNoticeLineWriter("Goroutine"), 1)
	}()

	// Shutdown

	if controller.packetTunnelClient != nil {
		controller.packetTunnelClient.Stop()
	}

	// Cleanup current network context
	controller.currentNetworkCancelFunc()

	// All workers -- runTunnels, establishment workers, and auxilliary
	// workers such as fetch remote server list and untunneled uprade
	// download -- operate with the controller run context and will all
	// be interrupted when the run context is done.
	controller.runWaitGroup.Wait()

	close(signalDoneShutdown)

	NoticeInfo("exiting controller")

	NoticeExiting()
}

// SignalComponentFailure notifies the controller that an associated component has failed.
// This will terminate the controller.
func (controller *Controller) SignalComponentFailure() {
	NoticeWarning("controller shutdown due to component failure")
	controller.stopRunning()
}

// SetDynamicConfig overrides the sponsor ID and authorizations fields of the
// Controller config with the input values. The new values will be used in the
// next tunnel connection.
func (controller *Controller) SetDynamicConfig(sponsorID string, authorizations []string) {
	controller.config.SetDynamicConfig(sponsorID, authorizations)
}

// NetworkChanged initiates a reset of all open network connections, including
// a tunnel reconnect, if one is running, as well as terminating any in-proxy
// proxy connections.
func (controller *Controller) NetworkChanged() {

	// Explicitly reset components that don't use the current network context.

	controller.TerminateNextActiveTunnel()

	if controller.inproxyProxyBrokerClientManager != nil {
		err := controller.inproxyProxyBrokerClientManager.NetworkChanged()
		if err != nil {
			NoticeError("NetworkChanged failed: %v", errors.Trace(err))
			// Log and continue running.
		}

	}
	err := controller.inproxyClientBrokerClientManager.NetworkChanged()
	if err != nil {
		NoticeError("NetworkChanged failed: %v", errors.Trace(err))
		// Log and continue running.
	}

	controller.config.networkIDGetter.FlushCache()

	// Cancel the previous current network context, which will interrupt any
	// operations using this context. Then create a new context for the new
	// current network.

	controller.currentNetworkMutex.Lock()
	defer controller.currentNetworkMutex.Unlock()

	controller.currentNetworkCancelFunc()

	controller.currentNetworkCtx, controller.currentNetworkCancelFunc =
		context.WithCancel(context.Background())
}

func (controller *Controller) getCurrentNetworkContext() context.Context {
	controller.currentNetworkMutex.Lock()
	defer controller.currentNetworkMutex.Unlock()

	return controller.currentNetworkCtx
}

// TerminateNextActiveTunnel terminates the active tunnel, which will initiate
// establishment of a new tunnel.
func (controller *Controller) TerminateNextActiveTunnel() {
	tunnel := controller.getNextActiveTunnel()
	if tunnel != nil {
		controller.SignalTunnelFailure(tunnel)
		NoticeInfo("terminated tunnel: %s", tunnel.dialParams.ServerEntry.GetDiagnosticID())
	}
}

// ExportExchangePayload creates a payload for client-to-client server
// connection info exchange. See the comment for psiphon.ExportExchangePayload
// for more details.
func (controller *Controller) ExportExchangePayload() string {
	return ExportExchangePayload(controller.config)
}

// ImportExchangePayload imports a payload generated by ExportExchangePayload.
// See the comment for psiphon.ImportExchangePayload for more details about
// the import.
//
// When the import is successful, a signal is set to trigger a restart any
// establishment in progress. This will cause the newly imported server entry
// to be prioritized, which it otherwise would not be in later establishment
// rounds. The establishment process continues after ImportExchangePayload
// returns.
//
// If the client already has a connected tunnel, or a tunnel connection is
// established concurrently with the import, the signal has no effect as the
// overall goal is establish _any_ connection.
func (controller *Controller) ImportExchangePayload(payload string) bool {

	// Race condition: if a new tunnel connection is established concurrently
	// with the import, either that tunnel's server entry of the imported server
	// entry may end up as the affinity server.

	ok := ImportExchangePayload(controller.config, payload)
	if !ok {
		return false
	}

	select {
	case controller.signalRestartEstablishing <- struct{}{}:
	default:
	}

	return true
}

// remoteServerListFetcher fetches an out-of-band list of server entries
// for more tunnel candidates. It fetches when signalled, with retries
// on failure.
func (controller *Controller) remoteServerListFetcher(
	name string,
	fetcher RemoteServerListFetcher,
	signal <-chan struct{}) {

	defer controller.runWaitGroup.Done()

	var lastFetchTime time.Time

fetcherLoop:
	for {
		// Wait for a signal before fetching
		select {
		case <-signal:
		case <-controller.runCtx.Done():
			break fetcherLoop
		}

		// Skip fetch entirely (i.e., send no request at all, even when ETag would save
		// on response size) when a recent fetch was successful

		stalePeriod := controller.config.GetParameters().Get().Duration(
			parameters.FetchRemoteServerListStalePeriod)

		if !lastFetchTime.IsZero() &&
			lastFetchTime.Add(stalePeriod).After(time.Now()) {
			continue
		}

	retryLoop:
		for attempt := 0; ; attempt++ {
			// Don't attempt to fetch while there is no network connectivity,
			// to avoid alert notice noise.
			if !WaitForNetworkConnectivity(
				controller.runCtx,
				controller.config.NetworkConnectivityChecker,
				nil) {
				break fetcherLoop
			}

			// Pick any active tunnel and make the next fetch attempt. If there's
			// no active tunnel, the untunneledDialConfig will be used.
			tunnel := controller.getNextActiveTunnel()

			err := fetcher(
				controller.runCtx,
				controller.config,
				attempt,
				tunnel,
				controller.untunneledDialConfig,
				controller.tlsClientSessionCache)

			if err == nil {
				lastFetchTime = time.Now()
				break retryLoop
			}

			NoticeWarning("failed to fetch %s remote server list: %v",
				name, errors.Trace(err))

			retryPeriod := controller.config.GetParameters().Get().Duration(
				parameters.FetchRemoteServerListRetryPeriod)

			timer := time.NewTimer(retryPeriod)
			select {
			case <-timer.C:
			case <-controller.runCtx.Done():
				timer.Stop()
				break fetcherLoop
			}
		}
	}

	NoticeInfo("exiting %s remote server list fetcher", name)
}

// upgradeDownloader makes periodic attempts to complete a client upgrade
// download. DownloadUpgrade() is resumable, so each attempt has potential for
// getting closer to completion, even in conditions where the download or
// tunnel is repeatedly interrupted.
// An upgrade download is triggered by either a handshake response indicating
// that a new version is available; or after failing to connect, in which case
// it's useful to check, out-of-band, for an upgrade with new circumvention
// capabilities.
// Once the download operation completes successfully, the downloader exits
// and is not run again: either there is not a newer version, or the upgrade
// has been downloaded and is ready to be applied.
// We're assuming that the upgrade will be applied and the entire system
// restarted before another upgrade is to be downloaded.
//
// TODO: refactor upgrade downloader and remote server list fetcher to use
// common code (including the resumable download routines).
func (controller *Controller) upgradeDownloader() {
	defer controller.runWaitGroup.Done()

	var lastDownloadTime time.Time

downloadLoop:
	for {
		// Wait for a signal before downloading
		var handshakeVersion string
		select {
		case handshakeVersion = <-controller.signalDownloadUpgrade:
		case <-controller.runCtx.Done():
			break downloadLoop
		}

		stalePeriod := controller.config.GetParameters().Get().Duration(
			parameters.FetchUpgradeStalePeriod)

		// Unless handshake is explicitly advertizing a new version, skip
		// checking entirely when a recent download was successful.
		if handshakeVersion == "" &&
			!lastDownloadTime.IsZero() &&
			lastDownloadTime.Add(stalePeriod).After(time.Now()) {
			continue
		}

	retryLoop:
		for attempt := 0; ; attempt++ {
			// Don't attempt to download while there is no network connectivity,
			// to avoid alert notice noise.
			if !WaitForNetworkConnectivity(
				controller.runCtx,
				controller.config.NetworkConnectivityChecker,
				nil) {
				break downloadLoop
			}

			// Pick any active tunnel and make the next download attempt. If there's
			// no active tunnel, the untunneledDialConfig will be used.
			tunnel := controller.getNextActiveTunnel()

			err := DownloadUpgrade(
				controller.runCtx,
				controller.config,
				attempt,
				handshakeVersion,
				tunnel,
				controller.untunneledDialConfig,
				controller.tlsClientSessionCache)

			if err == nil {
				lastDownloadTime = time.Now()
				break retryLoop
			}

			NoticeWarning("failed to download upgrade: %v", errors.Trace(err))

			timeout := controller.config.GetParameters().Get().Duration(
				parameters.FetchUpgradeRetryPeriod)

			timer := time.NewTimer(timeout)
			select {
			case <-timer.C:
			case <-controller.runCtx.Done():
				timer.Stop()
				break downloadLoop
			}
		}
	}

	NoticeInfo("exiting upgrade downloader")
}

type serverEntriesReportRequest struct {
	constraints *protocolSelectionConstraints
}

// serverEntriesReporter performs scans over all server entries to report on
// available tunnel candidates, subject to protocol selection constraints, and
// available egress regions.
//
// Because scans may be slow, depending on the client device and server entry
// list size, serverEntriesReporter is used to perform asychronous, background
// operations that would otherwise block establishment. This includes emitting
// diagnotic notices that are informational (CandidateServers) or which do not
// need to emit before establishment starts (AvailableEgressRegions).
//
// serverEntriesReporter also serves to combine these scans, which would
// otherwise be logically independent, due to the performance impact of scans.
//
// Limitation: The underlying datastore implementation _may_ block write
// transactions while there are open read transactions. For example, bolt
// write transactions which need to re-map the data file (when the datastore
// grows) will block on open read transactions. In these scenarios, a slow
// scan will still block other operations.
//
// serverEntriesReporter runs beyond the establishment phase, since it's
// important for notices such as AvailableEgressRegions to eventually emit
// even if already established. serverEntriesReporter scans are cancellable,
// so controller shutdown is not blocked by slow scans.
func (controller *Controller) serverEntriesReporter() {
	defer controller.runWaitGroup.Done()

loop:
	for {

		var request *serverEntriesReportRequest

		select {
		case request = <-controller.signalReportServerEntries:
		case <-controller.runCtx.Done():
			break loop
		}

		egressRegion := controller.config.EgressRegion
		constraints := request.constraints

		regions := make(map[string]bool)

		initialCandidates := 0
		candidates := 0

		callback := func(serverEntry *protocol.ServerEntry) bool {

			// In establishment, excludeIntensive depends on what set of protocols are
			// already being dialed. For these reports, don't exclude intensive
			// protocols as any intensive candidate can always be an available
			// candidate at some point.
			excludeIntensive := false

			isInitialCandidate := constraints.isInitialCandidate(excludeIntensive, serverEntry)
			isCandidate := constraints.isCandidate(excludeIntensive, serverEntry)

			if egressRegion == "" || serverEntry.Region == egressRegion {
				if isInitialCandidate {
					initialCandidates += 1
				}
				if isCandidate {
					candidates += 1
				}
			}

			isAvailable := isCandidate
			if constraints.hasInitialProtocols() {
				// Available egress regions is subject to an initial limit constraint, if
				// present: see AvailableEgressRegions comment in launchEstablishing.
				isAvailable = isInitialCandidate
			}

			if isAvailable {
				// Ignore server entries with no region field.
				if serverEntry.Region != "" {
					regions[serverEntry.Region] = true
				}
			}

			select {
			case <-controller.runCtx.Done():
				// Don't block controller shutdown: cancel the scan.
				return false
			default:
				return true
			}
		}

		startTime := time.Now()

		err := ScanServerEntries(callback)
		if err != nil {
			NoticeWarning("ScanServerEntries failed: %v", errors.Trace(err))
			continue
		}

		// Report this duration in CandidateServers as an indication of datastore
		// performance.
		duration := time.Since(startTime)

		NoticeCandidateServers(
			controller.config.EgressRegion,
			constraints,
			initialCandidates,
			candidates,
			duration)

		availableEgressRegions := make([]string, 0, len(regions))
		for region := range regions {
			availableEgressRegions = append(availableEgressRegions, region)
		}

		NoticeAvailableEgressRegions(
			availableEgressRegions)
	}

	NoticeInfo("exiting server entries reporter")
}

// signalServerEntriesReporter triggers a new server entry report.The report
// is considered to be informational and may or may not run, depending on
// whether another run is already in progress.
func (controller *Controller) signalServerEntriesReporter(
	request *serverEntriesReportRequest) {

	select {
	case controller.signalReportServerEntries <- request:
	default:
	}
}

// connectedReporter sends periodic "connected" requests to the Psiphon API.
// These requests are for server-side unique user stats calculation. See the
// comment in DoConnectedRequest for a description of the request mechanism.
//
// To correctly count daily unique users, only one connected request is made
// across all simultaneous multi-tunnels; and the connected request is
// repeated every 24h.
//
// The signalReportConnected mechanism is used to trigger a connected request
// immediately after a reconnect. While strictly only one connected request
// per 24h is required in order to count daily unique users, the connected
// request also delivers the establishment duration metric (which includes
// time elapsed performing the handshake request) and additional fragmentation
// metrics; these metrics are measured for each tunnel.
func (controller *Controller) connectedReporter() {
	defer controller.runWaitGroup.Done()

	// session is nil when DisableApi is set
	if controller.config.DisableApi {
		return
	}

	select {
	case <-controller.signalReportConnected:
		// Make the initial connected request
	case <-controller.runCtx.Done():
		return
	}

loop:
	for {

		// Pick any active tunnel and make the next connected request. No error is
		// logged if there's no active tunnel, as that's not an unexpected
		// condition.
		reported := false
		tunnel := controller.getNextActiveTunnel()
		if tunnel != nil {
			err := tunnel.serverContext.DoConnectedRequest()
			if err == nil {
				reported = true
			} else {
				NoticeWarning("failed to make connected request: %v",
					errors.Trace(err))
			}
		}

		// Schedule the next connected request and wait. This duration is not a
		// dynamic ClientParameter as the daily unique user stats logic specifically
		// requires a "connected" request no more or less often than every 24h.
		var duration time.Duration
		if reported {
			duration = 24 * time.Hour
		} else {
			duration = controller.config.GetParameters().Get().Duration(
				parameters.PsiphonAPIConnectedRequestRetryPeriod)
		}
		timer := time.NewTimer(duration)
		doBreak := false
		select {
		case <-controller.signalReportConnected:
		case <-timer.C:
			// Make another connected request
		case <-controller.runCtx.Done():
			doBreak = true
		}
		timer.Stop()
		if doBreak {
			break loop
		}
	}

	NoticeInfo("exiting connected reporter")
}

func (controller *Controller) signalConnectedReporter() {

	// session is nil when DisableApi is set
	if controller.config.DisableApi {
		return
	}

	select {
	case controller.signalReportConnected <- struct{}{}:
	default:
	}
}

// establishTunnelWatcher terminates the controller if a tunnel
// has not been established in the configured time period. This
// is regardless of how many tunnels are presently active -- meaning
// that if an active tunnel was established and lost the controller
// is left running (to re-establish).
func (controller *Controller) establishTunnelWatcher() {
	defer controller.runWaitGroup.Done()

	timeout := controller.config.GetParameters().Get().Duration(
		parameters.EstablishTunnelTimeout)

	if timeout > 0 {
		timer := time.NewTimer(timeout)
		defer timer.Stop()

		select {
		case <-timer.C:
			if !controller.hasEstablishedOnce() {
				NoticeEstablishTunnelTimeout(timeout)
				controller.SignalComponentFailure()
			}
		case <-controller.runCtx.Done():
		}
	}

	NoticeInfo("exiting establish tunnel watcher")
}

// runTunnels is the controller tunnel management main loop. It starts and stops
// establishing tunnels based on the target tunnel pool size and the current size
// of the pool. Tunnels are established asynchronously using worker goroutines.
//
// When there are no server entries for the target region/protocol, the
// establishCandidateGenerator will yield no candidates and wait before
// trying again. In the meantime, a remote server entry fetch may supply
// valid candidates.
//
// When a tunnel is established, it's added to the active pool. The tunnel's
// operateTunnel goroutine monitors the tunnel.
//
// When a tunnel fails, it's removed from the pool and the establish process is
// restarted to fill the pool.
func (controller *Controller) runTunnels() {
	defer controller.runWaitGroup.Done()

	// Start running

	controller.startEstablishing()
loop:
	for {
		select {

		case <-controller.signalRestartEstablishing:

			// signalRestartEstablishing restarts any establishment in progress. One
			// use case for this is to prioritize a newly imported, exchanged server
			// entry, which will be in the affinity position.
			//
			// It's possible for another connection to establish concurrent to signalling;
			// since the overall goal remains to establish _any_ connection, we accept that
			// in some cases the exchanged server entry may not get used.

			if controller.isEstablishing {
				controller.stopEstablishing()
				controller.startEstablishing()
			}

		case failedTunnel := <-controller.failedTunnels:
			NoticeWarning("tunnel failed: %s", failedTunnel.dialParams.ServerEntry.GetDiagnosticID())
			controller.terminateTunnel(failedTunnel)

			// Clear the reference to this tunnel before calling startEstablishing,
			// which will invoke a garbage collection.
			failedTunnel = nil

			// Concurrency note: only this goroutine may call startEstablishing/stopEstablishing,
			// which reference controller.isEstablishing.
			controller.startEstablishing()

		case connectedTunnel := <-controller.connectedTunnels:

			// Tunnel establishment has two phases: connection and activation.
			//
			// Connection is run concurrently by the establishTunnelWorkers, to minimize
			// delay when it's not yet known which server and protocol will be available
			// and unblocked.
			//
			// Activation is run serially, here, to minimize the overhead of making a
			// handshake request and starting the operateTunnel management worker for a
			// tunnel which may be discarded.
			//
			// When the active tunnel will complete establishment, establishment is
			// stopped before activation. This interrupts all connecting tunnels and
			// garbage collects their memory. The purpose is to minimize memory
			// pressure when the handshake request is made. In the unlikely case that the
			// handshake fails, establishment is restarted.
			//
			// Any delays in stopEstablishing will delay the handshake for the last
			// active tunnel.
			//
			// In the typical case of tunnelPoolSize of 1, only a single handshake is
			// performed and the homepages notices file, when used, will not be modifed
			// after the NoticeTunnels(1) [i.e., connected] until NoticeTunnels(0) [i.e.,
			// disconnected]. For tunnelPoolSize > 1, serial handshakes only ensures that
			// each set of emitted NoticeHomepages is contiguous.

			active, outstanding := controller.numTunnels()

			// discardTunnel will be true here when already fully established.

			discardTunnel := (outstanding <= 0)
			isFirstTunnel := (active == 0)
			isLastTunnel := (outstanding == 1)

			if !discardTunnel {

				if isLastTunnel {
					controller.stopEstablishing()
				}

				// In the case of multi-tunnels, only the first tunnel will send status requests,
				// including transfer stats (domain bytes), persistent stats, and prune checks.
				// While transfer stats and persistent stats use a "take out" scheme that would
				// allow for multiple, concurrent requesters, the prune check does not.

				isStatusReporter := isFirstTunnel

				err := connectedTunnel.Activate(
					controller.runCtx, controller, isStatusReporter)

				if err != nil {
					NoticeWarning("failed to activate %s: %v",
						connectedTunnel.dialParams.ServerEntry.GetDiagnosticID(),
						errors.Trace(err))
					discardTunnel = true
				} else {
					// It's unlikely that registerTunnel will fail, since only this goroutine
					// calls registerTunnel -- and after checking numTunnels; so failure is not
					// expected.
					if !controller.registerTunnel(connectedTunnel) {
						NoticeWarning("failed to register %s: %v",
							connectedTunnel.dialParams.ServerEntry.GetDiagnosticID(),
							errors.Trace(err))
						discardTunnel = true
					}
				}

				// May need to replace this tunnel
				if isLastTunnel && discardTunnel {
					controller.startEstablishing()
				}

			}

			if discardTunnel {
				controller.discardTunnel(connectedTunnel)

				// Clear the reference to this discarded tunnel and immediately run
				// a garbage collection to reclaim its memory.
				connectedTunnel = nil
				DoGarbageCollection()

				// Skip the rest of this case
				break
			}

			atomic.AddInt32(&controller.establishedTunnelsCount, 1)

			NoticeActiveTunnel(
				connectedTunnel.dialParams.ServerEntry.GetDiagnosticID(),
				connectedTunnel.dialParams.TunnelProtocol)

			NoticeConnectedServerRegion(connectedTunnel.dialParams.ServerEntry.Region)

			if isFirstTunnel {

				// Signal a connected request on each 1st tunnel establishment. For
				// multi-tunnels, the session is connected as long as at least one
				// tunnel is established.
				controller.signalConnectedReporter()

				// Signal a tunneled DSL fetch. The tunneled fetch is similar
				// to the handshake API discovery mechanism:
				// opportunistically distribute a small number of new server
				// entries to clients that are already able to connect.
				select {
				case controller.signalTunneledDSLFetch <- struct{}{}:
				default:
				}

				// If the handshake indicated that a new client version is available,
				// trigger an upgrade download.
				// Note: serverContext is nil when DisableApi is set
				if connectedTunnel.serverContext != nil &&
					connectedTunnel.serverContext.clientUpgradeVersion != "" {

					handshakeVersion := connectedTunnel.serverContext.clientUpgradeVersion
					select {
					case controller.signalDownloadUpgrade <- handshakeVersion:
					default:
					}
				}
			}

			// Set the new tunnel as the transport for the packet tunnel. The packet tunnel
			// client remains up when reestablishing, but no packets are relayed while there
			// is no connected tunnel. UseTunnel will establish a new packet tunnel SSH
			// channel over the new SSH tunnel and configure the packet tunnel client to use
			// the new SSH channel as its transport.
			//
			// Note: as is, this logic is suboptimal for tunnelPoolSize > 1, as this would
			// continuously initialize new packet tunnel sessions for each established
			// server. For now, config validation requires tunnelPoolSize == 1 when
			// the packet tunnel is used.

			if controller.packetTunnelTransport != nil {
				controller.packetTunnelTransport.UseTunnel(connectedTunnel)
			}

			if controller.isFullyEstablished() {
				controller.stopEstablishing()
			}

		case <-controller.runCtx.Done():
			break loop
		}
	}

	// Stop running

	controller.stopEstablishing()
	controller.terminateAllTunnels()

	// Drain tunnel channels
	close(controller.connectedTunnels)
	for tunnel := range controller.connectedTunnels {
		controller.discardTunnel(tunnel)
	}
	close(controller.failedTunnels)
	for tunnel := range controller.failedTunnels {
		controller.discardTunnel(tunnel)
	}

	NoticeInfo("exiting run tunnels")
}

// SignalSeededNewSLOK implements the TunnelOwner interface. This function
// is called by Tunnel.operateTunnel when the tunnel has received a new,
// previously unknown SLOK from the server. The Controller triggers an OSL
// fetch, as the new SLOK may be sufficient to access new OSLs.
func (controller *Controller) SignalSeededNewSLOK() {
	select {
	case controller.signalFetchObfuscatedServerLists <- struct{}{}:
	default:
	}

	// Reset any delay for the next tunneled DSL request. The next time a
	// tunnel connects, the DSL request will launch, and the fetcher will
	// attempt to reassemble OSLs, now with this new SLOK.
	//
	// The delay for the next untunneled DSL request is not reset since that
	// request typically fetches many more server entries, which is more
	// appropriate for when a client is unable to connect. Receiving a new
	// SLOK implies the client is currently connected and is likely to
	// reconnect again and arrive at the tunneled DSL request.
	//
	// TODO: launch an immediate tunneled DSL request?

	_ = DSLSetLastTunneledFetchTime(time.Time{})
}

// SignalTunnelFailure implements the TunnelOwner interface. This function
// is called by Tunnel.operateTunnel when the tunnel has detected that it
// has failed. The Controller will signal runTunnels to create a new
// tunnel and/or remove the tunnel from the list of active tunnels.
func (controller *Controller) SignalTunnelFailure(tunnel *Tunnel) {
	// Don't block. Assumes the receiver has a buffer large enough for
	// the typical number of operated tunnels. In case there's no room,
	// terminate the tunnel (runTunnels won't get a signal in this case,
	// but the tunnel will be removed from the list of active tunnels).
	select {
	case controller.failedTunnels <- tunnel:
	default:
		controller.terminateTunnel(tunnel)
	}
}

// discardTunnel disposes of a successful connection that is no longer required.
func (controller *Controller) discardTunnel(tunnel *Tunnel) {
	NoticeInfo("discard tunnel: %s", tunnel.dialParams.ServerEntry.GetDiagnosticID())
	// TODO: not calling PromoteServerEntry, since that would rank the
	// discarded tunnel before fully active tunnels. Can a discarded tunnel
	// be promoted (since it connects), but with lower rank than all active
	// tunnels?
	tunnel.Close(true)
}

// registerTunnel adds the connected tunnel to the pool of active tunnels
// which are candidates for port forwarding. Returns true if the pool has an
// empty slot and false if the pool is full (caller should discard the tunnel).
func (controller *Controller) registerTunnel(tunnel *Tunnel) bool {
	controller.tunnelMutex.Lock()
	defer controller.tunnelMutex.Unlock()
	if len(controller.tunnels) >= controller.tunnelPoolSize {
		return false
	}
	// Perform a final check just in case we've established
	// a duplicate connection.
	for _, activeTunnel := range controller.tunnels {
		if activeTunnel.dialParams.ServerEntry.IpAddress ==
			tunnel.dialParams.ServerEntry.IpAddress {

			NoticeWarning("duplicate tunnel: %s", tunnel.dialParams.ServerEntry.GetDiagnosticID())
			return false
		}
	}
	controller.establishedOnce = true
	controller.tunnels = append(controller.tunnels, tunnel)
	NoticeTunnels(len(controller.tunnels))

	// Promote this successful tunnel to first rank so it's one
	// of the first candidates next time establish runs.
	// Connecting to a TargetServerEntry does not change the
	// ranking.
	if controller.config.TargetServerEntry == "" {
		err := PromoteServerEntry(controller.config, tunnel.dialParams.ServerEntry.IpAddress)
		if err != nil {
			NoticeWarning("PromoteServerEntry failed: %v", errors.Trace(err))
			// Proceed with using tunnel
		}
	}

	return true
}

// hasEstablishedOnce indicates if at least one active tunnel has
// been established up to this point. This is regardeless of how many
// tunnels are presently active.
func (controller *Controller) hasEstablishedOnce() bool {
	controller.tunnelMutex.Lock()
	defer controller.tunnelMutex.Unlock()
	return controller.establishedOnce
}

// isFullyEstablished indicates if the pool of active tunnels is full.
func (controller *Controller) isFullyEstablished() bool {
	controller.tunnelMutex.Lock()
	defer controller.tunnelMutex.Unlock()
	return len(controller.tunnels) >= controller.tunnelPoolSize
}

// awaitFullyEstablished blocks until isFullyEstablished is true or the
// controller run ends.
func (controller *Controller) awaitFullyEstablished() bool {

	// TODO: don't poll, add a signal

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		if controller.isFullyEstablished() {
			return true
		}

		select {
		case <-ticker.C:
			// Check isFullyEstablished again
		case <-controller.runCtx.Done():
			return false
		}
	}
}

// numTunnels returns the number of active and outstanding tunnels.
// Oustanding is the number of tunnels required to fill the pool of
// active tunnels.
func (controller *Controller) numTunnels() (int, int) {
	controller.tunnelMutex.Lock()
	defer controller.tunnelMutex.Unlock()
	active := len(controller.tunnels)
	outstanding := controller.tunnelPoolSize - len(controller.tunnels)
	return active, outstanding
}

// terminateTunnel removes a tunnel from the pool of active tunnels
// and closes the tunnel. The next-tunnel state used by getNextActiveTunnel
// is adjusted as required.
func (controller *Controller) terminateTunnel(tunnel *Tunnel) {
	controller.tunnelMutex.Lock()
	defer controller.tunnelMutex.Unlock()
	for index, activeTunnel := range controller.tunnels {
		if tunnel == activeTunnel {
			controller.tunnels = append(
				controller.tunnels[:index], controller.tunnels[index+1:]...)
			if controller.nextTunnel > index {
				controller.nextTunnel--
			}
			if controller.nextTunnel >= len(controller.tunnels) {
				controller.nextTunnel = 0
			}
			activeTunnel.Close(false)
			NoticeTunnels(len(controller.tunnels))
			break
		}
	}
}

// terminateAllTunnels empties the tunnel pool, closing all active tunnels.
// This is used when shutting down the controller.
func (controller *Controller) terminateAllTunnels() {
	controller.tunnelMutex.Lock()
	defer controller.tunnelMutex.Unlock()
	// Closing all tunnels in parallel. In an orderly shutdown, each tunnel
	// may take a few seconds to send a final status request. We only want
	// to wait as long as the single slowest tunnel.
	closeWaitGroup := new(sync.WaitGroup)
	closeWaitGroup.Add(len(controller.tunnels))
	for _, activeTunnel := range controller.tunnels {
		tunnel := activeTunnel
		go func() {
			defer closeWaitGroup.Done()
			tunnel.Close(false)
		}()
	}
	closeWaitGroup.Wait()
	controller.tunnels = make([]*Tunnel, 0)
	controller.nextTunnel = 0
	NoticeTunnels(len(controller.tunnels))
}

// getNextActiveTunnel returns the next tunnel from the pool of active
// tunnels. Currently, tunnel selection order is simple round-robin.
func (controller *Controller) getNextActiveTunnel() (tunnel *Tunnel) {
	controller.tunnelMutex.Lock()
	defer controller.tunnelMutex.Unlock()
	if len(controller.tunnels) == 0 {
		return nil
	}
	tunnel = controller.tunnels[controller.nextTunnel]
	controller.nextTunnel =
		(controller.nextTunnel + 1) % len(controller.tunnels)
	return tunnel
}

// isActiveTunnelServerEntry is used to check if there's already
// an existing tunnel to a candidate server.
func (controller *Controller) isActiveTunnelServerEntry(
	serverEntry *protocol.ServerEntry) bool {

	controller.tunnelMutex.Lock()
	defer controller.tunnelMutex.Unlock()
	for _, activeTunnel := range controller.tunnels {
		if activeTunnel.dialParams.ServerEntry.IpAddress == serverEntry.IpAddress {
			return true
		}
	}
	return false
}

func (controller *Controller) setTunnelPoolSize(tunnelPoolSize int) {
	controller.tunnelMutex.Lock()
	defer controller.tunnelMutex.Unlock()
	if tunnelPoolSize < 1 {
		tunnelPoolSize = 1
	}
	if tunnelPoolSize > MAX_TUNNEL_POOL_SIZE {
		tunnelPoolSize = MAX_TUNNEL_POOL_SIZE
	}
	controller.tunnelPoolSize = tunnelPoolSize
}

func (controller *Controller) getTunnelPoolSize() int {
	controller.tunnelMutex.Lock()
	defer controller.tunnelMutex.Unlock()
	return controller.tunnelPoolSize
}

// Dial selects an active tunnel and establishes a port forward
// connection through the selected tunnel. Failure to connect is considered
// a port forward failure, for the purpose of monitoring tunnel health.
//
// When split tunnel mode is enabled, the connection may be untunneled,
// depending on GeoIP classification of the destination.
//
// downstreamConn is an optional parameter which specifies a connection to be
// explicitly closed when the dialed connection is closed. For instance, this
// is used to close downstreamConn App<->LocalProxy connections when the
// related LocalProxy<->SshPortForward connections close.
func (controller *Controller) Dial(
	remoteAddr string, downstreamConn net.Conn) (conn net.Conn, err error) {

	tunnel := controller.getNextActiveTunnel()
	if tunnel == nil {
		return nil, errors.TraceNew("no active tunnels")
	}

	if !tunnel.config.IsSplitTunnelEnabled() {

		tunneledConn, splitTunnel, err := tunnel.DialTCPChannel(
			remoteAddr, false, downstreamConn)
		if err != nil {
			return nil, errors.Trace(err)
		}

		if splitTunnel {
			return nil, errors.TraceNew(
				"unexpected split tunnel classification")
		}

		return tunneledConn, nil
	}

	// In split tunnel mode, TCP port forwards to destinations in the same
	// country as the client are untunneled.
	//
	// Split tunnel is implemented with assistence from the server to classify
	// destinations as being in the same country as the client. The server knows
	// the client's public IP GeoIP data, and, for clients with split tunnel mode
	// enabled, the server resolves the port forward destination address and
	// checks the destination IP GeoIP data.
	//
	// When the countries match, the server "rejects" the port forward with a
	// distinct response that indicates to the client that an untunneled port
	// foward should be established locally.
	//
	// The client maintains a classification cache that allows it to make
	// untunneled port forwards without requiring a round trip to the server.
	// Only destinations classified as untunneled are stored in the cache: a
	// destination classified as tunneled requires the same round trip as an
	// unknown destination.
	//
	// When the countries do not match, the server establishes a port forward, as
	// it does for all port forwards in non-split tunnel mode. There is no
	// additional round trip for tunneled port forwards.
	//
	// Each destination includes a host and port. Since there are special
	// cases where the server performs transparent redirection for specific
	// host:port combinations, including UDPInterceptUdpgwServerAddress, the
	// classification can differ for the same host but different ports and so
	// the classification is cached using the full address, host:port, as the
	// key. While this results in additional classification round trips for
	// destinations with the same domain but differing ports, in practise
	// most destinations use only port 443.

	untunneledCache := controller.untunneledSplitTunnelClassifications

	// If the destination is in the untunneled split tunnel classifications
	// cache, skip the round trip to the server and do the direct, untunneled
	// dial immediately.
	_, cachedUntunneled := untunneledCache.Get(remoteAddr)

	if !cachedUntunneled {

		tunneledConn, splitTunnel, err := tunnel.DialTCPChannel(
			remoteAddr, false, downstreamConn)
		if err != nil {
			return nil, errors.Trace(err)
		}

		if !splitTunnel {

			// Clear any cached untunneled classification entry for this
			// destination, as the server is now classifying it as tunneled.
			untunneledCache.Delete(remoteAddr)

			return tunneledConn, nil
		}

		// The server has indicated that the client should make a direct,
		// untunneled dial. Cache the classification to avoid this round trip in
		// the immediate future.
		untunneledCache.Set(remoteAddr, true, lrucache.DefaultExpiration)
	}

	NoticeUntunneled(remoteAddr)

	untunneledConn, err := controller.DirectDial(remoteAddr)
	if err != nil {
		return nil, errors.Trace(err)
	}

	return untunneledConn, nil
}

// DirectDial dials an untunneled TCP connection within the controller run context.
func (controller *Controller) DirectDial(remoteAddr string) (conn net.Conn, err error) {
	return DialTCP(controller.runCtx, remoteAddr, controller.untunneledDialConfig)
}

// triggerFetches signals RSL, OSL, DSL, and upgrade download fetchers to
// begin, if not already running. triggerFetches is called when tunnel
// establishment fails to complete within a deadline and in other cases where
// local circumvention capabilities are lacking and we may require new server
// entries or client versions with new capabilities.
func (controller *Controller) triggerFetches() {

	// Trigger a common remote server list fetch, since we may have failed
	// to connect with all known servers. Don't block sending signal, since
	// this signal may have already been sent.
	// Don't wait for fetch remote to succeed, since it may fail and
	// enter a retry loop and we're better off trying more known servers.
	// TODO: synchronize the fetch response, so it can be incorporated
	// into the server entry iterator as soon as available.
	select {
	case controller.signalFetchCommonRemoteServerList <- struct{}{}:
	default:
	}

	// Trigger an OSL fetch in parallel. Server list fetches are run in
	// parallel so that if one fetch is large or slow, it doesn't doesn't
	// entirely block fetching the others.
	select {
	case controller.signalFetchObfuscatedServerLists <- struct{}{}:
	default:
	}

	// Trigger the untunneled DSL fetch. The untunneled DSL fetch is similar
	// to the classic RSL and OSL fetches in that it will attempt to download
	// a larger, diverse selection of servers.
	select {
	case controller.signalUntunneledDSLFetch <- struct{}{}:
	default:
	}

	// Trigger an out-of-band upgrade availability check and download.
	// Since we may have failed to connect, we may benefit from upgrading
	// to a new client version with new circumvention capabilities.
	select {
	case controller.signalDownloadUpgrade <- "":
	default:
	}
}

type protocolSelectionConstraints struct {
	config                                    *Config
	initialLimitTunnelProtocols               protocol.TunnelProtocols
	initialLimitTunnelProtocolsCandidateCount int
	limitTunnelProtocols                      protocol.TunnelProtocols
	limitTunnelDialPortNumbers                protocol.TunnelProtocolPortLists
	limitQUICVersions                         protocol.QUICVersions
	replayCandidateCount                      int
	inproxyClientDialRateLimiter              *rate.Limiter
}

func (p *protocolSelectionConstraints) hasInitialProtocols() bool {
	return len(p.initialLimitTunnelProtocols) > 0 && p.initialLimitTunnelProtocolsCandidateCount > 0
}

func (p *protocolSelectionConstraints) isInitialCandidate(
	excludeIntensive bool,
	serverEntry *protocol.ServerEntry) bool {

	return p.hasInitialProtocols() &&
		len(serverEntry.GetSupportedProtocols(
			conditionallyEnabledComponents{},
			p.config.UseUpstreamProxy(),
			p.initialLimitTunnelProtocols,
			p.limitTunnelDialPortNumbers,
			p.limitQUICVersions,
			excludeIntensive)) > 0
}

func (p *protocolSelectionConstraints) isCandidate(
	excludeIntensive bool,
	serverEntry *protocol.ServerEntry) bool {

	return len(serverEntry.GetSupportedProtocols(
		conditionallyEnabledComponents{},
		p.config.UseUpstreamProxy(),
		p.limitTunnelProtocols,
		p.limitTunnelDialPortNumbers,
		p.limitQUICVersions,
		excludeIntensive)) > 0
}

func (p *protocolSelectionConstraints) canReplay(
	connectTunnelCount int,
	excludeIntensive bool,
	serverEntry *protocol.ServerEntry,
	replayProtocol string) bool {

	if p.replayCandidateCount != -1 && connectTunnelCount > p.replayCandidateCount {
		return false
	}

	return common.Contains(
		p.supportedProtocols(
			connectTunnelCount, excludeIntensive, serverEntry),
		replayProtocol)
}

func (p *protocolSelectionConstraints) getLimitTunnelProtocols(
	connectTunnelCount int) protocol.TunnelProtocols {

	protocols := p.limitTunnelProtocols

	if len(p.initialLimitTunnelProtocols) > 0 &&
		p.initialLimitTunnelProtocolsCandidateCount > connectTunnelCount {

		protocols = p.initialLimitTunnelProtocols
	}

	return protocols
}

func (p *protocolSelectionConstraints) supportedProtocols(
	connectTunnelCount int,
	excludeIntensive bool,
	serverEntry *protocol.ServerEntry) protocol.TunnelProtocols {

	return serverEntry.GetSupportedProtocols(
		conditionallyEnabledComponents{},
		p.config.UseUpstreamProxy(),
		p.getLimitTunnelProtocols(connectTunnelCount),
		p.limitTunnelDialPortNumbers,
		p.limitQUICVersions,
		excludeIntensive)
}

func (p *protocolSelectionConstraints) selectProtocol(
	connectTunnelCount int,
	excludeIntensive bool,
	preferInproxy bool,
	serverEntry *protocol.ServerEntry) (string, time.Duration, bool) {

	candidateProtocols := p.supportedProtocols(
		connectTunnelCount, excludeIntensive, serverEntry)

	// Prefer selecting an in-proxy tunnel protocol when indicated, but fall
	// back to other protocols when no in-proxy protocol is supported.

	if preferInproxy && candidateProtocols.HasInproxyTunnelProtocols() {
		NoticeInfo("in-proxy protocol preferred")
		candidateProtocols = candidateProtocols.PruneNonInproxyTunnelProtocols()
	}

	if len(candidateProtocols) == 0 {
		return "", 0, false
	}

	// Pick at random from the supported protocols. This ensures that we'll
	// eventually try all possible protocols. Depending on network
	// configuration, it may be the case that some protocol is only available
	// through multi-capability servers, and a simpler ranked preference of
	// protocols could lead to that protocol never being selected.

	selectedProtocol := candidateProtocols[prng.Intn(len(candidateProtocols))]

	if !protocol.TunnelProtocolUsesInproxy(selectedProtocol) ||
		p.inproxyClientDialRateLimiter == nil {

		return selectedProtocol, 0, true
	}

	// Rate limit in-proxy dials. This avoids triggering rate limits or
	// similar errors from any intermediate CDN between the client and the
	// broker. And avoids unnecessarily triggering the broker's
	// application-level rate limiter, which will incur some overhead logging
	// an event and returning a response.
	//
	// In personal pairing mode, or when protocol limits yield only in-proxy
	// tunnel protocol candidates, no non-in-proxy protocol can be selected,
	// so delay the dial. In other cases, skip the candidate and pick a
	// non-in-proxy tunnel protocol.
	//
	// Also delay, rather than skip, when preferring an in-proxy protocol.
	// Note that in the prefer case, failure to meet requirements, such as
	// having broker specs, will fail the dial and consume
	// InproxyTunnelProtocolForceSelectionCount, when that mechanism is
	// active. These fast failures should eventually lead to selecting
	// non-in-proxy candidates; as a potential future enhancement, check the
	// requirements _before_ applying InproxyTunnelProtocolPreferProbability
	// or InproxyTunnelProtocolForceSelectionCount.
	//
	// The delay is not applied here since the caller is holding the
	// concurrentEstablishTunnelsMutex lock, potentially blocking other
	// establishment workers. Instead the delay is returned and applied
	// outside of the lock. This also allows for the delay to be reduced when
	// the StaggerConnectionWorkers facility is active.
	//
	// Limitation: potential fast dial failures may cause excess rate
	// limiting, since tokens are consumed even if the dial fails before a
	// request arrives at the broker. WaitForNetworkConnectivity, when
	// configured, should pause calls to selectProtocol, although there are
	// other possible fast fail cases.
	//
	// TODO: replace token on fast failure that doesn't reach the broker?

	if preferInproxy ||
		p.config.IsInproxyClientPersonalPairingMode() ||
		p.getLimitTunnelProtocols(connectTunnelCount).IsOnlyInproxyTunnelProtocols() {

		// Check for missing in-proxy broker request requirements before
		// consuming a rate limit token.
		//
		// As a potential future enhancement, these checks, particularly
		// haveInproxyCommonCompartmentIDs which reads and unmarshals a data
		// store record, could be cached.
		if !haveInproxyClientBrokerSpecs(p.config) {
			NoticeInfo("in-proxy protocol selection failed: no broker specs")
			return "", 0, false
		}
		if !p.config.IsInproxyClientPersonalPairingMode() &&
			!haveInproxyCommonCompartmentIDs(p.config) {
			NoticeInfo("in-proxy protocol selection failed: no common compartment IDs")
			return "", 0, false
		}

		r := p.inproxyClientDialRateLimiter.Reserve()
		if !r.OK() {
			NoticeInfo("in-proxy protocol selection rate limited: burst size exceeded")
			return "", 0, false
		}
		delay := r.Delay()
		if delay > 0 {
			NoticeInfo("in-proxy protocol selection rate limited: %v", delay)
		}
		return selectedProtocol, delay, true

	} else {

		// Check for missing in-proxy broker request requirements before
		// consuming a rate limit token.
		skip := true
		if !haveInproxyClientBrokerSpecs(p.config) {
			NoticeInfo("in-proxy protocol selection skipped: no broker specs")
		} else if !haveInproxyCommonCompartmentIDs(p.config) {
			NoticeInfo("in-proxy protocol selection skipped: no common compartment IDs")
		} else if !p.inproxyClientDialRateLimiter.Allow() {
			NoticeInfo("in-proxy protocol selection skipped: rate limit exceeded")
		} else {
			skip = false
		}

		if skip {

			candidateProtocols = candidateProtocols.PruneInproxyTunnelProtocols()

			if len(candidateProtocols) == 0 {
				return "", 0, false
			}

			return candidateProtocols[prng.Intn(len(candidateProtocols))], 0, true
		}
	}

	return selectedProtocol, 0, true
}

type candidateServerEntry struct {
	serverEntry                *protocol.ServerEntry
	isServerAffinityCandidate  bool
	adjustedEstablishStartTime time.Time
}

// startEstablishing creates a pool of worker goroutines which will
// attempt to establish tunnels to candidate servers. The candidates
// are generated by another goroutine.
func (controller *Controller) startEstablishing() {
	if controller.isEstablishing {
		return
	}
	NoticeInfo("start establishing")

	// establishStartTime is used to calculate and report the client's tunnel
	// establishment duration. Establishment duration should include all
	// initialization in launchEstablishing and establishCandidateGenerator,
	// including any potentially long-running datastore iterations.
	establishStartTime := time.Now()

	controller.concurrentEstablishTunnelsMutex.Lock()
	controller.establishConnectTunnelCount = 0
	controller.concurrentEstablishTunnels = 0
	controller.concurrentIntensiveEstablishTunnels = 0
	controller.peakConcurrentEstablishTunnels = 0
	controller.peakConcurrentIntensiveEstablishTunnels = 0
	controller.establishInproxyForceSelectionCount = 0
	controller.concurrentEstablishTunnelsMutex.Unlock()

	DoGarbageCollection()
	emitMemoryMetrics()

	// The establish context cancelFunc, controller.stopEstablish, is called in
	// controller.stopEstablishing.

	controller.isEstablishing = true
	controller.establishStartTime = establishStartTime
	controller.establishCtx, controller.stopEstablish = context.WithCancel(controller.runCtx)
	controller.establishWaitGroup = new(sync.WaitGroup)
	controller.candidateServerEntries = make(chan *candidateServerEntry)

	// The server affinity mechanism attempts to favor the previously
	// used server when reconnecting. This is beneficial for user
	// applications which expect consistency in user IP address (for
	// example, a web site which prompts for additional user
	// authentication when the IP address changes).
	//
	// Only the very first server, as determined by
	// datastore.PromoteServerEntry(), is the server affinity candidate.
	// Concurrent connections attempts to many servers are launched
	// without delay, in case the affinity server connection fails.
	// While the affinity server connection is outstanding, when any
	// other connection is established, there is a short grace period
	// delay before delivering the established tunnel; this allows some
	// time for the affinity server connection to succeed first.
	// When the affinity server connection fails, any other established
	// tunnel is registered without delay.
	//
	// Note: the establishTunnelWorker that receives the affinity
	// candidate is solely resonsible for closing
	// controller.serverAffinityDoneBroadcast.
	controller.serverAffinityDoneBroadcast = make(chan struct{})

	// TODO: Add a buffer of 1 so we don't miss a signal while worker is
	// starting? Trade-off is potential back-to-back fetches. As-is,
	// establish will eventually signal another fetch.
	controller.establishSignalForceTacticsFetch = make(chan struct{})

	controller.establishWaitGroup.Add(1)
	go controller.launchEstablishing()
}

func (controller *Controller) launchEstablishing() {

	defer controller.establishWaitGroup.Done()

	// Before starting the establish tunnel workers, get and apply tactics,
	// launching a tactics request if required -- when there are no tactics,
	// or the cached tactics have expired.
	//
	// Wait only TacticsWaitPeriod for the tactics request to complete (or
	// fail) before proceeding with tunnel establishment, in case the tactics
	// request is blocked or takes very long to complete.
	//
	// An in-flight tactics request uses meek in round tripper mode, which
	// uses less resources than meek tunnel relay mode. For this reason, the
	// tactics request is not counted in concurrentIntensiveEstablishTunnels.
	//
	// TODO: HTTP/2 uses significantly more memory, so perhaps
	// concurrentIntensiveEstablishTunnels should be counted in that case.
	//
	// Any in-flight tactics request or pending retry will be
	// canceled when establishment is stopped.
	//
	// In some cases, no tunnel establishment can succeed without a fresh
	// tactics fetch, even if there is existing, non-expired cached tactics.
	// Currently, cases include in-proxy personal pairing mode and limiting
	// tunnel protocols to in-proxy, where broker specs are both required and
	// obtained exclusively from tactics. It is possible that cached tactics
	// are found and used, but broker configurations have recently changed
	// away from the broker specs in cached tactics.
	//
	// Another scenario, with exclusively in-proxy tunnel protocols, is a
	// fresh start with no embedded server entries, where the initial
	// GetTactics will fail with "no capable servers".
	//
	// To handle these cases, when cached tactics are used or no tactics can
	// be fetched, the tactics worker goroutine will remain running and await
	// a signal to force a tactics fetch that ignores any stored/cached
	// tactics. Multiple signals and fetch attempts are supported, to retry
	// when a GetTactics fetch iteration fails, including the "no capable
	// servers" case, which may only succeed after a concurrent server list
	// fetch completes.
	//
	// Limitation: this mechanism doesn't force repeated tactics fetches after
	// one success, which risks being excessive. There's at most one
	// successful fetch per establishment run. As such, it remains remotely
	// possible that a tactics change, such as new broker specs, deployed in
	// the middle of an establishment run, won't be fetched. A user-initiated
	// stop/start toggle will work around this.

	if !controller.config.DisableTactics {

		timeout := controller.config.GetParameters().Get().Duration(
			parameters.TacticsWaitPeriod)

		initialTacticsDone := make(chan struct{})
		tacticsWaitPeriod := time.NewTimer(timeout)
		defer tacticsWaitPeriod.Stop()

		controller.establishWaitGroup.Add(1)
		go func() {
			defer controller.establishWaitGroup.Done()

			useStoredTactics := true
			fetched := GetTactics(
				controller.establishCtx, controller.config, useStoredTactics)
			close(initialTacticsDone)

			if fetched {
				return
			}

			for {
				select {
				case <-controller.establishCtx.Done():
					return
				case <-controller.establishSignalForceTacticsFetch:
				}

				useStoredTactics = false
				fetched = GetTactics(
					controller.establishCtx, controller.config, useStoredTactics)
				if fetched {
					// No more forced tactics fetches after the first success.
					break
				}
			}
		}()

		select {
		case <-initialTacticsDone:
		case <-tacticsWaitPeriod.C:
		}

		tacticsWaitPeriod.Stop()

		if controller.isStopEstablishing() {
			// This check isn't strictly required but avoids the overhead of launching
			// workers if establishment stopped while awaiting a tactics request.
			return
		}
	}

	// Initial- and LimitTunnelProtocols may be set by tactics.
	//
	// These protocol limits are fixed once per establishment, for
	// consistent application of related probabilities (applied by
	// ParametersAccessor.TunnelProtocols). The
	// establishLimitTunnelProtocolsState field must be read-only after this
	// point, allowing concurrent reads by establishment workers.

	p := controller.config.GetParameters().Get()

	controller.protocolSelectionConstraints = &protocolSelectionConstraints{
		config: controller.config,

		initialLimitTunnelProtocols:               p.TunnelProtocols(parameters.InitialLimitTunnelProtocols),
		initialLimitTunnelProtocolsCandidateCount: p.Int(parameters.InitialLimitTunnelProtocolsCandidateCount),
		limitTunnelProtocols:                      p.TunnelProtocols(parameters.LimitTunnelProtocols),
		limitTunnelDialPortNumbers: protocol.TunnelProtocolPortLists(
			p.TunnelProtocolPortLists(parameters.LimitTunnelDialPortNumbers)),

		replayCandidateCount: p.Int(parameters.ReplayCandidateCount),

		inproxyClientDialRateLimiter: controller.inproxyClientDialRateLimiter,
	}

	// Adjust protocol limits for in-proxy personal proxy mode. In this mode,
	// the client will make connections only through a proxy with the
	// corresponding personal compartment ID, so non-in-proxy tunnel
	// protocols are disabled.

	if controller.config.IsInproxyClientPersonalPairingMode() {

		if len(controller.protocolSelectionConstraints.initialLimitTunnelProtocols) > 0 {
			controller.protocolSelectionConstraints.initialLimitTunnelProtocols =
				controller.protocolSelectionConstraints.
					initialLimitTunnelProtocols.PruneNonInproxyTunnelProtocols()
		}

		if len(controller.protocolSelectionConstraints.limitTunnelProtocols) > 0 {
			controller.protocolSelectionConstraints.limitTunnelProtocols =
				controller.protocolSelectionConstraints.
					limitTunnelProtocols.PruneNonInproxyTunnelProtocols()
		}

		// This covers two cases: if there was no limitTunnelProtocols to
		// start, then limit to any in-proxy tunnel protocol; or, if there
		// was a limit but OnlyInproxyTunnelProtocols evaluates to an empty
		// list, also set the limit to any in-proxy tunnel protocol.
		if len(controller.protocolSelectionConstraints.limitTunnelProtocols) == 0 {
			controller.protocolSelectionConstraints.limitTunnelProtocols =
				protocol.InproxyTunnelProtocols
		}
	}

	// Initialize the in-proxy client dial rate limiter, using the latest
	// tactics. Rate limits are used in
	// protocolSelectionConstraints.selectProtocol. When
	// InproxyClientDialRateLimitQuantity is 0, there is no rate limit.
	//
	// The rate limiter is reset for each establishment, which ensures no
	// delays carry over from a previous establishment run. However, this
	// does mean that very frequent re-establishments may exceed the rate
	// limit overall.

	inproxyRateLimitQuantity := p.Int(parameters.InproxyClientDialRateLimitQuantity)
	inproxyRateLimitInterval := p.Duration(parameters.InproxyClientDialRateLimitInterval)
	if inproxyRateLimitQuantity > 0 {
		controller.inproxyClientDialRateLimiter = rate.NewLimiter(
			rate.Limit(float64(inproxyRateLimitQuantity)/inproxyRateLimitInterval.Seconds()),
			inproxyRateLimitQuantity)
	}

	// InproxyTunnelProtocolForceSelectionCount forces the specified number of
	// early candidates to select in-proxy protocols.
	//
	// Only server entries with INPROXY capabilities are counted as forced
	// selection candidates; and, as currently implemented, these server
	// entries are not sorted to the front of the server entry iterator, so
	// force selection is applied opportunistically as server entries with
	// the necessary capabilities are encountered.
	//
	// If a forced server entry has existing replay data for a non-in-proxy
	// protocol, that replay data is ignored for this dial, but not deleted.
	//
	// The affinity server entry candidate is a potential candidate for forced
	// selection.

	controller.establishInproxyForceSelectionCount =
		p.Int(parameters.InproxyTunnelProtocolForceSelectionCount)

	// ConnectionWorkerPoolSize may be set by tactics.
	//
	// In-proxy personal pairing mode uses a distinct parameter which is
	// typically configured to a lower number, limiting concurrent load and
	// announcement consumption for personal proxies.

	var workerPoolSize int
	if controller.config.IsInproxyClientPersonalPairingMode() {
		workerPoolSize = p.Int(parameters.InproxyPersonalPairingConnectionWorkerPoolSize)
	} else {
		workerPoolSize = p.Int(parameters.ConnectionWorkerPoolSize)
	}

	// When TargetServerEntry is used, override any worker pool size config or
	// tactic parameter and use a pool size of 1. The typical use case for
	// TargetServerEntry is to test a specific server with a single connection
	// attempt. Furthermore, too many concurrent attempts to connect to the
	// same server will trigger rate limiting.
	if controller.config.TargetServerEntry != "" {
		workerPoolSize = 1
	}

	// When DisableConnectionWorkerPool is set, no tunnel establishment
	// workers are run. See Config.DisableConnectionWorkerPool.
	if controller.config.DisableConnectionWorkerPool {
		workerPoolSize = 0
	}

	// TunnelPoolSize may be set by tactics, subject to local constraints. A pool
	// size of one is forced in packet tunnel mode or when using a
	// TargetServerEntry. The tunnel pool size is reduced when there are
	// insufficent known server entries, within the set region and protocol
	// constraints, to satisfy the target.
	//
	// Limitations, to simplify concurrent access to shared state: a ceiling of
	// MAX_TUNNEL_POOL_SIZE is enforced by setTunnelPoolSize; the tunnel pool
	// size target is not re-adjusted after an API handshake, even though the
	// handshake response may deliver new tactics, or prune server entries which
	// were potential candidates; nor is the target re-adjusted after fetching
	// new server entries during this establishment.

	tunnelPoolSize := p.Int(parameters.TunnelPoolSize)
	if controller.config.PacketTunnelTunFileDescriptor > 0 ||
		controller.config.TargetServerEntry != "" {
		tunnelPoolSize = 1
	}
	controller.setTunnelPoolSize(tunnelPoolSize)

	p.Close()

	// Trigger CandidateServers and AvailableEgressRegions notices. By default,
	// this is an asynchronous operation, as the underlying full server entry
	// list enumeration may be a slow operation.
	//
	// AvailableEgressRegions: after a fresh install, the outer client may not
	// have a list of regions to display; and LimitTunnelProtocols may reduce the
	// number of available regions.
	//
	// When the outer client receives NoticeAvailableEgressRegions and the
	// configured EgressRegion is not included in the region list, the outer
	// client _should_ stop tunnel-core and prompt the user to change the region
	// selection, as there are insufficient servers/capabilities to establish a
	// tunnel in the selected region.
	//
	// This report is delayed until after tactics are likely to be applied,
	// above; this avoids a ReportAvailableRegions reporting too many regions,
	// followed shortly by a ReportAvailableRegions reporting fewer regions. That
	// sequence could cause issues in the outer client UI.
	//
	// The reported regions are limited by protocolSelectionConstraints; in the
	// case where an initial limit is in place, only regions available for the
	// initial limit are reported. The initial phase will not complete if
	// EgressRegion is set such that there are no server entries with the
	// necessary protocol capabilities (either locally or from a remote server
	// list fetch).

	// Concurrency note: controller.protocolSelectionConstraints and its
	// fields may be overwritten before serverEntriesReporter reads it, and
	// so cannot be accessed directly by serverEntriesReporter.
	//
	// Limitation: the non-deep copy here shares slices (tunnel protocol
	// lists) with the original; the contents of these slices don't change
	// past this point. The rate limiter should not be used by
	// serverEntriesReporter, but is cleared just in case.
	copyConstraints := *controller.protocolSelectionConstraints
	copyConstraints.inproxyClientDialRateLimiter = nil
	controller.signalServerEntriesReporter(
		&serverEntriesReportRequest{
			constraints: &copyConstraints,
		})

	if controller.protocolSelectionConstraints.hasInitialProtocols() ||
		tunnelPoolSize > 1 {

		// Perform a synchronous scan over server entries in order to check if
		// there are sufficient candidates to satisfy any initial tunnel
		// protocol limit constraint and/or tunnel pool size > 1. If these
		// requirements can't be met, the constraint and/or pool size are
		// adjusted in order to avoid spinning unable to select any protocol
		// or trying to establish more tunnels than is possible.
		controller.doConstraintsScan()
	}

	controller.resetServerEntryIterationMetrics()

	for i := 0; i < workerPoolSize; i++ {
		controller.establishWaitGroup.Add(1)
		go controller.establishTunnelWorker()
	}

	controller.establishWaitGroup.Add(1)
	go controller.establishCandidateGenerator()
}

func (controller *Controller) doConstraintsScan() {

	// Scan over server entries in order to check and adjust any initial
	// tunnel protocol limit and tunnel pool size.
	//
	// The scan in serverEntriesReporter is _not_ used for these checks,
	// since it takes too long to complete with 1000s of server entries,
	// greatly delaying the start(or restart, if already scanning) of
	// establishment. Instead a 2nd ScanServerEntries is run here, with an
	// early exit when sufficient candidates are found, which is expected
	// to happen quickly in the typical case.

	hasInitialLimitTunnelProtocols :=
		controller.protocolSelectionConstraints.hasInitialProtocols()
	tunnelPoolSize := controller.getTunnelPoolSize()

	scanCount := 0
	scanCancelled := false
	candidates := 0

	callback := func(serverEntry *protocol.ServerEntry) bool {

		scanCount += 1

		// As in serverEntryReporter:
		// - egress region is ignored, since AvailableEgressRegion alerts
		//   the front end client when unable to connect due to egress
		//   region constraints.
		// - excludeIntensive is false, as any intensive candidate will
		//   eventually be an available candidate.

		excludeIntensive := false
		if (hasInitialLimitTunnelProtocols &&
			controller.protocolSelectionConstraints.isInitialCandidate(excludeIntensive, serverEntry)) ||
			(!hasInitialLimitTunnelProtocols &&
				controller.protocolSelectionConstraints.isCandidate(excludeIntensive, serverEntry)) {
			candidates += 1
		}

		if candidates >= tunnelPoolSize {
			// Exit the scan early once sufficient candidates have been found.
			scanCancelled = true
			return false
		}

		select {
		case <-controller.runCtx.Done():
			// Don't block controller shutdown: cancel the scan.
			return false
		default:
			return true
		}
	}

	startTime := time.Now()
	scanErr := ScanServerEntries(callback)
	if scanErr != nil && !scanCancelled {
		NoticeWarning("ScanServerEntries failed: %v", errors.Trace(scanErr))
		// Continue and make adjustments based on any partial results.
	}
	NoticeInfo("Awaited ScanServerEntries: scanned %d entries in %v", scanCount, time.Since(startTime))

	// Make adjustments based on candidate counts.

	if tunnelPoolSize > candidates && candidates > 0 {
		tunnelPoolSize = candidates
	}

	// If InitialLimitTunnelProtocols is configured but cannot be satisfied,
	// skip the initial phase in this establishment. This avoids spinning,
	// unable to connect, in this case. InitialLimitTunnelProtocols is
	// intended to prioritize certain protocols, but not strictly select them.
	//
	// The candidate count check ignores egress region selection. When an egress
	// region is selected, it's the responsibility of the outer client to react
	// to the following ReportAvailableRegions output and clear the user's
	// selected region to prevent spinning, unable to connect. The initial phase
	// is skipped only when InitialLimitTunnelProtocols cannot be satisfied
	// _regardless_ of region selection.
	//
	// We presume that, in practise, most clients will have embedded server
	// entries with capabilities for most protocols; and that clients will
	// often perform RSL checks. So clients should most often have the
	// necessary capabilities to satisfy InitialLimitTunnelProtocols. When
	// this check fails, RSL/OSL/upgrade checks are triggered in order to gain
	// new capabilities.
	//
	// LimitTunnelProtocols remains a hard limit, as using prohibited
	// protocols may have some bad effect, such as a firewall blocking all
	// traffic from a host.

	if hasInitialLimitTunnelProtocols && candidates == 0 {
		NoticeWarning("skipping initial limit tunnel protocols")
		controller.protocolSelectionConstraints.initialLimitTunnelProtocolsCandidateCount = 0
		// Since we were unable to satisfy the InitialLimitTunnelProtocols
		// tactic, trigger RSL, OSL, and upgrade fetches to potentially
		// gain new capabilities.
		controller.triggerFetches()
	}
}

// stopEstablishing signals the establish goroutines to stop and waits
// for the group to halt.
func (controller *Controller) stopEstablishing() {
	if !controller.isEstablishing {
		return
	}
	NoticeInfo("stop establishing")
	controller.stopEstablish()
	// Note: establishCandidateGenerator closes controller.candidateServerEntries
	// (as it may be sending to that channel).
	controller.establishWaitGroup.Wait()
	NoticeInfo("stopped establishing")

	controller.isEstablishing = false
	controller.establishStartTime = time.Time{}
	controller.establishCtx = nil
	controller.stopEstablish = nil
	controller.establishWaitGroup = nil
	controller.candidateServerEntries = nil
	controller.serverAffinityDoneBroadcast = nil
	controller.establishSignalForceTacticsFetch = nil
	controller.inproxyClientDialRateLimiter = nil

	controller.concurrentEstablishTunnelsMutex.Lock()
	peakConcurrent := controller.peakConcurrentEstablishTunnels
	peakConcurrentIntensive := controller.peakConcurrentIntensiveEstablishTunnels
	controller.establishConnectTunnelCount = 0
	controller.concurrentEstablishTunnels = 0
	controller.concurrentIntensiveEstablishTunnels = 0
	controller.peakConcurrentEstablishTunnels = 0
	controller.peakConcurrentIntensiveEstablishTunnels = 0
	controller.concurrentEstablishTunnelsMutex.Unlock()
	NoticeInfo("peak concurrent establish tunnels: %d", peakConcurrent)
	NoticeInfo("peak concurrent resource intensive establish tunnels: %d", peakConcurrentIntensive)

	emitMemoryMetrics()
	DoGarbageCollection()

	// Record datastore metrics after establishment, the phase which generates
	// the bulk of all datastore transactions: iterating over server entries,
	// storing new server entries, etc.
	emitDatastoreMetrics()

	// Similarly, establishment generates the bulk of domain resolves.
	emitDNSMetrics(controller.resolver)
}

func (controller *Controller) resetServerEntryIterationMetrics() {
	controller.serverEntryIterationMetricsMutex.Lock()
	defer controller.serverEntryIterationMetricsMutex.Unlock()

	controller.serverEntryIterationUniqueCandidates = hyperloglog.New()
	controller.serverEntryIterationFirstFrontedMeekCandidateNumber = -1
	controller.serverEntryIterationMovedToFrontCount = 0
}

func (controller *Controller) updateServerEntryIterationDialMetrics(dialParams *DialParameters) {
	controller.serverEntryIterationMetricsMutex.Lock()
	defer controller.serverEntryIterationMetricsMutex.Unlock()

	// Unique candidate counting track the number of different server entries
	// attempted. To avoid the memory overhead of a large map, we use a
	// probabilistic HyperLogLog with a fixed overhead of 16KB. As a result,
	// the count is an estimate with on the order of ~1% relative error.

	controller.serverEntryIterationUniqueCandidates.Insert([]byte(dialParams.ServerEntry.IpAddress))

	if controller.serverEntryIterationFirstFrontedMeekCandidateNumber == -1 &&
		protocol.TunnelProtocolUsesFrontedMeek(dialParams.TunnelProtocol) {
		controller.serverEntryIterationFirstFrontedMeekCandidateNumber = dialParams.CandidateNumber
	}

	// Capture a snapshot of server entry iteration metrics to be recorded
	// with the server_tunnel or failed_tunnel for this candidate.
	//
	// See rounding comment in GetLastServerEntryCount.

	estimate := roundServerEntryCount(int(controller.serverEntryIterationUniqueCandidates.Estimate()))

	dialParams.ServerEntryIterationUniqueCandidateEstimate = estimate
	dialParams.ServerEntryIterationMovedToFrontCount = controller.serverEntryIterationMovedToFrontCount
	dialParams.ServerEntryIterationFirstFrontedMeekCandidate = controller.serverEntryIterationFirstFrontedMeekCandidateNumber
}

func (controller *Controller) updateServerEntryIterationResetMetrics(movedToFront int) {
	controller.serverEntryIterationMetricsMutex.Lock()
	defer controller.serverEntryIterationMetricsMutex.Unlock()

	controller.serverEntryIterationMovedToFrontCount += movedToFront
}

// establishCandidateGenerator populates the candidate queue with server entries
// from the data store. Server entries are iterated in rank order, so that promoted
// servers with higher rank are priority candidates.
func (controller *Controller) establishCandidateGenerator() {
	defer controller.establishWaitGroup.Done()
	defer close(controller.candidateServerEntries)

	// networkWaitDuration is the elapsed time spent waiting
	// for network connectivity. This duration will be excluded
	// from reported tunnel establishment duration.
	var totalNetworkWaitDuration time.Duration

	applyServerAffinity, iterator, err := NewServerEntryIterator(controller.config)
	if err != nil {
		NoticeError("failed to iterate over candidates: %v", errors.Trace(err))
		controller.SignalComponentFailure()
		return
	}
	defer iterator.Close()

	// TODO: reconcile server affinity scheme with multi-tunnel mode
	if controller.getTunnelPoolSize() > 1 {
		applyServerAffinity = false
	}

	isServerAffinityCandidate := true
	if !applyServerAffinity {
		isServerAffinityCandidate = false
		close(controller.serverAffinityDoneBroadcast)
	}

loop:
	// Repeat until stopped
	for {

		// A "round" consists of a new shuffle of the server entries and attempted
		// connections up to the end of the server entry iterator, or
		// parameters.EstablishTunnelWorkTime elapsed. Time spent waiting for
		// network connectivity is excluded from round elapsed time.
		//
		// After a round, if parameters.EstablishTunnelWorkTime has elapsed in total
		// with no tunnel established, remote server list and upgrade checks are
		// triggered.
		//
		// A complete server entry iteration does not trigger fetches since it's
		// possible to have fewer than parameters.ConnectionWorkerPoolSize
		// candidates, in which case rounds end instantly due to the complete server
		// entry iteration. An exception is made for an empty server entry iterator;
		// in that case fetches may be triggered immediately.
		//
		// The number of server candidates may change during this loop, due to
		// remote server list fetches. Due to the performance impact, we will not
		// trigger additional, informational CandidateServer notices while in the
		// establishing loop. Clients typically re-establish often enough that we
		// will see the effect of the remote server list fetch in diagnostics.

		completedServerEntryIteration := false

		roundStartTime := time.Now()
		var roundNetworkWaitDuration time.Duration

		workTime := controller.config.GetParameters().Get().Duration(
			parameters.EstablishTunnelWorkTime)

		candidateServerEntryCount := 0

		// Send each iterator server entry to the establish workers
		for {

			networkWaitStartTime := time.Now()
			if !WaitForNetworkConnectivity(
				controller.establishCtx,
				controller.config.NetworkConnectivityChecker,
				nil) {
				break loop
			}
			networkWaitDuration := time.Since(networkWaitStartTime)
			roundNetworkWaitDuration += networkWaitDuration
			totalNetworkWaitDuration += networkWaitDuration

			serverEntry, err := iterator.Next()
			if err != nil {
				NoticeError("failed to get next candidate: %v", errors.Trace(err))
				controller.SignalComponentFailure()
				return
			}
			if serverEntry == nil {
				// Completed this iteration
				NoticeInfo("completed server entry iteration")
				completedServerEntryIteration = true
				break
			}

			if controller.config.TargetAPIProtocol == protocol.PSIPHON_API_PROTOCOL_SSH &&
				!serverEntry.SupportsSSHAPIRequests() {
				continue
			}

			candidateServerEntryCount += 1

			// adjustedEstablishStartTime is establishStartTime shifted
			// to exclude time spent waiting for network connectivity.
			adjustedEstablishStartTime := controller.establishStartTime.Add(
				totalNetworkWaitDuration)

			candidate := &candidateServerEntry{
				serverEntry:                serverEntry,
				isServerAffinityCandidate:  isServerAffinityCandidate,
				adjustedEstablishStartTime: adjustedEstablishStartTime,
			}

			wasServerAffinityCandidate := isServerAffinityCandidate

			// Note: there must be only one server affinity candidate, as it
			// closes the serverAffinityDoneBroadcast channel.
			isServerAffinityCandidate = false

			// TODO: here we could generate multiple candidates from the
			// server entry when there are many MeekFrontingAddresses.

			select {
			case controller.candidateServerEntries <- candidate:
			case <-controller.establishCtx.Done():
				break loop
			}

			if time.Since(roundStartTime)-roundNetworkWaitDuration > workTime {
				// Start over, after a brief pause, with a new shuffle of the server
				// entries, and potentially some newly fetched server entries.
				break
			}

			if wasServerAffinityCandidate {

				// Don't start the next candidate until either the server affinity
				// candidate has completed (success or failure) or is still working
				// and the grace period has elapsed.

				gracePeriod := controller.config.GetParameters().Get().Duration(
					parameters.EstablishTunnelServerAffinityGracePeriod)

				if gracePeriod > 0 {
					timer := time.NewTimer(gracePeriod)
					select {
					case <-timer.C:
					case <-controller.serverAffinityDoneBroadcast:
					case <-controller.establishCtx.Done():
						timer.Stop()
						break loop
					}
					timer.Stop()
				}
			}
		}

		// Trigger RSL, OSL, and upgrade checks after failing to establish a
		// tunnel within parameters.EstablishTunnelWorkTime, or if there are
		// no server entries present.
		//
		// While the trigger is made after each round,
		// parameter.FetchRemoteServerListStalePeriod will limit the actual
		// frequency of fetches. Continuing to trigger allows for very long running
		// establishments to perhaps eventually succeed.
		//
		// No fetches are triggered when TargetServerEntry is specified. In that
		// case, we're only trying to connect to a specific server entry.

		if candidateServerEntryCount == 0 ||
			time.Since(controller.establishStartTime)-totalNetworkWaitDuration > workTime {

			if controller.config.TargetServerEntry == "" {
				controller.triggerFetches()
			}

			// Trigger a forced tactics fetch. Currently, this is done only
			// for cases where in-proxy tunnel protocols must be selected.
			// When there were no server entries, wait until a server entry
			// fetch has completed.

			// Lock required to access controller.establishConnectTunnelCount.
			controller.concurrentEstablishTunnelsMutex.Lock()
			limitInproxyOnly := controller.protocolSelectionConstraints.getLimitTunnelProtocols(
				controller.establishConnectTunnelCount).IsOnlyInproxyTunnelProtocols()
			controller.concurrentEstablishTunnelsMutex.Unlock()

			if limitInproxyOnly || controller.config.IsInproxyClientPersonalPairingMode() {

				// Simply sleep and poll for any imported server entries;
				// perform one sleep after HasServerEntries, in order to give
				// the import some extra time. Limitation: if the sleep loop
				// ends too soon, the tactics fetch won't find a
				// tactics-capable server entry; in this case, workTime must
				// elapse before another tactics fetch is triggered.
				//
				// TODO: synchronize with server list fetch/import complete;
				// or use ScanServerEntries (but see function comment about
				// performance concern) to check for at least one
				// tactics-capable server entry.

				if candidateServerEntryCount == 0 {
					stopWaiting := false
					for {
						if HasServerEntries() {
							stopWaiting = true
						}
						common.SleepWithContext(controller.establishCtx, 1*time.Second)
						if stopWaiting || controller.establishCtx.Err() != nil {
							break
						}
					}
				}

				select {
				case controller.establishSignalForceTacticsFetch <- struct{}{}:
				default:
				}
			}
		}

		// If the round ended without exhausting the server entry iterator,
		// decide whether to keep iterating in order, or to perform a reset.
		// Resets perform a new random shuffle, move replay and prioritized
		// dial server entries to the front, and incorporate any newly
		// download server entries.

		p := controller.config.GetParameters().Get()

		resetIterator := completedServerEntryIteration ||
			p.WeightedCoinFlip(parameters.ServerEntryIteratorResetProbability)

		if resetIterator {
			// Free up resources now, but don't reset until after the pause.
			iterator.Close()
		}

		// After a round, pause before iterating again. This helps avoid some
		// busy wait loop conditions, and also allows some time for network
		// conditions to change. Also allows for fetch remote to complete, in
		// typical conditions (it isn't strictly necessary to wait for this,
		// there will be more rounds if required).

		pausePeriod := p.Duration(parameters.EstablishTunnelPausePeriod)
		if controller.config.TargetServerEntry == "" &&
			GetLastServerEntryCount() == 0 &&
			((!controller.config.DisableRemoteServerListFetcher &&
				(controller.config.RemoteServerListURLs != nil ||
					controller.config.ObfuscatedServerListRootURLs != nil)) ||
				!controller.config.DisableDSLFetcher) {

			// Reduce/alter the wait time if the client has no server entries
			// and at least one type of server list fetch is configured.
			//
			// As a future enhancement, check for an in-flight server list fetch,
			// and stop waiting as soon as it's finished.

			pausePeriod = p.Duration(parameters.EstablishTunnelNoServersPausePeriod)
		}

		timeout := prng.JitterDuration(
			pausePeriod,
			p.Float(parameters.EstablishTunnelPausePeriodJitter))

		p.Close()

		timer := time.NewTimer(timeout)
		select {
		case <-timer.C:
			// Retry iterating
		case <-controller.establishCtx.Done():
			timer.Stop()
			break loop
		}
		timer.Stop()

		if resetIterator {
			err := iterator.Reset()
			if err != nil {
				NoticeError("failed to reset iterator: %v", errors.Trace(err))
				controller.SignalComponentFailure()
				return
			}
		}
	}
}

// establishTunnelWorker pulls candidates from the candidate queue, establishes
// a connection to the tunnel server, and delivers the connected tunnel to a channel.
func (controller *Controller) establishTunnelWorker() {
	defer controller.establishWaitGroup.Done()
loop:
	for candidateServerEntry := range controller.candidateServerEntries {

		// Note: don't receive from candidateServerEntries and isStopEstablishing
		// in the same select, since we want to prioritize receiving the stop signal
		if controller.isStopEstablishing() {
			break loop
		}

		// There may already be a tunnel to this candidate. If so, skip it.
		if controller.isActiveTunnelServerEntry(candidateServerEntry.serverEntry) {
			continue
		}

		// TODO: we allow multiple, concurrent workers to attempt to connect to the
		// same server. This is not wasteful if the server supports several
		// different protocols, some of which may be blocked while others are not
		// blocked. Limiting protocols with [Initial]LimitTunnelProtocols may make
		// these multiple attempts redundent. Also, replay should be used only by
		// the first attempt.

		// upstreamProxyErrorCallback will post NoticeUpstreamProxyError when the
		// tunnel dial fails due to an upstream proxy error. As the upstream proxy
		// is user configured, the error message may need to be relayed to the user.

		// As the callback may be invoked after establishment is over (e.g., if an
		// initial dial isn't fully shutdown when ConnectTunnel returns; or a meek
		// underlying TCP connection re-dial) don't access these variables
		// directly.
		callbackCandidateServerEntry := candidateServerEntry
		callbackEstablishCtx := controller.establishCtx

		upstreamProxyErrorCallback := func(err error) {

			// Do not post the notice when overall establishment context is canceled or
			// timed-out: the upstream proxy connection error is likely a result of the
			// cancellation, and not a condition to be fixed by the user. In the case
			// of meek underlying TCP connection re-dials, this condition will always
			// be true; however in this case the initial dial succeeded with the
			// current upstream proxy settings, so any upstream proxy error is
			// transient.
			if callbackEstablishCtx.Err() != nil {
				return
			}

			// Another class of non-fatal upstream proxy error arises from proxies
			// which limit permitted proxied ports. In this case, some tunnels may fail
			// due to dial port, while others may eventually succeed. To avoid this
			// class of errors, delay posting the notice. If the upstream proxy works,
			// _some_ tunnel should connect. If the upstream proxy configuration is
			// broken, the error should persist and eventually get posted.

			p := controller.config.GetParameters().Get()
			workerPoolSize := p.Int(parameters.ConnectionWorkerPoolSize)
			minWaitDuration := p.Duration(parameters.UpstreamProxyErrorMinWaitDuration)
			maxWaitDuration := p.Duration(parameters.UpstreamProxyErrorMaxWaitDuration)
			p.Close()

			controller.concurrentEstablishTunnelsMutex.Lock()
			establishConnectTunnelCount := controller.establishConnectTunnelCount
			controller.concurrentEstablishTunnelsMutex.Unlock()

			// Delay UpstreamProxyErrorMinWaitDuration (excluding time spent waiting
			// for network connectivity) and then until either
			// UpstreamProxyErrorMaxWaitDuration has elapsed or, to post sooner if many
			// candidates are failing, at least workerPoolSize tunnel connection
			// attempts have completed. We infer that at least workerPoolSize
			// candidates have completed by checking that at least 2*workerPoolSize
			// candidates have started.

			elapsedTime := time.Since(
				callbackCandidateServerEntry.adjustedEstablishStartTime)

			if elapsedTime < minWaitDuration ||
				(elapsedTime < maxWaitDuration &&
					establishConnectTunnelCount < 2*workerPoolSize) {
				return
			}

			NoticeUpstreamProxyError(err)
		}

		// Select the tunnel protocol. The selection will be made at random
		// from protocols supported by the server entry, optionally limited by
		// LimitTunnelProtocols.
		//
		// When limiting concurrent resource intensive protocol connection
		// workers, and at the limit, do not select resource intensive
		// protocols since otherwise the candidate must be skipped.
		//
		// If at the limit and unabled to select a non-intensive protocol,
		// skip the candidate entirely and move on to the next. Since
		// candidates are shuffled it's likely that the next candidate is not
		// intensive. In this case, a StaggerConnectionWorkersMilliseconds
		// delay may still be incurred.

		p := controller.config.GetParameters().Get()
		limitIntensiveConnectionWorkers := p.Int(parameters.LimitIntensiveConnectionWorkers)
		inproxyPreferProbability := p.Float(parameters.InproxyTunnelProtocolPreferProbability)
		staggerPeriod := p.Duration(parameters.StaggerConnectionWorkersPeriod)
		staggerJitter := p.Float(parameters.StaggerConnectionWorkersJitter)
		p.Close()

		// Access to controller fields is synchronized with this lock. The
		// canReplay and selectProtocol callbacks are intended to be invoked
		// in MakeDialParameters while lock is held.

		controller.concurrentEstablishTunnelsMutex.Lock()

		excludeIntensive := false
		if limitIntensiveConnectionWorkers > 0 &&
			controller.concurrentIntensiveEstablishTunnels >= limitIntensiveConnectionWorkers {
			excludeIntensive = true
		}

		// Force in-proxy protocol selection as required, and if the server
		// entry supports in-proxy protocols. If this candidate happens to be
		// a replay of an in-proxy protocol, it's still counted as a forced
		// selection.
		//
		// Forced selection is skipped when excluding intensive protocols, as
		// TunnelProtocolIsResourceIntensive currently includes
		// TunnelProtocolUsesInproxy.

		inproxyForceSelection := false
		if !excludeIntensive &&
			controller.establishInproxyForceSelectionCount > 0 &&
			controller.protocolSelectionConstraints.supportedProtocols(
				controller.establishConnectTunnelCount,
				excludeIntensive,
				candidateServerEntry.serverEntry).HasInproxyTunnelProtocols() {

			NoticeInfo("in-proxy protocol selection forced")
			inproxyForceSelection = true
			controller.establishInproxyForceSelectionCount -= 1
		}

		canReplay := func(serverEntry *protocol.ServerEntry, replayProtocol string) bool {

			if inproxyForceSelection {
				if !protocol.TunnelProtocolUsesInproxy(replayProtocol) {

					// Skip replay when forcing in-proxy protocol selection.
					// MakeDialParameters will call the following
					// selectProtocol callback with in-proxy preferred.
					//
					// Skipping here retains the existing replay data, as
					// DialParameters.Failed will only delete it when
					// IsReplay. However, the old replay data can be replaced
					// if the in-proxy tunnel is successful.

					return false

				} else {

					// MakeDialParameters calls canReplay only once it has
					// replay data for the server entry candidate, so this
					// will be a replay.

					NoticeInfo("in-proxy protocol selection replayed")
					return true
				}
			}

			return controller.protocolSelectionConstraints.canReplay(
				controller.establishConnectTunnelCount,
				excludeIntensive,
				serverEntry,
				replayProtocol)
		}

		// The dial rate limit delay, determined by protocolSelectionConstraints.selectProtocol, is
		// not applied within that function since this worker holds the concurrentEstablishTunnelsMutex
		// lock when that's called. Instead, the required delay is passed out and applied below.
		// It's safe for the selectProtocol callback to write to dialRateLimitDelay without
		// synchronization since this worker goroutine invokes the callback.

		var dialRateLimitDelay time.Duration

		selectProtocol := func(
			serverEntry *protocol.ServerEntry) (string, bool) {

			preferInproxy := inproxyForceSelection || prng.FlipWeightedCoin(inproxyPreferProbability)

			selectedProtocol, rateLimitDelay, ok := controller.protocolSelectionConstraints.selectProtocol(
				controller.establishConnectTunnelCount,
				excludeIntensive,
				preferInproxy,
				serverEntry)

			dialRateLimitDelay = rateLimitDelay

			return selectedProtocol, ok
		}

		// MakeDialParameters may return a replay instance, if the server
		// entry has a previous, recent successful connection and
		// tactics/config has not changed.
		//
		// In the first round -- and later rounds, with some probability -- of
		// establishing, ServerEntryIterator will move potential replay candidates
		// to the front of the iterator after the random shuffle, which greatly
		// prioritizes previously successful servers for that round.
		//
		// As ServerEntryIterator does not unmarshal and validate replay
		// candidate dial parameters, some potential replay candidates may
		// have expired or otherwise ineligible dial parameters; in this case
		// the candidate proceeds without replay.
		//
		// The ReplayCandidateCount tactic determines how many candidates may use
		// replay. After ReplayCandidateCount candidates of any type, replay or no,
		// replay is skipped. If ReplayCandidateCount exceeds the intial round,
		// replay may still be performed but the iterator may no longer move
		// potential replay server entries to the front. When ReplayCandidateCount
		// is set to -1, unlimited candidates may use replay.

		dialParams, err := MakeDialParameters(
			controller.config,
			controller.steeringIPCache,
			controller.quicTLSClientSessionCache,
			controller.tlsClientSessionCache,
			upstreamProxyErrorCallback,
			canReplay,
			selectProtocol,
			candidateServerEntry.serverEntry,
			controller.inproxyClientBrokerClientManager,
			controller.inproxyNATStateManager,
			false,
			controller.establishConnectTunnelCount,
			int(atomic.LoadInt32(&controller.establishedTunnelsCount)))
		if dialParams == nil || err != nil {

			controller.concurrentEstablishTunnelsMutex.Unlock()

			// MakeDialParameters returns nil/nil when the server entry is to
			// be skipped. See MakeDialParameters for skip cases and skip
			// logging. Silently fail the candidate in this case. Otherwise,
			// emit error.
			if err != nil {
				NoticeInfo("failed to make dial parameters for %s: %v",
					candidateServerEntry.serverEntry.GetDiagnosticID(),
					errors.Trace(err))
			}

			// Unblock other candidates immediately when server affinity
			// candidate is skipped.
			if candidateServerEntry.isServerAffinityCandidate {
				close(controller.serverAffinityDoneBroadcast)
			}

			continue
		}

		// Increment establishConnectTunnelCount only after selectProtocol has
		// succeeded to ensure InitialLimitTunnelProtocolsCandidateCount
		// candidates use InitialLimitTunnelProtocols.
		//
		// TODO: add escape from initial limit to cover cases where the
		// initial scan indicates there are sufficient candidates, but then
		// server entries are deleted.
		establishConnectTunnelCount := controller.establishConnectTunnelCount
		controller.establishConnectTunnelCount += 1

		isIntensive := protocol.TunnelProtocolIsResourceIntensive(dialParams.TunnelProtocol)

		if isIntensive {
			controller.concurrentIntensiveEstablishTunnels += 1
			if controller.concurrentIntensiveEstablishTunnels > controller.peakConcurrentIntensiveEstablishTunnels {
				controller.peakConcurrentIntensiveEstablishTunnels = controller.concurrentIntensiveEstablishTunnels
			}
		}
		controller.concurrentEstablishTunnels += 1
		if controller.concurrentEstablishTunnels > controller.peakConcurrentEstablishTunnels {
			controller.peakConcurrentEstablishTunnels = controller.concurrentEstablishTunnels
		}

		controller.concurrentEstablishTunnelsMutex.Unlock()

		startStagger := time.Now()

		// Apply stagger only now that we're past MakeDialParameters and
		// protocol selection logic which may have caused the candidate to be
		// skipped. The stagger logic delays dialing, and we don't want to
		// incur that delay that when skipping.
		//
		// Locking staggerMutex serializes staggers, so that multiple workers
		// don't simply sleep in parallel.
		//
		// The stagger is applied when establishConnectTunnelCount > 0 -- that
		// is, for all but the first dial.

		if establishConnectTunnelCount > 0 && staggerPeriod != 0 {
			controller.staggerMutex.Lock()
			timer := time.NewTimer(prng.JitterDuration(staggerPeriod, staggerJitter))
			select {
			case <-timer.C:
			case <-controller.establishCtx.Done():
			}
			timer.Stop()
			controller.staggerMutex.Unlock()
		}

		// Apply any dial rate limit delay now, after unlocking
		// concurrentEstablishTunnelsMutex. The delay may be reduced by the
		// time spent waiting to stagger.

		dialRateLimitDelay -= time.Since(startStagger)
		if dialRateLimitDelay > 0 {
			common.SleepWithContext(controller.establishCtx, dialRateLimitDelay)
		}

		// Now that this candidate will be dialed, update the server entry
		// iteration metrics to reflect this dial. This call also populates
		// dialParams with a snapshot of the current iteration metrics.

		controller.updateServerEntryIterationDialMetrics(dialParams)

		// ConnectTunnel will allocate significant memory, so first attempt to
		// reclaim as much as possible.
		DoGarbageCollection()

		tunnel, err := ConnectTunnel(
			controller.establishCtx,
			controller.config,
			candidateServerEntry.adjustedEstablishStartTime,
			dialParams)

		controller.concurrentEstablishTunnelsMutex.Lock()
		if isIntensive {
			controller.concurrentIntensiveEstablishTunnels -= 1
		}
		controller.concurrentEstablishTunnels -= 1
		controller.concurrentEstablishTunnelsMutex.Unlock()

		// Periodically emit memory metrics during the establishment cycle.
		if !controller.isStopEstablishing() {
			emitMemoryMetrics()
		}

		// Immediately reclaim memory allocated by the establishment. In the case
		// of failure, first clear the reference to the tunnel. In the case of
		// success, the garbage collection may still be effective as the initial
		// phases of some protocols involve significant memory allocation that
		// could now be reclaimed.
		if err != nil {
			tunnel = nil
		}
		DoGarbageCollection()

		if err != nil {

			// Unblock other candidates immediately when server affinity
			// candidate fails.
			if candidateServerEntry.isServerAffinityCandidate {
				close(controller.serverAffinityDoneBroadcast)
			}

			// Before emitting error, check if establish interrupted, in which
			// case the error is noise.
			if controller.isStopEstablishing() {
				break loop
			}

			NoticeInfo("failed to connect to %s: %v",
				candidateServerEntry.serverEntry.GetDiagnosticID(),
				errors.Trace(err))

			continue
		}

		// Deliver connected tunnel.
		// Don't block. Assumes the receiver has a buffer large enough for
		// the number of desired tunnels. If there's no room, the tunnel must
		// not be required so it's discarded.
		select {
		case controller.connectedTunnels <- tunnel:
		default:
			controller.discardTunnel(tunnel)

			// Clear the reference to this discarded tunnel and immediately run
			// a garbage collection to reclaim its memory.
			//
			// Note: this assignment is flagged by github.com/gordonklaus/ineffassign,
			// but should still have some effect on garbage collection?
			tunnel = nil
			DoGarbageCollection()
		}

		// Unblock other candidates only after delivering when
		// server affinity candidate succeeds.
		if candidateServerEntry.isServerAffinityCandidate {
			close(controller.serverAffinityDoneBroadcast)
		}
	}
}

func (controller *Controller) isStopEstablishing() bool {
	select {
	case <-controller.establishCtx.Done():
		return true
	default:
	}
	return false
}

func (controller *Controller) runInproxyProxy() {
	defer controller.runWaitGroup.Done()

	// Obtain and apply tactics before connecting to the broker and
	// announcing proxies.

	if !controller.config.DisableTunnels &&
		!controller.config.InproxySkipAwaitFullyConnected {

		// When running client tunnel establishment, awaiting establishment
		// guarantees fresh tactics from either an OOB request or a handshake
		// response.
		//
		// While it may be possible to proceed sooner, using cached tactics,
		// waiting until establishment is complete avoids potential races
		// between tactics updates.

		if !controller.awaitFullyEstablished() {
			// Controller is shutting down
			return
		}

	} else {

		// Await the necessary proxy broker specs. These may already be
		// available in cached tactics.
		//
		// When not already available, and when not also running client tunnel
		// establishment, i.e., when DisableTunnels is set,
		// inproxyAwaitProxyBrokerSpecs will perform tactics fetches, in
		// addition to triggering remote server list fetches in case
		// tactics-capable server entries are not available. In this mode,
		// inproxyAwaitProxyBrokerSpecs can return, after a fresh tactics
		// fetch yielding no broker specs, without broker specs.
		// haveInproxyProxyBrokerSpecs is checked again below.
		//
		// InproxySkipAwaitFullyConnected is a special testing case to support
		// server/server_test, where a client must be its own proxy; in this
		// case, awaitFullyEstablished will block forever and can't be used.
		// When InproxySkipAwaitFullyConnected is set and when also running
		// client tunnel establishment, inproxyAwaitProxyBrokerSpecs simply
		// waits until any broker specs become available, which is sufficient
		// for the test but is not as robust as awaiting fresh tactics.

		if !controller.inproxyAwaitProxyBrokerSpecs() {
			// Controller is shutting down
			return
		}
	}

	// Don't announce proxies if tactics indicates it won't be allowed. This
	// is also enforced on the broker; this client-side check cuts down on
	// load from well-behaved proxies.
	//
	// This early check is enforced only when there are tactics, as indicated
	// by presence of a tactics tag. In the proxy-only case where broker
	// specs are shipped in the proxy config, inproxyAwaitProxyBrokerSpecs
	// may return before any tactics are fetched, in which case
	// InproxyAllowProxy will always evaluate to the default, false.
	// inproxyHandleProxyTacticsPayload will check InproxyAllowProxy again,
	// after an initial proxy announce returns fresh tactics.

	p := controller.config.GetParameters().Get()
	disallowProxy := !p.Bool(parameters.InproxyAllowProxy) && p.Tag() != ""
	activityNoticePeriod := p.Duration(parameters.InproxyProxyTotalActivityNoticePeriod)
	p.Close()

	// Running an upstream proxy is also an incompatible case.
	useUpstreamProxy := controller.config.UseUpstreamProxy()

	// In both the awaitFullyEstablished and inproxyAwaitProxyBrokerSpecs
	// cases, we may arrive at this point without broker specs, and must
	// recheck.
	haveBrokerSpecs := haveInproxyProxyBrokerSpecs(controller.config)

	if disallowProxy || useUpstreamProxy || !haveBrokerSpecs || !inproxy.Enabled() {
		if disallowProxy {
			NoticeError("inproxy proxy: not allowed")
		}
		if useUpstreamProxy {
			NoticeError("inproxy proxy: not run due to upstream proxy configuration")
		}
		if !haveBrokerSpecs {
			NoticeError("inproxy proxy: no proxy broker specs")
		}
		if !inproxy.Enabled() {
			NoticeError("inproxy proxy: inproxy implementation is not enabled")
		}
		// Signal failure -- and shutdown -- only if running in proxy-only
		// mode. If also running a tunnel, keep running without proxies.
		if controller.config.DisableTunnels {
			NoticeError("inproxy proxy: aborting")
			controller.SignalComponentFailure()
		}
		return
	}

	// The debugLogging flag is passed to both NoticeCommonLogger and to the
	// inproxy package as well; skipping debug logs in the inproxy package,
	// before calling into the notice logger, avoids unnecessary allocations
	// and formatting when debug logging is off.
	debugLogging := controller.config.InproxyEnableWebRTCDebugLogging

	var lastActivityNotice time.Time
	var lastActivityConnectingClients, lastActivityConnectedClients int32
	var lastActivityConnectingClientsTotal, lastActivityConnectedClientsTotal int32
	var activityTotalBytesUp, activityTotalBytesDown int64
	activityUpdater := func(
		connectingClients int32,
		connectedClients int32,
		bytesUp int64,
		bytesDown int64,
		_ time.Duration) {

		// This emit logic mirrors the logic for NoticeBytesTransferred and
		// NoticeTotalBytesTransferred in tunnel.operateTunnel.

		// InproxyProxyActivity frequently emits bytes transferred since the
		// last notice, when not idle; in addition to the current number of
		// connecting and connected clients, whenever that changes. This
		// frequent notice is excluded from diagnostics and is for UI
		// activity display.

		if controller.config.EmitInproxyProxyActivity &&
			(bytesUp > 0 || bytesDown > 0) ||
			connectingClients != lastActivityConnectingClients ||
			connectedClients != lastActivityConnectedClients {

			NoticeInproxyProxyActivity(
				connectingClients, connectedClients, bytesUp, bytesDown)

			lastActivityConnectingClients = connectingClients
			lastActivityConnectedClients = connectedClients
		}

		activityTotalBytesUp += bytesUp
		activityTotalBytesDown += bytesDown

		// InproxyProxyTotalActivity periodically emits total bytes
		// transferred since starting; in addition to the current number of
		// connecting and connected clients, whenever that changes. This
		// notice is for diagnostics.

		if lastActivityNotice.Add(activityNoticePeriod).Before(time.Now()) ||
			connectingClients != lastActivityConnectingClientsTotal ||
			connectedClients != lastActivityConnectedClientsTotal {

			NoticeInproxyProxyTotalActivity(
				connectingClients, connectedClients,
				activityTotalBytesUp, activityTotalBytesDown)
			lastActivityNotice = time.Now()

			lastActivityConnectingClientsTotal = connectingClients
			lastActivityConnectedClientsTotal = connectedClients
		}
	}

	config := &inproxy.ProxyConfig{
		Logger:                        NoticeCommonLogger(debugLogging),
		EnableWebRTCDebugLogging:      debugLogging,
		WaitForNetworkConnectivity:    controller.inproxyWaitForNetworkConnectivity,
		GetCurrentNetworkContext:      controller.getCurrentNetworkContext,
		GetBrokerClient:               controller.inproxyGetProxyBrokerClient,
		GetBaseAPIParameters:          controller.inproxyGetProxyAPIParameters,
		MakeWebRTCDialCoordinator:     controller.inproxyMakeProxyWebRTCDialCoordinator,
		HandleTacticsPayload:          controller.inproxyHandleProxyTacticsPayload,
		MaxClients:                    controller.config.InproxyMaxClients,
		LimitUpstreamBytesPerSecond:   controller.config.InproxyLimitUpstreamBytesPerSecond,
		LimitDownstreamBytesPerSecond: controller.config.InproxyLimitDownstreamBytesPerSecond,
		MustUpgrade:                   controller.config.OnInproxyMustUpgrade,
		ActivityUpdater:               activityUpdater,
	}

	proxy, err := inproxy.NewProxy(config)
	if err != nil {
		NoticeError("inproxy.NewProxy failed: %v", errors.Trace(err))
		controller.SignalComponentFailure()
		return
	}

	NoticeInfo("inproxy proxy: running")

	proxy.Run(controller.runCtx)

	// Emit one last NoticeInproxyProxyTotalActivity with the final byte counts.
	NoticeInproxyProxyTotalActivity(
		lastActivityConnectingClients, lastActivityConnectedClients,
		activityTotalBytesUp, activityTotalBytesDown)

	NoticeInfo("inproxy proxy: stopped")
}

// inproxyAwaitProxyBrokerSpecs awaits proxy broker specs or a fresh tactics
// fetch indicating that there are no proxy broker specs. The caller should
// check haveInproxyProxyBrokerSpecs to determine which is the case.
//
// inproxyAwaitProxyBrokerSpecs is intended for use either when DisableTunnels
// is set or when InproxySkipAwaitFullyConnected is set.
//
// In the DisableTunnels case, inproxyAwaitProxyBrokerSpecs will perform
// tactics fetches and trigger remote server list fetches in case
// tactics-capable server entries are required. The DisableTunnels case
// assumes client tunnel establishment is not also running, as the tactics
// operations could otherwise conflict.
//
// In the InproxySkipAwaitFullyConnected case, which is intended only to
// support testing, inproxyAwaitProxyBrokerSpecs simply polls forever for
// proxy broker specs expected, in the test, to be obtained from concurrent
// client tunnel establishment operations.
//
// inproxyAwaitProxyBrokerSpecs returns false when the Controller is
// stopping.
func (controller *Controller) inproxyAwaitProxyBrokerSpecs() bool {

	// Check for any broker specs in cached tactics or config parameters
	// already loaded by NewController or Config.Commit.
	if haveInproxyProxyBrokerSpecs(controller.config) {
		return true
	}

	// If there are no broker specs in config parameters and tactics are
	// disabled, there is nothing more to await.
	if controller.config.DisableTactics {
		NoticeWarning("inproxy proxy: no broker specs and tactics disabled")
		return true
	}

	NoticeInfo("inproxy proxy: await tactics with proxy broker specs")

	// Orchestrating fetches roughly follows the same pattern as
	// establishCandidateGenerator, with a WaitForNetworkConnectivity check,
	// followed by the fetch operation; and a remote server list trigger when
	// that fails, followed by a short pause.
	doFetches := controller.config.DisableTunnels

	// pollPeriod for InproxySkipAwaitFullyConnected case.
	pollPeriod := 100 * time.Millisecond

	for {
		fetched := false
		if doFetches {
			if !WaitForNetworkConnectivity(
				controller.runCtx,
				controller.config.NetworkConnectivityChecker,
				nil) {
				// Controller is shutting down
				return false
			}
			// Force a fetch for the latest tactics, since cached tactics, if
			// any, did not yield proxy broker specs.
			useStoredTactics := false
			fetched = GetTactics(controller.runCtx, controller.config, useStoredTactics)
		}

		if haveInproxyProxyBrokerSpecs(controller.config) {
			return true
		} else if fetched {
			// If fresh tactics yielded no proxy broker specs, there is
			// nothing more to await.
			NoticeWarning("inproxy proxy: no broker specs in tactics")
			return true
		}

		timeout := pollPeriod
		if doFetches {

			// Trigger remote server list fetches in case the tactics fetch
			// failed due to "no capable servers". Repeated triggers will
			// have no effect, subject to FetchRemoteServerListStalePeriod.
			//
			// While triggerFetches also triggers upgrade downloads, currently
			// the upgrade downloader is not enabled when DisableTunnels is
			// set. See Controller.Run.
			//
			// TODO: make the trigger conditional on the specific "no capable
			// servers" failure condition.
			controller.triggerFetches()

			// Pause before attempting to fetch tactics again. This helps
			// avoid some busy wait loop conditions, allows some time for
			// network conditions to change, and also allows for remote server
			// list fetches to complete. The EstablishTunnelPausePeriod and
			// Jitter parameters used in establishCandidateGenerator are also
			// appropriate in this instance.
			p := controller.config.GetParameters().Get()
			timeout = prng.JitterDuration(
				p.Duration(parameters.EstablishTunnelPausePeriod),
				p.Float(parameters.EstablishTunnelPausePeriodJitter))
			p.Close()
		}

		timer := time.NewTimer(timeout)
		select {
		case <-timer.C:
		case <-controller.runCtx.Done():
			timer.Stop()
			// Controller is shutting down
			return false
		}
		timer.Stop()
	}
}

func (controller *Controller) inproxyWaitForNetworkConnectivity() bool {

	var isCompatibleNetwork func() bool
	emittedIncompatibleNetworkNotice := false

	if !controller.config.IsInproxyProxyPersonalPairingMode() {

		// Pause announcing proxies when currently running on an incompatible
		// network, such as a non-Psiphon VPN.

		p := controller.config.GetParameters().Get()
		incompatibleNetworkTypes := p.Strings(parameters.InproxyProxyIncompatibleNetworkTypes)
		p.Close()

		isCompatibleNetwork = func() bool {
			compatibleNetwork := !common.Contains(
				incompatibleNetworkTypes,
				GetNetworkType(controller.config.GetNetworkID()))
			if !compatibleNetwork && !emittedIncompatibleNetworkNotice {
				NoticeInfo("inproxy proxy: waiting due to incompatible network")
				emittedIncompatibleNetworkNotice = true
			}
			return compatibleNetwork
		}
	}

	return WaitForNetworkConnectivity(
		controller.runCtx,
		controller.config.NetworkConnectivityChecker,
		isCompatibleNetwork)
}

// inproxyGetProxyBrokerClient returns the broker client shared by all proxy
// operations.
func (controller *Controller) inproxyGetProxyBrokerClient() (*inproxy.BrokerClient, error) {

	brokerClient, _, err := controller.inproxyProxyBrokerClientManager.GetBrokerClient(
		controller.config.GetNetworkID())
	if err != nil {
		return nil, errors.Trace(err)
	}
	return brokerClient, nil
}

func (controller *Controller) inproxyGetProxyAPIParameters(includeTacticsParameters bool) (
	common.APIParameters, string, error) {

	// TODO: include broker fronting dial parameters to be logged by the
	// broker.
	includeSessionID := true
	params := getBaseAPIParameters(
		baseParametersNoDialParameters, nil, includeSessionID, controller.config, nil)

	if controller.config.DisableTactics {
		return params, "", nil
	}

	// Add the stored tactics tag, so that the broker can return new tactics if
	// available.
	//
	// The active network ID is recorded returned and rechecked for
	// consistency when storing any new tactics returned from the broker;
	// other tactics fetches have this same check.

	networkID := controller.config.GetNetworkID()

	if includeTacticsParameters {
		err := tactics.SetTacticsAPIParameters(
			GetTacticsStorer(controller.config), networkID, params)
		if err != nil {
			return nil, "", errors.Trace(err)
		}

		p := controller.config.GetParameters().Get()
		compressTactics := p.Bool(parameters.CompressTactics)
		p.Close()

		if compressTactics {
			protocol.SetCompressTactics(params)
		}
	}

	return params, networkID, nil
}

func (controller *Controller) inproxyMakeProxyWebRTCDialCoordinator() (
	inproxy.WebRTCDialCoordinator, error) {

	// nil is passed in for both InproxySTUNDialParameters and
	// InproxyWebRTCDialParameters, so those parameters will be newly
	// auto-generated for each client/proxy connection attempt. Unlike the
	// in-proxy client, there is currently no replay of STUN or WebRTC dial
	// parameters.

	isProxy := true
	webRTCDialInstance, err := NewInproxyWebRTCDialInstance(
		controller.config,
		controller.config.GetNetworkID(),
		isProxy,
		controller.inproxyNATStateManager,
		nil,
		nil)
	if err != nil {
		return nil, errors.Trace(err)
	}

	return webRTCDialInstance, nil
}

// inproxyHandleProxyTacticsPayload handles new tactics returned from the
// proxy and returns when tactics have changed.
//
// inproxyHandleTacticsPayload duplicates some tactics-handling code from
// doHandshakeRequest.
func (controller *Controller) inproxyHandleProxyTacticsPayload(
	networkID string, compressTactics bool, tacticsPayload []byte) bool {

	if controller.config.DisableTactics {
		return false
	}

	if controller.config.GetNetworkID() != networkID {
		// Ignore the tactics if the network ID has changed.
		return false
	}

	var payloadUnmarshaler func([]byte, any) error
	payloadUnmarshaler = json.Unmarshal
	if compressTactics {
		payloadUnmarshaler = cbor.Unmarshal
	}

	var payload *tactics.Payload
	err := payloadUnmarshaler(tacticsPayload, &payload)
	if err != nil {
		NoticeError("unmarshal tactics payload failed: %v", errors.Trace(err))
		return false
	}

	if payload == nil {
		// See "null" comment in doHandshakeRequest.
		return false
	}

	// The in-proxy proxy implementation arranges for the first ProxyAnnounce
	// request to get a head start in case there are new tactics available
	// from the broker. Additional requests are also staggered.
	//
	// It can still happen that concurrent in-flight ProxyAnnounce requests
	// receive duplicate new-tactics responses.
	//
	// TODO: detect this case and avoid resetting the broker client and NAT
	// state managers more than necessary.

	// Serialize processing of tactics from ProxyAnnounce responses.
	controller.inproxyHandleTacticsMutex.Lock()
	defer controller.inproxyHandleTacticsMutex.Unlock()

	// When tactics are unchanged, the broker, as in the handshake case,
	// returns a tactics payload, but without new tactics. As in the
	// handshake case, HandleTacticsPayload is called in order to extend the
	// TTL of the locally cached, unchanged tactics. Due to the potential
	// high frequency and concurrency of ProxyAnnnounce requests vs.
	// handshakes, a limit is added to update the data store's tactics TTL no
	// more than one per minute.

	appliedNewTactics := payload.Tactics != nil
	now := time.Now()
	if !appliedNewTactics && now.Sub(controller.inproxyLastStoredTactics) > 1*time.Minute {
		// Skip TTL-only disk write.
		return false
	}
	controller.inproxyLastStoredTactics = now

	tacticsRecord, err := tactics.HandleTacticsPayload(
		GetTacticsStorer(controller.config), networkID, payload)
	if err != nil {
		NoticeError("HandleTacticsPayload failed: %v", errors.Trace(err))
		return false
	}

	if tacticsRecord != nil {

		// SetParameters signals registered components, including broker
		// client and NAT state managers, that must reset upon tactics changes.

		err := controller.config.SetParameters(
			tacticsRecord.Tag, true, tacticsRecord.Tactics.Parameters)
		if err != nil {
			NoticeInfo("apply inproxy broker tactics failed: %s", err)
			return false
		}
	} else {
		appliedNewTactics = false
	}

	if appliedNewTactics {

		// Shutdown if running in proxy-only and tactics now indicate the
		// proxy is not allowed.
		//
		// Limitation: does not immediately stop proxy in dual proxy/tunnel mode.

		p := controller.config.GetParameters().Get()
		disallowProxy := !p.Bool(parameters.InproxyAllowProxy)
		p.Close()

		if disallowProxy {
			NoticeError("inproxy proxy: not allowed")
			if controller.config.DisableTunnels {
				NoticeError("inproxy proxy: shutdown")
				controller.SignalComponentFailure()
			}

		}
	}

	return appliedNewTactics
}
