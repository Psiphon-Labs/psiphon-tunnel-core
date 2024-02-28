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
	"fmt"
	"math/rand"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	tls "github.com/Psiphon-Labs/psiphon-tls"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/parameters"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/resolver"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/tun"
	lrucache "github.com/cognusion/go-cache-lru"
	utls "github.com/refraction-networking/utls"
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
	establishCtx                            context.Context
	stopEstablish                           context.CancelFunc
	establishWaitGroup                      *sync.WaitGroup
	establishedTunnelsCount                 int32
	candidateServerEntries                  chan *candidateServerEntry
	untunneledDialConfig                    *DialConfig
	untunneledSplitTunnelClassifications    *lrucache.Cache
	splitTunnelClassificationTTL            time.Duration
	splitTunnelClassificationMaxEntries     int
	signalFetchCommonRemoteServerList       chan struct{}
	signalFetchObfuscatedServerLists        chan struct{}
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
	tlsClientSessionCache                   tls.ClientSessionCache
	utlsClientSessionCache                  utls.ClientSessionCache
}

// NewController initializes a new controller.
func NewController(config *Config) (controller *Controller, err error) {

	if !config.IsCommitted() {
		return nil, errors.TraceNew("uncommitted config")
	}

	// Needed by regen, at least
	rand.Seed(int64(time.Now().Nanosecond()))

	// The session ID for the Psiphon server API is used across all
	// tunnels established by the controller.
	NoticeSessionId(config.SessionID)

	// Attempt to apply any valid, local stored tactics. The pre-done context
	// ensures no tactics request is attempted now.
	doneContext, cancelFunc := context.WithCancel(context.Background())
	cancelFunc()
	GetTactics(doneContext, config)

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

		tlsClientSessionCache:  tls.NewLRUClientSessionCache(0),
		utlsClientSessionCache: utls.NewLRUClientSessionCache(0),
	}

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
			Logger:                    NoticeCommonLogger(),
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

	// Wait while running

	<-controller.runCtx.Done()
	NoticeInfo("controller stopped")

	if controller.packetTunnelClient != nil {
		controller.packetTunnelClient.Stop()
	}

	// All workers -- runTunnels, establishment workers, and auxilliary
	// workers such as fetch remote server list and untunneled uprade
	// download -- operate with the controller run context and will all
	// be interrupted when the run context is done.

	controller.runWaitGroup.Wait()

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
				controller.config.NetworkConnectivityChecker) {
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
				controller.untunneledDialConfig)

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
				controller.config.NetworkConnectivityChecker) {
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
				controller.untunneledDialConfig)

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
	constraints   *protocolSelectionConstraints
	awaitResponse chan *serverEntriesReportResponse
}

type serverEntriesReportResponse struct {
	err                              error
	candidates                       int
	initialCandidates                int
	initialCandidatesAnyEgressRegion int
	availableEgressRegions           []string
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
// The underlying datastore implementation _may_ block write transactions
// while there are open read transactions. For example, bolt write
// transactions which need to  re-map the data file (when the datastore grows)
// will block on open read transactions. In these scenarios, a slow scan will
// still block other operations.
//
// serverEntriesReporter runs beyond the establishment phase, since it's
// important for notices such as AvailableEgressRegions to eventually emit
// even if already established. serverEntriesReporter scans are cancellable,
// so controller shutdown is not blocked by slow scans.
//
// In some special cases, establishment cannot begin without candidate counts
// up front. In these cases only, the request contains a non-nil
// awaitResponse, a channel which is used by the requester to block until the
// scan is complete and the candidate counts are available.
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

		var response serverEntriesReportResponse

		regions := make(map[string]bool)

		callback := func(serverEntry *protocol.ServerEntry) bool {

			// In establishment, excludeIntensive depends on what set of protocols are
			// already being dialed. For these reports, don't exclude intensive
			// protocols as any intensive candidate can always be an available
			// candidate at some point.
			excludeIntensive := false

			isInitialCandidate := constraints.isInitialCandidate(excludeIntensive, serverEntry)
			isCandidate := constraints.isCandidate(excludeIntensive, serverEntry)

			if isInitialCandidate {
				response.initialCandidatesAnyEgressRegion += 1
			}

			if egressRegion == "" || serverEntry.Region == egressRegion {
				if isInitialCandidate {
					response.initialCandidates += 1
				}
				if isCandidate {
					response.candidates += 1
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

		response.err = ScanServerEntries(callback)

		// Report this duration in CandidateServers as an indication of datastore
		// performance.
		duration := time.Since(startTime)

		response.availableEgressRegions = make([]string, 0, len(regions))
		for region := range regions {
			response.availableEgressRegions = append(response.availableEgressRegions, region)
		}

		if response.err != nil {

			// For diagnostics, we'll post this even when cancelled due to shutdown.
			NoticeWarning("ScanServerEntries failed: %v", errors.Trace(response.err))

			// Continue and send error reponse. Clear any partial data to avoid
			// misuse.
			response.candidates = 0
			response.initialCandidates = 0
			response.initialCandidatesAnyEgressRegion = 0
			response.availableEgressRegions = []string{}
		}

		if request.awaitResponse != nil {
			select {
			case request.awaitResponse <- &response:
			case <-controller.runCtx.Done():
				// The receiver may be gone when shutting down.
			}
		}

		if response.err == nil {

			NoticeCandidateServers(
				controller.config.EgressRegion,
				controller.protocolSelectionConstraints,
				response.initialCandidates,
				response.candidates,
				duration)

			NoticeAvailableEgressRegions(
				response.availableEgressRegions)
		}
	}

	NoticeInfo("exiting server entries reporter")
}

// signalServerEntriesReporter triggers a new server entry report. Set
// request.awaitResponse to obtain the report output. When awaitResponse is
// set, signalServerEntriesReporter blocks until the reporter receives the
// request, guaranteeing the new report runs. Otherwise, the report is
// considered to be informational and may or may not run, depending on whether
// another run is already in progress.
func (controller *Controller) signalServerEntriesReporter(request *serverEntriesReportRequest) {

	if request.awaitResponse == nil {
		select {
		case controller.signalReportServerEntries <- request:
		default:
		}
	} else {
		controller.signalReportServerEntries <- request
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

				err := connectedTunnel.Activate(controller.runCtx, controller)

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
				connectedTunnel.dialParams.TunnelProtocol,
				connectedTunnel.dialParams.ServerEntry.SupportsSSHAPIRequests())

			if isFirstTunnel {

				// Signal a connected request on each 1st tunnel establishment. For
				// multi-tunnels, the session is connected as long as at least one
				// tunnel is established.
				controller.signalConnectedReporter()

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
		PromoteServerEntry(controller.config, tunnel.dialParams.ServerEntry.IpAddress)
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

	splitTunnelHost, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return nil, errors.Trace(err)
	}

	untunneledCache := controller.untunneledSplitTunnelClassifications

	// If the destination hostname is in the untunneled split tunnel
	// classifications cache, skip the round trip to the server and do the
	// direct, untunneled dial immediately.
	_, cachedUntunneled := untunneledCache.Get(splitTunnelHost)

	if !cachedUntunneled {

		tunneledConn, splitTunnel, err := tunnel.DialTCPChannel(
			remoteAddr, false, downstreamConn)
		if err != nil {
			return nil, errors.Trace(err)
		}

		if !splitTunnel {

			// Clear any cached untunneled classification entry for this destination
			// hostname, as the server is now classifying it as tunneled.
			untunneledCache.Delete(splitTunnelHost)

			return tunneledConn, nil
		}

		// The server has indicated that the client should make a direct,
		// untunneled dial. Cache the classification to avoid this round trip in
		// the immediate future.
		untunneledCache.Add(splitTunnelHost, true, lrucache.DefaultExpiration)
	}

	NoticeUntunneled(splitTunnelHost)

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

// triggerFetches signals RSL, OSL, and upgrade download fetchers to begin, if
// not already running. triggerFetches is called when tunnel establishment
// fails to complete within a deadline and in other cases where local
// circumvention capabilities are lacking and we may require new server
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

	// Trigger an OSL fetch in parallel. Both fetches are run in parallel
	// so that if one out of the common RLS and OSL set is large, it doesn't
	// doesn't entirely block fetching the other.
	select {
	case controller.signalFetchObfuscatedServerLists <- struct{}{}:
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
	useUpstreamProxy                          bool
	initialLimitTunnelProtocols               protocol.TunnelProtocols
	initialLimitTunnelProtocolsCandidateCount int
	limitTunnelProtocols                      protocol.TunnelProtocols
	limitTunnelDialPortNumbers                protocol.TunnelProtocolPortLists
	limitQUICVersions                         protocol.QUICVersions
	replayCandidateCount                      int
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
			p.useUpstreamProxy,
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
		p.useUpstreamProxy,
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
		p.supportedProtocols(connectTunnelCount, excludeIntensive, serverEntry),
		replayProtocol)
}

func (p *protocolSelectionConstraints) supportedProtocols(
	connectTunnelCount int,
	excludeIntensive bool,
	serverEntry *protocol.ServerEntry) []string {

	limitTunnelProtocols := p.limitTunnelProtocols

	if len(p.initialLimitTunnelProtocols) > 0 &&
		p.initialLimitTunnelProtocolsCandidateCount > connectTunnelCount {

		limitTunnelProtocols = p.initialLimitTunnelProtocols
	}

	return serverEntry.GetSupportedProtocols(
		conditionallyEnabledComponents{},
		p.useUpstreamProxy,
		limitTunnelProtocols,
		p.limitTunnelDialPortNumbers,
		p.limitQUICVersions,
		excludeIntensive)
}

func (p *protocolSelectionConstraints) selectProtocol(
	connectTunnelCount int,
	excludeIntensive bool,
	serverEntry *protocol.ServerEntry) (string, bool) {

	candidateProtocols := p.supportedProtocols(connectTunnelCount, excludeIntensive, serverEntry)

	if len(candidateProtocols) == 0 {
		return "", false
	}

	// Pick at random from the supported protocols. This ensures that we'll
	// eventually try all possible protocols. Depending on network
	// configuration, it may be the case that some protocol is only available
	// through multi-capability servers, and a simpler ranked preference of
	// protocols could lead to that protocol never being selected.

	index := prng.Intn(len(candidateProtocols))

	return candidateProtocols[index], true

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

	controller.establishWaitGroup.Add(1)
	go controller.launchEstablishing()
}

func (controller *Controller) launchEstablishing() {

	defer controller.establishWaitGroup.Done()

	// Before starting the establish tunnel workers, get and apply
	// tactics, launching a tactics request if required.
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

	if !controller.config.DisableTactics {

		timeout := controller.config.GetParameters().Get().Duration(
			parameters.TacticsWaitPeriod)

		tacticsDone := make(chan struct{})
		tacticsWaitPeriod := time.NewTimer(timeout)
		defer tacticsWaitPeriod.Stop()

		controller.establishWaitGroup.Add(1)
		go func() {
			defer controller.establishWaitGroup.Done()
			defer close(tacticsDone)
			GetTactics(controller.establishCtx, controller.config)
		}()

		select {
		case <-tacticsDone:
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
		useUpstreamProxy:                          controller.config.UseUpstreamProxy(),
		initialLimitTunnelProtocols:               p.TunnelProtocols(parameters.InitialLimitTunnelProtocols),
		initialLimitTunnelProtocolsCandidateCount: p.Int(parameters.InitialLimitTunnelProtocolsCandidateCount),
		limitTunnelProtocols:                      p.TunnelProtocols(parameters.LimitTunnelProtocols),

		limitTunnelDialPortNumbers: protocol.TunnelProtocolPortLists(
			p.TunnelProtocolPortLists(parameters.LimitTunnelDialPortNumbers)),

		replayCandidateCount: p.Int(parameters.ReplayCandidateCount),
	}

	// ConnectionWorkerPoolSize may be set by tactics.

	workerPoolSize := p.Int(parameters.ConnectionWorkerPoolSize)

	// When TargetServerEntry is used, override any worker pool size config or
	// tactic parameter and use a pool size of 1. The typical use case for
	// TargetServerEntry is to test a specific server with a single connection
	// attempt. Furthermore, too many concurrent attempts to connect to the
	// same server will trigger rate limiting.
	if controller.config.TargetServerEntry != "" {
		workerPoolSize = 1
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

	p.Close()

	// Trigger CandidateServers and AvailableEgressRegions notices. By default,
	// this is an asynchronous operation, as the underlying full server entry
	// list enumeration may be a slow operation. In certain cases, where
	// candidate counts are required up front, await the result before
	// proceeding.

	awaitResponse := tunnelPoolSize > 1 ||
		controller.protocolSelectionConstraints.initialLimitTunnelProtocolsCandidateCount > 0

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

	// Concurrency note: controller.protocolSelectionConstraints may be
	// overwritten before serverEntriesReporter reads it, and so cannot be
	// accessed directly by serverEntriesReporter.
	reportRequest := &serverEntriesReportRequest{
		constraints: controller.protocolSelectionConstraints,
	}

	if awaitResponse {
		// Buffer size of 1 ensures the sender, serverEntryReporter, won't block on
		// sending the response in the case where launchEstablishing exits due to
		// stopping establishment.
		reportRequest.awaitResponse = make(chan *serverEntriesReportResponse, 1)
	}

	controller.signalServerEntriesReporter(reportRequest)

	if awaitResponse {

		var reportResponse *serverEntriesReportResponse
		select {
		case reportResponse = <-reportRequest.awaitResponse:
		case <-controller.establishCtx.Done():
			// The sender may be gone when shutting down, or may not send until after
			// stopping establishment.
			return
		}
		if reportResponse.err != nil {
			NoticeError("failed to report server entries: %v",
				errors.Trace(reportResponse.err))
			controller.SignalComponentFailure()
			return
		}

		// Make adjustments based on candidate counts.

		if tunnelPoolSize > 1 {
			// Initial canidate count is ignored as count candidates will eventually
			// become available.
			if reportResponse.candidates < tunnelPoolSize {
				tunnelPoolSize = reportResponse.candidates
			}
			if tunnelPoolSize < 1 {
				tunnelPoolSize = 1
			}
		}
		controller.setTunnelPoolSize(tunnelPoolSize)

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

		if controller.protocolSelectionConstraints.initialLimitTunnelProtocolsCandidateCount > 0 {

			if reportResponse.initialCandidatesAnyEgressRegion == 0 {
				NoticeWarning("skipping initial limit tunnel protocols")
				controller.protocolSelectionConstraints.initialLimitTunnelProtocolsCandidateCount = 0

				// Since we were unable to satisfy the InitialLimitTunnelProtocols
				// tactic, trigger RSL, OSL, and upgrade fetches to potentially
				// gain new capabilities.
				controller.triggerFetches()
			}
		}
	}

	for i := 0; i < workerPoolSize; i++ {
		controller.establishWaitGroup.Add(1)
		go controller.establishTunnelWorker()
	}

	controller.establishWaitGroup.Add(1)
	go controller.establishCandidateGenerator()
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
				controller.config.NetworkConnectivityChecker) {
				break loop
			}
			networkWaitDuration := time.Since(networkWaitStartTime)
			roundNetworkWaitDuration += networkWaitDuration
			totalNetworkWaitDuration += networkWaitDuration

			serverEntry, err := iterator.Next()
			if err != nil {
				NoticeError("failed to get next candidate: %v", errors.Trace(err))
				controller.SignalComponentFailure()
				break loop
			}
			if serverEntry == nil {
				// Completed this iteration
				NoticeInfo("completed server entry iteration")
				break
			}

			if controller.config.TargetApiProtocol == protocol.PSIPHON_SSH_API_PROTOCOL &&
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

		// Free up resources now, but don't reset until after the pause.
		iterator.Close()

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

		if (candidateServerEntryCount == 0 ||
			time.Since(controller.establishStartTime)-totalNetworkWaitDuration > workTime) &&
			controller.config.TargetServerEntry == "" {

			controller.triggerFetches()
		}

		// After a complete iteration of candidate servers, pause before iterating again.
		// This helps avoid some busy wait loop conditions, and also allows some time for
		// network conditions to change. Also allows for fetch remote to complete,
		// in typical conditions (it isn't strictly necessary to wait for this, there will
		// be more rounds if required).

		p := controller.config.GetParameters().Get()
		timeout := prng.JitterDuration(
			p.Duration(parameters.EstablishTunnelPausePeriod),
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

		iterator.Reset()
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

		limitIntensiveConnectionWorkers := controller.config.GetParameters().Get().Int(
			parameters.LimitIntensiveConnectionWorkers)

		controller.concurrentEstablishTunnelsMutex.Lock()

		excludeIntensive := false
		if limitIntensiveConnectionWorkers > 0 &&
			controller.concurrentIntensiveEstablishTunnels >= limitIntensiveConnectionWorkers {
			excludeIntensive = true
		}

		canReplay := func(serverEntry *protocol.ServerEntry, replayProtocol string) bool {
			return controller.protocolSelectionConstraints.canReplay(
				controller.establishConnectTunnelCount,
				excludeIntensive,
				serverEntry,
				replayProtocol)
		}

		selectProtocol := func(serverEntry *protocol.ServerEntry) (string, bool) {
			return controller.protocolSelectionConstraints.selectProtocol(
				controller.establishConnectTunnelCount,
				excludeIntensive,
				serverEntry)
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
			controller.tlsClientSessionCache,
			controller.utlsClientSessionCache,
			upstreamProxyErrorCallback,
			canReplay,
			selectProtocol,
			candidateServerEntry.serverEntry,
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

		p := controller.config.GetParameters().Get()
		staggerPeriod := p.Duration(parameters.StaggerConnectionWorkersPeriod)
		staggerJitter := p.Float(parameters.StaggerConnectionWorkersJitter)
		p.Close()

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
