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
	std_errors "errors"
	"fmt"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/parameters"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/tactics"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/tun"
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
	tunnels                                 []*Tunnel
	nextTunnel                              int
	isEstablishing                          bool
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
	splitTunnelClassifier                   *SplitTunnelClassifier
	signalFetchCommonRemoteServerList       chan struct{}
	signalFetchObfuscatedServerLists        chan struct{}
	signalDownloadUpgrade                   chan string
	signalReportConnected                   chan struct{}
	signalRestartEstablishing               chan struct{}
	serverAffinityDoneBroadcast             chan struct{}
	packetTunnelClient                      *tun.Client
	packetTunnelTransport                   *PacketTunnelTransport
	staggerMutex                            sync.Mutex
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

	untunneledDialConfig := &DialConfig{
		UpstreamProxyURL:              config.UpstreamProxyURL,
		CustomHeaders:                 config.CustomHeaders,
		DeviceBinder:                  config.deviceBinder,
		DnsServerGetter:               config.DnsServerGetter,
		IPv6Synthesizer:               config.IPv6Synthesizer,
		TrustedCACertificatesFilename: config.TrustedCACertificatesFilename,
	}

	controller = &Controller{
		config:       config,
		runWaitGroup: new(sync.WaitGroup),
		// connectedTunnels and failedTunnels buffer sizes are large enough to
		// receive full pools of tunnels without blocking. Senders should not block.
		connectedTunnels:     make(chan *Tunnel, config.TunnelPoolSize),
		failedTunnels:        make(chan *Tunnel, config.TunnelPoolSize),
		tunnels:              make([]*Tunnel, 0),
		establishedOnce:      false,
		isEstablishing:       false,
		untunneledDialConfig: untunneledDialConfig,
		// TODO: Add a buffer of 1 so we don't miss a signal while receiver is
		// starting? Trade-off is potential back-to-back fetch remotes. As-is,
		// establish will eventually signal another fetch remote.
		signalFetchCommonRemoteServerList: make(chan struct{}),
		signalFetchObfuscatedServerLists:  make(chan struct{}),
		signalDownloadUpgrade:             make(chan string),
		signalReportConnected:             make(chan struct{}),

		// signalRestartEstablishing has a buffer of 1 to ensure sending the
		// signal doesn't block and receiving won't miss a signal.
		signalRestartEstablishing: make(chan struct{}, 1),
	}

	controller.splitTunnelClassifier = NewSplitTunnelClassifier(config, controller)

	if config.PacketTunnelTunFileDescriptor > 0 {

		// Run a packet tunnel client. The lifetime of the tun.Client is the
		// lifetime of the Controller, so it exists across tunnel establishments
		// and reestablishments. The PacketTunnelTransport provides a layer
		// that presents a continuosuly existing transport to the tun.Client;
		// it's set to use new SSH channels after new SSH tunnel establishes.

		packetTunnelTransport := NewPacketTunnelTransport()

		packetTunnelClient, err := tun.NewClient(&tun.ClientConfig{
			Logger:            NoticeCommonLogger(),
			TunFileDescriptor: config.PacketTunnelTunFileDescriptor,
			Transport:         packetTunnelTransport,
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
			NoticeError("error getting listener IP: %s", errors.Trace(err))
			return
		}
		listenIP = IPv4Address.String()
	}

	if !controller.config.DisableLocalSocksProxy {
		socksProxy, err := NewSocksProxy(controller.config, controller, listenIP)
		if err != nil {
			NoticeWarning("error initializing local SOCKS proxy: %s", err)
			return
		}
		defer socksProxy.Close()
	}

	if !controller.config.DisableLocalHTTPProxy {
		httpProxy, err := NewHttpProxy(controller.config, controller, listenIP)
		if err != nil {
			NoticeWarning("error initializing local HTTP proxy: %s", err)
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

	if controller.config.UpgradeDownloadURLs != nil {
		controller.runWaitGroup.Add(1)
		go controller.upgradeDownloader()
	}

	controller.runWaitGroup.Add(1)
	go controller.connectedReporter()

	controller.runWaitGroup.Add(1)
	go controller.runTunnels()

	controller.runWaitGroup.Add(1)
	go controller.establishTunnelWatcher()

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

	controller.splitTunnelClassifier.Shutdown()

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

		stalePeriod := controller.config.GetClientParameters().Get().Duration(
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

			NoticeWarning("failed to fetch %s remote server list: %s", name, err)

			retryPeriod := controller.config.GetClientParameters().Get().Duration(
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

// establishTunnelWatcher terminates the controller if a tunnel
// has not been established in the configured time period. This
// is regardless of how many tunnels are presently active -- meaning
// that if an active tunnel was established and lost the controller
// is left running (to re-establish).
func (controller *Controller) establishTunnelWatcher() {
	defer controller.runWaitGroup.Done()

	timeout := controller.config.GetClientParameters().Get().Duration(
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

loop:
	for {

		select {
		case <-controller.signalReportConnected:
			// Make the initial connected request
		case <-controller.runCtx.Done():
			break loop
		}

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
				NoticeWarning("failed to make connected request: %s", err)
			}
		}

		// Schedule the next connected request and wait. This duration is not a
		// dynamic ClientParameter as the daily unique user stats logic specifically
		// requires a "connected" request no more or less often than every 24h.
		var duration time.Duration
		if reported {
			duration = 24 * time.Hour
		} else {
			duration = controller.config.GetClientParameters().Get().Duration(
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
//
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

		stalePeriod := controller.config.GetClientParameters().Get().Duration(
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

			NoticeWarning("failed to download upgrade: %s", err)

			timeout := controller.config.GetClientParameters().Get().Duration(
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
			// In the typical case of TunnelPoolSize of 1, only a single handshake is
			// performed and the homepages notices file, when used, will not be modifed
			// after the NoticeTunnels(1) [i.e., connected] until NoticeTunnels(0) [i.e.,
			// disconnected]. For TunnelPoolSize > 1, serial handshakes only ensures that
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
					NoticeWarning("failed to activate %s: %s",
						connectedTunnel.dialParams.ServerEntry.GetDiagnosticID(), err)
					discardTunnel = true
				} else {
					// It's unlikely that registerTunnel will fail, since only this goroutine
					// calls registerTunnel -- and after checking numTunnels; so failure is not
					// expected.
					if !controller.registerTunnel(connectedTunnel) {
						NoticeWarning("failed to register %s: %s",
							connectedTunnel.dialParams.ServerEntry.GetDiagnosticID(), err)
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

				// The split tunnel classifier is started once the first tunnel is
				// established. This first tunnel is passed in to be used to make
				// the routes data request.
				// A long-running controller may run while the host device is present
				// in different regions. In this case, we want the split tunnel logic
				// to switch to routes for new regions and not classify traffic based
				// on routes installed for older regions.
				// We assume that when regions change, the host network will also
				// change, and so all tunnels will fail and be re-established. Under
				// that assumption, the classifier will be re-Start()-ed here when
				// the region has changed.
				controller.splitTunnelClassifier.Start(connectedTunnel)

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
			// Note: as is, this logic is suboptimal for TunnelPoolSize > 1, as this would
			// continuously initialize new packet tunnel sessions for each established
			// server. For now, config validation requires TunnelPoolSize == 1 when
			// the packet tunnel is used.

			if controller.packetTunnelTransport != nil {
				controller.packetTunnelTransport.UseTunnel(connectedTunnel)
			}

			// TODO: design issue -- might not be enough server entries with region/caps to ever fill tunnel slots;
			// possible solution is establish target MIN(CountServerEntries(region, protocol), TunnelPoolSize)
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
	if len(controller.tunnels) >= controller.config.TunnelPoolSize {
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
	return len(controller.tunnels) >= controller.config.TunnelPoolSize
}

// numTunnels returns the number of active and outstanding tunnels.
// Oustanding is the number of tunnels required to fill the pool of
// active tunnels.
func (controller *Controller) numTunnels() (int, int) {
	controller.tunnelMutex.Lock()
	defer controller.tunnelMutex.Unlock()
	active := len(controller.tunnels)
	outstanding := controller.config.TunnelPoolSize - len(controller.tunnels)
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

// Dial selects an active tunnel and establishes a port forward
// connection through the selected tunnel. Failure to connect is considered
// a port forward failure, for the purpose of monitoring tunnel health.
func (controller *Controller) Dial(
	remoteAddr string, alwaysTunnel bool, downstreamConn net.Conn) (conn net.Conn, err error) {

	tunnel := controller.getNextActiveTunnel()
	if tunnel == nil {
		return nil, errors.TraceNew("no active tunnels")
	}

	// Perform split tunnel classification when feature is enabled, and if the remote
	// address is classified as untunneled, dial directly.
	if !alwaysTunnel && controller.config.SplitTunnelDNSServer != "" {

		host, _, err := net.SplitHostPort(remoteAddr)
		if err != nil {
			return nil, errors.Trace(err)
		}

		// Note: a possible optimization, when split tunnel is active and IsUntunneled performs
		// a DNS resolution in order to make its classification, is to reuse that IP address in
		// the following Dials so they do not need to make their own resolutions. However, the
		// way this is currently implemented ensures that, e.g., DNS geo load balancing occurs
		// relative to the outbound network.

		if controller.splitTunnelClassifier.IsUntunneled(host) {
			return controller.DirectDial(remoteAddr)
		}
	}

	tunneledConn, err := tunnel.Dial(remoteAddr, alwaysTunnel, downstreamConn)
	if err != nil {
		return nil, errors.Trace(err)
	}

	return tunneledConn, nil
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
	useUpstreamProxy                    bool
	initialLimitProtocols               protocol.TunnelProtocols
	initialLimitProtocolsCandidateCount int
	limitProtocols                      protocol.TunnelProtocols
	replayCandidateCount                int
}

func (p *protocolSelectionConstraints) hasInitialProtocols() bool {
	return len(p.initialLimitProtocols) > 0 && p.initialLimitProtocolsCandidateCount > 0
}

func (p *protocolSelectionConstraints) isInitialCandidate(
	excludeIntensive bool,
	serverEntry *protocol.ServerEntry) bool {

	return p.hasInitialProtocols() &&
		len(serverEntry.GetSupportedProtocols(
			conditionallyEnabledComponents{},
			p.useUpstreamProxy,
			p.initialLimitProtocols,
			excludeIntensive)) > 0
}

func (p *protocolSelectionConstraints) isCandidate(
	excludeIntensive bool,
	serverEntry *protocol.ServerEntry) bool {

	return len(p.limitProtocols) == 0 ||
		len(serverEntry.GetSupportedProtocols(
			conditionallyEnabledComponents{},
			p.useUpstreamProxy,
			p.limitProtocols,
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

	limitProtocols := p.limitProtocols

	if len(p.initialLimitProtocols) > 0 && p.initialLimitProtocolsCandidateCount > connectTunnelCount {
		limitProtocols = p.initialLimitProtocols
	}

	return serverEntry.GetSupportedProtocols(
		conditionallyEnabledComponents{},
		p.useUpstreamProxy,
		limitProtocols,
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

	controller.concurrentEstablishTunnelsMutex.Lock()
	controller.establishConnectTunnelCount = 0
	controller.concurrentEstablishTunnels = 0
	controller.concurrentIntensiveEstablishTunnels = 0
	controller.peakConcurrentEstablishTunnels = 0
	controller.peakConcurrentIntensiveEstablishTunnels = 0
	controller.concurrentEstablishTunnelsMutex.Unlock()

	DoGarbageCollection()
	emitMemoryMetrics()

	// Note: the establish context cancelFunc, controller.stopEstablish,
	// is called in controller.stopEstablishing.

	controller.isEstablishing = true
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

		timeout := controller.config.GetClientParameters().Get().Duration(
			parameters.TacticsWaitPeriod)

		tacticsDone := make(chan struct{})
		tacticsWaitPeriod := time.NewTimer(timeout)
		defer tacticsWaitPeriod.Stop()

		controller.establishWaitGroup.Add(1)
		go controller.getTactics(tacticsDone)

		select {
		case <-tacticsDone:
		case <-tacticsWaitPeriod.C:
		}

		tacticsWaitPeriod.Stop()

		if controller.isStopEstablishing() {
			// This check isn't strictly required by avoids the
			// overhead of launching workers if establishment
			// stopped while awaiting a tactics request.
			return
		}
	}

	// LimitTunnelProtocols and ConnectionWorkerPoolSize may be set by
	// tactics.

	// Initial- and LimitTunnelProtocols are set once per establishment, for
	// consistent application of related probabilities (applied by
	// ClientParametersAccessor.TunnelProtocols). The
	// establishLimitTunnelProtocolsState field must be read-only after this
	// point, allowing concurrent reads by establishment workers.

	p := controller.config.GetClientParameters().Get()

	controller.protocolSelectionConstraints = &protocolSelectionConstraints{
		useUpstreamProxy:                    controller.config.UseUpstreamProxy(),
		initialLimitProtocols:               p.TunnelProtocols(parameters.InitialLimitTunnelProtocols),
		initialLimitProtocolsCandidateCount: p.Int(parameters.InitialLimitTunnelProtocolsCandidateCount),
		limitProtocols:                      p.TunnelProtocols(parameters.LimitTunnelProtocols),
		replayCandidateCount:                p.Int(parameters.ReplayCandidateCount),
	}

	workerPoolSize := p.Int(parameters.ConnectionWorkerPoolSize)

	p.Close()

	// When TargetServerEntry is used, override any worker pool size config or
	// tactic parameter and use a pool size of 1. The typical use case for
	// TargetServerEntry is to test a specific server with a single connection
	// attempt. Furthermore, too many concurrent attempts to connect to the
	// same server will trigger rate limiting.
	if controller.config.TargetServerEntry != "" {
		workerPoolSize = 1
	}

	// If InitialLimitTunnelProtocols is configured but cannot be satisfied,
	// skip the initial phase in this establishment. This avoids spinning,
	// unable to connect, in this case. InitialLimitTunnelProtocols is
	// intended to prioritize certain protocols, but not strictly select them.
	//
	// The candidate count check is made with egress region selection unset.
	// When an egress region is selected, it's the responsibility of the outer
	// client to react to the following ReportAvailableRegions output and
	// clear the user's selected region to prevent spinning, unable to
	// connect. The initial phase is skipped only when
	// InitialLimitTunnelProtocols cannot be satisfied _regardless_ of region
	// selection.
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

	if controller.protocolSelectionConstraints.initialLimitProtocolsCandidateCount > 0 {

		egressRegion := "" // no egress region

		initialCount, count := CountServerEntriesWithConstraints(
			controller.config.UseUpstreamProxy(),
			egressRegion,
			controller.protocolSelectionConstraints)

		if initialCount == 0 {
			NoticeCandidateServers(
				egressRegion,
				controller.protocolSelectionConstraints,
				initialCount,
				count)
			NoticeWarning("skipping initial limit tunnel protocols")
			controller.protocolSelectionConstraints.initialLimitProtocolsCandidateCount = 0

			// Since we were unable to satisfy the InitialLimitTunnelProtocols
			// tactic, trigger RSL, OSL, and upgrade fetches to potentially
			// gain new capabilities.
			controller.triggerFetches()
		}
	}

	// Report available egress regions. After a fresh install, the outer
	// client may not have a list of regions to display; and
	// LimitTunnelProtocols may reduce the number of available regions.
	//
	// When the outer client receives NoticeAvailableEgressRegions and the
	// configured EgressRegion is not included in the region list, the outer
	// client _should_ stop tunnel-core and prompt the user to change the
	// region selection, as there are insufficient servers/capabilities to
	// establish a tunnel in the selected region.
	//
	// This report is delayed until after tactics are likely to be applied;
	// this avoids a ReportAvailableRegions reporting too many regions,
	// followed shortly by a ReportAvailableRegions reporting fewer regions.
	// That sequence could cause issues in the outer client UI.
	//
	// The reported regions are limited by protocolSelectionConstraints;
	// in the case where an initial limit is in place, only regions available
	// for the initial limit are reported. The initial phase will not complete
	// if EgressRegion is set such that there are no server entries with the
	// necessary protocol capabilities (either locally or from a remote server
	// list fetch).

	ReportAvailableRegions(
		controller.config,
		controller.protocolSelectionConstraints)

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
}

func (controller *Controller) getTactics(done chan struct{}) {
	defer controller.establishWaitGroup.Done()
	defer close(done)

	// Limitation: GetNetworkID may not account for device VPN status, so
	// Psiphon-over-Psiphon or Psiphon-over-other-VPN scenarios can encounter
	// this issue:
	//
	// 1. Tactics are established when tunneling through a VPN and egressing
	//    through a remote region/ISP.
	// 2. Psiphon is next run when _not_ tunneling through the VPN. Yet the
	//    network ID remains the same. Initial applied tactics will be for the
	//    remote egress region/ISP, not the local region/ISP.

	tacticsRecord, err := tactics.UseStoredTactics(
		GetTacticsStorer(),
		controller.config.GetNetworkID())
	if err != nil {
		NoticeWarning("get stored tactics failed: %s", err)

		// The error will be due to a local datastore problem.
		// While we could proceed with the tactics request, this
		// could result in constant tactics requests. So, abort.
		return
	}

	if tacticsRecord == nil {

		iterator, err := NewTacticsServerEntryIterator(
			controller.config)
		if err != nil {
			NoticeWarning("tactics iterator failed: %s", err)
			return
		}
		defer iterator.Close()

		for iteration := 0; ; iteration++ {

			if !WaitForNetworkConnectivity(
				controller.runCtx,
				controller.config.NetworkConnectivityChecker) {
				return
			}

			serverEntry, err := iterator.Next()
			if err != nil {
				NoticeWarning("tactics iterator failed: %s", err)
				return
			}

			if serverEntry == nil {
				if iteration == 0 {
					NoticeWarning("tactics request skipped: no capable servers")
					return
				}

				iterator.Reset()
				continue
			}

			tacticsRecord, err = controller.doFetchTactics(serverEntry)
			if err == nil {
				break
			}

			NoticeWarning("tactics request failed: %s", err)

			// On error, proceed with a retry, as the error is likely
			// due to a network failure.
			//
			// TODO: distinguish network and local errors and abort
			// on local errors.

			p := controller.config.GetClientParameters().Get()
			timeout := prng.JitterDuration(
				p.Duration(parameters.TacticsRetryPeriod),
				p.Float(parameters.TacticsRetryPeriodJitter))
			p.Close()

			tacticsRetryDelay := time.NewTimer(timeout)

			select {
			case <-controller.establishCtx.Done():
				return
			case <-tacticsRetryDelay.C:
			}

			tacticsRetryDelay.Stop()
		}
	}

	if tacticsRecord != nil &&
		prng.FlipWeightedCoin(tacticsRecord.Tactics.Probability) {

		err := controller.config.SetClientParameters(
			tacticsRecord.Tag, true, tacticsRecord.Tactics.Parameters)
		if err != nil {
			NoticeWarning("apply tactics failed: %s", err)

			// The error will be due to invalid tactics values from
			// the server. When ApplyClientParameters fails, all
			// previous tactics values are left in place. Abort
			// without retry since the server is highly unlikely
			// to return different values immediately.
			return
		}
	}

	// Reclaim memory from the completed tactics request as we're likely
	// to be proceeding to the memory-intensive tunnel establishment phase.
	DoGarbageCollection()
	emitMemoryMetrics()
}

func (controller *Controller) doFetchTactics(
	serverEntry *protocol.ServerEntry) (*tactics.Record, error) {

	canReplay := func(serverEntry *protocol.ServerEntry, replayProtocol string) bool {
		return common.Contains(
			serverEntry.GetSupportedTacticsProtocols(), replayProtocol)
	}

	selectProtocol := func(serverEntry *protocol.ServerEntry) (string, bool) {
		tacticsProtocols := serverEntry.GetSupportedTacticsProtocols()
		if len(tacticsProtocols) == 0 {
			return "", false
		}
		index := prng.Intn(len(tacticsProtocols))
		return tacticsProtocols[index], true
	}

	dialParams, err := MakeDialParameters(
		controller.config,
		canReplay,
		selectProtocol,
		serverEntry,
		true,
		0,
		0)
	if dialParams == nil {
		// MakeDialParameters may return nil, nil when the server entry can't
		// satisfy protocol selection criteria. This case in not expected
		// since NewTacticsServerEntryIterator should only return tactics-
		// capable server entries and selectProtocol will select any tactics
		// protocol.
		err = std_errors.New("failed to make dial parameters")
	}
	if err != nil {
		return nil, errors.Trace(err)
	}

	NoticeRequestingTactics(dialParams)

	// TacticsTimeout should be a very long timeout, since it's not
	// adjusted by tactics in a new network context, and so clients
	// with very slow connections must be accomodated. This long
	// timeout will not entirely block the beginning of tunnel
	// establishment, which beings after the shorter TacticsWaitPeriod.
	//
	// Using controller.establishCtx will cancel FetchTactics
	// if tunnel establishment completes first.

	timeout := controller.config.GetClientParameters().Get().Duration(
		parameters.TacticsTimeout)

	ctx, cancelFunc := context.WithTimeout(
		controller.establishCtx,
		timeout)
	defer cancelFunc()

	// DialMeek completes the TCP/TLS handshakes for HTTPS
	// meek protocols but _not_ for HTTP meek protocols.
	//
	// TODO: pre-dial HTTP protocols to conform with speed
	// test RTT spec.
	//
	// TODO: ensure that meek in round trip mode will fail
	// the request when the pre-dial connection is broken,
	// to minimize the possibility of network ID mismatches.

	meekConn, err := DialMeek(
		ctx, dialParams.GetMeekConfig(), dialParams.GetDialConfig())
	if err != nil {
		return nil, errors.Trace(err)
	}
	defer meekConn.Close()

	apiParams := getBaseAPIParameters(
		baseParametersAll, controller.config, dialParams)

	tacticsRecord, err := tactics.FetchTactics(
		ctx,
		controller.config.clientParameters,
		GetTacticsStorer(),
		controller.config.GetNetworkID,
		apiParams,
		serverEntry.Region,
		dialParams.TunnelProtocol,
		serverEntry.TacticsRequestPublicKey,
		serverEntry.TacticsRequestObfuscatedKey,
		meekConn.RoundTrip)
	if err != nil {
		return nil, errors.Trace(err)
	}

	NoticeRequestedTactics(dialParams)

	return tacticsRecord, nil
}

// establishCandidateGenerator populates the candidate queue with server entries
// from the data store. Server entries are iterated in rank order, so that promoted
// servers with higher rank are priority candidates.
func (controller *Controller) establishCandidateGenerator() {
	defer controller.establishWaitGroup.Done()
	defer close(controller.candidateServerEntries)

	// establishStartTime is used to calculate and report the
	// client's tunnel establishment duration.
	//
	// networkWaitDuration is the elapsed time spent waiting
	// for network connectivity. This duration will be excluded
	// from reported tunnel establishment duration.
	establishStartTime := time.Now()
	var totalNetworkWaitDuration time.Duration

	applyServerAffinity, iterator, err := NewServerEntryIterator(controller.config)
	if err != nil {
		NoticeWarning("failed to iterate over candidates: %s", err)
		controller.SignalComponentFailure()
		return
	}
	defer iterator.Close()

	// TODO: reconcile server affinity scheme with multi-tunnel mode
	if controller.config.TunnelPoolSize > 1 {
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

		// For diagnostics, emits counts of the number of known server
		// entries that satisfy both the egress region and tunnel protocol
		// requirements (excluding excludeIntensive logic).
		// Counts may change during establishment due to remote server
		// list fetches, etc.

		initialCount, count := CountServerEntriesWithConstraints(
			controller.config.UseUpstreamProxy(),
			controller.config.EgressRegion,
			controller.protocolSelectionConstraints)

		NoticeCandidateServers(
			controller.config.EgressRegion,
			controller.protocolSelectionConstraints,
			initialCount,
			count)

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

		roundStartTime := time.Now()
		var roundNetworkWaitDuration time.Duration

		workTime := controller.config.GetClientParameters().Get().Duration(
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
				NoticeWarning("failed to get next candidate: %s", err)
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
			adjustedEstablishStartTime := establishStartTime.Add(totalNetworkWaitDuration)

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

				gracePeriod := controller.config.GetClientParameters().Get().Duration(
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
			time.Since(establishStartTime)-totalNetworkWaitDuration > workTime) &&
			controller.config.TargetServerEntry == "" {

			controller.triggerFetches()
		}

		// After a complete iteration of candidate servers, pause before iterating again.
		// This helps avoid some busy wait loop conditions, and also allows some time for
		// network conditions to change. Also allows for fetch remote to complete,
		// in typical conditions (it isn't strictly necessary to wait for this, there will
		// be more rounds if required).

		p := controller.config.GetClientParameters().Get()
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

		limitIntensiveConnectionWorkers := controller.config.GetClientParameters().Get().Int(
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
			canReplay,
			selectProtocol,
			candidateServerEntry.serverEntry,
			false,
			controller.establishConnectTunnelCount,
			int(atomic.LoadInt32(&controller.establishedTunnelsCount)))
		if dialParams == nil || err != nil {

			controller.concurrentEstablishTunnelsMutex.Unlock()

			// dialParams is nil when the server does not support any protocol
			// that remains after applying the LimitTunnelProtocols parameter
			// and the excludeIntensive flag.
			// Silently skip the candidate in this case. Otherwise, emit error.
			if err != nil {
				NoticeInfo("failed to select protocol for %s: %s",
					candidateServerEntry.serverEntry.GetDiagnosticID(), err)
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

		p := controller.config.GetClientParameters().Get()
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

			NoticeInfo("failed to connect to %s: %s",
				candidateServerEntry.serverEntry.GetDiagnosticID(), err)

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
