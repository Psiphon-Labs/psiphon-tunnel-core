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
	"errors"
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/Psiphon-Inc/goarista/monotime"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
)

// Controller is a tunnel lifecycle coordinator. It manages lists of servers to
// connect to; establishes and monitors tunnels; and runs local proxies which
// route traffic through the tunnels.
type Controller struct {
	config                         *Config
	sessionId                      string
	componentFailureSignal         chan struct{}
	shutdownBroadcast              chan struct{}
	runWaitGroup                   *sync.WaitGroup
	establishedTunnels             chan *Tunnel
	failedTunnels                  chan *Tunnel
	tunnelMutex                    sync.Mutex
	establishedOnce                bool
	tunnels                        []*Tunnel
	nextTunnel                     int
	startedConnectedReporter       bool
	isEstablishing                 bool
	establishWaitGroup             *sync.WaitGroup
	stopEstablishingBroadcast      chan struct{}
	candidateServerEntries         chan *candidateServerEntry
	establishPendingConns          *common.Conns
	untunneledPendingConns         *common.Conns
	untunneledDialConfig           *DialConfig
	splitTunnelClassifier          *SplitTunnelClassifier
	signalFetchRemoteServerList    chan struct{}
	signalDownloadUpgrade          chan string
	impairedProtocolClassification map[string]int
	signalReportConnected          chan struct{}
	serverAffinityDoneBroadcast    chan struct{}
	newClientVerificationPayload   chan string
}

type candidateServerEntry struct {
	serverEntry                *ServerEntry
	isServerAffinityCandidate  bool
	adjustedEstablishStartTime monotime.Time
}

// NewController initializes a new controller.
func NewController(config *Config) (controller *Controller, err error) {

	// Needed by regen, at least
	rand.Seed(int64(time.Now().Nanosecond()))

	// Supply a default HostNameTransformer
	if config.HostNameTransformer == nil {
		config.HostNameTransformer = &IdentityHostNameTransformer{}
	}

	// Generate a session ID for the Psiphon server API. This session ID is
	// used across all tunnels established by the controller.
	sessionId, err := MakeSessionId()
	if err != nil {
		return nil, common.ContextError(err)
	}
	NoticeSessionId(sessionId)

	// untunneledPendingConns may be used to interrupt the fetch remote server list
	// request and other untunneled connection establishments. BindToDevice may be
	// used to exclude these requests and connection from VPN routing.
	// TODO: fetch remote server list and untunneled upgrade download should remove
	// their completed conns from untunneledPendingConns.
	untunneledPendingConns := new(common.Conns)
	untunneledDialConfig := &DialConfig{
		UpstreamProxyUrl:              config.UpstreamProxyUrl,
		UpstreamProxyCustomHeaders:    config.UpstreamProxyCustomHeaders,
		PendingConns:                  untunneledPendingConns,
		DeviceBinder:                  config.DeviceBinder,
		DnsServerGetter:               config.DnsServerGetter,
		UseIndistinguishableTLS:       config.UseIndistinguishableTLS,
		TrustedCACertificatesFilename: config.TrustedCACertificatesFilename,
		DeviceRegion:                  config.DeviceRegion,
	}

	controller = &Controller{
		config:    config,
		sessionId: sessionId,
		// componentFailureSignal receives a signal from a component (including socks and
		// http local proxies) if they unexpectedly fail. Senders should not block.
		// Buffer allows at least one stop signal to be sent before there is a receiver.
		componentFailureSignal: make(chan struct{}, 1),
		shutdownBroadcast:      make(chan struct{}),
		runWaitGroup:           new(sync.WaitGroup),
		// establishedTunnels and failedTunnels buffer sizes are large enough to
		// receive full pools of tunnels without blocking. Senders should not block.
		establishedTunnels:             make(chan *Tunnel, config.TunnelPoolSize),
		failedTunnels:                  make(chan *Tunnel, config.TunnelPoolSize),
		tunnels:                        make([]*Tunnel, 0),
		establishedOnce:                false,
		startedConnectedReporter:       false,
		isEstablishing:                 false,
		establishPendingConns:          new(common.Conns),
		untunneledPendingConns:         untunneledPendingConns,
		untunneledDialConfig:           untunneledDialConfig,
		impairedProtocolClassification: make(map[string]int),
		// TODO: Add a buffer of 1 so we don't miss a signal while receiver is
		// starting? Trade-off is potential back-to-back fetch remotes. As-is,
		// establish will eventually signal another fetch remote.
		signalFetchRemoteServerList: make(chan struct{}),
		signalDownloadUpgrade:       make(chan string),
		signalReportConnected:       make(chan struct{}),
		// Buffer allows SetClientVerificationPayloadForActiveTunnels to submit one
		// new payload without blocking or dropping it.
		newClientVerificationPayload: make(chan string, 1),
	}

	controller.splitTunnelClassifier = NewSplitTunnelClassifier(config, controller)

	return controller, nil
}

// Run executes the controller. It launches components and then monitors
// for a shutdown signal; after receiving the signal it shuts down the
// controller.
// The components include:
// - the periodic remote server list fetcher
// - the connected reporter
// - the tunnel manager
// - a local SOCKS proxy that port forwards through the pool of tunnels
// - a local HTTP proxy that port forwards through the pool of tunnels
func (controller *Controller) Run(shutdownBroadcast <-chan struct{}) {
	ReportAvailableRegions()

	// Start components

	listenIP, err := GetInterfaceIPAddress(controller.config.ListenInterface)
	if err != nil {
		NoticeError("error getting listener IP: %s", err)
		return
	}

	socksProxy, err := NewSocksProxy(controller.config, controller, listenIP)
	if err != nil {
		NoticeAlert("error initializing local SOCKS proxy: %s", err)
		return
	}
	defer socksProxy.Close()

	httpProxy, err := NewHttpProxy(
		controller.config, controller.untunneledDialConfig, controller, listenIP)
	if err != nil {
		NoticeAlert("error initializing local HTTP proxy: %s", err)
		return
	}
	defer httpProxy.Close()

	if !controller.config.DisableRemoteServerListFetcher {
		controller.runWaitGroup.Add(1)
		go controller.remoteServerListFetcher()
	}

	if controller.config.UpgradeDownloadUrl != "" &&
		controller.config.UpgradeDownloadFilename != "" {

		controller.runWaitGroup.Add(1)
		go controller.upgradeDownloader()
	}

	/// Note: the connected reporter isn't started until a tunnel is
	// established

	controller.runWaitGroup.Add(1)
	go controller.runTunnels()

	if *controller.config.EstablishTunnelTimeoutSeconds != 0 {
		controller.runWaitGroup.Add(1)
		go controller.establishTunnelWatcher()
	}

	// Wait while running

	select {
	case <-shutdownBroadcast:
		NoticeInfo("controller shutdown by request")
	case <-controller.componentFailureSignal:
		NoticeAlert("controller shutdown due to component failure")
	}

	close(controller.shutdownBroadcast)

	// Interrupts and stops establish workers blocking on
	// tunnel establishment network operations.
	controller.establishPendingConns.CloseAll()

	// Interrupts and stops workers blocking on untunneled
	// network operations. This includes fetch remote server
	// list and untunneled uprade download.
	// Note: this doesn't interrupt the final, untunneled status
	// requests started in operateTunnel after shutdownBroadcast.
	// This is by design -- we want to give these requests a short
	// timer period to succeed and deliver stats. These particular
	// requests opt out of untunneledPendingConns and use the
	// PSIPHON_API_SHUTDOWN_SERVER_TIMEOUT timeout (see
	// doUntunneledStatusRequest).
	controller.untunneledPendingConns.CloseAll()

	// Now with all workers signaled to stop and with all
	// blocking network operations interrupted, wait for
	// all workers to terminate.
	controller.runWaitGroup.Wait()

	controller.splitTunnelClassifier.Shutdown()

	NoticeInfo("exiting controller")

	NoticeExiting()
}

// SignalComponentFailure notifies the controller that an associated component has failed.
// This will terminate the controller.
func (controller *Controller) SignalComponentFailure() {
	select {
	case controller.componentFailureSignal <- *new(struct{}):
	default:
	}
}

// SetClientVerificationPayloadForActiveTunnels sets the client verification
// payload that is to be sent in client verification requests to all established
// tunnels.
//
// Client verification is used to verify that the client is a
// valid Psiphon client, which will determine how the server treats
// the client traffic. The proof-of-validity is platform-specific
// and the payload is opaque to this function but assumed to be JSON.
//
// Since, in some cases, verification payload cannot be determined until
// after tunnel-core starts, the payload cannot be simply specified in
// the Config.
//
// SetClientVerificationPayloadForActiveTunnels will not block enqueuing a new verification
// payload. One new payload can be enqueued, after which additional payloads
// will be dropped if a payload is still enqueued.
func (controller *Controller) SetClientVerificationPayloadForActiveTunnels(clientVerificationPayload string) {
	select {
	case controller.newClientVerificationPayload <- clientVerificationPayload:
	default:
	}
}

// remoteServerListFetcher fetches an out-of-band list of server entries
// for more tunnel candidates. It fetches when signalled, with retries
// on failure.
func (controller *Controller) remoteServerListFetcher() {
	defer controller.runWaitGroup.Done()

	if controller.config.RemoteServerListUrl == "" {
		NoticeAlert("remote server list URL is blank")
		return
	}
	if controller.config.RemoteServerListSignaturePublicKey == "" {
		NoticeAlert("remote server list signature public key blank")
		return
	}

	var lastFetchTime monotime.Time

fetcherLoop:
	for {
		// Wait for a signal before fetching
		select {
		case <-controller.signalFetchRemoteServerList:
		case <-controller.shutdownBroadcast:
			break fetcherLoop
		}

		// Skip fetch entirely (i.e., send no request at all, even when ETag would save
		// on response size) when a recent fetch was successful
		if lastFetchTime != 0 &&
			lastFetchTime.Add(FETCH_REMOTE_SERVER_LIST_STALE_PERIOD).After(monotime.Now()) {
			continue
		}

	retryLoop:
		for {
			// Don't attempt to fetch while there is no network connectivity,
			// to avoid alert notice noise.
			if !WaitForNetworkConnectivity(
				controller.config.NetworkConnectivityChecker,
				controller.shutdownBroadcast) {
				break fetcherLoop
			}

			// Pick any active tunnel and make the next fetch attempt. If there's
			// no active tunnel, the untunneledDialConfig will be used.
			tunnel := controller.getNextActiveTunnel()

			err := FetchRemoteServerList(
				controller.config,
				tunnel,
				controller.untunneledDialConfig)

			if err == nil {
				lastFetchTime = monotime.Now()
				break retryLoop
			}

			NoticeAlert("failed to fetch remote server list: %s", err)

			timeout := time.After(
				time.Duration(*controller.config.FetchRemoteServerListRetryPeriodSeconds) * time.Second)
			select {
			case <-timeout:
			case <-controller.shutdownBroadcast:
				break fetcherLoop
			}
		}
	}

	NoticeInfo("exiting remote server list fetcher")
}

// establishTunnelWatcher terminates the controller if a tunnel
// has not been established in the configured time period. This
// is regardless of how many tunnels are presently active -- meaning
// that if an active tunnel was established and lost the controller
// is left running (to re-establish).
func (controller *Controller) establishTunnelWatcher() {
	defer controller.runWaitGroup.Done()

	timeout := time.After(
		time.Duration(*controller.config.EstablishTunnelTimeoutSeconds) * time.Second)
	select {
	case <-timeout:
		if !controller.hasEstablishedOnce() {
			NoticeAlert("failed to establish tunnel before timeout")
			controller.SignalComponentFailure()
		}
	case <-controller.shutdownBroadcast:
	}

	NoticeInfo("exiting establish tunnel watcher")
}

// connectedReporter sends periodic "connected" requests to the Psiphon API.
// These requests are for server-side unique user stats calculation. See the
// comment in DoConnectedRequest for a description of the request mechanism.
// To ensure we don't over- or under-count unique users, only one connected
// request is made across all simultaneous multi-tunnels; and the connected
// request is repeated periodically for very long-lived tunnels.
// The signalReportConnected mechanism is used to trigger another connected
// request immediately after a reconnect.
func (controller *Controller) connectedReporter() {
	defer controller.runWaitGroup.Done()
loop:
	for {

		// Pick any active tunnel and make the next connected request. No error
		// is logged if there's no active tunnel, as that's not an unexpected condition.
		reported := false
		tunnel := controller.getNextActiveTunnel()
		if tunnel != nil {
			err := tunnel.serverContext.DoConnectedRequest()
			if err == nil {
				reported = true
			} else {
				NoticeAlert("failed to make connected request: %s", err)
			}
		}

		// Schedule the next connected request and wait.
		var duration time.Duration
		if reported {
			duration = PSIPHON_API_CONNECTED_REQUEST_PERIOD
		} else {
			duration = PSIPHON_API_CONNECTED_REQUEST_RETRY_PERIOD
		}
		timeout := time.After(duration)
		select {
		case <-controller.signalReportConnected:
		case <-timeout:
			// Make another connected request

		case <-controller.shutdownBroadcast:
			break loop
		}
	}

	NoticeInfo("exiting connected reporter")
}

func (controller *Controller) startOrSignalConnectedReporter() {
	// session is nil when DisableApi is set
	if controller.config.DisableApi {
		return
	}

	// Start the connected reporter after the first tunnel is established.
	// Concurrency note: only the runTunnels goroutine may access startedConnectedReporter.
	if !controller.startedConnectedReporter {
		controller.startedConnectedReporter = true
		controller.runWaitGroup.Add(1)
		go controller.connectedReporter()
	} else {
		select {
		case controller.signalReportConnected <- *new(struct{}):
		default:
		}
	}
}

// upgradeDownloader makes periodic attemps to complete a client upgrade
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

	var lastDownloadTime monotime.Time

downloadLoop:
	for {
		// Wait for a signal before downloading
		var handshakeVersion string
		select {
		case handshakeVersion = <-controller.signalDownloadUpgrade:
		case <-controller.shutdownBroadcast:
			break downloadLoop
		}

		// Unless handshake is explicitly advertizing a new version, skip
		// checking entirely when a recent download was successful.
		if handshakeVersion == "" &&
			lastDownloadTime != 0 &&
			lastDownloadTime.Add(DOWNLOAD_UPGRADE_STALE_PERIOD).After(monotime.Now()) {
			continue
		}

	retryLoop:
		for {
			// Don't attempt to download while there is no network connectivity,
			// to avoid alert notice noise.
			if !WaitForNetworkConnectivity(
				controller.config.NetworkConnectivityChecker,
				controller.shutdownBroadcast) {
				break downloadLoop
			}

			// Pick any active tunnel and make the next download attempt. If there's
			// no active tunnel, the untunneledDialConfig will be used.
			tunnel := controller.getNextActiveTunnel()

			err := DownloadUpgrade(
				controller.config,
				handshakeVersion,
				tunnel,
				controller.untunneledDialConfig)

			if err == nil {
				lastDownloadTime = monotime.Now()
				break retryLoop
			}

			NoticeAlert("failed to download upgrade: %s", err)

			timeout := time.After(
				time.Duration(*controller.config.DownloadUpgradeRetryPeriodSeconds) * time.Second)
			select {
			case <-timeout:
			case <-controller.shutdownBroadcast:
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

	var clientVerificationPayload string

	// Start running

	controller.startEstablishing()
loop:
	for {
		select {
		case failedTunnel := <-controller.failedTunnels:
			NoticeAlert("tunnel failed: %s", failedTunnel.serverEntry.IpAddress)
			controller.terminateTunnel(failedTunnel)

			// Note: we make this extra check to ensure the shutdown signal takes priority
			// and that we do not start establishing. Critically, startEstablishing() calls
			// establishPendingConns.Reset() which clears the closed flag in
			// establishPendingConns; this causes the pendingConns.Add() within
			// interruptibleTCPDial to succeed instead of aborting, and the result
			// is that it's possible for establish goroutines to run all the way through
			// NewServerContext before being discarded... delaying shutdown.
			select {
			case <-controller.shutdownBroadcast:
				break loop
			default:
			}

			controller.classifyImpairedProtocol(failedTunnel)

			// Concurrency note: only this goroutine may call startEstablishing/stopEstablishing
			// and access isEstablishing.
			if !controller.isEstablishing {
				controller.startEstablishing()
			}

		case establishedTunnel := <-controller.establishedTunnels:

			if controller.isImpairedProtocol(establishedTunnel.protocol) {

				NoticeAlert("established tunnel with impaired protocol: %s", establishedTunnel.protocol)

				// Protocol was classified as impaired while this tunnel
				// established, so discard.
				controller.discardTunnel(establishedTunnel)

				// Reset establish generator to stop producing tunnels
				// with impaired protocols.
				if controller.isEstablishing {
					controller.stopEstablishing()
					controller.startEstablishing()
				}
				break
			}

			tunnelCount, registered := controller.registerTunnel(establishedTunnel)
			if !registered {
				// Already fully established, so discard.
				controller.discardTunnel(establishedTunnel)
				break
			}

			NoticeActiveTunnel(establishedTunnel.serverEntry.IpAddress, establishedTunnel.protocol)

			if tunnelCount == 1 {

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
				controller.splitTunnelClassifier.Start(establishedTunnel)

				// Signal a connected request on each 1st tunnel establishment. For
				// multi-tunnels, the session is connected as long as at least one
				// tunnel is established.
				controller.startOrSignalConnectedReporter()

				// If the handshake indicated that a new client version is available,
				// trigger an upgrade download.
				// Note: serverContext is nil when DisableApi is set
				if establishedTunnel.serverContext != nil &&
					establishedTunnel.serverContext.clientUpgradeVersion != "" {

					handshakeVersion := establishedTunnel.serverContext.clientUpgradeVersion
					select {
					case controller.signalDownloadUpgrade <- handshakeVersion:
					default:
					}
				}
			}

			// TODO: design issue -- might not be enough server entries with region/caps to ever fill tunnel slots;
			// possible solution is establish target MIN(CountServerEntries(region, protocol), TunnelPoolSize)
			if controller.isFullyEstablished() {
				controller.stopEstablishing()
			}

		case clientVerificationPayload = <-controller.newClientVerificationPayload:
			controller.setClientVerificationPayloadForActiveTunnels(clientVerificationPayload)

		case <-controller.shutdownBroadcast:
			break loop
		}
	}

	// Stop running

	controller.stopEstablishing()
	controller.terminateAllTunnels()

	// Drain tunnel channels
	close(controller.establishedTunnels)
	for tunnel := range controller.establishedTunnels {
		controller.discardTunnel(tunnel)
	}
	close(controller.failedTunnels)
	for tunnel := range controller.failedTunnels {
		controller.discardTunnel(tunnel)
	}

	NoticeInfo("exiting run tunnels")
}

// classifyImpairedProtocol tracks "impaired" protocol classifications for failed
// tunnels. A protocol is classified as impaired if a tunnel using that protocol
// fails, repeatedly, shortly after the start of the connection. During tunnel
// establishment, impaired protocols are briefly skipped.
//
// One purpose of this measure is to defend against an attack where the adversary,
// for example, tags an OSSH TCP connection as an "unidentified" protocol; allows
// it to connect; but then kills the underlying TCP connection after a short time.
// Since OSSH has less latency than other protocols that may bypass an "unidentified"
// filter, these other protocols might never be selected for use.
//
// Concurrency note: only the runTunnels() goroutine may call classifyImpairedProtocol
func (controller *Controller) classifyImpairedProtocol(failedTunnel *Tunnel) {
	if failedTunnel.establishedTime.Add(IMPAIRED_PROTOCOL_CLASSIFICATION_DURATION).After(monotime.Now()) {
		controller.impairedProtocolClassification[failedTunnel.protocol] += 1
	} else {
		controller.impairedProtocolClassification[failedTunnel.protocol] = 0
	}
	if len(controller.getImpairedProtocols()) == len(common.SupportedTunnelProtocols) {
		// Reset classification if all protocols are classified as impaired as
		// the network situation (or attack) may not be protocol-specific.
		// TODO: compare against count of distinct supported protocols for
		// current known server entries.
		controller.impairedProtocolClassification = make(map[string]int)
	}
}

// getImpairedProtocols returns a list of protocols that have sufficient
// classifications to be considered impaired protocols.
//
// Concurrency note: only the runTunnels() goroutine may call getImpairedProtocols
func (controller *Controller) getImpairedProtocols() []string {
	NoticeImpairedProtocolClassification(controller.impairedProtocolClassification)
	impairedProtocols := make([]string, 0)
	for protocol, count := range controller.impairedProtocolClassification {
		if count >= IMPAIRED_PROTOCOL_CLASSIFICATION_THRESHOLD {
			impairedProtocols = append(impairedProtocols, protocol)
		}
	}
	return impairedProtocols
}

// isImpairedProtocol checks if the specified protocol is classified as impaired.
//
// Concurrency note: only the runTunnels() goroutine may call isImpairedProtocol
func (controller *Controller) isImpairedProtocol(protocol string) bool {
	count, ok := controller.impairedProtocolClassification[protocol]
	return ok && count >= IMPAIRED_PROTOCOL_CLASSIFICATION_THRESHOLD
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
	NoticeInfo("discard tunnel: %s", tunnel.serverEntry.IpAddress)
	// TODO: not calling PromoteServerEntry, since that would rank the
	// discarded tunnel before fully active tunnels. Can a discarded tunnel
	// be promoted (since it connects), but with lower rank than all active
	// tunnels?
	tunnel.Close(true)
}

// registerTunnel adds the connected tunnel to the pool of active tunnels
// which are candidates for port forwarding. Returns true if the pool has an
// empty slot and false if the pool is full (caller should discard the tunnel).
func (controller *Controller) registerTunnel(tunnel *Tunnel) (int, bool) {
	controller.tunnelMutex.Lock()
	defer controller.tunnelMutex.Unlock()
	if len(controller.tunnels) >= controller.config.TunnelPoolSize {
		return len(controller.tunnels), false
	}
	// Perform a final check just in case we've established
	// a duplicate connection.
	for _, activeTunnel := range controller.tunnels {
		if activeTunnel.serverEntry.IpAddress == tunnel.serverEntry.IpAddress {
			NoticeAlert("duplicate tunnel: %s", tunnel.serverEntry.IpAddress)
			return len(controller.tunnels), false
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
		PromoteServerEntry(tunnel.serverEntry.IpAddress)
	}

	return len(controller.tunnels), true
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
	for i := len(controller.tunnels); i > 0; i-- {
		tunnel = controller.tunnels[controller.nextTunnel]
		controller.nextTunnel =
			(controller.nextTunnel + 1) % len(controller.tunnels)
		return tunnel
	}
	return nil
}

// isActiveTunnelServerEntry is used to check if there's already
// an existing tunnel to a candidate server.
func (controller *Controller) isActiveTunnelServerEntry(serverEntry *ServerEntry) bool {
	controller.tunnelMutex.Lock()
	defer controller.tunnelMutex.Unlock()
	for _, activeTunnel := range controller.tunnels {
		if activeTunnel.serverEntry.IpAddress == serverEntry.IpAddress {
			return true
		}
	}
	return false
}

// setClientVerificationPayloadForActiveTunnels triggers the client verification
// request for all active tunnels.
func (controller *Controller) setClientVerificationPayloadForActiveTunnels(
	clientVerificationPayload string) {

	controller.tunnelMutex.Lock()
	defer controller.tunnelMutex.Unlock()

	for _, activeTunnel := range controller.tunnels {
		activeTunnel.SetClientVerificationPayload(clientVerificationPayload)
	}
}

// Dial selects an active tunnel and establishes a port forward
// connection through the selected tunnel. Failure to connect is considered
// a port foward failure, for the purpose of monitoring tunnel health.
func (controller *Controller) Dial(
	remoteAddr string, alwaysTunnel bool, downstreamConn net.Conn) (conn net.Conn, err error) {

	tunnel := controller.getNextActiveTunnel()
	if tunnel == nil {
		return nil, common.ContextError(errors.New("no active tunnels"))
	}

	// Perform split tunnel classification when feature is enabled, and if the remote
	// address is classified as untunneled, dial directly.
	if !alwaysTunnel && controller.config.SplitTunnelDnsServer != "" {

		host, _, err := net.SplitHostPort(remoteAddr)
		if err != nil {
			return nil, common.ContextError(err)
		}

		// Note: a possible optimization, when split tunnel is active and IsUntunneled performs
		// a DNS resolution in order to make its classification, is to reuse that IP address in
		// the following Dials so they do not need to make their own resolutions. However, the
		// way this is currently implemented ensures that, e.g., DNS geo load balancing occurs
		// relative to the outbound network.

		if controller.splitTunnelClassifier.IsUntunneled(host) {
			// TODO: track downstreamConn and close it when the DialTCP conn closes, as with tunnel.Dial conns?
			return DialTCP(remoteAddr, controller.untunneledDialConfig)
		}
	}

	tunneledConn, err := tunnel.Dial(remoteAddr, alwaysTunnel, downstreamConn)
	if err != nil {
		return nil, common.ContextError(err)
	}

	return tunneledConn, nil
}

// startEstablishing creates a pool of worker goroutines which will
// attempt to establish tunnels to candidate servers. The candidates
// are generated by another goroutine.
func (controller *Controller) startEstablishing() {
	if controller.isEstablishing {
		return
	}
	NoticeInfo("start establishing")

	controller.isEstablishing = true
	controller.establishWaitGroup = new(sync.WaitGroup)
	controller.stopEstablishingBroadcast = make(chan struct{})
	controller.candidateServerEntries = make(chan *candidateServerEntry)
	controller.establishPendingConns.Reset()

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
	//
	// Note: if config.EgressRegion or config.TunnelProtocol has changed
	// since the top server was promoted, the first server may not actually
	// be the last connected server.
	// TODO: should not favor the first server in this case
	controller.serverAffinityDoneBroadcast = make(chan struct{})

	for i := 0; i < controller.config.ConnectionWorkerPoolSize; i++ {
		controller.establishWaitGroup.Add(1)
		go controller.establishTunnelWorker()
	}

	controller.establishWaitGroup.Add(1)
	go controller.establishCandidateGenerator(
		controller.getImpairedProtocols())
}

// stopEstablishing signals the establish goroutines to stop and waits
// for the group to halt. pendingConns is used to interrupt any worker
// blocked on a socket connect.
func (controller *Controller) stopEstablishing() {
	if !controller.isEstablishing {
		return
	}
	NoticeInfo("stop establishing")
	close(controller.stopEstablishingBroadcast)
	// Note: interruptibleTCPClose doesn't really interrupt socket connects
	// and may leave goroutines running for a time after the Wait call.
	controller.establishPendingConns.CloseAll()
	// Note: establishCandidateGenerator closes controller.candidateServerEntries
	// (as it may be sending to that channel).
	controller.establishWaitGroup.Wait()

	controller.isEstablishing = false
	controller.establishWaitGroup = nil
	controller.stopEstablishingBroadcast = nil
	controller.candidateServerEntries = nil
	controller.serverAffinityDoneBroadcast = nil
}

// establishCandidateGenerator populates the candidate queue with server entries
// from the data store. Server entries are iterated in rank order, so that promoted
// servers with higher rank are priority candidates.
func (controller *Controller) establishCandidateGenerator(impairedProtocols []string) {
	defer controller.establishWaitGroup.Done()
	defer close(controller.candidateServerEntries)

	// establishStartTime is used to calculate and report the
	// client's tunnel establishment duration.
	//
	// networkWaitDuration is the elapsed time spent waiting
	// for network connectivity. This duration will be excluded
	// from reported tunnel establishment duration.
	establishStartTime := monotime.Now()
	var networkWaitDuration time.Duration

	iterator, err := NewServerEntryIterator(controller.config)
	if err != nil {
		NoticeAlert("failed to iterate over candidates: %s", err)
		controller.SignalComponentFailure()
		return
	}
	defer iterator.Close()

	isServerAffinityCandidate := true

	// TODO: reconcile server affinity scheme with multi-tunnel mode
	if controller.config.TunnelPoolSize > 1 {
		isServerAffinityCandidate = false
		close(controller.serverAffinityDoneBroadcast)
	}

loop:
	// Repeat until stopped
	for i := 0; ; i++ {

		networkWaitStartTime := monotime.Now()

		if !WaitForNetworkConnectivity(
			controller.config.NetworkConnectivityChecker,
			controller.stopEstablishingBroadcast,
			controller.shutdownBroadcast) {
			break loop
		}

		networkWaitDuration += monotime.Since(networkWaitStartTime)

		// Send each iterator server entry to the establish workers
		startTime := monotime.Now()
		for {
			serverEntry, err := iterator.Next()
			if err != nil {
				NoticeAlert("failed to get next candidate: %s", err)
				controller.SignalComponentFailure()
				break loop
			}
			if serverEntry == nil {
				// Completed this iteration
				break
			}

			if controller.config.TargetApiProtocol == common.PSIPHON_SSH_API_PROTOCOL &&
				!serverEntry.SupportsSSHAPIRequests() {
				continue
			}

			// Disable impaired protocols. This is only done for the
			// first iteration of the ESTABLISH_TUNNEL_WORK_TIME
			// loop since (a) one iteration should be sufficient to
			// evade the attack; (b) there's a good chance of false
			// positives (such as short tunnel durations due to network
			// hopping on a mobile device).
			// Impaired protocols logic is not applied when
			// config.TunnelProtocol is specified.
			// The edited serverEntry is temporary copy which is not
			// stored or reused.
			if i == 0 && controller.config.TunnelProtocol == "" {
				serverEntry.DisableImpairedProtocols(impairedProtocols)
				if len(serverEntry.GetSupportedProtocols()) == 0 {
					// Skip this server entry, as it has no supported
					// protocols after disabling the impaired ones
					// TODO: modify ServerEntryIterator to skip these?
					continue
				}
			}

			// adjustedEstablishStartTime is establishStartTime shifted
			// to exclude time spent waiting for network connectivity.

			candidate := &candidateServerEntry{
				serverEntry:                serverEntry,
				isServerAffinityCandidate:  isServerAffinityCandidate,
				adjustedEstablishStartTime: establishStartTime.Add(networkWaitDuration),
			}

			// Note: there must be only one server affinity candidate, as it
			// closes the serverAffinityDoneBroadcast channel.
			isServerAffinityCandidate = false

			// TODO: here we could generate multiple candidates from the
			// server entry when there are many MeekFrontingAddresses.

			select {
			case controller.candidateServerEntries <- candidate:
			case <-controller.stopEstablishingBroadcast:
				break loop
			case <-controller.shutdownBroadcast:
				break loop
			}

			if startTime.Add(ESTABLISH_TUNNEL_WORK_TIME).Before(monotime.Now()) {
				// Start over, after a brief pause, with a new shuffle of the server
				// entries, and potentially some newly fetched server entries.
				break
			}
		}
		// Free up resources now, but don't reset until after the pause.
		iterator.Close()

		// Trigger a fetch remote server list, since we may have failed to
		// connect with all known servers. Don't block sending signal, since
		// this signal may have already been sent.
		// Don't wait for fetch remote to succeed, since it may fail and
		// enter a retry loop and we're better off trying more known servers.
		// TODO: synchronize the fetch response, so it can be incorporated
		// into the server entry iterator as soon as available.
		select {
		case controller.signalFetchRemoteServerList <- *new(struct{}):
		default:
		}

		// Trigger an out-of-band upgrade availability check and download.
		// Since we may have failed to connect, we may benefit from upgrading
		// to a new client version with new circumvention capabilities.
		select {
		case controller.signalDownloadUpgrade <- "":
		default:
		}

		// After a complete iteration of candidate servers, pause before iterating again.
		// This helps avoid some busy wait loop conditions, and also allows some time for
		// network conditions to change. Also allows for fetch remote to complete,
		// in typical conditions (it isn't strictly necessary to wait for this, there will
		// be more rounds if required).
		timeout := time.After(
			time.Duration(*controller.config.EstablishTunnelPausePeriodSeconds) * time.Second)
		select {
		case <-timeout:
			// Retry iterating
		case <-controller.stopEstablishingBroadcast:
			break loop
		case <-controller.shutdownBroadcast:
			break loop
		}

		iterator.Reset()
	}

	NoticeInfo("stopped candidate generator")
}

// establishTunnelWorker pulls candidates from the candidate queue, establishes
// a connection to the tunnel server, and delivers the established tunnel to a channel.
func (controller *Controller) establishTunnelWorker() {
	defer controller.establishWaitGroup.Done()
loop:
	for candidateServerEntry := range controller.candidateServerEntries {
		// Note: don't receive from candidateServerEntries and stopEstablishingBroadcast
		// in the same select, since we want to prioritize receiving the stop signal
		if controller.isStopEstablishingBroadcast() {
			break loop
		}

		// There may already be a tunnel to this candidate. If so, skip it.
		if controller.isActiveTunnelServerEntry(candidateServerEntry.serverEntry) {
			continue
		}

		tunnel, err := EstablishTunnel(
			controller.config,
			controller.untunneledDialConfig,
			controller.sessionId,
			controller.establishPendingConns,
			candidateServerEntry.serverEntry,
			candidateServerEntry.adjustedEstablishStartTime,
			controller) // TunnelOwner
		if err != nil {

			// Unblock other candidates immediately when
			// server affinity candidate fails.
			if candidateServerEntry.isServerAffinityCandidate {
				close(controller.serverAffinityDoneBroadcast)
			}

			// Before emitting error, check if establish interrupted, in which
			// case the error is noise.
			if controller.isStopEstablishingBroadcast() {
				break loop
			}
			NoticeInfo("failed to connect to %s: %s", candidateServerEntry.serverEntry.IpAddress, err)
			continue
		}

		// Block for server affinity grace period before delivering.
		if !candidateServerEntry.isServerAffinityCandidate {
			timer := time.NewTimer(ESTABLISH_TUNNEL_SERVER_AFFINITY_GRACE_PERIOD)
			select {
			case <-timer.C:
			case <-controller.serverAffinityDoneBroadcast:
			case <-controller.stopEstablishingBroadcast:
			}
		}

		// Deliver established tunnel.
		// Don't block. Assumes the receiver has a buffer large enough for
		// the number of desired tunnels. If there's no room, the tunnel must
		// not be required so it's discarded.
		select {
		case controller.establishedTunnels <- tunnel:
		default:
			controller.discardTunnel(tunnel)
		}

		// Unblock other candidates only after delivering when
		// server affinity candidate succeeds.
		if candidateServerEntry.isServerAffinityCandidate {
			close(controller.serverAffinityDoneBroadcast)
		}
	}
	NoticeInfo("stopped establish worker")
}

func (controller *Controller) isStopEstablishingBroadcast() bool {
	select {
	case <-controller.stopEstablishingBroadcast:
		return true
	default:
	}
	return false
}
