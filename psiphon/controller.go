/*
 * Copyright (c) 2014, Psiphon Inc.
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
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"time"
)

// Controller is a tunnel lifecycle coordinator. It manages lists of servers to
// connect to; establishes and monitors tunnels; and runs local proxies which
// route traffic through the tunnels.
type Controller struct {
	config                    *Config
	failureSignal             chan struct{}
	shutdownBroadcast         chan struct{}
	runWaitGroup              *sync.WaitGroup
	establishedTunnels        chan *Tunnel
	failedTunnels             chan *Tunnel
	tunnelMutex               sync.Mutex
	tunnels                   []*Tunnel
	nextTunnel                int
	operateWaitGroup          *sync.WaitGroup
	isEstablishing            bool
	establishWaitGroup        *sync.WaitGroup
	stopEstablishingBroadcast chan struct{}
	candidateServerEntries    chan *ServerEntry
	pendingConns              *Conns
}

// NewController initializes a new controller.
func NewController(config *Config) (controller *Controller) {
	return &Controller{
		config: config,
		// failureSignal receives a signal from a component (including socks and
		// http local proxies) if they unexpectedly fail. Senders should not block.
		// A buffer allows at least one stop signal to be sent before there is a receiver.
		failureSignal:     make(chan struct{}, 1),
		shutdownBroadcast: make(chan struct{}),
		runWaitGroup:      new(sync.WaitGroup),
		// establishedTunnels and failedTunnels buffer sizes are large enough to
		// receive full pools of tunnels without blocking. Senders should not block.
		establishedTunnels: make(chan *Tunnel, config.TunnelPoolSize),
		failedTunnels:      make(chan *Tunnel, config.TunnelPoolSize),
		tunnels:            make([]*Tunnel, 0),
		operateWaitGroup:   new(sync.WaitGroup),
		isEstablishing:     false,
		pendingConns:       new(Conns),
	}
}

// Run executes the controller. It launches components and then monitors
// for a shutdown signal; after receiving the signal it shuts down the
// controller.
// The components include:
// - the periodic remote server list fetcher
// - the tunnel manager
// - a local SOCKS proxy that port forwards through the pool of tunnels
// - a local HTTP proxy that port forwards through the pool of tunnels
func (controller *Controller) Run(shutdownBroadcast <-chan struct{}) {
	socksProxy, err := NewSocksProxy(controller.config, controller)
	if err != nil {
		Notice(NOTICE_ALERT, "error initializing local SOCKS proxy: %s", err)
		return
	}
	defer socksProxy.Close()
	httpProxy, err := NewHttpProxy(controller.config, controller)
	if err != nil {
		Notice(NOTICE_ALERT, "error initializing local SOCKS proxy: %s", err)
		return
	}
	defer httpProxy.Close()

	controller.runWaitGroup.Add(2)
	go controller.remoteServerListFetcher()
	go controller.runTunnels()

	select {
	case <-shutdownBroadcast:
		Notice(NOTICE_INFO, "controller shutdown by request")
	case <-controller.failureSignal:
		Notice(NOTICE_ALERT, "controller shutdown due to failure")
	}

	// Note: in addition to establish(), this pendingConns will interrupt
	// FetchRemoteServerList
	controller.pendingConns.CloseAll()
	close(controller.shutdownBroadcast)
	controller.runWaitGroup.Wait()

	Notice(NOTICE_INFO, "exiting controller")
}

// SignalFailure notifies the controller that an associated component has failed.
// This will terminate the controller.
func (controller *Controller) SignalFailure() {
	select {
	case controller.failureSignal <- *new(struct{}):
	default:
	}
}

// remoteServerListFetcher fetches an out-of-band list of server entries
// for more tunnel candidates. It fetches immediately, retries after failure
// with a wait period, and refetches after success with a longer wait period.
func (controller *Controller) remoteServerListFetcher() {
	defer controller.runWaitGroup.Done()

	// Note: unlike existing Psiphon clients, this code
	// always makes the fetch remote server list request
loop:
	for {
		// TODO: FetchRemoteServerList should have its own pendingConns,
		// otherwise it may needlessly abort when establish is stopped.
		err := FetchRemoteServerList(controller.config, controller.pendingConns)
		var duration time.Duration
		if err != nil {
			Notice(NOTICE_ALERT, "failed to fetch remote server list: %s", err)
			duration = FETCH_REMOTE_SERVER_LIST_RETRY_TIMEOUT
		} else {
			duration = FETCH_REMOTE_SERVER_LIST_STALE_TIMEOUT
		}
		timeout := time.After(duration)
		select {
		case <-timeout:
			// Fetch again
		case <-controller.shutdownBroadcast:
			break loop
		}
	}

	Notice(NOTICE_INFO, "exiting remote server list fetcher")
}

// runTunnels is the controller tunnel management main loop. It starts and stops
// establishing tunnels based on the target tunnel pool size and the current size
// of the pool. Tunnels are established asynchronously using worker goroutines.
// When a tunnel is established, it's added to the active pool and a corresponding
// operateTunnel goroutine is launched which starts a session in the tunnel and
// monitors the tunnel for failures.
// When a tunnel fails, it's removed from the pool and the establish process is
// restarted to fill the pool.
func (controller *Controller) runTunnels() {
	defer controller.runWaitGroup.Done()

	// Don't start establishing until there are some server candidates. The
	// typical case is a client with no server entries which will wait for
	// the first successful FetchRemoteServerList to populate the data store.
	for {
		if HasServerEntries(
			controller.config.EgressRegion, controller.config.TunnelProtocol) {
			break
		}
		// TODO: replace polling with signal
		timeout := time.After(1 * time.Second)
		select {
		case <-timeout:
		case <-controller.shutdownBroadcast:
			return
		}
	}
	controller.startEstablishing()
loop:
	for {
		select {
		case failedTunnel := <-controller.failedTunnels:
			Notice(NOTICE_ALERT, "tunnel failed: %s", failedTunnel.serverEntry.IpAddress)
			controller.terminateTunnel(failedTunnel)
			// Note: only this goroutine may call startEstablishing/stopEstablishing and access
			// isEstablishing.
			if !controller.isEstablishing {
				controller.startEstablishing()
			}

		// !TODO! design issue: might not be enough server entries with region/caps to ever fill tunnel slots
		// solution(?) target MIN(CountServerEntries(region, protocol), TunnelPoolSize)
		case establishedTunnel := <-controller.establishedTunnels:
			Notice(NOTICE_INFO, "established tunnel: %s", establishedTunnel.serverEntry.IpAddress)
			// !TODO! design issue: activateTunnel makes tunnel avail for port forward *before* operates does handshake
			// solution(?) distinguish between two stages or states: connected, and then active.
			if controller.activateTunnel(establishedTunnel) {
				Notice(NOTICE_INFO, "active tunnel: %s", establishedTunnel.serverEntry.IpAddress)
				controller.operateWaitGroup.Add(1)
				go controller.operateTunnel(establishedTunnel)
			} else {
				controller.discardTunnel(establishedTunnel)
			}
			if controller.isFullyEstablished() {
				controller.stopEstablishing()
			}

		case <-controller.shutdownBroadcast:
			break loop
		}
	}
	controller.stopEstablishing()
	controller.terminateAllTunnels()
	controller.operateWaitGroup.Wait()

	// Drain tunnel channels
	close(controller.establishedTunnels)
	for tunnel := range controller.establishedTunnels {
		controller.discardTunnel(tunnel)
	}
	close(controller.failedTunnels)
	for tunnel := range controller.failedTunnels {
		controller.discardTunnel(tunnel)
	}

	Notice(NOTICE_INFO, "exiting run tunnels")
}

// discardTunnel disposes of a successful connection that is no longer required.
func (controller *Controller) discardTunnel(tunnel *Tunnel) {
	Notice(NOTICE_INFO, "discard tunnel: %s", tunnel.serverEntry.IpAddress)
	// TODO: not calling PromoteServerEntry, since that would rank the
	// discarded tunnel before fully active tunnels. Can a discarded tunnel
	// be promoted (since it connects), but with lower rank than all active
	// tunnels?
	tunnel.Close()
}

// activateTunnel adds the connected tunnel to the pool of active tunnels
// which are used for port forwarding. Returns true if the pool has an empty
// slot and false if the pool is full (caller should discard the tunnel).
func (controller *Controller) activateTunnel(tunnel *Tunnel) bool {
	controller.tunnelMutex.Lock()
	defer controller.tunnelMutex.Unlock()
	// !TODO! double check not already a tunnel to this server
	if len(controller.tunnels) >= controller.config.TunnelPoolSize {
		return false
	}
	controller.tunnels = append(controller.tunnels, tunnel)
	Notice(NOTICE_TUNNEL, "%d tunnels", len(controller.tunnels))
	return true
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
			activeTunnel.Close()
			Notice(NOTICE_TUNNEL, "%d tunnels", len(controller.tunnels))
			break
		}
	}
}

// terminateAllTunnels empties the tunnel pool, closing all active tunnels.
// This is used when shutting down the controller.
func (controller *Controller) terminateAllTunnels() {
	controller.tunnelMutex.Lock()
	defer controller.tunnelMutex.Unlock()
	for _, activeTunnel := range controller.tunnels {
		activeTunnel.Close()
	}
	controller.tunnels = make([]*Tunnel, 0)
	controller.nextTunnel = 0
	Notice(NOTICE_TUNNEL, "%d tunnels", len(controller.tunnels))
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

// getActiveTunnelServerEntries lists the Server Entries for
// all the active tunnels. This is used to exclude those servers
// from the set of candidates to establish connections to.
func (controller *Controller) getActiveTunnelServerEntries() (serverEntries []*ServerEntry) {
	controller.tunnelMutex.Lock()
	defer controller.tunnelMutex.Unlock()
	serverEntries = make([]*ServerEntry, 0)
	for _, activeTunnel := range controller.tunnels {
		serverEntries = append(serverEntries, activeTunnel.serverEntry)
	}
	return serverEntries
}

// operateTunnel starts a Psiphon session (handshake, etc.) on a newly
// connected tunnel, and then monitors the tunnel for failures:
//
// 1. Overall tunnel failure: the tunnel sends a signal to the ClosedSignal
// channel on keep-alive failure and other transport I/O errors. In case
// of such a failure, the tunnel is marked as failed.
//
// 2. Tunnel port forward failures: the tunnel connection may stay up but
// the client may still fail to establish port forwards due to server load
// and other conditions. After a threshold number of such failures, the
// overall tunnel is marked as failed.
//
// TODO: currently, any connect (dial), read, or write error associated with
// a port forward is counted as a failure. It may be important to differentiate
// between failures due to Psiphon server conditions and failures due to the
// origin/target server (in the latter case, the tunnel is healthy). Here are
// some typical error messages to consider matching against (or ignoring):
//
// - "ssh: rejected: administratively prohibited (open failed)"
// - "ssh: rejected: connect failed (Connection timed out)"
// - "write tcp ... broken pipe"
// - "read tcp ... connection reset by peer"
// - "ssh: unexpected packet in response to channel open: <nil>"
//
func (controller *Controller) operateTunnel(tunnel *Tunnel) {
	defer controller.operateWaitGroup.Done()

	tunnelClosedSignal := make(chan struct{}, 1)
	err := tunnel.conn.SetClosedSignal(tunnelClosedSignal)
	if err != nil {
		err = fmt.Errorf("failed to set closed signal: %s", err)
	}

	Notice(NOTICE_INFO, "starting session for %s", tunnel.serverEntry.IpAddress)
	// TODO: NewSession server API calls may block shutdown
	_, err = NewSession(controller.config, tunnel)
	if err != nil {
		err = fmt.Errorf("error starting session for %s: %s", tunnel.serverEntry.IpAddress, err)
	}

	// Promote this successful tunnel to first rank so it's one
	// of the first candidates next time establish runs.
	PromoteServerEntry(tunnel.serverEntry.IpAddress)

	for err == nil {
		select {
		case failures := <-tunnel.portForwardFailures:
			tunnel.portForwardFailureTotal += failures
			if tunnel.portForwardFailureTotal > controller.config.PortForwardFailureThreshold {
				err = errors.New("tunnel exceeded port forward failure threshold")
			}

		case <-tunnelClosedSignal:
			// TODO: this signal can be received during a commanded shutdown due to
			// how tunnels are closed; should rework this to avoid log noise.
			err = errors.New("tunnel closed unexpectedly")

		case <-controller.shutdownBroadcast:
			Notice(NOTICE_INFO, "shutdown operate tunnel")
			return
		}
	}

	if err != nil {
		Notice(NOTICE_ALERT, "operate tunnel error for %s: %s", tunnel.serverEntry.IpAddress, err)
		// Don't block. Assumes the receiver has a buffer large enough for
		// the typical number of operated tunnels. In case there's no room,
		// terminate the tunnel (runTunnels won't get a signal in this case).
		select {
		case controller.failedTunnels <- tunnel:
		default:
			controller.terminateTunnel(tunnel)
		}
	}
}

// TunneledConn implements net.Conn and wraps a port foward connection.
// It is used to hook into Read and Write to observe I/O errors and
// report these errors back to the tunnel monitor as port forward failures.
type TunneledConn struct {
	net.Conn
	tunnel *Tunnel
}

func (conn *TunneledConn) Read(buffer []byte) (n int, err error) {
	n, err = conn.Conn.Read(buffer)
	if err != nil {
		// Report 1 new failure. Won't block; assumes the receiver
		// has a sufficient buffer for the threshold number of reports.
		// TODO: conditional on type of error or error message?
		select {
		case conn.tunnel.portForwardFailures <- 1:
		default:
		}
	}
	return
}

func (conn *TunneledConn) Write(buffer []byte) (n int, err error) {
	n, err = conn.Conn.Write(buffer)
	if err != nil {
		// Same as TunneledConn.Read()
		select {
		case conn.tunnel.portForwardFailures <- 1:
		default:
		}
	}
	return
}

// Dial selects an active tunnel and establishes a port forward
// connection through the selected tunnel. Failure to connect is considered
// a port foward failure, for the purpose of monitoring tunnel health.
func (controller *Controller) Dial(remoteAddr string) (conn net.Conn, err error) {
	tunnel := controller.getNextActiveTunnel()
	if tunnel == nil {
		return nil, ContextError(errors.New("no active tunnels"))
	}
	tunnelConn, err := tunnel.Dial(remoteAddr)
	if err != nil {
		// TODO: conditional on type of error or error message?
		select {
		case tunnel.portForwardFailures <- 1:
		default:
		}
		return nil, ContextError(err)
	}
	return &TunneledConn{
			Conn:   tunnelConn,
			tunnel: tunnel},
		nil
}

// startEstablishing creates a pool of worker goroutines which will
// attempt to establish tunnels to candidate servers. The candidates
// are generated by another goroutine.
func (controller *Controller) startEstablishing() {
	if controller.isEstablishing {
		return
	}
	Notice(NOTICE_INFO, "start establishing")
	controller.isEstablishing = true
	controller.establishWaitGroup = new(sync.WaitGroup)
	controller.stopEstablishingBroadcast = make(chan struct{})
	controller.candidateServerEntries = make(chan *ServerEntry)

	for i := 0; i < controller.config.ConnectionWorkerPoolSize; i++ {
		controller.establishWaitGroup.Add(1)
		go controller.establishTunnelWorker()
	}

	controller.establishWaitGroup.Add(1)
	go controller.establishCandidateGenerator()
}

// stopEstablishing signals the establish goroutines to stop and waits
// for the group to halt. pendingConns is used to interrupt any worker
// blocked on a socket connect.
func (controller *Controller) stopEstablishing() {
	if !controller.isEstablishing {
		return
	}
	Notice(NOTICE_INFO, "stop establishing")
	// Note: on Windows, interruptibleTCPClose doesn't really interrupt socket connects
	// and may leave goroutines running for a time after the Wait call.
	controller.pendingConns.CloseAll()
	close(controller.stopEstablishingBroadcast)
	// Note: establishCandidateGenerator closes controller.candidateServerEntries
	// (as it may be sending to that channel).
	controller.establishWaitGroup.Wait()

	controller.isEstablishing = false
	controller.establishWaitGroup = nil
	controller.stopEstablishingBroadcast = nil
	controller.candidateServerEntries = nil
}

// establishCandidateGenerator populates the candidate queue with server entries
// from the data store. Server entries are iterated in rank order, so that promoted
// servers with higher rank are priority candidates.
func (controller *Controller) establishCandidateGenerator() {
	defer controller.establishWaitGroup.Done()
loop:
	for {
		// Note: it's possible that an active tunnel in excludeServerEntries will
		// fail during this iteration of server entries and in that case the
		// cooresponding server will not be retried (within the same iteration).
		// !TODO! is there also a race that can result in multiple tunnels to the same server
		excludeServerEntries := controller.getActiveTunnelServerEntries()
		iterator, err := NewServerEntryIterator(
			controller.config.EgressRegion, controller.config.TunnelProtocol, excludeServerEntries)
		if err != nil {
			Notice(NOTICE_ALERT, "failed to iterate over candidates: %s", err)
			controller.SignalFailure()
			break loop
		}
		for {
			serverEntry, err := iterator.Next()
			if err != nil {
				Notice(NOTICE_ALERT, "failed to get next candidate: %s", err)
				controller.SignalFailure()
				break loop
			}
			if serverEntry == nil {
				// Completed this iteration
				break
			}
			select {
			case controller.candidateServerEntries <- serverEntry:
			case <-controller.stopEstablishingBroadcast:
				break loop
			case <-controller.shutdownBroadcast:
				break loop
			}
		}
		iterator.Close()
		// After a complete iteration of candidate servers, pause before iterating again.
		// This helps avoid some busy wait loop conditions, and also allows some time for
		// network conditions to change.
		timeout := time.After(ESTABLISH_TUNNEL_PAUSE_PERIOD)
		select {
		case <-timeout:
			// Retry iterating
		case <-controller.stopEstablishingBroadcast:
			break loop
		case <-controller.shutdownBroadcast:
			break loop
		}
	}
	close(controller.candidateServerEntries)
	Notice(NOTICE_INFO, "stopped candidate generator")
}

// establishTunnelWorker pulls candidates from the candidate queue, establishes
// a connection to the tunnel server, and delivers the established tunnel to a channel.
func (controller *Controller) establishTunnelWorker() {
	defer controller.establishWaitGroup.Done()
	for serverEntry := range controller.candidateServerEntries {
		// Note: don't receive from candidateQueue and broadcastStopWorkers in the same
		// select, since we want to prioritize receiving the stop signal
		select {
		case <-controller.stopEstablishingBroadcast:
			return
		default:
		}
		tunnel, err := EstablishTunnel(
			controller.config, controller.pendingConns, serverEntry)
		if err != nil {
			// TODO: distingush case where conn is interrupted?
			Notice(NOTICE_INFO, "failed to connect to %s: %s", serverEntry.IpAddress, err)
		} else {
			// Don't block. Assumes the receiver has a buffer large enough for
			// the number of desired tunnels. If there's no room, the tunnel must
			// not be required so it's discarded.
			select {
			case controller.establishedTunnels <- tunnel:
			default:
				controller.discardTunnel(tunnel)
			}
		}
	}
	Notice(NOTICE_INFO, "stopped establish worker")
}

// RunForever executes the main loop of the Psiphon client. It launches
// the controller with a shutdown that it never signaled.
func RunForever(config *Config) {

	if config.LogFilename != "" {
		logFile, err := os.OpenFile(config.LogFilename, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			Fatal("error opening log file: %s", err)
		}
		defer logFile.Close()
		log.SetOutput(logFile)
	}

	Notice(NOTICE_VERSION, VERSION)

	controller := NewController(config)
	shutdownBroadcast := make(chan struct{})
	controller.Run(shutdownBroadcast)
}
