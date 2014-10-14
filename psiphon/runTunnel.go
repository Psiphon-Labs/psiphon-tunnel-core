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
// The main interface is RunTunnelForever, which obtains lists of servers,
// establishes tunnel connections, and runs local proxies through which
// tunnelled traffic may be sent.
package psiphon

import (
	"errors"
	"fmt"
	"log"
	"os"
	"sync"
	"time"
)

// establishTunnelWorker pulls candidates from the potential tunnel queue, establishes
// a connection to the tunnel server, and delivers the established tunnel to a channel,
// if there's not already an established tunnel. This function is to be used in a pool
// of goroutines.
func establishTunnelWorker(
	tunnelProtocol, sessionId string,
	workerWaitGroup *sync.WaitGroup,
	candidateServerEntries chan *ServerEntry,
	broadcastStopWorkers chan struct{},
	pendingConns *PendingConns,
	establishedTunnels chan *Tunnel) {

	defer workerWaitGroup.Done()
	for serverEntry := range candidateServerEntries {
		// Note: don't receive from candidateQueue and broadcastStopWorkers in the same
		// select, since we want to prioritize receiving the stop signal
		select {
		case <-broadcastStopWorkers:
			return
		default:
		}
		tunnel, err := EstablishTunnel(tunnelProtocol, sessionId, serverEntry, pendingConns)
		if err != nil {
			// TODO: distingush case where conn is interrupted?
			Notice(NOTICE_INFO, "failed to connect to %s: %s", serverEntry.IpAddress, err)
		} else {
			Notice(NOTICE_INFO, "successfully connected to %s", serverEntry.IpAddress)
			select {
			case establishedTunnels <- tunnel:
			default:
				discardTunnel(tunnel)
			}
		}
	}
}

// discardTunnel is used to dispose of a successful connection that is
// no longer required (another tunnel has already been selected). Since
// the connection was successful, the server entry is still promoted.
func discardTunnel(tunnel *Tunnel) {
	Notice(NOTICE_INFO, "discard connection to %s", tunnel.serverEntry.IpAddress)
	PromoteServerEntry(tunnel.serverEntry.IpAddress)
	tunnel.Close()
}

// establishTunnel coordinates a worker pool of goroutines to attempt several
// tunnel connections in parallel, and this process is stopped once the first
// tunnel is established.
func establishTunnel(config *Config, sessionId string) (tunnel *Tunnel, err error) {
	workerWaitGroup := new(sync.WaitGroup)
	candidateServerEntries := make(chan *ServerEntry)
	pendingConns := new(PendingConns)
	establishedTunnels := make(chan *Tunnel, 1)
	timeout := time.After(ESTABLISH_TUNNEL_TIMEOUT)
	broadcastStopWorkers := make(chan struct{})
	for i := 0; i < config.ConnectionWorkerPoolSize; i++ {
		workerWaitGroup.Add(1)
		go establishTunnelWorker(
			config.TunnelProtocol, sessionId,
			workerWaitGroup, candidateServerEntries, broadcastStopWorkers,
			pendingConns, establishedTunnels)
	}
	// TODO: add a throttle after each full cycle?
	// Note: errors fall through to ensure worker and channel cleanup (is started, at least)
	var selectedTunnel *Tunnel
	cycler, err := NewServerEntryCycler(config.EgressRegion)
	for selectedTunnel == nil && err == nil {
		var serverEntry *ServerEntry
		// Note: don't mask err here, we want to reference it after the loop
		serverEntry, err = cycler.Next()
		if err != nil {
			break
		}
		select {
		case candidateServerEntries <- serverEntry:
		case selectedTunnel = <-establishedTunnels:
			Notice(NOTICE_INFO, "selected connection to %s", selectedTunnel.serverEntry.IpAddress)
		case <-timeout:
			err = errors.New("timeout establishing tunnel")
		}
	}
	if cycler != nil {
		cycler.Close()
	}
	close(candidateServerEntries)
	close(broadcastStopWorkers)
	// Clean up is now asynchronous since Windows doesn't support interruptible connections
	go func() {
		// Interrupt any partial connections in progress, so that
		// the worker will terminate immediately
		pendingConns.Interrupt()
		workerWaitGroup.Wait()
		// Drain any excess tunnels
		close(establishedTunnels)
		for tunnel := range establishedTunnels {
			discardTunnel(tunnel)
		}
		// Note: only call this PromoteServerEntry after all discards so the selected
		// tunnel is the top ranked
		if selectedTunnel != nil {
			PromoteServerEntry(selectedTunnel.serverEntry.IpAddress)
		}
	}()
	// Note: end of error fall through
	if err != nil {
		return nil, ContextError(err)
	}
	return selectedTunnel, nil
}

// runTunnel establishes a tunnel session and runs local proxies that make use of
// that tunnel. The tunnel connection is monitored and this function returns an
// error when the tunnel unexpectedly disconnects.
func runTunnel(config *Config) error {
	Notice(NOTICE_INFO, "establishing tunnel")
	sessionId, err := MakeSessionId()
	if err != nil {
		return ContextError(err)
	}
	tunnel, err := establishTunnel(config, sessionId)
	if err != nil {
		return ContextError(err)
	}
	defer tunnel.Close()
	// Tunnel connection and local proxies will send signals to this channel
	// when they close or stop. Signal senders should not block. Allows at
	// least one stop signal to be sent before there is a receiver.
	stopTunnelSignal := make(chan struct{}, 1)
	err = tunnel.conn.SetClosedSignal(stopTunnelSignal)
	if err != nil {
		return fmt.Errorf("failed to set closed signal: %s", err)
	}
	socksProxy, err := NewSocksProxy(config.LocalSocksProxyPort, tunnel, stopTunnelSignal)
	if err != nil {
		return fmt.Errorf("error initializing local SOCKS proxy: %s", err)
	}
	defer socksProxy.Close()
	httpProxy, err := NewHttpProxy(config.LocalHttpProxyPort, tunnel, stopTunnelSignal)
	if err != nil {
		return fmt.Errorf("error initializing local HTTP proxy: %s", err)
	}
	defer httpProxy.Close()
	Notice(NOTICE_INFO, "starting session")
	localHttpProxyAddress := httpProxy.listener.Addr().String()
	_, err = NewSession(config, tunnel, localHttpProxyAddress, sessionId)
	if err != nil {
		return fmt.Errorf("error starting session: %s", err)
	}
	Notice(NOTICE_TUNNEL, "tunnel started")
	Notice(NOTICE_INFO, "monitoring tunnel")
	<-stopTunnelSignal
	Notice(NOTICE_TUNNEL, "tunnel stopped")
	return nil
}

// RunTunnelForever executes the main loop of the Psiphon client. It establishes
// a tunnel and reconnects when the tunnel unexpectedly disconnects.
// FetchRemoteServerList is used to obtain a fresh list of servers to attempt
// to connect to.
func RunTunnelForever(config *Config) {
	if config.LogFilename != "" {
		logFile, err := os.OpenFile(config.LogFilename, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			Fatal("error opening log file: %s", err)
		}
		defer logFile.Close()
		log.SetOutput(logFile)
	}
	Notice(NOTICE_VERSION, VERSION)
	// TODO: unlike existing Psiphon clients, this code
	// always makes the fetch remote server list request
	go func() {
		for {
			err := FetchRemoteServerList(config)
			if err != nil {
				Notice(NOTICE_ALERT, "failed to fetch remote server list: %s", err)
				time.Sleep(FETCH_REMOTE_SERVER_LIST_RETRY_TIMEOUT)
			} else {
				time.Sleep(FETCH_REMOTE_SERVER_LIST_STALE_TIMEOUT)
			}
		}
	}()
	for {
		if HasServerEntries(config.EgressRegion) {
			err := runTunnel(config)
			if err != nil {
				Notice(NOTICE_ALERT, "run tunnel error: %s", err)
			}
		}
		time.Sleep(1 * time.Second)
	}
}
