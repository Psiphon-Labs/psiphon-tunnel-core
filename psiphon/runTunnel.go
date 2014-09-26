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
	waitGroup *sync.WaitGroup,
	candidateServerEntries chan *ServerEntry,
	broadcastStopWorkers chan bool,
	pendingConns *PendingConns,
	establishedTunnels chan *Tunnel) {

	defer waitGroup.Done()
	for serverEntry := range candidateServerEntries {
		// Note: don't receive from candidateQueue and broadcastStopWorkers in the same
		// select, since we want to prioritize receiving the stop signal
		if IsSignalled(broadcastStopWorkers) {
			return
		}
		log.Printf("connecting to %s", serverEntry.IpAddress)
		tunnel, err := EstablishTunnel(serverEntry, pendingConns)
		if err != nil {
			// TODO: distingush case where conn is interrupted?
			log.Printf("failed to connect to %s: %s", serverEntry.IpAddress, err)
		} else {
			log.Printf("successfully connected to %s", serverEntry.IpAddress)
			select {
			case establishedTunnels <- tunnel:
			default:
				discardTunnel(tunnel)
			}
		}
	}
}

func discardTunnel(tunnel *Tunnel) {
	log.Printf("discard connection to %s", tunnel.serverEntry.IpAddress)
	PromoteServerEntry(tunnel.serverEntry.IpAddress)
	tunnel.Close()
}

// runTunnel establishes a tunnel session and runs local proxies that make use of
// that tunnel. The tunnel connection is monitored and this function returns an
// error when the tunnel unexpectedly disconnects.
// fetchRemoteServerList is used to obtain a fresh list of servers to attempt
// to connect to. A worker pool of goroutines is used to attempt several tunnel
// connections in parallel, and this process is stopped once the first tunnel
// is established.
func runTunnel(config *Config) error {
	log.Printf("establishing tunnel")
	waitGroup := new(sync.WaitGroup)
	candidateServerEntries := make(chan *ServerEntry)
	pendingConns := new(PendingConns)
	establishedTunnels := make(chan *Tunnel, 1)
	timeout := time.After(ESTABLISH_TUNNEL_TIMEOUT)
	broadcastStopWorkers := make(chan bool)
	for i := 0; i < CONNECTION_WORKER_POOL_SIZE; i++ {
		waitGroup.Add(1)
		go establishTunnelWorker(
			waitGroup, candidateServerEntries, broadcastStopWorkers,
			pendingConns, establishedTunnels)
	}
	// TODO: add a throttle after each full cycle?
	// Note: errors fall through to ensure worker and channel cleanup
	var selectedTunnel *Tunnel
	cycler, err := NewServerEntryCycler()
	for selectedTunnel == nil && err == nil {
		serverEntry, err := cycler.Next()
		if err != nil {
			break
		}
		select {
		case candidateServerEntries <- serverEntry:
		case selectedTunnel = <-establishedTunnels:
			defer selectedTunnel.Close()
			log.Printf("selected connection to %s", selectedTunnel.serverEntry.IpAddress)
		case <-timeout:
			err = errors.New("timeout establishing tunnel")
		}
	}
	cycler.Close()
	close(candidateServerEntries)
	close(broadcastStopWorkers)
	// Interrupt any partial connections in progress, so that
	// the worker will terminate immediately
	pendingConns.Interrupt()
	waitGroup.Wait()
	// Drain any excess tunnels
	close(establishedTunnels)
	for tunnel := range establishedTunnels {
		discardTunnel(tunnel)
	}
	// Note: end of error fall through
	if err != nil {
		return fmt.Errorf("failed to establish tunnel: %s", err)
	}
	// Don't hold references to candidates while running tunnel
	candidateServerEntries = nil
	pendingConns = nil
	// TODO: could start local proxies, etc., before synchronizing work group
	if selectedTunnel != nil {
		log.Printf("tunnel established")
		PromoteServerEntry(selectedTunnel.serverEntry.IpAddress)
		stopTunnelSignal := make(chan bool)
		err = selectedTunnel.conn.SetClosedSignal(stopTunnelSignal)
		if err != nil {
			return fmt.Errorf("failed to set closed signal: %s", err)
		}
		log.Printf("starting local SOCKS proxy")
		socksProxy, err := NewSocksProxy(selectedTunnel, stopTunnelSignal)
		if err != nil {
			return fmt.Errorf("error initializing local SOCKS proxy: %s", err)
		}
		defer socksProxy.Close()
		log.Printf("starting local HTTP proxy")
		httpProxy, err := NewHttpProxy(selectedTunnel, stopTunnelSignal)
		if err != nil {
			return fmt.Errorf("error initializing local HTTP proxy: %s", err)
		}
		defer httpProxy.Close()
		log.Printf("starting session")
		localHttpProxyAddress := httpProxy.listener.Addr().String()
		_, err = NewSession(config, selectedTunnel, localHttpProxyAddress)
		if err != nil {
			return fmt.Errorf("error starting session: %s", err)
		}
		log.Printf("monitoring tunnel")
		<-stopTunnelSignal
	}
	return err
}

// RunTunnelForever executes the main loop of the Psiphon client. It establishes
// a tunnel and reconnects when the tunnel unexpectedly disconnects.
func RunTunnelForever(config *Config) {
	if config.LogFilename != "" {
		logFile, err := os.OpenFile(config.LogFilename, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			log.Fatalf("error opening log file: %s", err)
		}
		defer logFile.Close()
		log.SetOutput(logFile)
	} else {
		// TODO
		//log.SetOutput(ioutil.Discard)
	}
	// TODO: unlike existing Psiphon clients, this code
	// always makes the fetch remote server list request
	go func() {
		for {
			err := FetchRemoteServerList(config)
			if err != nil {
				log.Printf("failed to fetch remote server list: %s", err)
				time.Sleep(FETCH_REMOTE_SERVER_LIST_RETRY_TIMEOUT)
			} else {
				time.Sleep(FETCH_REMOTE_SERVER_LIST_STALE_TIMEOUT)
			}
		}
	}()
	for {
		if HasServerEntries() {
			err := runTunnel(config)
			if err != nil {
				log.Printf("run tunnel error: %s", err)
			}
		}
		time.Sleep(1 * time.Second)
	}
}
