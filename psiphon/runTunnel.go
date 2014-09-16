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
	waitGroup *sync.WaitGroup, candidateQueue chan *Tunnel, firstEstablishedTunnel chan *Tunnel) {
	defer waitGroup.Done()
	for tunnel := range candidateQueue {
		log.Printf("Connecting to %s...", tunnel.serverEntry.IpAddress)
		err := EstablishTunnel(tunnel)
		if err != nil {
			log.Printf("failed to connect to %s: %s", tunnel.serverEntry.IpAddress, err)
		} else {
			log.Printf("success connecting to %s", tunnel.serverEntry.IpAddress)
			select {
			case firstEstablishedTunnel <- tunnel:
			default:
				tunnel.Close()
			}
		}
	}
}

// runTunnel establishes a tunnel session and runs local proxies that make use of
// that tunnel. The tunnel connection is monitored and this function returns an
// error when the tunnel unexpectedly disconnects.
// fetchRemoteServerList is used to obtain a fresh list of servers to attempt
// to connect to. A worker pool of goroutines is used to attempt several tunnel
// connections in parallel, and this process is stopped once the first tunnel
// is established.
func runTunnel(config *Config) error {
	log.Printf("fetching remote server list")
	// TODO: fetch in parallel goroutine (if have local server entries)
	serverList, err := FetchRemoteServerList(config)
	if err != nil {
		return fmt.Errorf("failed to fetch remote server list: %s", err)
	}
	log.Printf("establishing tunnel")
	candidateList := make([]*Tunnel, 0)
	for _, serverEntry := range serverList {
		candidateList = append(candidateList, &Tunnel{serverEntry: serverEntry})
	}
	waitGroup := new(sync.WaitGroup)
	candidateQueue := make(chan *Tunnel, len(candidateList))
	firstEstablishedTunnel := make(chan *Tunnel, 1)
	timeout := time.After(ESTABLISH_TUNNEL_TIMEOUT)
	for i := 0; i < CONNECTION_WORKER_POOL_SIZE; i++ {
		waitGroup.Add(1)
		go establishTunnelWorker(waitGroup, candidateQueue, firstEstablishedTunnel)
	}
	for _, tunnel := range candidateList {
		candidateQueue <- tunnel
	}
	close(candidateQueue)
	var establishedTunnel *Tunnel
	select {
	case establishedTunnel = <-firstEstablishedTunnel:
		defer establishedTunnel.Close()
	case <-timeout:
		return errors.New("timeout establishing tunnel")
	}
	log.Printf("stopping workers")
	for _, candidate := range candidateList {
		if candidate != establishedTunnel {
			// Immediately cancel any partial connections in progress
			candidate.Close()
		}
	}
	// TODO: can start SOCKS before synchronizing work group
	waitGroup.Wait()
	if establishedTunnel != nil {
		stopSignal := make(chan bool)
		err = establishedTunnel.conn.SetDisconnectionSignal(stopSignal)
		if err != nil {
			return fmt.Errorf("failed to set disconnection signal: %s", err)
		}
		log.Printf("starting local SOCKS proxy")
		socksServer := NewSocksServer(establishedTunnel, stopSignal)
		if err != nil {
			return fmt.Errorf("error initializing local SOCKS proxy: %s", err)
		}
		err = socksServer.Run()
		if err != nil {
			return fmt.Errorf("error running local SOCKS proxy: %s", err)
		}
		defer socksServer.Close()
		log.Printf("monitoring for failure")
		<-stopSignal
	}
	return nil
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
	for {
		err := runTunnel(config)
		if err != nil {
			log.Printf("error: %s", err)
		}
		time.Sleep(1 * time.Second)
	}
}
