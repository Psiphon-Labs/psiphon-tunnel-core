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

package main

import (
	"flag"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"runtime/pprof"
	"sync"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon"
)

func main() {

	// Define command-line parameters

	var configFilename string
	flag.StringVar(&configFilename, "config", "", "configuration input file")

	var embeddedServerEntryListFilename string
	flag.StringVar(&embeddedServerEntryListFilename, "serverList", "", "embedded server entry list input file")

	var profileFilename string
	flag.StringVar(&profileFilename, "profile", "", "CPU profile output file")

	flag.Parse()

	// Handle required config file parameter

	if configFilename == "" {
		log.Fatalf("configuration file is required")
	}
	configFileContents, err := ioutil.ReadFile(configFilename)
	if err != nil {
		log.Fatalf("error loading configuration file: %s", err)
	}
	config, err := psiphon.LoadConfig(configFileContents)
	if err != nil {
		log.Fatalf("error processing configuration file: %s", err)
	}

	// Set logfile, if configured

	if config.LogFilename != "" {
		logFile, err := os.OpenFile(config.LogFilename, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			log.Fatalf("error opening log file: %s", err)
		}
		defer logFile.Close()
		log.SetOutput(logFile)
	}

	// Handle optional profiling parameter

	if profileFilename != "" {
		profileFile, err := os.Create(profileFilename)
		if err != nil {
			log.Fatalf("error opening profile file: %s", err)
		}
		pprof.StartCPUProfile(profileFile)
		defer pprof.StopCPUProfile()
	}

	// Initialize data store

	err = psiphon.InitDataStore(config)
	if err != nil {
		log.Fatalf("error initializing datastore: %s", err)
	}

	// Handle optional embedded server list file parameter
	// If specified, the embedded server list is loaded and stored before
	// running Psiphon.

	if embeddedServerEntryListFilename != "" {
		serverEntryList, err := ioutil.ReadFile(embeddedServerEntryListFilename)
		if err != nil {
			log.Fatalf("error loading embedded server entry list file: %s", err)
		}
		// TODO: stream embedded server list data? also, the cast makaes an unnecessary copy of a large buffer?
		serverEntries, err := psiphon.DecodeServerEntryList(string(serverEntryList))
		if err != nil {
			log.Fatalf("error decoding embedded server entry list file: %s", err)
		}
		// Since embedded server list entries may become stale, they will not
		// overwrite existing stored entries for the same server.
		err = psiphon.StoreServerEntries(serverEntries, false)
		if err != nil {
			log.Fatalf("error storing embedded server entry list data: %s", err)
		}
	}

	// Run Psiphon

	controller := psiphon.NewController(config)
	controllerStopSignal := make(chan struct{}, 1)
	shutdownBroadcast := make(chan struct{})
	controllerWaitGroup := new(sync.WaitGroup)
	controllerWaitGroup.Add(1)
	go func() {
		defer controllerWaitGroup.Done()
		controller.Run(shutdownBroadcast)
		controllerStopSignal <- *new(struct{})
	}()

	// Wait for an OS signal or a Run stop signal, then stop Psiphon and exit

	systemStopSignal := make(chan os.Signal, 1)
	signal.Notify(systemStopSignal, os.Interrupt, os.Kill)
	select {
	case <-systemStopSignal:
		psiphon.Notice(psiphon.NOTICE_INFO, "shutdown by system")
		close(shutdownBroadcast)
		controllerWaitGroup.Wait()
	case <-controllerStopSignal:
		psiphon.Notice(psiphon.NOTICE_INFO, "shutdown by controller")
	}
}
