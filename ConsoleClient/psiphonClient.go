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
	"io"
	"io/ioutil"
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

	var formatNotices bool
	flag.BoolVar(&formatNotices, "formatNotices", false, "emit notices in human-readable format")

	var profileFilename string
	flag.StringVar(&profileFilename, "profile", "", "CPU profile output file")

	var interfaceName string
	flag.StringVar(&interfaceName, "listenInterface", "", "Interface Name")

	flag.Parse()

	// Initialize default Notice output (stderr)

	var noticeWriter io.Writer
	noticeWriter = os.Stderr
	if formatNotices {
		noticeWriter = psiphon.NewNoticeConsoleRewriter(noticeWriter)
	}
	psiphon.SetNoticeOutput(noticeWriter)

	psiphon.EmitNoticeBuildInfo()

	// Handle required config file parameter

	if configFilename == "" {
		psiphon.NoticeError("configuration file is required")
		os.Exit(1)
	}
	configFileContents, err := ioutil.ReadFile(configFilename)
	if err != nil {
		psiphon.NoticeError("error loading configuration file: %s", err)
		os.Exit(1)
	}
	config, err := psiphon.LoadConfig(configFileContents)
	if err != nil {
		psiphon.NoticeError("error processing configuration file: %s", err)
		os.Exit(1)
	}

	// When a logfile is configured, reinitialize Notice output

	if config.LogFilename != "" {
		logFile, err := os.OpenFile(config.LogFilename, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			psiphon.NoticeError("error opening log file: %s", err)
			os.Exit(1)
		}
		defer logFile.Close()
		var noticeWriter io.Writer
		noticeWriter = logFile
		if formatNotices {
			noticeWriter = psiphon.NewNoticeConsoleRewriter(noticeWriter)
		}
		psiphon.SetNoticeOutput(noticeWriter)
	}

	// Handle optional profiling parameter

	if profileFilename != "" {
		profileFile, err := os.Create(profileFilename)
		if err != nil {
			psiphon.NoticeError("error opening profile file: %s", err)
			os.Exit(1)
		}
		pprof.StartCPUProfile(profileFile)
		defer pprof.StopCPUProfile()
	}

	// Initialize data store

	err = psiphon.InitDataStore(config)
	if err != nil {
		psiphon.NoticeError("error initializing datastore: %s", err)
		os.Exit(1)
	}

	// Handle optional embedded server list file parameter
	// If specified, the embedded server list is loaded and stored. When there
	// are no server candidates at all, we wait for this import to complete
	// before starting the Psiphon controller. Otherwise, we import while
	// concurrently starting the controller to minimize delay before attempting
	// to connect to existing candidate servers.
	// If the import fails, an error notice is emitted, but the controller is
	// still started: either existing candidate servers may suffice, or the
	// remote server list fetch may obtain candidate servers.
	if embeddedServerEntryListFilename != "" {
		embeddedServerListWaitGroup := new(sync.WaitGroup)
		embeddedServerListWaitGroup.Add(1)
		go func() {
			defer embeddedServerListWaitGroup.Done()
			serverEntryList, err := ioutil.ReadFile(embeddedServerEntryListFilename)
			if err != nil {
				psiphon.NoticeError("error loading embedded server entry list file: %s", err)
				return
			}
			// TODO: stream embedded server list data? also, the cast makes an unnecessary copy of a large buffer?
			serverEntries, err := psiphon.DecodeAndValidateServerEntryList(
				string(serverEntryList),
				psiphon.GetCurrentTimestamp(),
				psiphon.SERVER_ENTRY_SOURCE_EMBEDDED)
			if err != nil {
				psiphon.NoticeError("error decoding embedded server entry list file: %s", err)
				return
			}
			// Since embedded server list entries may become stale, they will not
			// overwrite existing stored entries for the same server.
			err = psiphon.StoreServerEntries(serverEntries, false)
			if err != nil {
				psiphon.NoticeError("error storing embedded server entry list data: %s", err)
				return
			}
		}()

		if psiphon.CountServerEntries(config.EgressRegion, config.TunnelProtocol) == 0 {
			embeddedServerListWaitGroup.Wait()
		} else {
			defer embeddedServerListWaitGroup.Wait()
		}
	}

	if interfaceName != "" {
		config.ListenInterface = interfaceName
	}

	// Run Psiphon

	controller, err := psiphon.NewController(config)
	if err != nil {
		psiphon.NoticeError("error creating controller: %s", err)
		os.Exit(1)
	}

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
		psiphon.NoticeInfo("shutdown by system")
		close(shutdownBroadcast)
		controllerWaitGroup.Wait()
	case <-controllerStopSignal:
		psiphon.NoticeInfo("shutdown by controller")
	}
}
