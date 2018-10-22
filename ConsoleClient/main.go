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
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/signal"
	"sort"
	"sync"
	"syscall"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/tun"
)

func main() {

	// Define command-line parameters

	var configFilename string
	flag.StringVar(&configFilename, "config", "", "configuration input file")

	var embeddedServerEntryListFilename string
	flag.StringVar(&embeddedServerEntryListFilename, "serverList", "", "embedded server entry list input file")

	var formatNotices bool
	flag.BoolVar(&formatNotices, "formatNotices", false, "emit notices in human-readable format")

	var interfaceName string
	flag.StringVar(&interfaceName, "listenInterface", "", "bind local proxies to specified interface")

	var versionDetails bool
	flag.BoolVar(&versionDetails, "version", false, "print build information and exit")
	flag.BoolVar(&versionDetails, "v", false, "print build information and exit")

	var tunDevice, tunBindInterface, tunPrimaryDNS, tunSecondaryDNS string
	if tun.IsSupported() {

		// When tunDevice is specified, a packet tunnel is run and packets are relayed between
		// the specified tun device and the server.
		//
		// The tun device is expected to exist and should be configured with an IP address and
		// routing.
		//
		// The tunBindInterface/tunPrimaryDNS/tunSecondaryDNS parameters are used to bypass any
		// tun device routing when connecting to Psiphon servers.
		//
		// For transparent tunneled DNS, set the host or DNS clients to use the address specfied
		// in tun.GetTransparentDNSResolverIPv4Address().
		//
		// Packet tunnel mode is supported only on certains platforms.

		flag.StringVar(&tunDevice, "tunDevice", "", "run packet tunnel for specified tun device")
		flag.StringVar(&tunBindInterface, "tunBindInterface", tun.DEFAULT_PUBLIC_INTERFACE_NAME, "bypass tun device via specified interface")
		flag.StringVar(&tunPrimaryDNS, "tunPrimaryDNS", "8.8.8.8", "primary DNS resolver for bypass")
		flag.StringVar(&tunSecondaryDNS, "tunSecondaryDNS", "8.8.4.4", "secondary DNS resolver for bypass")
	}

	var noticeFilename string
	flag.StringVar(&noticeFilename, "notices", "", "notices output file (defaults to stderr)")

	var homepageFilename string
	flag.StringVar(&homepageFilename, "homepages", "", "homepages notices output file")

	var rotatingFilename string
	flag.StringVar(&rotatingFilename, "rotating", "", "rotating notices output file")

	var rotatingFileSize int
	flag.IntVar(&rotatingFileSize, "rotatingFileSize", 1<<20, "rotating notices file size")

	var rotatingSyncFrequency int
	flag.IntVar(&rotatingSyncFrequency, "rotatingSyncFrequency", 100, "rotating notices file sync frequency")

	flag.Parse()

	if versionDetails {
		b := common.GetBuildInfo()

		var printableDependencies bytes.Buffer
		var dependencyMap map[string]string
		longestRepoUrl := 0
		json.Unmarshal(b.Dependencies, &dependencyMap)

		sortedRepoUrls := make([]string, 0, len(dependencyMap))
		for repoUrl := range dependencyMap {
			repoUrlLength := len(repoUrl)
			if repoUrlLength > longestRepoUrl {
				longestRepoUrl = repoUrlLength
			}

			sortedRepoUrls = append(sortedRepoUrls, repoUrl)
		}
		sort.Strings(sortedRepoUrls)

		for repoUrl := range sortedRepoUrls {
			printableDependencies.WriteString(fmt.Sprintf("    %s  ", sortedRepoUrls[repoUrl]))
			for i := 0; i < (longestRepoUrl - len(sortedRepoUrls[repoUrl])); i++ {
				printableDependencies.WriteString(" ")
			}
			printableDependencies.WriteString(fmt.Sprintf("%s\n", dependencyMap[sortedRepoUrls[repoUrl]]))
		}

		fmt.Printf("Psiphon Console Client\n  Build Date: %s\n  Built With: %s\n  Repository: %s\n  Revision: %s\n  Dependencies:\n%s\n", b.BuildDate, b.GoVersion, b.BuildRepo, b.BuildRev, printableDependencies.String())
		os.Exit(0)
	}

	// Initialize notice output

	var noticeWriter io.Writer
	noticeWriter = os.Stderr

	if noticeFilename != "" {
		noticeFile, err := os.OpenFile(noticeFilename, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			fmt.Printf("error opening notice file: %s\n", err)
			os.Exit(1)
		}
		defer noticeFile.Close()
		noticeWriter = noticeFile
	}

	if formatNotices {
		noticeWriter = psiphon.NewNoticeConsoleRewriter(noticeWriter)
	}
	psiphon.SetNoticeWriter(noticeWriter)
	err := psiphon.SetNoticeFiles(
		homepageFilename,
		rotatingFilename,
		rotatingFileSize,
		rotatingSyncFrequency)
	if err != nil {
		fmt.Printf("error initializing notice files: %s\n", err)
		os.Exit(1)
	}

	// Handle required config file parameter

	// EmitDiagnosticNotices is set by LoadConfig; force to true
	// an emit diagnostics when LoadConfig-related errors occur.

	if configFilename == "" {
		psiphon.SetEmitDiagnosticNotices(true)
		psiphon.NoticeError("configuration file is required")
		os.Exit(1)
	}
	configFileContents, err := ioutil.ReadFile(configFilename)
	if err != nil {
		psiphon.SetEmitDiagnosticNotices(true)
		psiphon.NoticeError("error loading configuration file: %s", err)
		os.Exit(1)
	}
	config, err := psiphon.LoadConfig(configFileContents)
	if err != nil {
		psiphon.SetEmitDiagnosticNotices(true)
		psiphon.NoticeError("error processing configuration file: %s", err)
		os.Exit(1)
	}

	if interfaceName != "" {
		config.ListenInterface = interfaceName
	}

	// Configure packet tunnel, including updating the config.

	if tun.IsSupported() && tunDevice != "" {
		tunDeviceFile, err := configurePacketTunnel(
			config, tunDevice, tunBindInterface, tunPrimaryDNS, tunSecondaryDNS)
		if err != nil {
			psiphon.SetEmitDiagnosticNotices(true)
			psiphon.NoticeError("error configuring packet tunnel: %s", err)
			os.Exit(1)
		}
		defer tunDeviceFile.Close()
	}

	// All config fields should be set before calling Commit.

	err = config.Commit()
	if err != nil {
		psiphon.SetEmitDiagnosticNotices(true)
		psiphon.NoticeError("error loading configuration file: %s", err)
		os.Exit(1)
	}

	// BuildInfo is a diagnostic notice, so emit only after config.Commit
	// sets EmitDiagnosticNotices.

	psiphon.NoticeBuildInfo()

	// Initialize data store

	err = psiphon.OpenDataStore(config)
	if err != nil {
		psiphon.NoticeError("error initializing datastore: %s", err)
		os.Exit(1)
	}
	defer psiphon.CloseDataStore()

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
			serverEntries, err := protocol.DecodeServerEntryList(
				string(serverEntryList),
				common.GetCurrentTimestamp(),
				protocol.SERVER_ENTRY_SOURCE_EMBEDDED)
			if err != nil {
				psiphon.NoticeError("error decoding embedded server entry list file: %s", err)
				return
			}
			// Since embedded server list entries may become stale, they will not
			// overwrite existing stored entries for the same server.
			err = psiphon.StoreServerEntries(config, serverEntries, false)
			if err != nil {
				psiphon.NoticeError("error storing embedded server entry list data: %s", err)
				return
			}
		}()

		if psiphon.CountServerEntries() == 0 {
			embeddedServerListWaitGroup.Wait()
		} else {
			defer embeddedServerListWaitGroup.Wait()
		}
	}

	// Run Psiphon

	controller, err := psiphon.NewController(config)
	if err != nil {
		psiphon.NoticeError("error creating controller: %s", err)
		os.Exit(1)
	}

	controllerCtx, stopController := context.WithCancel(context.Background())
	defer stopController()

	controllerWaitGroup := new(sync.WaitGroup)
	controllerWaitGroup.Add(1)
	go func() {
		defer controllerWaitGroup.Done()
		controller.Run(controllerCtx)

		// Signal the <-controllerCtx.Done() case below. If the <-systemStopSignal
		// case already called stopController, this is a noop.
		stopController()
	}()

	systemStopSignal := make(chan os.Signal, 1)
	signal.Notify(systemStopSignal, os.Interrupt, os.Kill)

	writeProfilesSignal := make(chan os.Signal, 1)
	signal.Notify(writeProfilesSignal, syscall.SIGUSR2)

	// Wait for an OS signal or a Run stop signal, then stop Psiphon and exit

	for exit := false; !exit; {
		select {
		case <-writeProfilesSignal:
			psiphon.NoticeInfo("write profiles")
			profileSampleDurationSeconds := 5
			common.WriteRuntimeProfiles(
				psiphon.NoticeCommonLogger(),
				config.DataStoreDirectory,
				profileSampleDurationSeconds,
				profileSampleDurationSeconds)
		case <-systemStopSignal:
			psiphon.NoticeInfo("shutdown by system")
			stopController()
			controllerWaitGroup.Wait()
			exit = true
		case <-controllerCtx.Done():
			psiphon.NoticeInfo("shutdown by controller")
			exit = true
		}
	}
}

func configurePacketTunnel(
	config *psiphon.Config,
	tunDevice, tunBindInterface, tunPrimaryDNS, tunSecondaryDNS string) (*os.File, error) {

	file, _, err := tun.OpenTunDevice(tunDevice)
	if err != nil {
		return nil, common.ContextError(err)
	}

	provider := &tunProvider{
		bindInterface: tunBindInterface,
		primaryDNS:    tunPrimaryDNS,
		secondaryDNS:  tunSecondaryDNS,
	}

	config.PacketTunnelTunFileDescriptor = int(file.Fd())
	config.DeviceBinder = provider
	config.DnsServerGetter = provider

	return file, nil
}

type tunProvider struct {
	bindInterface string
	primaryDNS    string
	secondaryDNS  string
}

// BindToDevice implements the psiphon.DeviceBinder interface.
func (p *tunProvider) BindToDevice(fileDescriptor int) (string, error) {
	return p.bindInterface, tun.BindToDevice(fileDescriptor, p.bindInterface)
}

// GetPrimaryDnsServer implements the psiphon.DnsServerGetter interface.
func (p *tunProvider) GetPrimaryDnsServer() string {
	return p.primaryDNS
}

// GetSecondaryDnsServer implements the psiphon.DnsServerGetter interface.
func (p *tunProvider) GetSecondaryDnsServer() string {
	return p.secondaryDNS
}
