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
	"context"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/buildinfo"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/tun"
)

func main() {

	// Define command-line parameters

	var configFilename string
	flag.StringVar(&configFilename, "config", "", "configuration input file")

	var dataRootDirectory string
	flag.StringVar(&dataRootDirectory, "dataRootDirectory", "", "directory where persistent files will be stored")

	var embeddedServerEntryListFilename string
	flag.StringVar(&embeddedServerEntryListFilename, "serverList", "", "embedded server entry list input file")

	var formatNotices bool
	flag.BoolVar(&formatNotices, "formatNotices", false, "emit notices in human-readable format")

	var interfaceName string
	flag.StringVar(&interfaceName, "listenInterface", "", "bind local proxies to specified interface")

	var versionDetails bool
	flag.BoolVar(&versionDetails, "version", false, "print build information and exit")
	flag.BoolVar(&versionDetails, "v", false, "print build information and exit")

	var feedbackUpload bool
	flag.BoolVar(&feedbackUpload, "feedbackUpload", false,
		"Run in feedback upload mode to send a feedback package to Psiphon Inc.\n"+
			"The feedback package will be read as a UTF-8 encoded string from stdin.\n"+
			"Informational notices will be written to stdout. If the upload succeeds,\n"+
			"the process will exit with status code 0; otherwise, the process will\n"+
			"exit with status code 1. A feedback compatible config must be specified\n"+
			"with the \"-config\" flag. Config must be provided by Psiphon Inc.")

	var feedbackUploadPath string
	flag.StringVar(&feedbackUploadPath, "feedbackUploadPath", "",
		"The path at which to upload the feedback package when the \"-feedbackUpload\"\n"+
			"flag is provided. Must be provided by Psiphon Inc.")

	var tunDevice, tunBindInterface, tunDNSServers string
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
		flag.StringVar(&tunDNSServers, "tunDNSServers", "8.8.8.8,8.8.4.4", "Comma-delimited list of tun bypass DNS server IP addresses")
	}

	var noticeFilename string
	flag.StringVar(&noticeFilename, "notices", "", "notices output file (defaults to stderr)")

	var useNoticeFiles bool
	useNoticeFilesUsage := fmt.Sprintf("output homepage notices and rotating notices to <dataRootDirectory>/%s and <dataRootDirectory>/%s respectively", psiphon.HomepageFilename, psiphon.NoticesFilename)
	flag.BoolVar(&useNoticeFiles, "useNoticeFiles", false, useNoticeFilesUsage)

	var rotatingFileSize int
	flag.IntVar(&rotatingFileSize, "rotatingFileSize", 1<<20, "rotating notices file size")

	var rotatingSyncFrequency int
	flag.IntVar(&rotatingSyncFrequency, "rotatingSyncFrequency", 100, "rotating notices file sync frequency")

	flag.Parse()

	if versionDetails {
		b := buildinfo.GetBuildInfo()
		fmt.Printf(
			"Psiphon Console Client\n  Build Date: %s\n  Built With: %s\n  Repository: %s\n  Revision: %s\n",
			b.BuildDate, b.GoVersion, b.BuildRepo, b.BuildRev)
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
	err := psiphon.SetNoticeWriter(noticeWriter)
	if err != nil {
		fmt.Printf("error setting notice writer: %s\n", err)
		os.Exit(1)
	}
	defer psiphon.ResetNoticeWriter()

	// Handle required config file parameter

	// EmitDiagnosticNotices is set by LoadConfig; force to true
	// and emit diagnostics when LoadConfig-related errors occur.

	if configFilename == "" {
		psiphon.SetEmitDiagnosticNotices(true, false)
		psiphon.NoticeError("configuration file is required")
		os.Exit(1)
	}
	configFileContents, err := ioutil.ReadFile(configFilename)
	if err != nil {
		psiphon.SetEmitDiagnosticNotices(true, false)
		psiphon.NoticeError("error loading configuration file: %s", err)
		os.Exit(1)
	}
	config, err := psiphon.LoadConfig(configFileContents)
	if err != nil {
		psiphon.SetEmitDiagnosticNotices(true, false)
		psiphon.NoticeError("error processing configuration file: %s", err)
		os.Exit(1)
	}

	// Set data root directory
	if dataRootDirectory != "" {
		config.DataRootDirectory = dataRootDirectory
	}

	if interfaceName != "" {
		config.ListenInterface = interfaceName
	}

	// Configure notice files

	if useNoticeFiles {
		config.UseNoticeFiles = &psiphon.UseNoticeFiles{
			RotatingFileSize:      rotatingFileSize,
			RotatingSyncFrequency: rotatingSyncFrequency,
		}
	}

	// Configure packet tunnel, including updating the config.

	if tun.IsSupported() && tunDevice != "" {
		tunDeviceFile, err := configurePacketTunnel(
			config, tunDevice, tunBindInterface, strings.Split(tunDNSServers, ","))
		if err != nil {
			psiphon.SetEmitDiagnosticNotices(true, false)
			psiphon.NoticeError("error configuring packet tunnel: %s", err)
			os.Exit(1)
		}
		defer tunDeviceFile.Close()
	}

	// All config fields should be set before calling Commit.

	err = config.Commit(true)
	if err != nil {
		psiphon.SetEmitDiagnosticNotices(true, false)
		psiphon.NoticeError("error loading configuration file: %s", err)
		os.Exit(1)
	}

	// BuildInfo is a diagnostic notice, so emit only after config.Commit
	// sets EmitDiagnosticNotices.

	psiphon.NoticeBuildInfo()

	var worker Worker

	if feedbackUpload {
		// Feedback upload mode
		worker = &FeedbackWorker{
			feedbackUploadPath: feedbackUploadPath,
		}
	} else {
		// Tunnel mode
		worker = &TunnelWorker{
			embeddedServerEntryListFilename: embeddedServerEntryListFilename,
		}
	}

	workCtx, stopWork := context.WithCancel(context.Background())
	defer stopWork()

	err = worker.Init(workCtx, config)
	if err != nil {
		psiphon.NoticeError("error in init: %s", err)
		os.Exit(1)
	}

	workWaitGroup := new(sync.WaitGroup)
	workWaitGroup.Add(1)
	go func() {
		defer workWaitGroup.Done()

		err := worker.Run(workCtx)
		if err != nil {
			psiphon.NoticeError("%s", err)
			stopWork()
			os.Exit(1)
		}

		// Signal the <-controllerCtx.Done() case below. If the <-systemStopSignal
		// case already called stopController, this is a noop.
		stopWork()
	}()

	systemStopSignal := make(chan os.Signal, 1)
	signal.Notify(systemStopSignal, os.Interrupt, syscall.SIGTERM)

	// writeProfilesSignal is nil and non-functional on Windows
	writeProfilesSignal := makeSIGUSR2Channel()

	// Wait for an OS signal or a Run stop signal, then stop Psiphon and exit

	for exit := false; !exit; {
		select {
		case <-writeProfilesSignal:
			psiphon.NoticeInfo("write profiles")
			profileSampleDurationSeconds := 5
			common.WriteRuntimeProfiles(
				psiphon.NoticeCommonLogger(false),
				config.DataRootDirectory,
				"",
				profileSampleDurationSeconds,
				profileSampleDurationSeconds)
		case <-systemStopSignal:
			psiphon.NoticeInfo("shutdown by system")
			stopWork()
			workWaitGroup.Wait()
			exit = true
		case <-workCtx.Done():
			psiphon.NoticeInfo("shutdown by controller")
			exit = true
		}
	}
}

func configurePacketTunnel(
	config *psiphon.Config,
	tunDevice string,
	tunBindInterface string,
	tunDNSServers []string) (*os.File, error) {

	file, _, err := tun.OpenTunDevice(tunDevice)
	if err != nil {
		return nil, errors.Trace(err)
	}

	provider := &tunProvider{
		bindInterface: tunBindInterface,
		dnsServers:    tunDNSServers,
	}

	config.PacketTunnelTunFileDescriptor = int(file.Fd())
	config.DeviceBinder = provider
	config.DNSServerGetter = provider

	return file, nil
}

type tunProvider struct {
	bindInterface string
	dnsServers    []string
}

// BindToDevice implements the psiphon.DeviceBinder interface.
func (p *tunProvider) BindToDevice(fileDescriptor int) (string, error) {
	return p.bindInterface, tun.BindToDevice(fileDescriptor, p.bindInterface)
}

// GetDNSServers implements the psiphon.DNSServerGetter interface.
func (p *tunProvider) GetDNSServers() []string {
	return p.dnsServers
}

// Worker creates a protocol around the different run modes provided by the
// compiled executable.
type Worker interface {
	// Init is called once for the worker to perform any initialization.
	Init(ctx context.Context, config *psiphon.Config) error
	// Run is called once, after Init(..), for the worker to perform its
	// work. The provided context should control the lifetime of the work
	// being performed.
	Run(ctx context.Context) error
}

// TunnelWorker is the Worker protocol implementation used for tunnel mode.
type TunnelWorker struct {
	embeddedServerEntryListFilename string
	embeddedServerListWaitGroup     *sync.WaitGroup
	controller                      *psiphon.Controller
}

// Init implements the Worker interface.
func (w *TunnelWorker) Init(ctx context.Context, config *psiphon.Config) error {

	// Initialize data store

	err := psiphon.OpenDataStore(config)
	if err != nil {
		psiphon.NoticeError("error initializing datastore: %s", err)
		os.Exit(1)
	}

	// If specified, the embedded server list is loaded and stored. When there
	// are no server candidates at all, we wait for this import to complete
	// before starting the Psiphon controller. Otherwise, we import while
	// concurrently starting the controller to minimize delay before attempting
	// to connect to existing candidate servers.
	//
	// If the import fails, an error notice is emitted, but the controller is
	// still started: either existing candidate servers may suffice, or the
	// remote server list fetch may obtain candidate servers.
	//
	// The import will be interrupted if it's still running when the controller
	// is stopped.
	if w.embeddedServerEntryListFilename != "" {
		w.embeddedServerListWaitGroup = new(sync.WaitGroup)
		w.embeddedServerListWaitGroup.Add(1)
		go func() {
			defer w.embeddedServerListWaitGroup.Done()

			err := psiphon.ImportEmbeddedServerEntries(
				ctx,
				config,
				w.embeddedServerEntryListFilename,
				"")

			if err != nil {
				psiphon.NoticeError("error importing embedded server entry list: %s", err)
				return
			}
		}()

		if !psiphon.HasServerEntries() {
			psiphon.NoticeInfo("awaiting embedded server entry list import")
			w.embeddedServerListWaitGroup.Wait()
		}
	}

	controller, err := psiphon.NewController(config)
	if err != nil {
		psiphon.NoticeError("error creating controller: %s", err)
		return errors.Trace(err)
	}
	w.controller = controller

	return nil
}

// Run implements the Worker interface.
func (w *TunnelWorker) Run(ctx context.Context) error {
	defer psiphon.CloseDataStore()
	if w.embeddedServerListWaitGroup != nil {
		defer w.embeddedServerListWaitGroup.Wait()
	}

	w.controller.Run(ctx)
	return nil
}

// FeedbackWorker is the Worker protocol implementation used for feedback
// upload mode.
type FeedbackWorker struct {
	config             *psiphon.Config
	feedbackUploadPath string
}

// Init implements the Worker interface.
func (f *FeedbackWorker) Init(ctx context.Context, config *psiphon.Config) error {

	// The datastore is not opened here, with psiphon.OpenDatastore,
	// because it is opened/closed transiently in the psiphon.SendFeedback
	// operation. We do not want to contest database access incase another
	// process needs to use the database. E.g. a process running in tunnel
	// mode, which will fail if it cannot aquire a lock on the database
	// within a short period of time.

	f.config = config

	return nil
}

// Run implements the Worker interface.
func (f *FeedbackWorker) Run(ctx context.Context) error {

	// TODO: cancel blocking read when worker context cancelled?
	diagnostics, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		return errors.TraceMsg(err, "FeedbackUpload: read stdin failed")
	}

	if len(diagnostics) == 0 {
		return errors.TraceNew("FeedbackUpload: error zero bytes of diagnostics read from stdin")
	}

	err = psiphon.SendFeedback(ctx, f.config, string(diagnostics), f.feedbackUploadPath)
	if err != nil {
		return errors.TraceMsg(err, "FeedbackUpload: upload failed")
	}

	psiphon.NoticeInfo("FeedbackUpload: upload succeeded")

	return nil
}
