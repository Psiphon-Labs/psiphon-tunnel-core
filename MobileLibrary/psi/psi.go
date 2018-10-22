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

package psi

// This package is a shim between Java/Obj-C and the "psiphon" package. Due to limitations
// on what Go types may be exposed (http://godoc.org/golang.org/x/mobile/cmd/gobind),
// a psiphon.Controller cannot be directly used by Java. This shim exposes a trivial
// Start/Stop interface on top of a single Controller instance.

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/tun"
)

type PsiphonProvider interface {
	Notice(noticeJSON string)
	HasNetworkConnectivity() int
	BindToDevice(fileDescriptor int) (string, error)
	IPv6Synthesize(IPv4Addr string) string
	GetPrimaryDnsServer() string
	GetSecondaryDnsServer() string
	GetNetworkID() string
}

func SetNoticeFiles(
	homepageFilename,
	rotatingFilename string,
	rotatingFileSize,
	rotatingSyncFrequency int) error {

	return psiphon.SetNoticeFiles(
		homepageFilename,
		rotatingFilename,
		rotatingFileSize,
		rotatingSyncFrequency)
}

func NoticeUserLog(message string) {
	psiphon.NoticeUserLog(message)
}

var controllerMutex sync.Mutex
var controller *psiphon.Controller
var controllerCtx context.Context
var stopController context.CancelFunc
var controllerWaitGroup *sync.WaitGroup

func Start(
	configJson,
	embeddedServerEntryList,
	embeddedServerEntryListFilename string,
	provider PsiphonProvider,
	useDeviceBinder,
	useIPv6Synthesizer bool) error {

	controllerMutex.Lock()
	defer controllerMutex.Unlock()

	if controller != nil {
		return fmt.Errorf("already started")
	}

	// Clients may toggle Stop/Start immediately to apply new config settings
	// such as EgressRegion or Authorizations. When this restart is within the
	// same process and in a memory contrained environment, it is useful to
	// force garbage collection here to reclaim memory used by the previous
	// Controller.
	psiphon.DoGarbageCollection()

	// Wrap the provider in a layer that locks a mutex before calling a provider function.
	// As the provider callbacks are Java/Obj-C via gomobile, they are cgo calls that
	// can cause OS threads to be spawned. The mutex prevents many calling goroutines from
	// causing unbounded numbers of OS threads to be spawned.
	// TODO: replace the mutex with a semaphore, to allow a larger but still bounded concurrent
	// number of calls to the provider?
	provider = newMutexPsiphonProvider(provider)

	config, err := psiphon.LoadConfig([]byte(configJson))
	if err != nil {
		return fmt.Errorf("error loading configuration file: %s", err)
	}

	config.NetworkConnectivityChecker = provider

	config.NetworkIDGetter = provider

	if useDeviceBinder {
		config.DeviceBinder = provider
		config.DnsServerGetter = provider
	}

	if useIPv6Synthesizer {
		config.IPv6Synthesizer = provider
	}

	// All config fields should be set before calling Commit.

	err = config.Commit()
	if err != nil {
		return fmt.Errorf("error committing configuration file: %s", err)
	}

	psiphon.SetNoticeWriter(psiphon.NewNoticeReceiver(
		func(notice []byte) {
			provider.Notice(string(notice))
		}))

	// BuildInfo is a diagnostic notice, so emit only after config.Commit
	// sets EmitDiagnosticNotices.

	psiphon.NoticeBuildInfo()

	err = psiphon.OpenDataStore(config)
	if err != nil {
		return fmt.Errorf("error initializing datastore: %s", err)
	}

	// Stores list of server entries.
	err = storeServerEntries(
		config,
		embeddedServerEntryListFilename,
		embeddedServerEntryList)
	if err != nil {
		return err
	}

	controller, err = psiphon.NewController(config)
	if err != nil {
		return fmt.Errorf("error initializing controller: %s", err)
	}

	controllerCtx, stopController = context.WithCancel(context.Background())

	controllerWaitGroup = new(sync.WaitGroup)
	controllerWaitGroup.Add(1)
	go func() {
		defer controllerWaitGroup.Done()
		controller.Run(controllerCtx)
	}()

	return nil
}

func Stop() {

	controllerMutex.Lock()
	defer controllerMutex.Unlock()

	if controller != nil {
		stopController()
		controllerWaitGroup.Wait()
		psiphon.CloseDataStore()
		controller = nil
		controllerCtx = nil
		stopController = nil
		controllerWaitGroup = nil
	}
}

// ReconnectTunnel initiates a reconnect of the current tunnel, if one is
// running.
func ReconnectTunnel() {

	controllerMutex.Lock()
	defer controllerMutex.Unlock()

	if controller != nil {
		controller.TerminateNextActiveTunnel()
	}
}

// SetDynamicConfig overrides the sponsor ID and authorizations fields set in
// the config passed to Start. SetDynamicConfig has no effect if no Controller
// is started.
//
// The input newAuthorizationsList is a space-delimited list of base64
// authorizations. This is a workaround for gobind type limitations.
func SetDynamicConfig(newSponsorID, newAuthorizationsList string) {

	controllerMutex.Lock()
	defer controllerMutex.Unlock()

	if controller != nil {
		controller.SetDynamicConfig(
			newSponsorID,
			strings.Split(newAuthorizationsList, " "))
	}
}

// Encrypt and upload feedback.
func SendFeedback(configJson, diagnosticsJson, b64EncodedPublicKey, uploadServer, uploadPath, uploadServerHeaders string) error {
	return psiphon.SendFeedback(configJson, diagnosticsJson, b64EncodedPublicKey, uploadServer, uploadPath, uploadServerHeaders)
}

// Get build info from tunnel-core
func GetBuildInfo() string {
	buildInfo, err := json.Marshal(common.GetBuildInfo())
	if err != nil {
		return ""
	}
	return string(buildInfo)
}

func GetPacketTunnelMTU() int {
	return tun.DEFAULT_MTU
}

func GetPacketTunnelDNSResolverIPv4Address() string {
	return tun.GetTransparentDNSResolverIPv4Address().String()
}

func GetPacketTunnelDNSResolverIPv6Address() string {
	return tun.GetTransparentDNSResolverIPv6Address().String()
}

// WriteRuntimeProfiles writes Go runtime profile information to a set of
// files in the specified output directory. See common.WriteRuntimeProfiles
// for more details.
//
// If called before Start, log notices will emit to stderr.
func WriteRuntimeProfiles(outputDirectory string, cpuSampleDurationSeconds, blockSampleDurationSeconds int) {
	common.WriteRuntimeProfiles(
		psiphon.NoticeCommonLogger(),
		outputDirectory,
		cpuSampleDurationSeconds,
		blockSampleDurationSeconds)
}

// Helper function to store a list of server entries.
// if embeddedServerEntryListFilename is not empty, embeddedServerEntryList will be ignored.
func storeServerEntries(
	config *psiphon.Config,
	embeddedServerEntryListFilename, embeddedServerEntryList string) error {

	if embeddedServerEntryListFilename != "" {

		file, err := os.Open(embeddedServerEntryListFilename)
		if err != nil {
			return fmt.Errorf("error reading embedded server list file: %s", common.ContextError(err))
		}
		defer file.Close()

		err = psiphon.StreamingStoreServerEntries(
			config,
			protocol.NewStreamingServerEntryDecoder(
				file,
				common.GetCurrentTimestamp(),
				protocol.SERVER_ENTRY_SOURCE_EMBEDDED),
			false)
		if err != nil {
			return fmt.Errorf("error storing embedded server list: %s", common.ContextError(err))
		}

	} else {

		serverEntries, err := protocol.DecodeServerEntryList(
			embeddedServerEntryList,
			common.GetCurrentTimestamp(),
			protocol.SERVER_ENTRY_SOURCE_EMBEDDED)
		if err != nil {
			return fmt.Errorf("error decoding embedded server list: %s", err)
		}
		err = psiphon.StoreServerEntries(config, serverEntries, false)
		if err != nil {
			return fmt.Errorf("error storing embedded server list: %s", err)
		}
	}

	return nil
}

type mutexPsiphonProvider struct {
	sync.Mutex
	p PsiphonProvider
}

func newMutexPsiphonProvider(p PsiphonProvider) *mutexPsiphonProvider {
	return &mutexPsiphonProvider{p: p}
}

func (p *mutexPsiphonProvider) Notice(noticeJSON string) {
	p.Lock()
	defer p.Unlock()
	p.p.Notice(noticeJSON)
}

func (p *mutexPsiphonProvider) HasNetworkConnectivity() int {
	p.Lock()
	defer p.Unlock()
	return p.p.HasNetworkConnectivity()
}

func (p *mutexPsiphonProvider) BindToDevice(fileDescriptor int) (string, error) {
	p.Lock()
	defer p.Unlock()
	return p.p.BindToDevice(fileDescriptor)
}

func (p *mutexPsiphonProvider) IPv6Synthesize(IPv4Addr string) string {
	p.Lock()
	defer p.Unlock()
	return p.p.IPv6Synthesize(IPv4Addr)
}

func (p *mutexPsiphonProvider) GetPrimaryDnsServer() string {
	p.Lock()
	defer p.Unlock()
	return p.p.GetPrimaryDnsServer()
}

func (p *mutexPsiphonProvider) GetSecondaryDnsServer() string {
	p.Lock()
	defer p.Unlock()
	return p.p.GetSecondaryDnsServer()
}

func (p *mutexPsiphonProvider) GetNetworkID() string {
	p.Lock()
	defer p.Unlock()
	return p.p.GetNetworkID()
}
