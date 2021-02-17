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
	"path/filepath"
	"strings"
	"sync"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/buildinfo"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/tun"
)

type PsiphonProviderNoticeHandler interface {
	Notice(noticeJSON string)
}

type PsiphonProviderNetwork interface {
	HasNetworkConnectivity() int
	GetNetworkID() string
	IPv6Synthesize(IPv4Addr string) string
}

type PsiphonProvider interface {
	PsiphonProviderNoticeHandler
	PsiphonProviderNetwork
	BindToDevice(fileDescriptor int) (string, error)
	GetPrimaryDnsServer() string
	GetSecondaryDnsServer() string
}

type PsiphonProviderFeedbackHandler interface {
	SendFeedbackCompleted(err error)
}

func NoticeUserLog(message string) {
	psiphon.NoticeUserLog(message)
}

// HomepageFilePath returns the path where homepage files will be paved.
//
// rootDataDirectoryPath is the configured data root directory.
//
// Note: homepage files will only be paved if UseNoticeFiles is set in the
// config passed to Start().
func HomepageFilePath(rootDataDirectoryPath string) string {
	return filepath.Join(rootDataDirectoryPath, psiphon.PsiphonDataDirectoryName, psiphon.HomepageFilename)
}

// NoticesFilePath returns the path where the notices file will be paved.
//
// rootDataDirectoryPath is the configured data root directory.
//
// Note: notices will only be paved if UseNoticeFiles is set in the config
// passed to Start().
func NoticesFilePath(rootDataDirectoryPath string) string {
	return filepath.Join(rootDataDirectoryPath, psiphon.PsiphonDataDirectoryName, psiphon.NoticesFilename)
}

// OldNoticesFilePath returns the path where the notices file is moved to when
// file rotation occurs.
//
// rootDataDirectoryPath is the configured data root directory.
//
// Note: notices will only be paved if UseNoticeFiles is set in the config
// passed to Start().
func OldNoticesFilePath(rootDataDirectoryPath string) string {
	return filepath.Join(rootDataDirectoryPath, psiphon.PsiphonDataDirectoryName, psiphon.OldNoticesFilename)
}

// UpgradeDownloadFilePath returns the path where the downloaded upgrade file
// will be paved.
//
// rootDataDirectoryPath is the configured data root directory.
//
// Note: upgrades will only be paved if UpgradeDownloadURLs is set in the config
// passed to Start() and there are upgrades available.
func UpgradeDownloadFilePath(rootDataDirectoryPath string) string {
	return filepath.Join(rootDataDirectoryPath, psiphon.PsiphonDataDirectoryName, psiphon.UpgradeDownloadFilename)
}

var controllerMutex sync.Mutex
var embeddedServerListWaitGroup *sync.WaitGroup
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

	err = config.Commit(true)
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

	controllerCtx, stopController = context.WithCancel(context.Background())

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
	embeddedServerListWaitGroup = new(sync.WaitGroup)
	embeddedServerListWaitGroup.Add(1)
	go func() {
		defer embeddedServerListWaitGroup.Done()

		err := psiphon.ImportEmbeddedServerEntries(
			controllerCtx,
			config,
			embeddedServerEntryListFilename,
			embeddedServerEntryList)
		if err != nil {
			psiphon.NoticeError("error importing embedded server entry list: %s", err)
			return
		}
	}()
	if !psiphon.HasServerEntries() {
		psiphon.NoticeInfo("awaiting embedded server entry list import")
		embeddedServerListWaitGroup.Wait()
	}

	controller, err = psiphon.NewController(config)
	if err != nil {
		stopController()
		embeddedServerListWaitGroup.Wait()
		psiphon.CloseDataStore()
		return fmt.Errorf("error initializing controller: %s", err)
	}

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
		embeddedServerListWaitGroup.Wait()
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

		var authorizations []string
		if len(newAuthorizationsList) > 0 {
			authorizations = strings.Split(newAuthorizationsList, " ")
		}

		controller.SetDynamicConfig(
			newSponsorID,
			authorizations)
	}
}

// ExportExchangePayload creates a payload for client-to-client server
// connection info exchange.
//
// ExportExchangePayload will succeed only when Psiphon is running, between
// Start and Stop.
//
// The return value is a payload that may be exchanged with another client;
// when "", the export failed and a diagnostic has been logged.
func ExportExchangePayload() string {

	controllerMutex.Lock()
	defer controllerMutex.Unlock()

	if controller == nil {
		return ""
	}

	return controller.ExportExchangePayload()
}

// ImportExchangePayload imports a payload generated by ExportExchangePayload.
//
// If an import occurs when Psiphon is working to establsh a tunnel, the newly
// imported server entry is prioritized.
//
// The return value indicates a successful import. If the import failed, a a
// diagnostic notice has been logged.
func ImportExchangePayload(payload string) bool {

	controllerMutex.Lock()
	defer controllerMutex.Unlock()

	if controller == nil {
		return false
	}

	return controller.ImportExchangePayload(payload)
}

var sendFeedbackMutex sync.Mutex
var sendFeedbackCtx context.Context
var stopSendFeedback context.CancelFunc
var sendFeedbackWaitGroup *sync.WaitGroup

// StartSendFeedback encrypts the provided diagnostics and then attempts to
// upload the encrypted diagnostics to one of the feedback upload locations
// supplied by the provided config or tactics.
//
// Returns immediately after starting the operation in a goroutine. The
// operation has completed when SendFeedbackCompleted(error) is called on the
// provided PsiphonProviderFeedbackHandler; if error is non-nil, then the
// operation failed.
//
// Only one active upload is supported at a time. An ongoing upload will be
// cancelled if this function is called again before it completes.
//
// Warnings:
// - Should not be used with Start concurrently in the same process
// - An ongoing feedback upload started with StartSendFeedback should be
//   stopped with StopSendFeedback before the process exists. This ensures that
//   any underlying resources are cleaned up; failing to do so may result in
//   data store corruption or other undefined behavior.
// - Start and StartSendFeedback both make an attempt to migrate persistent
//   files from legacy locations in a one-time operation. If these functions
//   are called in parallel, then there is a chance that the migration attempts
//   could execute at the same time and result in non-fatal errors in one, or
//   both, of the migration operations.
// - Calling StartSendFeedback or StopSendFeedback on the same call stack
//   that the PsiphonProviderFeedbackHandler.SendFeedbackCompleted() callback
//   is delivered on can cause a deadlock. I.E. the callback code must return
//   so the wait group can complete and the lock acquired in StopSendFeedback
//   can be released.
func StartSendFeedback(
	configJson,
	diagnosticsJson,
	uploadPath string,
	feedbackHandler PsiphonProviderFeedbackHandler,
	networkInfoProvider PsiphonProviderNetwork,
	noticeHandler PsiphonProviderNoticeHandler,
	useIPv6Synthesizer bool) error {

	// Cancel any ongoing uploads.
	StopSendFeedback()

	sendFeedbackMutex.Lock()
	defer sendFeedbackMutex.Unlock()

	sendFeedbackCtx, stopSendFeedback = context.WithCancel(context.Background())

	// Unlike in Start, the provider is not wrapped in a newMutexPsiphonProvider
	// or equivilent, as SendFeedback is not expected to be used in a memory
	// constrained environment.

	psiphon.SetNoticeWriter(psiphon.NewNoticeReceiver(
		func(notice []byte) {
			noticeHandler.Notice(string(notice))
		}))

	config, err := psiphon.LoadConfig([]byte(configJson))
	if err != nil {
		return fmt.Errorf("error loading configuration file: %s", err)
	}

	config.NetworkConnectivityChecker = networkInfoProvider

	config.NetworkIDGetter = networkInfoProvider

	if useIPv6Synthesizer {
		config.IPv6Synthesizer = networkInfoProvider
	}

	// All config fields should be set before calling Commit.

	err = config.Commit(true)
	if err != nil {
		return fmt.Errorf("error committing configuration file: %s", err)
	}

	sendFeedbackWaitGroup = new(sync.WaitGroup)
	sendFeedbackWaitGroup.Add(1)
	go func() {
		defer sendFeedbackWaitGroup.Done()
		err := psiphon.SendFeedback(sendFeedbackCtx, config,
			diagnosticsJson, uploadPath)
		feedbackHandler.SendFeedbackCompleted(err)
	}()

	return nil
}

// StopSendFeedback interrupts an in-progress feedback upload operation
// started with `StartSendFeedback`.
//
// Warning: should not be used with Start concurrently in the same process.
func StopSendFeedback() {

	sendFeedbackMutex.Lock()
	defer sendFeedbackMutex.Unlock()

	if stopSendFeedback != nil {
		stopSendFeedback()
		sendFeedbackWaitGroup.Wait()
		sendFeedbackCtx = nil
		stopSendFeedback = nil
		sendFeedbackWaitGroup = nil
		// Allow the notice receiver to be deallocated.
		psiphon.SetNoticeWriter(os.Stderr)
	}
}

// Get build info from tunnel-core
func GetBuildInfo() string {
	buildInfo, err := json.Marshal(buildinfo.GetBuildInfo())
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
		"",
		cpuSampleDurationSeconds,
		blockSampleDurationSeconds)
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
