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
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/buildinfo"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/tun"
)

type PsiphonProviderNoticeHandler interface {
	Notice(noticeJSON string)
}

type PsiphonProviderNetwork interface {
	HasNetworkConnectivity() int
	GetNetworkID() string
	IPv6Synthesize(IPv4Addr string) string
	HasIPv6Route() int
}

type PsiphonProvider interface {
	PsiphonProviderNoticeHandler
	PsiphonProviderNetwork
	BindToDevice(fileDescriptor int) (string, error)
	OnAccessToken(token string)

	// TODO: move GetDNSServersAsString to PsiphonProviderNetwork to
	// facilitate custom tunnel-core resolver support in SendFeedback.

	// GetDNSServersAsString must return a comma-delimited list of DNS server
	// addresses. A single string return value is used since gobind does not
	// support string slice types.
	GetDNSServersAsString() string
}

type PsiphonProviderFeedbackHandler interface {
	SendFeedbackCompleted(err error)
}

// controllerLifecycleMutex serializes Start and Stop and is held across the
// full start or stop. It also guards controllerCtx, stopController,
// controllerWaitGroup, and embeddedServerListWaitGroup.
//
// controllerAccessMutex guards the controller pointer for all other API
// functions, which must not block on Start or Stop. It is write-locked only
// to publish or clear the pointer, never across full start or stop.
// In-flight API calls hold the read lock and complete before Stop clears the
// pointer, so no API call runs against a stopping or stopped controller.
//
// dropPacketTunnelTrafficMutex serializes updates to the latched
// dropPacketTunnelTraffic value with application to the controller, so that
// concurrent toggles cannot apply out of order.
//
// Lock order: controllerLifecycleMutex, then dropPacketTunnelTrafficMutex,
// then controllerAccessMutex. Only Start and Stop take the lifecycle mutex.
// An API function holding the read lock must not call Start or Stop.

var controllerLifecycleMutex sync.Mutex
var controllerAccessMutex sync.RWMutex
var embeddedServerListWaitGroup *sync.WaitGroup
var controller *psiphon.Controller
var controllerCtx context.Context
var stopController context.CancelFunc
var controllerWaitGroup *sync.WaitGroup

var dropPacketTunnelTrafficMutex sync.Mutex
var dropPacketTunnelTraffic bool

// Start starts the singleton controller. Start does not block other API
// functions. API calls made before Start publishes the controller are
// no-ops.
func Start(
	configJson string,
	embeddedServerEntryList string,
	embeddedServerEntryListFilename string,
	provider PsiphonProvider,
	useDeviceBinder bool,
	useIPv6Synthesizer bool,
	useHasIPv6RouteGetter bool) error {

	controllerLifecycleMutex.Lock()
	defer controllerLifecycleMutex.Unlock()

	if controller != nil {
		return errors.TraceNew("already started")
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
	wrappedProvider := newMutexPsiphonProvider(provider)

	config, err := psiphon.LoadConfig([]byte(configJson))
	if err != nil {
		return errors.Trace(err)
	}

	// Set up callbacks.

	config.NetworkConnectivityChecker = wrappedProvider
	config.NetworkIDGetter = wrappedProvider
	config.DNSServerGetter = wrappedProvider
	config.OnAccessToken = wrappedProvider.OnAccessToken

	if useDeviceBinder {
		config.DeviceBinder = wrappedProvider
	}

	if useIPv6Synthesizer {
		config.IPv6Synthesizer = wrappedProvider
	}

	if useHasIPv6RouteGetter {
		config.HasIPv6RouteGetter = wrappedProvider
	}

	// All config fields should be set before calling Commit.

	err = config.Commit(true)
	if err != nil {
		return errors.Trace(err)
	}

	err = psiphon.SetNoticeWriter(psiphon.NewNoticeReceiver(
		func(notice []byte) {
			wrappedProvider.Notice(string(notice))
		}))
	if err != nil {
		return errors.Trace(err)
	}

	// BuildInfo is a diagnostic notice, so emit only after config.Commit
	// sets EmitDiagnosticNotices.

	psiphon.NoticeBuildInfo()

	err = psiphon.OpenDataStore(config)
	if err != nil {
		psiphon.ResetNoticeWriter()
		return errors.Trace(err)
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

	runController, err := psiphon.NewController(config)
	if err != nil {
		stopController()
		embeddedServerListWaitGroup.Wait()
		psiphon.CloseDataStore()
		psiphon.ResetNoticeWriter()
		return errors.Trace(err)
	}

	controllerWaitGroup = new(sync.WaitGroup)

	// The new controller pointer is made available before Run starts. This
	// ensures that GetDSLAccessToken won't fail with no controller pointer
	// when called in response to an early NoticeDSLAccessTokenAvailable.
	//
	// As a consequence of this ordering, all API functions must be safe to
	// call after NewController and before Run.

	dropPacketTunnelTrafficMutex.Lock()
	controllerAccessMutex.Lock()
	runController.DropPacketTunnelTraffic(dropPacketTunnelTraffic)
	controller = runController
	controllerAccessMutex.Unlock()
	dropPacketTunnelTrafficMutex.Unlock()

	controllerWaitGroup.Add(1)
	go func() {
		defer controllerWaitGroup.Done()
		runController.Run(controllerCtx)
	}()

	return nil
}

// Stop stops the singleton controller. Stop does not block other API
// functions; calls made after Stop clears the controller are no-ops.
func Stop() {

	controllerLifecycleMutex.Lock()
	defer controllerLifecycleMutex.Unlock()

	if controller != nil {

		// Clear the pointer before shutting down. This waits only for
		// in-flight API calls to release the read lock.
		controllerAccessMutex.Lock()
		controller = nil
		controllerAccessMutex.Unlock()

		stopController()
		controllerWaitGroup.Wait()
		embeddedServerListWaitGroup.Wait()
		psiphon.CloseDataStore()
		controllerCtx = nil
		stopController = nil
		controllerWaitGroup = nil
		// Allow the provider to be garbage collected.
		psiphon.ResetNoticeWriter()
	}
}

// ReconnectTunnel initiates a reconnect of the current tunnel, if one is
// running.
func ReconnectTunnel() {

	controllerAccessMutex.RLock()
	defer controllerAccessMutex.RUnlock()

	if controller != nil {
		controller.TerminateNextActiveTunnel()
	}
}

// NetworkChanged initiates a reset of all open network connections, including
// a tunnel reconnect.
func NetworkChanged() {

	controllerAccessMutex.RLock()
	defer controllerAccessMutex.RUnlock()

	if controller != nil {
		controller.NetworkChanged()
	}
}

// DropPacketTunnelTraffic toggles packet tunnel mode traffic dropping.
//
// The value is latched, so DropPacketTunnelTraffic may be called before Start,
// in which case it is applied to the Controller once it is started. The latched
// value persists across Stop/Start cycles until changed.
//
// If PacketTunnelTunFileDescriptor is not set, this has no effect.
func DropPacketTunnelTraffic(drop bool) {

	dropPacketTunnelTrafficMutex.Lock()
	defer dropPacketTunnelTrafficMutex.Unlock()

	dropPacketTunnelTraffic = drop

	controllerAccessMutex.RLock()
	defer controllerAccessMutex.RUnlock()

	if controller != nil {
		controller.DropPacketTunnelTraffic(drop)
	}
}

// AppResumed notifies Psiphon that the host app has resumed from background.
func AppResumed() {

	controllerAccessMutex.RLock()
	defer controllerAccessMutex.RUnlock()

	if controller != nil {
		controller.AppResumed()
	}
}

// SetDynamicConfig overrides the sponsor ID and authorizations fields set in
// the config passed to Start. SetDynamicConfig has no effect if no Controller
// is started.
//
// The input newAuthorizationsList is a space-delimited list of base64
// authorizations. This is a workaround for gobind type limitations.
func SetDynamicConfig(newSponsorID, newAuthorizationsList string) {

	controllerAccessMutex.RLock()
	defer controllerAccessMutex.RUnlock()

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

	controllerAccessMutex.RLock()
	defer controllerAccessMutex.RUnlock()

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
// The return value indicates a successful import. If the import failed, a
// diagnostic notice has been logged.
func ImportExchangePayload(payload string) bool {

	controllerAccessMutex.RLock()
	defer controllerAccessMutex.RUnlock()

	if controller == nil {
		return false
	}

	return controller.ImportExchangePayload(payload)
}

// ImportPushPayload imports a server entry push payload.
//
// If an import occurs when Psiphon is working to establsh a tunnel, the
// imported server entries are prioritized as indicated in the payload.
//
// Returns true if the import succeeded and false on any error. Error
// details are logged to diagnostics. If an import is partially
// successful, the imported server entries are retained and prioritized.
func ImportPushPayload(payload []byte) bool {

	controllerAccessMutex.RLock()
	defer controllerAccessMutex.RUnlock()

	if controller == nil {
		return false
	}

	return controller.ImportPushPayload(payload)
}

// GetDSLAccessToken returns the persisted opaque DSL access token as unpadded
// Base64URL text. An empty string is returned when Psiphon is not running or
// no token has been registered, or when retrieval fails. A
// DSLAccessTokenAvailable notice indicates that a token is available.
// PsiphonProvider.OnAccessToken also delivers the token directly.
func GetDSLAccessToken() string {
	controllerAccessMutex.RLock()
	defer controllerAccessMutex.RUnlock()

	if controller == nil {
		return ""
	}

	return controller.GetDSLAccessToken()
}

// RecordClientEvent records a client event attributed to the current tunnel
// or light proxy.
func RecordClientEvent(event string) {

	controllerAccessMutex.RLock()
	defer controllerAccessMutex.RUnlock()

	if controller != nil {
		controller.RecordClientEvent(event)
	}
}

var sendFeedbackMutex sync.Mutex
var sendFeedbackCtx context.Context
var stopSendFeedback context.CancelFunc
var sendFeedbackWaitGroup *sync.WaitGroup
var sendFeedbackResetNoticeWriter bool

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
// If StartSendFeedback is called concurrent with Start:
//
//   - noticeHandler MUST be nil, otherwise Start's notice handler and
//     callbacks can be hijacked.
//
//   - configJson EmitDiagnosticNotices and UseNoticeFiles settings SHOULD be
//     the same as those passed to Start, or else Start's notice logging
//     configuration can change.
//
// Additional warnings:
//
//   - An ongoing feedback upload started with StartSendFeedback should be
//     stopped with StopSendFeedback before the process exits. This ensures that
//     any underlying resources are cleaned up; failing to do so may result in
//     data store corruption or other undefined behavior.
//
//   - Start and StartSendFeedback both make an attempt to migrate persistent
//     files from legacy locations in a one-time operation. If these functions
//     are called in parallel, then there is a chance that the migration attempts
//     could execute at the same time and result in non-fatal errors in one, or
//     both, of the migration operations.
//
//   - Calling StartSendFeedback or StopSendFeedback on the same call stack
//     that the PsiphonProviderFeedbackHandler.SendFeedbackCompleted() callback
//     is delivered on can cause a deadlock. I.E. the callback code must return
//     so the wait group can complete and the lock acquired in StopSendFeedback
//     can be released.
func StartSendFeedback(
	configJson,
	diagnosticsJson,
	uploadPath string,
	feedbackHandler PsiphonProviderFeedbackHandler,
	networkInfoProvider PsiphonProviderNetwork,
	noticeHandler PsiphonProviderNoticeHandler,
	useIPv6Synthesizer bool,
	useHasIPv6RouteGetter bool) error {

	// Cancel any ongoing uploads.
	StopSendFeedback()

	sendFeedbackMutex.Lock()
	defer sendFeedbackMutex.Unlock()

	if stopSendFeedback != nil {
		// Another goroutine invoked StartSendFeedback before the mutex lock
		// was acquired.
		return errors.TraceNew("already started")
	}

	config, err := psiphon.LoadConfig([]byte(configJson))
	if err != nil {
		return errors.Trace(err)
	}

	// Unlike in Start, the provider is not wrapped in a newMutexPsiphonProvider
	// or equivalent, as SendFeedback is not expected to be used in a memory
	// constrained environment.

	// Set up callbacks.

	config.NetworkConnectivityChecker = networkInfoProvider
	config.NetworkIDGetter = networkInfoProvider

	if useIPv6Synthesizer {
		config.IPv6Synthesizer = networkInfoProvider
	}

	if useHasIPv6RouteGetter {
		config.HasIPv6RouteGetter = networkInfoProvider
	}

	// Limitation: config.DNSServerGetter is not set up in the SendFeedback
	// case, as we don't currently implement network path and system DNS
	// server monitoring for SendFeedback in the platform code. To ensure we
	// fallback to the system resolver and don't always use the custom
	// resolver with alternate DNS servers, clear that config field (this may
	// still be set via tactics).
	config.DNSResolverAlternateServers = nil

	// All config fields should be set before calling Commit.

	err = config.Commit(true)
	if err != nil {
		return errors.Trace(err)
	}

	setNoticeWriter := noticeHandler != nil

	if setNoticeWriter {
		err := psiphon.SetNoticeWriter(psiphon.NewNoticeReceiver(
			func(notice []byte) {
				noticeHandler.Notice(string(notice))
			}))
		if err != nil {
			return errors.Trace(err)
		}
	}

	// Initialize stopSendFeedback, which also serves as the "is started"
	// flag, only after all early error returns.

	sendFeedbackCtx, stopSendFeedback = context.WithCancel(context.Background())

	sendFeedbackResetNoticeWriter = setNoticeWriter

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
		if sendFeedbackResetNoticeWriter {
			// Allow the notice handler to be garbage collected.
			psiphon.ResetNoticeWriter()
		}
		sendFeedbackResetNoticeWriter = false
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

func NoticeUserLog(message string) {
	psiphon.NoticeUserLog(message)
}

// WriteRuntimeProfiles writes Go runtime profile information to a set of
// files in the specified output directory. See common.WriteRuntimeProfiles
// for more details.
//
// If called before Start, log notices will emit to stderr.
func WriteRuntimeProfiles(outputDirectory string, cpuSampleDurationSeconds, blockSampleDurationSeconds int) {
	common.WriteRuntimeProfiles(
		psiphon.NoticeCommonLogger(false),
		outputDirectory,
		"",
		cpuSampleDurationSeconds,
		blockSampleDurationSeconds)
}

// CrashTracebackLevel values configure the amount of Go runtime traceback
// detail captured in fatal crash output.
const (
	CrashTracebackLevelSingle = "single"
	CrashTracebackLevelAll    = "all"
	CrashTracebackLevelSystem = "system"
)

var crashHandlingMutex sync.Mutex

// ConfigureCrashHandling enables Go runtime crash output for the current
// process and routes it to crashReportPath.
//
// Call this after loading the Go shared library and before invoking other
// tunnel-core operations. The caller owns crashReportPath lifecycle: it should
// promote or delete any previous contents, and pre-create or truncate the file
// if it wants a fresh session header or empty sink. ConfigureCrashHandling
// appends Go runtime crash output to the existing file.
func ConfigureCrashHandling(crashReportPath string, tracebackLevel string) error {
	if crashReportPath == "" {
		return errors.TraceNew("crashReportPath is required")
	}

	if tracebackLevel == "" {
		tracebackLevel = CrashTracebackLevelSingle
	}

	switch tracebackLevel {
	case CrashTracebackLevelSingle, CrashTracebackLevelAll, CrashTracebackLevelSystem:
	default:
		return errors.Tracef("invalid tracebackLevel: %s", tracebackLevel)
	}

	crashHandlingMutex.Lock()
	defer crashHandlingMutex.Unlock()

	err := os.MkdirAll(filepath.Dir(crashReportPath), 0700)
	if err != nil {
		return errors.Trace(err)
	}

	crashOutputFile, err := os.OpenFile(
		crashReportPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return errors.Trace(err)
	}
	defer crashOutputFile.Close()

	debug.SetTraceback(tracebackLevel)

	err = debug.SetCrashOutput(crashOutputFile, debug.CrashOptions{})
	if err != nil {
		return errors.Trace(err)
	}

	return nil
}

// ResetCrashHandling disables any previously configured Go runtime crash
// output for the current process.
func ResetCrashHandling() error {
	crashHandlingMutex.Lock()
	defer crashHandlingMutex.Unlock()

	err := debug.SetCrashOutput(nil, debug.CrashOptions{})
	if err != nil {
		return errors.Trace(err)
	}

	return nil
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

func (p *mutexPsiphonProvider) OnAccessToken(token string) {
	p.Lock()
	defer p.Unlock()
	p.p.OnAccessToken(token)
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

func (p *mutexPsiphonProvider) HasIPv6Route() int {
	p.Lock()
	defer p.Unlock()
	return p.p.HasIPv6Route()
}

func (p *mutexPsiphonProvider) GetDNSServersAsString() string {
	p.Lock()
	defer p.Unlock()
	return p.p.GetDNSServersAsString()
}

func (p *mutexPsiphonProvider) GetDNSServers() []string {
	p.Lock()
	defer p.Unlock()
	s := p.p.GetDNSServersAsString()
	if s == "" {
		return []string{}
	}
	return strings.Split(s, ",")
}

func (p *mutexPsiphonProvider) GetNetworkID() string {
	p.Lock()
	defer p.Unlock()
	return p.p.GetNetworkID()
}
