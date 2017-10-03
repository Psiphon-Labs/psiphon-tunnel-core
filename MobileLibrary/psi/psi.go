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
	"encoding/json"
	"fmt"
	"sync"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/tun"
	"os"
)

type PsiphonProvider interface {
	Notice(noticeJSON string)
	HasNetworkConnectivity() int
	BindToDevice(fileDescriptor int) (string, error)
	IPv6Synthesize(IPv4Addr string) string
	GetPrimaryDnsServer() string
	GetSecondaryDnsServer() string
}

var controllerMutex sync.Mutex
var controller *psiphon.Controller
var shutdownBroadcast chan struct{}
var controllerWaitGroup *sync.WaitGroup

func Start(
	configJson,
	embeddedServerEntryList,
	embeddedServerEntryListFilename,
	homepageFilename,
	rotatingFilename string,
	rotatingFileSize int,
	rotatingSyncFrequency int,
	provider PsiphonProvider,
	useDeviceBinder,
	useIPv6Synthesizer bool) error {

	controllerMutex.Lock()
	defer controllerMutex.Unlock()

	if controller != nil {
		return fmt.Errorf("already started")
	}

	// Wrap the provider in a layer that locks a mutex before calling a provider function.
	// The the provider callbacks are Java/Obj-C via gomobile, they are cgo calls that
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

	if useDeviceBinder {
		config.DeviceBinder = newLoggingDeviceBinder(provider)
		config.DnsServerGetter = provider
	}

	if useIPv6Synthesizer {
		config.IPv6Synthesizer = provider
	}

	err = psiphon.SetNoticeOutput(psiphon.NewNoticeReceiver(
		func(notice []byte) {
			provider.Notice(string(notice))
		}),
		homepageFilename,
		rotatingFilename,
		rotatingFileSize,
		rotatingSyncFrequency)
	if err != nil {
		return fmt.Errorf("error initializing notice output: %s\n", err)
	}

	psiphon.NoticeBuildInfo()

	// TODO: should following errors be Notices?

	err = psiphon.InitDataStore(config)
	if err != nil {
		return fmt.Errorf("error initializing datastore: %s", err)
	}

	// Stores list of server entries.
	err = storeServerEntries(embeddedServerEntryListFilename, embeddedServerEntryList)
	if err != nil {
		return err
	}

	controller, err = psiphon.NewController(config)
	if err != nil {
		return fmt.Errorf("error initializing controller: %s", err)
	}

	shutdownBroadcast = make(chan struct{})
	controllerWaitGroup = new(sync.WaitGroup)
	controllerWaitGroup.Add(1)
	go func() {
		defer controllerWaitGroup.Done()
		controller.Run(shutdownBroadcast)
	}()

	return nil
}

func Stop() {

	controllerMutex.Lock()
	defer controllerMutex.Unlock()

	if controller != nil {
		close(shutdownBroadcast)
		controllerWaitGroup.Wait()
		controller = nil
		shutdownBroadcast = nil
		controllerWaitGroup = nil
	}
}

// SetClientVerificationPayload is a passthrough to
// Controller.SetClientVerificationPayloadForActiveTunnels.
// Note: should only be called after Start() and before Stop(); otherwise,
// will silently take no action.
func SetClientVerificationPayload(clientVerificationPayload string) {

	controllerMutex.Lock()
	defer controllerMutex.Unlock()

	if controller != nil {
		controller.SetClientVerificationPayloadForActiveTunnels(clientVerificationPayload)
	}
}

// Encrypt and upload feedback.
func SendFeedback(configJson, diagnosticsJson, b64EncodedPublicKey, uploadServer, uploadPath, uploadServerHeaders string) {
	err := psiphon.SendFeedback(configJson, diagnosticsJson, b64EncodedPublicKey, uploadServer, uploadPath, uploadServerHeaders)
	if err != nil {
		psiphon.NoticeAlert("error uploading feedback: %s", err)
	} else {
		psiphon.NoticeInfo("feedback uploaded successfully")
	}
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

// Helper function to store a list of server entries.
// if embeddedServerEntryListFilename is not empty, embeddedServerEntryList will be ignored.
func storeServerEntries(embeddedServerEntryListFilename, embeddedServerEntryList string) error {

	if embeddedServerEntryListFilename != "" {

		file, err := os.Open(embeddedServerEntryListFilename)
		if err != nil {
			return fmt.Errorf("error reading embedded server list file: %s", common.ContextError(err))
		}
		defer file.Close()

		err = psiphon.StreamingStoreServerEntries(
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
		err = psiphon.StoreServerEntries(serverEntries, false)
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

type loggingDeviceBinder struct {
	p PsiphonProvider
}

func newLoggingDeviceBinder(p PsiphonProvider) *loggingDeviceBinder {
	return &loggingDeviceBinder{p: p}
}

func (d *loggingDeviceBinder) BindToDevice(fileDescriptor int) error {
	deviceInfo, err := d.p.BindToDevice(fileDescriptor)
	if err == nil && deviceInfo != "" {
		NoticeInfo("BindToDevice: %s", deviceInfo)
	}
	return err
}
