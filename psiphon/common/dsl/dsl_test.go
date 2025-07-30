/*
 * Copyright (c) 2025, Psiphon Inc.
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

package dsl

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/osl"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/stacktrace"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/server"
	"github.com/fxamacker/cbor/v2"
)

type testConfig struct {
	name               string
	alreadyDiscovered  bool
	requireOSLKeys     bool
	interruptDownloads bool
	enableRetries      bool
	repeatBeforeTTL    bool
	isConnected        bool
	expectFailure      bool
}

func TestDSLs(t *testing.T) {

	tests := []*testConfig{
		{
			name: "undiscovered server entries",
		},
		{
			name: "require OSL keys",

			requireOSLKeys: true,
		},
		{
			name: "interruptions without retry",

			interruptDownloads: true,
			expectFailure:      true,
		},
		{
			name: "interruptions with retry",

			interruptDownloads: true,
			enableRetries:      true,
		},
		{
			name: "require OSL keys with interruptions",

			requireOSLKeys:     true,
			interruptDownloads: true,
			enableRetries:      true,
		},
		{
			name: "repeat before TTL",

			repeatBeforeTTL: true,
		},
		{
			name: "previously discovered server entries",

			alreadyDiscovered: true,
		},
		{
			name: "first request is-connected",

			isConnected: true,
		},
	}

	for _, testConfig := range tests {
		t.Run(testConfig.name, func(t *testing.T) {
			err := testDSLs(testConfig)
			if err != nil && !testConfig.expectFailure {
				t.Fatal(err.Error())
			}
		})
	}
}

var testClientIP = "192.168.0.1"
var testClientGeoIPData = common.GeoIPData{"Country", "City", "ISP", "ASN", "ASO"}

func testDSLs(testConfig *testConfig) error {

	// Initialize OSLs

	var backendOSLPaveData1 []*osl.PaveData
	var backendOSLPaveData2 []*osl.PaveData
	var clientSLOKs []*osl.SLOK
	if testConfig.requireOSLKeys {
		var err error
		backendOSLPaveData1, backendOSLPaveData2, clientSLOKs, err = initializeOSLs()
		if err != nil {
			return errors.Trace(err)
		}
	}

	// Initialize backend

	tlsConfig, err := initializeTLSConfiguration()
	if err != nil {
		return errors.Trace(err)
	}

	backend, err := initializeDSLBackend(backendOSLPaveData1)
	if err != nil {
		return errors.Trace(err)
	}

	err = backend.start(tlsConfig)
	if err != nil {
		return errors.Trace(err)
	}
	defer backend.stop()

	// Initialize relay

	relayConfig := &RelayConfig{
		Logger:                      newTestLoggerWithComponent("relay"),
		CACertificates:              []*x509.Certificate{tlsConfig.CACertificate},
		HostCertificate:             tlsConfig.relayCertificate,
		DynamicServerListServiceURL: backend.getAddress(),
	}

	relay, err := NewRelay(relayConfig)
	if err != nil {
		return errors.Trace(err)
	}

	// Initialize client fetcher

	// Set transfer targets that will exercise various scenarios, including
	// requiring request size backoff (e.g. see Fetcher.doGetServerEntriesRequest)
	// to succeed.

	if len(backend.serverEntries) != 128 {
		return errors.TraceNew("unexpected server entry count")
	}
	discoverCount := 128
	getCount := 64
	oslCount := 1
	interruptLimit := 0
	if testConfig.interruptDownloads {
		interruptLimit = 8192
	}
	retryCount := 0
	if testConfig.enableRetries {
		retryCount = 20
	}
	isConnected := testConfig.isConnected
	if isConnected {
		discoverCount = 1
	}

	dslClient := newDSLClient(clientSLOKs)

	clientRelayRoundTripper := func(
		ctx context.Context,
		requestPayload []byte) ([]byte, error) {

		// Normally, the Fetcher.RoundTripper would add a circumvention,
		// blocking resistant first hop. For this test, it's just a stub that
		// directly invokes the relay.

		responsePayload := relay.HandleRequest(
			ctx,
			testClientIP,
			testClientGeoIPData,
			requestPayload)

		// Simulate interruption of large response.
		if interruptLimit > 0 && len(responsePayload) > interruptLimit {
			return nil, errors.TraceNew("interrupted")
		}

		return responsePayload, nil
	}

	// TODO: exercise BaseAPIParameters?

	fetcherConfig := &FetcherConfig{
		Logger: newTestLoggerWithComponent("fetcher"),

		RoundTripper: clientRelayRoundTripper,

		DatastoreGetLastDiscoverTime:   dslClient.DatastoreGetLastDiscoverTime,
		DatastoreSetLastDiscoverTime:   dslClient.DatastoreSetLastDiscoverTime,
		DatastoreGetLastActiveOSLsTime: dslClient.DatastoreGetLastActiveOSLsTime,
		DatastoreSetLastActiveOSLsTime: dslClient.DatastoreSetLastActiveOSLsTime,
		DatastoreHasServerEntry:        dslClient.DatastoreHasServerEntry,
		DatastoreStoreServerEntry:      dslClient.DatastoreStoreServerEntry,
		DatastoreKnownOSLIDs:           dslClient.DatastoreKnownOSLIDs,
		DatastoreGetOSLState:           dslClient.DatastoreGetOSLState,
		DatastoreStoreOSLState:         dslClient.DatastoreStoreOSLState,
		DatastoreDeleteOSLState:        dslClient.DatastoreDeleteOSLState,
		DatastoreSLOKLookup:            dslClient.DatastoreSLOKLookup,

		RequestTimeout:          1 * time.Second,
		RequestRetryCount:       retryCount,
		RequestRetryDelay:       1 * time.Millisecond,
		RequestRetryDelayJitter: 0.1,

		DiscoverServerEntriesTTL:      1 * time.Hour,
		DiscoverServerEntriesMinCount: discoverCount,
		DiscoverServerEntriesMaxCount: discoverCount,
		GetServerEntriesMinCount:      getCount,
		GetServerEntriesMaxCount:      getCount,
		GetLastActiveOSLsTTL:          1 * time.Hour,
		GetOSLFileSpecsMinCount:       oslCount,
		GetOSLFileSpecsMaxCount:       oslCount,

		DoGarbageCollection: debug.FreeOSMemory,
	}

	fetcher, err := NewFetcher(fetcherConfig)
	if err != nil {
		return errors.Trace(err)
	}

	// Fetch server entries

	ctx, cancelFunc := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancelFunc()

	err = fetcher.Run(ctx, isConnected)
	if testConfig.expectFailure && err == nil {
		err = errors.TraceNew("unexpected success")
	}
	if err != nil {
		return errors.Trace(err)
	}

	if testConfig.repeatBeforeTTL {

		// Invoke fetch again with before the last discover time TTL expires.
		// The always-failing round tripper will be hit if an unexpected
		// request is sent.

		fetcherConfig.RoundTripper = func(
			context.Context,
			[]byte) ([]byte, error) {
			return nil, errors.TraceNew("round trip not permitted")
		}

		err = fetcher.Run(ctx, isConnected)
		if err != nil {
			return errors.Trace(err)
		}
	}

	if testConfig.alreadyDiscovered && testConfig.isConnected {
		return errors.TraceNew("invalid test configuration")
	}

	if testConfig.alreadyDiscovered {

		// Fetch again after resetting the last discover time TTL. A
		// DiscoverServerEntries request will be sent, but all tags should be
		// known, and no GetServerEntries requests should be sent or any
		// server entries stores, as will be checked via
		// dslClient.serverEntryStoreCount.

		dslClient.lastDiscoverTime = time.Time{}
		dslClient.lastActiveOSLsTime = time.Time{}

		err = fetcher.Run(ctx, isConnected)
		if err != nil {
			return errors.Trace(err)
		}
	}

	if testConfig.isConnected {

		// If the first request was isConnected, only one server entry will
		// have been fetched and the last discover time TTL should not be
		// set. Do another full fetch, and the
		// dslClient.serverEntryStoreCount check will demonstrate that all
		// remaining server entries were downloaded and stored.

		discoverCount = 128
		isConnected = false

		fetcherConfig.DiscoverServerEntriesMinCount = discoverCount
		fetcherConfig.DiscoverServerEntriesMaxCount = discoverCount

		err = fetcher.Run(ctx, isConnected)
		if err != nil {
			return errors.Trace(err)
		}
	}

	// TODO: check "updated" and "known" counters in "DSL: fetched server
	// entries" logs.

	if dslClient.serverEntryStoreCount != len(backend.serverEntries) {
		return errors.Tracef(
			"unexpected server entry store count: %d", dslClient.serverEntryStoreCount)
	}

	if testConfig.requireOSLKeys {

		// Rotate to the next OSL period and clear all server entries. The
		// fetcher will download the new, unknown OSL and reassemble the key,
		// or else no server entries will be downloaded. Check that the
		// fetcher cleans up the old, no longer active OSL state via
		// dslClient.deleteOSLStateCount.

		dslClient.lastDiscoverTime = time.Time{}
		dslClient.lastActiveOSLsTime = time.Time{}

		dslClient.serverEntries = make(map[string]protocol.ServerEntryFields)

		backend.oslPaveData = backendOSLPaveData2

		err = fetcher.Run(ctx, isConnected)
		if err != nil {
			return errors.Trace(err)
		}

		if dslClient.serverEntryStoreCount != len(backend.serverEntries) {
			return errors.Tracef(
				"unexpected server entry store count: %d", dslClient.serverEntryStoreCount)
		}

		if dslClient.deleteOSLStateCount < 1 {
			return errors.Tracef(
				"unexpected delete OSL state count: %d", dslClient.deleteOSLStateCount)
		}
	}

	return nil
}

type dslClient struct {
	mutex                 sync.Mutex
	lastDiscoverTime      time.Time
	lastActiveOSLsTime    time.Time
	serverEntries         map[string]protocol.ServerEntryFields
	serverEntryStoreCount int
	oslStates             map[string][]byte
	deleteOSLStateCount   int
	SLOKs                 []*osl.SLOK
}

func newDSLClient(SLOKs []*osl.SLOK) *dslClient {
	return &dslClient{
		serverEntries: make(map[string]protocol.ServerEntryFields),
		oslStates:     make(map[string][]byte),
		SLOKs:         SLOKs,
	}
}

func (c *dslClient) DatastoreGetLastDiscoverTime() (time.Time, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	return c.lastDiscoverTime, nil
}

func (c *dslClient) DatastoreSetLastDiscoverTime(time time.Time) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.lastDiscoverTime = time
	return nil
}

func (c *dslClient) DatastoreGetLastActiveOSLsTime() (time.Time, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	return c.lastActiveOSLsTime, nil
}

func (c *dslClient) DatastoreSetLastActiveOSLsTime(time time.Time) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.lastActiveOSLsTime = time
	return nil
}

func (c *dslClient) DatastoreHasServerEntry(tag ServerEntryTag, version int) bool {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	_, ok := c.serverEntries[base64.StdEncoding.EncodeToString(tag)]
	return ok
}

func (c *dslClient) DatastoreStoreServerEntry(
	packedServerEntryFields protocol.PackedServerEntryFields, source string) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.serverEntryStoreCount += 1

	serverEntryFields, err := protocol.DecodePackedServerEntryFields(packedServerEntryFields)
	if err != nil {
		return errors.Trace(err)
	}

	serverEntryFields.SetLocalSource(source)
	serverEntryFields.SetLocalTimestamp(
		common.TruncateTimestampToHour(common.GetCurrentTimestamp()))

	c.serverEntries[serverEntryFields.GetTag()] = serverEntryFields

	return nil
}

func (c *dslClient) DatastoreKnownOSLIDs() ([]OSLID, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	var IDs []OSLID
	for IDStr, _ := range c.oslStates {
		ID, _ := hex.DecodeString(IDStr)
		IDs = append(IDs, ID)
	}

	return IDs, nil
}

func (c *dslClient) DatastoreGetOSLState(ID OSLID) ([]byte, bool, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	state, ok := c.oslStates[hex.EncodeToString(ID)]
	return state, ok, nil
}

func (c *dslClient) DatastoreStoreOSLState(ID OSLID, state []byte) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.oslStates[hex.EncodeToString(ID)] = state
	return nil
}

func (c *dslClient) DatastoreDeleteOSLState(ID OSLID) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.deleteOSLStateCount += 1

	delete(c.oslStates, hex.EncodeToString(ID))
	return nil
}

func (c *dslClient) DatastoreSLOKLookup(SLOKID []byte) []byte {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	for _, slok := range c.SLOKs {
		if bytes.Equal(slok.ID, SLOKID) {
			return slok.Key
		}
	}

	return nil
}

func (c *dslClient) DatastoreFatalError(err error) {
	panic(err.Error())
}

// TODO: move dslBackend to an internal/testing package to share with an
// eventual psiphon/server end-to-end test? Also move testLogger to
// internal/testing to share with common/inproxy and other packages.

type dslBackend struct {
	serverEntries map[string]*SourcedServerEntry
	oslPaveData   []*osl.PaveData
	listener      net.Listener
}

func initializeDSLBackend(backendOSLPaveData []*osl.PaveData) (*dslBackend, error) {

	backend := &dslBackend{
		serverEntries: make(map[string]*SourcedServerEntry),
		oslPaveData:   backendOSLPaveData,
	}

	// Run GenerateConfig concurrently to try to take advantage of multiple
	// CPU cores.

	var initMutex sync.Mutex
	var initGroup sync.WaitGroup
	var initErr error

	for i := 1; i <= 128; i++ {

		initGroup.Add(1)
		go func(i int) (retErr error) {
			defer initGroup.Done()
			defer func() {
				if retErr != nil {
					initMutex.Lock()
					initErr = retErr
					initMutex.Unlock()
				}
			}()

			_, _, _, _, encodedServerEntry, err := server.GenerateConfig(
				&server.GenerateConfigParams{
					ServerIPAddress:     fmt.Sprintf("192.0.2.%d", i),
					TunnelProtocolPorts: map[string]int{"OSSH": 1},
				})
			if err != nil {
				return errors.Trace(err)
			}

			serverEntryFields, err := protocol.DecodeServerEntryFields(
				string(encodedServerEntry), "", "")
			if err != nil {
				return errors.Trace(err)
			}

			tag := serverEntryFields.GetTag()
			if tag == "" {
				return errors.TraceNew("unexpected tag")
			}

			packed, err := protocol.EncodePackedServerEntryFields(serverEntryFields)
			if err != nil {
				return errors.Trace(err)
			}

			source := fmt.Sprintf("compartment-%d", i)

			initMutex.Lock()

			if backend.serverEntries[tag] != nil {
				initMutex.Unlock()
				return errors.TraceNew("duplicate tag")
			}

			backend.serverEntries[tag] = &SourcedServerEntry{
				ServerEntryFields: packed,
				Source:            source,
			}

			initMutex.Unlock()

			return nil
		}(i)
	}
	initGroup.Wait()

	if initErr != nil {
		return nil, errors.Trace(initErr)
	}

	return backend, nil
}

func (b *dslBackend) start(tlsConfig *tlsConfig) error {

	logger := newTestLoggerWithComponent("backend")

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return errors.Trace(err)
	}

	certificatePool := x509.NewCertPool()
	certificatePool.AddCert(tlsConfig.CACertificate)

	listener = tls.NewListener(
		listener,
		&tls.Config{
			Certificates: []tls.Certificate{*tlsConfig.backendCertificate},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    certificatePool,
		})

	mux := http.NewServeMux()

	handlerAdapter := func(
		w http.ResponseWriter,
		r *http.Request,
		handler func([]byte) ([]byte, error)) (retErr error) {

		defer func() {
			if retErr != nil {
				logger.WithTrace().Warning(fmt.Sprintf("handler failed: %s\n", retErr))
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
		}()

		clientIPHeader, ok := r.Header[psiphonClientIPHeader]
		if !ok {
			return errors.Tracef("missing header: psiphonClientIPHeader")
		}
		if len(clientIPHeader) != 1 || clientIPHeader[0] != testClientIP {
			return errors.Tracef("invalid header: psiphonClientIPHeader")
		}

		clientGeoIPDataHeader, ok := r.Header[psiphonClientGeoIPDataHeader]
		if !ok {
			return errors.Tracef("missing header: psiphonClientGeoIPDataHeader")
		}
		var geoIPData common.GeoIPData
		if len(clientGeoIPDataHeader) != 1 ||
			json.Unmarshal([]byte(clientGeoIPDataHeader[0]), &geoIPData) != nil ||
			geoIPData != testClientGeoIPData {
			return errors.Tracef("invalid header: psiphonClientGeoIPDataHeader")
		}

		request, err := io.ReadAll(r.Body)
		if err != nil {
			return errors.Trace(err)
		}
		r.Body.Close()

		response, err := handler(request)
		if err != nil {
			return errors.Trace(err)
		}

		_, err = w.Write(response)
		if err != nil {
			return errors.Trace(err)
		}

		return nil
	}

	mux.HandleFunc(requestTypeToHTTPPath[requestTypeDiscoverServerEntries],
		func(w http.ResponseWriter, r *http.Request) {
			_ = handlerAdapter(w, r, b.handleDiscoverServerEntries)
		})
	mux.HandleFunc(requestTypeToHTTPPath[requestTypeGetServerEntries],
		func(w http.ResponseWriter, r *http.Request) {
			_ = handlerAdapter(w, r, b.handleGetServerEntries)
		})
	mux.HandleFunc(requestTypeToHTTPPath[requestTypeGetActiveOSLs],
		func(w http.ResponseWriter, r *http.Request) {
			_ = handlerAdapter(w, r, b.handleGetActiveOSLs)
		})
	mux.HandleFunc(requestTypeToHTTPPath[requestTypeGetOSLFileSpecs],
		func(w http.ResponseWriter, r *http.Request) {
			_ = handlerAdapter(w, r, b.handleGetOSLFileSpecs)
		})

	server := &http.Server{
		Handler: mux,
	}

	go func() {
		_ = server.Serve(listener)
	}()

	b.listener = listener

	return nil
}

func (b *dslBackend) getAddress() string {
	if b.listener == nil {
		return ""
	}
	return b.listener.Addr().String()
}

func (b *dslBackend) stop() {
	if b.listener == nil {
		return
	}
	_ = b.listener.Close()
}

func (b *dslBackend) handleDiscoverServerEntries(cborRequest []byte) ([]byte, error) {

	var request *DiscoverServerEntriesRequest
	err := cbor.Unmarshal(cborRequest, &request)
	if err != nil {
		return nil, errors.Trace(err)
	}

	response := &DiscoverServerEntriesResponse{}

	missingOSLs := false
	if b.oslPaveData != nil {

		// When b.oslPaveData is set, the client must provide the expected OSL
		// keys in order to discover any server entries.

		for _, oslPaveData := range b.oslPaveData {
			found := false
			for _, key := range request.OSLKeys {
				if bytes.Equal(key, oslPaveData.FileKey) {
					found = true
					break
				}

			}
			if !found {
				missingOSLs = true
				break
			}
		}
	}

	if !missingOSLs {

		count := 0
		for tag, _ := range b.serverEntries {
			if count >= int(request.DiscoverCount) {
				break
			}
			count += 1

			// Test server entry tags are base64-encoded random byte strings.
			serverEntryTag, err := base64.StdEncoding.DecodeString(tag)
			if err != nil {
				return nil, errors.Trace(err)
			}

			response.VersionedServerEntryTags = append(
				response.VersionedServerEntryTags,
				VersionedServerEntryTag{Tag: serverEntryTag, Version: 1})
		}
	}

	cborResponse, err := protocol.CBOREncoding.Marshal(response)
	if err != nil {
		return nil, errors.Trace(err)
	}

	return cborResponse, nil
}

func (b *dslBackend) handleGetServerEntries(cborRequest []byte) ([]byte, error) {

	var request *GetServerEntriesRequest
	err := cbor.Unmarshal(cborRequest, &request)
	if err != nil {
		return nil, errors.Trace(err)
	}

	response := &GetServerEntriesResponse{}

	for _, serverEntryTag := range request.ServerEntryTags {

		tag := base64.StdEncoding.EncodeToString(serverEntryTag)

		sourcedServerEntry, ok := b.serverEntries[tag]
		if !ok {

			// An actual DSL backend must return empty slot in this case, as
			// the requested server entry could be pruned or unavailable. For
			// this test, this case is unexpected.

			return nil, errors.TraceNew("unknown server entry tag")
		}

		response.SourcedServerEntries = append(
			response.SourcedServerEntries, sourcedServerEntry)
	}

	cborResponse, err := protocol.CBOREncoding.Marshal(response)
	if err != nil {
		return nil, errors.Trace(err)
	}

	return cborResponse, nil
}

func (b *dslBackend) handleGetActiveOSLs(cborRequest []byte) ([]byte, error) {

	var request *GetActiveOSLsRequest
	err := cbor.Unmarshal(cborRequest, &request)
	if err != nil {
		return nil, errors.Trace(err)
	}

	response := &GetActiveOSLsResponse{}
	for _, oslPaveData := range b.oslPaveData {
		response.ActiveOSLIDs = append(
			response.ActiveOSLIDs,
			oslPaveData.FileSpec.ID)
	}

	cborResponse, err := protocol.CBOREncoding.Marshal(response)
	if err != nil {
		return nil, errors.Trace(err)
	}

	return cborResponse, nil
}

func (b *dslBackend) handleGetOSLFileSpecs(cborRequest []byte) ([]byte, error) {

	var request *GetOSLFileSpecsRequest
	err := cbor.Unmarshal(cborRequest, &request)
	if err != nil {
		return nil, errors.Trace(err)
	}

	response := &GetOSLFileSpecsResponse{}

	for _, oslID := range request.OSLIDs {

		var matchingPaveData *osl.PaveData
		for _, oslPaveData := range b.oslPaveData {
			if bytes.Equal(oslID, oslPaveData.FileSpec.ID) {
				matchingPaveData = oslPaveData
				break
			}

		}
		if matchingPaveData == nil {

			// An actual DSL backend must return empty slot in this case, as
			// the requested OSL may no longer be active. For this test, this
			// case is unexpected.

			return nil, errors.TraceNew("unknown server entry tag")
		}

		cborOSLFileSpec, err := protocol.CBOREncoding.Marshal(matchingPaveData.FileSpec)
		if err != nil {
			return nil, errors.Trace(err)
		}

		response.OSLFileSpecs = append(
			response.OSLFileSpecs, cborOSLFileSpec)
	}

	cborResponse, err := protocol.CBOREncoding.Marshal(response)
	if err != nil {
		return nil, errors.Trace(err)
	}

	return cborResponse, nil
}

func initializeOSLs() ([]*osl.PaveData, []*osl.PaveData, []*osl.SLOK, error) {

	// Adapted from testObfuscatedRemoteServerLists in psiphon/remoteServerList_test.go

	oslConfigJSONTemplate := `
    {
      "Schemes" : [
        {
          "Epoch" : "%s",
          "PaveDataOSLCount" : 2,
          "Regions" : [],
          "PropagationChannelIDs" : ["%s"],
          "MasterKey" : "vwab2WY3eNyMBpyFVPtsivMxF4MOpNHM/T7rHJIXctg=",
          "SeedSpecs" : [
            {
              "ID" : "KuP2V6gLcROIFzb/27fUVu4SxtEfm2omUoISlrWv1mA=",
              "UpstreamSubnets" : ["0.0.0.0/0"],
              "Targets" :
              {
                  "BytesRead" : 1,
                  "BytesWritten" : 1,
                  "PortForwardDurationNanoseconds" : 1
              }
            }
          ],
          "SeedSpecThreshold" : 1,
          "SeedPeriodNanoseconds" : %d,
          "SeedPeriodKeySplits": [
            {
              "Total": 1,
              "Threshold": 1
            }
          ]
        }
      ]
    }`

	now := time.Now().UTC()
	seedPeriod := 1 * time.Second
	epoch := now.Truncate(seedPeriod)
	epochStr := epoch.Format(time.RFC3339Nano)

	propagationChannelID := prng.HexString(8)

	oslConfigJSON := fmt.Sprintf(
		oslConfigJSONTemplate,
		epochStr,
		propagationChannelID,
		seedPeriod)

	oslConfig, err := osl.LoadConfig([]byte(oslConfigJSON))
	if err != nil {
		return nil, nil, nil, errors.Trace(err)
	}

	oslPaveData, err := oslConfig.GetPaveData(0)
	if err != nil {
		return nil, nil, nil, errors.Trace(err)
	}

	backendPaveData1, ok := oslPaveData[propagationChannelID]
	if !ok {
		return nil, nil, nil, errors.TraceNew("unexpected missing OSL file data")
	}

	// Mock seeding SLOKs
	//
	// Normally, clients supplying the specified propagation channel ID would
	// receive SLOKs via the psiphond tunnel connection

	seedState := oslConfig.NewClientSeedState("", propagationChannelID, nil)
	seedPortForward := seedState.NewClientSeedPortForward(net.ParseIP("0.0.0.0"), nil)
	seedPortForward.UpdateProgress(1, 1, 1)
	payload := seedState.GetSeedPayload()
	if len(payload.SLOKs) != 1 {
		return nil, nil, nil, errors.Tracef("unexpected SLOK count %d", len(payload.SLOKs))
	}
	clientSLOKs := payload.SLOKs

	// Rollover to the next OSL time period and generate a new set of active
	// OSLs and SLOKs.

	time.Sleep(2 * seedPeriod)

	oslPaveData, err = oslConfig.GetPaveData(0)
	if err != nil {
		return nil, nil, nil, errors.Trace(err)
	}

	backendPaveData2, ok := oslPaveData[propagationChannelID]
	if !ok {
		return nil, nil, nil, errors.TraceNew("unexpected missing OSL file data")
	}

	seedState = oslConfig.NewClientSeedState("", propagationChannelID, nil)
	seedPortForward = seedState.NewClientSeedPortForward(net.ParseIP("0.0.0.0"), nil)
	seedPortForward.UpdateProgress(1, 1, 1)
	payload = seedState.GetSeedPayload()
	if len(payload.SLOKs) != 1 {
		return nil, nil, nil, errors.Tracef("unexpected SLOK count %d", len(payload.SLOKs))
	}
	clientSLOKs = append(clientSLOKs, payload.SLOKs...)

	// Double check that PaveData periods don't overlap.
	for _, paveData1 := range backendPaveData1 {
		for _, paveData2 := range backendPaveData2 {
			if bytes.Equal(paveData1.FileSpec.ID, paveData2.FileSpec.ID) {
				return nil, nil, nil, errors.TraceNew("unexpected pave data overlap")
			}
		}
	}

	return backendPaveData1, backendPaveData2, clientSLOKs, nil
}

type tlsConfig struct {
	CACertificate      *x509.Certificate
	backendCertificate *tls.Certificate
	relayCertificate   *tls.Certificate
}

func initializeTLSConfiguration() (*tlsConfig, error) {

	CAPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, errors.Trace(err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"test root CA"},
		},
		NotBefore:             now,
		NotAfter:              now.AddDate(0, 0, 1),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}

	CACertificateDER, err := x509.CreateCertificate(
		rand.Reader, template, template, &CAPrivateKey.PublicKey, CAPrivateKey)
	if err != nil {
		return nil, errors.Trace(err)
	}

	CACertificate, err := x509.ParseCertificate(CACertificateDER)
	if err != nil {
		return nil, errors.Trace(err)
	}

	issueCertificate := func(
		name string, isServer bool) (*tls.Certificate, error) {

		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, errors.Trace(err)
		}

		now := time.Now()
		template := &x509.Certificate{
			SerialNumber: big.NewInt(time.Now().UnixNano()),
			Subject: pkix.Name{
				CommonName: name,
			},
			NotBefore: now,
			NotAfter:  now.AddDate(0, 0, 1),
			KeyUsage:  x509.KeyUsageDigitalSignature,
		}
		if isServer {
			template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
			template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		} else {
			template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		}

		certificateDER, err := x509.CreateCertificate(
			rand.Reader, template, CACertificate, &privateKey.PublicKey, CAPrivateKey)
		if err != nil {
			return nil, errors.Trace(err)
		}

		keyPEM := pem.EncodeToMemory(
			&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})

		certPEM := pem.EncodeToMemory(
			&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})

		tlsCertificate, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			return nil, errors.Trace(err)
		}

		return &tlsCertificate, nil
	}

	backendCertificate, err := issueCertificate("backend", true)
	if err != nil {
		return nil, errors.Trace(err)
	}

	relayCertificate, err := issueCertificate("relay", false)
	if err != nil {
		return nil, errors.Trace(err)
	}

	return &tlsConfig{
		CACertificate:      CACertificate,
		backendCertificate: backendCertificate,
		relayCertificate:   relayCertificate,
	}, nil
}

type testLogger struct {
	component     string
	logLevelDebug int32
}

func newTestLogger() *testLogger {
	return &testLogger{
		logLevelDebug: 0,
	}
}

func newTestLoggerWithComponent(component string) *testLogger {
	return &testLogger{
		component:     component,
		logLevelDebug: 0,
	}
}

func (logger *testLogger) WithTrace() common.LogTrace {
	return &testLoggerTrace{
		logger: logger,
		trace:  stacktrace.GetParentFunctionName(),
	}
}

func (logger *testLogger) WithTraceFields(fields common.LogFields) common.LogTrace {
	return &testLoggerTrace{
		logger: logger,
		trace:  stacktrace.GetParentFunctionName(),
		fields: fields,
	}
}

func (logger *testLogger) LogMetric(metric string, fields common.LogFields) {
	jsonFields, _ := json.Marshal(fields)
	var component string
	if len(logger.component) > 0 {
		component = fmt.Sprintf("[%s]", logger.component)
	}
	fmt.Printf(
		"[%s]%s METRIC: %s: %s\n",
		time.Now().UTC().Format(time.RFC3339),
		component,
		metric,
		string(jsonFields))
}

func (logger *testLogger) IsLogLevelDebug() bool {
	return atomic.LoadInt32(&logger.logLevelDebug) == 1
}

func (logger *testLogger) SetLogLevelDebug(logLevelDebug bool) {
	value := int32(0)
	if logLevelDebug {
		value = 1
	}
	atomic.StoreInt32(&logger.logLevelDebug, value)
}

type testLoggerTrace struct {
	logger *testLogger
	trace  string
	fields common.LogFields
}

func (logger *testLoggerTrace) log(priority, message string) {
	now := time.Now().UTC().Format(time.RFC3339)
	var component string
	if len(logger.logger.component) > 0 {
		component = fmt.Sprintf("[%s]", logger.logger.component)
	}
	if len(logger.fields) == 0 {
		fmt.Printf(
			"[%s]%s %s: %s: %s\n",
			now, component, priority, logger.trace, message)
	} else {
		fields := common.LogFields{}
		for k, v := range logger.fields {
			switch v := v.(type) {
			case error:
				// Workaround for Go issue 5161: error types marshal to "{}"
				fields[k] = v.Error()
			default:
				fields[k] = v
			}
		}
		jsonFields, _ := json.Marshal(fields)
		fmt.Printf(
			"[%s]%s %s: %s: %s %s\n",
			now, component, priority, logger.trace, message, string(jsonFields))
	}
}

func (logger *testLoggerTrace) Debug(args ...interface{}) {
	if !logger.logger.IsLogLevelDebug() {
		return
	}
	logger.log("DEBUG", fmt.Sprint(args...))
}

func (logger *testLoggerTrace) Info(args ...interface{}) {
	logger.log("INFO", fmt.Sprint(args...))
}

func (logger *testLoggerTrace) Warning(args ...interface{}) {
	logger.log("WARNING", fmt.Sprint(args...))
}

func (logger *testLoggerTrace) Error(args ...interface{}) {
	logger.log("ERROR", fmt.Sprint(args...))
}
