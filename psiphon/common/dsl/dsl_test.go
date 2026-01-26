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
	"encoding/base64"
	"encoding/hex"
	"io/ioutil"
	"os"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/osl"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/internal/testutils"
)

type testConfig struct {
	name               string
	alreadyDiscovered  bool
	requireOSLKeys     bool
	interruptDownloads bool
	enableRetries      bool
	repeatBeforeTTL    bool
	isTunneled         bool
	expectFailure      bool
	cacheServerEntries bool
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
			name: "first request is-tunneled",

			isTunneled: true,
		},
		{
			name: "cache server entries",

			interruptDownloads: true,
			enableRetries:      true,
			cacheServerEntries: true,
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

var (
	testClientIP        = "192.168.0.1"
	testClientGeoIPData = common.GeoIPData{
		Country: "Country",
		City:    "City",
		ISP:     "ISP",
		ASN:     "ASN",
		ASO:     "ASO",
	}
	testHostID = "host_id"
)

func testDSLs(testConfig *testConfig) error {

	testDataDirName, err := ioutil.TempDir("", "psiphon-dsl-test")
	if err != nil {
		return errors.Trace(err)
	}
	defer os.RemoveAll(testDataDirName)

	// Initialize OSLs

	var backendOSLPaveData1 []*osl.PaveData
	var backendOSLPaveData2 []*osl.PaveData
	var clientSLOKs []*osl.SLOK
	if testConfig.requireOSLKeys {
		var err error
		backendOSLPaveData1, backendOSLPaveData2, clientSLOKs, err =
			testutils.InitializeTestOSLPaveData()
		if err != nil {
			return errors.Trace(err)
		}
	}

	// Initialize backend

	tlsConfig, err := testutils.NewTestDSLTLSConfig()
	if err != nil {
		return errors.Trace(err)
	}

	backend, err := testutils.NewTestDSLBackend(
		NewBackendTestShim(),
		tlsConfig,
		testClientIP, &testClientGeoIPData, testHostID,
		backendOSLPaveData1)
	if err != nil {
		return errors.Trace(err)
	}

	err = backend.Start()
	if err != nil {
		return errors.Trace(err)
	}
	defer backend.Stop()

	// Initialize relay

	expectValidMetric := false
	metricsValidator := func(metric string, fields common.LogFields) bool { return false }
	if testConfig.cacheServerEntries {
		expectValidMetric = true
		metricsValidator = func(metric string, fields common.LogFields) bool {
			return metric == "dsl_relay_get_server_entries"
		}
	}

	relayLogger := testutils.NewTestLoggerWithMetricValidator("relay", metricsValidator)

	relayCACertificatesFilename,
		relayHostCertificateFilename,
		relayHostKeyFilename,
		err := tlsConfig.WriteRelayFiles(testDataDirName)
	if err != nil {
		return errors.Trace(err)
	}

	relayGetServiceAddress := func(_ common.GeoIPData) (string, error) {
		return backend.GetAddress(), nil
	}

	relayConfig := &RelayConfig{
		Logger:                  relayLogger,
		CACertificatesFilename:  relayCACertificatesFilename,
		HostCertificateFilename: relayHostCertificateFilename,
		HostKeyFilename:         relayHostKeyFilename,
		GetServiceAddress:       relayGetServiceAddress,
		HostID:                  testHostID,

		APIParameterValidator: func(params common.APIParameters) error { return nil },

		APIParameterLogFieldFormatter: func(
			_ string, _ common.GeoIPData, params common.APIParameters) common.LogFields {
			logFields := common.LogFields{}
			logFields.Add(common.LogFields(params))
			return logFields
		},
	}

	relay, err := NewRelay(relayConfig)
	if err != nil {
		return errors.Trace(err)
	}

	if !testConfig.cacheServerEntries {
		relay.SetCacheParameters(0, 0)
	}

	// Initialize client fetcher

	// Set transfer targets that will exercise various scenarios, including
	// requiring request size backoff (e.g. see Fetcher.doGetServerEntriesRequest)
	// to succeed.

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
	isTunneled := testConfig.isTunneled
	if isTunneled {
		discoverCount = 1
	}

	if backend.GetServerEntryCount(isTunneled) != 128 {
		return errors.TraceNew("unexpected server entry count")
	}

	dslClient := newDSLClient(clientSLOKs)

	clientRelayRoundTripper := func(
		ctx context.Context,
		requestPayload []byte) ([]byte, error) {

		// Normally, the Fetcher.RoundTripper would add a circumvention,
		// blocking resistant first hop. For this test, it's just a stub that
		// directly invokes the relay.

		responsePayload, err := relay.HandleRequest(
			ctx,
			nil,
			testClientIP,
			testClientGeoIPData,
			isTunneled,
			requestPayload)
		if err != nil {
			return GetRelayGenericErrorResponse(), errors.Trace(err)
		}

		// Simulate interruption of large response.
		if interruptLimit > 0 && len(responsePayload) > interruptLimit {
			return nil, errors.TraceNew("interrupted")
		}

		return responsePayload, nil
	}

	// TODO: exercise BaseAPIParameters?

	var unexpectedServerEntrySource atomic.Int32
	var unexpectedServerEntryPrioritizeDial atomic.Int32

	datastoreHasServerEntryWithCheck := func(
		tag ServerEntryTag,
		version int,
		prioritizeDial bool) bool {

		_, expectedPrioritizeDial, err := backend.GetServerEntryProperties(tag.String())
		if err != nil || prioritizeDial != expectedPrioritizeDial {
			unexpectedServerEntryPrioritizeDial.Store(1)
		}
		return dslClient.DatastoreHasServerEntry(tag, version)
	}

	datastoreStoreServerEntryWithCheck := func(
		packedServerEntryFields protocol.PackedServerEntryFields,
		source string,
		prioritizeDial bool) error {

		serverEntryFields, _ := protocol.DecodePackedServerEntryFields(packedServerEntryFields)
		tag := serverEntryFields.GetTag()

		expectedSource, expectedPrioritizeDial, err := backend.GetServerEntryProperties(tag)
		if err != nil || prioritizeDial != expectedPrioritizeDial {
			unexpectedServerEntryPrioritizeDial.Store(1)
		}
		if err != nil || source != expectedSource {
			unexpectedServerEntrySource.Store(1)
		}
		return errors.Trace(
			dslClient.DatastoreStoreServerEntry(packedServerEntryFields, source))
	}

	fetcherConfig := &FetcherConfig{
		Logger: testutils.NewTestLoggerWithComponent("fetcher"),

		RoundTripper: clientRelayRoundTripper,

		DatastoreGetLastFetchTime:      dslClient.DatastoreGetLastFetchTime,
		DatastoreSetLastFetchTime:      dslClient.DatastoreSetLastFetchTime,
		DatastoreGetLastActiveOSLsTime: dslClient.DatastoreGetLastActiveOSLsTime,
		DatastoreSetLastActiveOSLsTime: dslClient.DatastoreSetLastActiveOSLsTime,
		DatastoreHasServerEntry:        datastoreHasServerEntryWithCheck,
		DatastoreStoreServerEntry:      datastoreStoreServerEntryWithCheck,
		DatastoreKnownOSLIDs:           dslClient.DatastoreKnownOSLIDs,
		DatastoreGetOSLState:           dslClient.DatastoreGetOSLState,
		DatastoreStoreOSLState:         dslClient.DatastoreStoreOSLState,
		DatastoreDeleteOSLState:        dslClient.DatastoreDeleteOSLState,
		DatastoreSLOKLookup:            dslClient.DatastoreSLOKLookup,

		RequestTimeout:          1 * time.Second,
		RequestRetryCount:       retryCount,
		RequestRetryDelay:       1 * time.Millisecond,
		RequestRetryDelayJitter: 0.1,

		FetchTTL:                      1 * time.Hour,
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

	err = fetcher.Run(ctx)
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

		err = fetcher.Run(ctx)
		if err != nil {
			return errors.Trace(err)
		}
	}

	if testConfig.alreadyDiscovered && testConfig.isTunneled {
		return errors.TraceNew("invalid test configuration")
	}

	if testConfig.alreadyDiscovered {

		// Fetch again after resetting the last discover time TTL. A
		// DiscoverServerEntries request will be sent, but all tags should be
		// known, and no GetServerEntries requests should be sent or any
		// server entries stores, as will be checked via
		// dslClient.serverEntryStoreCount.

		dslClient.lastFetchTime = time.Time{}
		dslClient.lastActiveOSLsTime = time.Time{}

		err = fetcher.Run(ctx)
		if err != nil {
			return errors.Trace(err)
		}
	}

	if testConfig.isTunneled {

		if dslClient.serverEntryStoreCount != 1 {
			return errors.Tracef(
				"unexpected server entry store count: %d", dslClient.serverEntryStoreCount)
		}

		// If the first request was isTunneled, only one server entry will
		// have been fetched. Do another full fetch, and the following
		// dslClient.serverEntryStoreCount check will demonstrate that all
		// remaining server entries were downloaded and stored.

		dslClient.lastFetchTime = time.Time{}

		discoverCount = 128

		fetcherConfig.DiscoverServerEntriesMinCount = discoverCount
		fetcherConfig.DiscoverServerEntriesMaxCount = discoverCount

		err = fetcher.Run(ctx)
		if err != nil {
			return errors.Trace(err)
		}
	}

	// TODO: check "updated" and "known" counters in "DSL: fetched server
	// entries" logs.

	if dslClient.serverEntryStoreCount != backend.GetServerEntryCount(isTunneled) {
		return errors.Tracef(
			"unexpected server entry store count: %d", dslClient.serverEntryStoreCount)
	}

	if testConfig.requireOSLKeys {

		// Rotate to the next OSL period and clear all server entries. The
		// fetcher will download the new, unknown OSL and reassemble the key,
		// or else no server entries will be downloaded. Check that the
		// fetcher cleans up the old, no longer active OSL state via
		// dslClient.deleteOSLStateCount.

		dslClient.lastFetchTime = time.Time{}
		dslClient.lastActiveOSLsTime = time.Time{}

		dslClient.serverEntries = make(map[string]protocol.ServerEntryFields)

		backend.SetOSLPaveData(backendOSLPaveData2)

		err = fetcher.Run(ctx)
		if err != nil {
			return errors.Trace(err)
		}

		if dslClient.serverEntryStoreCount != backend.GetServerEntryCount(isTunneled) {
			return errors.Tracef(
				"unexpected server entry store count: %d", dslClient.serverEntryStoreCount)
		}

		if dslClient.deleteOSLStateCount < 1 {
			return errors.Tracef(
				"unexpected delete OSL state count: %d", dslClient.deleteOSLStateCount)
		}
	}

	err = relayLogger.CheckMetrics(expectValidMetric)
	if err != nil {
		return errors.Trace(err)
	}

	if unexpectedServerEntrySource.Load() != 0 {
		return errors.TraceNew("unexpected server entry source")
	}

	if unexpectedServerEntryPrioritizeDial.Load() != 0 {
		return errors.TraceNew("unexpected server entry prioritize dial")
	}

	return nil
}

type dslClient struct {
	mutex                 sync.Mutex
	lastFetchTime         time.Time
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

func (c *dslClient) DatastoreGetLastFetchTime() (time.Time, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	return c.lastFetchTime, nil
}

func (c *dslClient) DatastoreSetLastFetchTime(time time.Time) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.lastFetchTime = time
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
	for IDStr := range c.oslStates {
		ID, _ := hex.DecodeString(IDStr)
		IDs = append(IDs, ID)
	}

	return IDs, nil
}

func (c *dslClient) DatastoreGetOSLState(ID OSLID) ([]byte, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	state, ok := c.oslStates[hex.EncodeToString(ID)]
	if !ok {
		return nil, nil
	}
	return state, nil
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
