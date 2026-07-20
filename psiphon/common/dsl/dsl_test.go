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
	"reflect"
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
	"github.com/fxamacker/cbor/v2"
)

func TestDiscoverServerEntriesRequestCBORCompatibility(t *testing.T) {
	type oldDiscoverServerEntriesRequest struct {
		BaseAPIParameters        protocol.PackedAPIParameters `cbor:"1,keyasint,omitempty"`
		OSLKeys                  []OSLKey                     `cbor:"2,keyasint,omitempty"`
		ServerEntryDiscoverCount int32                        `cbor:"3,keyasint,omitempty"`
		LightProxyDiscoverCount  int32                        `cbor:"4,keyasint,omitempty"`
	}

	oldRequest := &oldDiscoverServerEntriesRequest{
		BaseAPIParameters:        protocol.PackedAPIParameters{1: "value"},
		OSLKeys:                  []OSLKey{{1, 2, 3}},
		ServerEntryDiscoverCount: 4,
		LightProxyDiscoverCount:  5,
	}
	encodedOldRequest, err := protocol.CBOREncoding.Marshal(oldRequest)
	if err != nil {
		t.Fatal(err)
	}

	var decodedNewRequest DiscoverServerEntriesRequest
	if err := cbor.Unmarshal(encodedOldRequest, &decodedNewRequest); err != nil {
		t.Fatal(err)
	}
	if decodedNewRequest.DSLTokenRegistration {
		t.Fatal("unexpected DSL token registration in old request")
	}

	newRequest := &DiscoverServerEntriesRequest{
		BaseAPIParameters:        oldRequest.BaseAPIParameters,
		OSLKeys:                  oldRequest.OSLKeys,
		ServerEntryDiscoverCount: oldRequest.ServerEntryDiscoverCount,
		LightProxyDiscoverCount:  oldRequest.LightProxyDiscoverCount,
		DSLTokenRegistration:     true,
	}
	encodedNewRequest, err := protocol.CBOREncoding.Marshal(newRequest)
	if err != nil {
		t.Fatal(err)
	}
	var newRequestFields map[uint64]cbor.RawMessage
	if err := cbor.Unmarshal(encodedNewRequest, &newRequestFields); err != nil {
		t.Fatal(err)
	}
	for key := uint64(1); key <= 5; key++ {
		if _, ok := newRequestFields[key]; !ok {
			t.Fatalf("request CBOR key %d is missing", key)
		}
	}

	var decodedOldRequest oldDiscoverServerEntriesRequest
	if err := cbor.Unmarshal(encodedNewRequest, &decodedOldRequest); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(&decodedOldRequest, oldRequest) {
		t.Fatalf("old request fields changed: got %#v, want %#v", decodedOldRequest, *oldRequest)
	}

	var roundTripRequest DiscoverServerEntriesRequest
	if err := cbor.Unmarshal(encodedNewRequest, &roundTripRequest); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(&roundTripRequest, newRequest) {
		t.Fatalf("request round trip failed: got %#v, want %#v", roundTripRequest, *newRequest)
	}
}

func TestDiscoverServerEntriesResponseCBORCompatibility(t *testing.T) {
	type oldDiscoverServerEntriesResponse struct {
		VersionedServerEntryTags []*VersionedServerEntryTag `cbor:"1,keyasint,omitempty"`
		LightProxyEntries        []*LightProxyEntry         `cbor:"2,keyasint,omitempty"`
	}

	oldResponse := &oldDiscoverServerEntriesResponse{
		VersionedServerEntryTags: []*VersionedServerEntryTag{{Tag: []byte{1}, Version: 2}},
		LightProxyEntries:        []*LightProxyEntry{{ProxyEntry: []byte{3}, ProxyEntryTracker: 4}},
	}
	encodedOldResponse, err := protocol.CBOREncoding.Marshal(oldResponse)
	if err != nil {
		t.Fatal(err)
	}

	var decodedNewResponse DiscoverServerEntriesResponse
	if err := cbor.Unmarshal(encodedOldResponse, &decodedNewResponse); err != nil {
		t.Fatal(err)
	}
	if decodedNewResponse.DSLToken != "" {
		t.Fatalf("unexpected DSL token in old response: %q", decodedNewResponse.DSLToken)
	}

	newResponse := &DiscoverServerEntriesResponse{
		VersionedServerEntryTags: oldResponse.VersionedServerEntryTags,
		LightProxyEntries:        oldResponse.LightProxyEntries,
		DSLToken:                 "BQYH",
	}
	encodedNewResponse, err := protocol.CBOREncoding.Marshal(newResponse)
	if err != nil {
		t.Fatal(err)
	}
	var newResponseFields map[uint64]cbor.RawMessage
	if err := cbor.Unmarshal(encodedNewResponse, &newResponseFields); err != nil {
		t.Fatal(err)
	}
	for key := uint64(1); key <= 3; key++ {
		if _, ok := newResponseFields[key]; !ok {
			t.Fatalf("response CBOR key %d is missing", key)
		}
	}

	var decodedOldResponse oldDiscoverServerEntriesResponse
	if err := cbor.Unmarshal(encodedNewResponse, &decodedOldResponse); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(&decodedOldResponse, oldResponse) {
		t.Fatalf("old response fields changed: got %#v, want %#v", decodedOldResponse, *oldResponse)
	}

	var roundTripResponse DiscoverServerEntriesResponse
	if err := cbor.Unmarshal(encodedNewResponse, &roundTripResponse); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(&roundTripResponse, newResponse) {
		t.Fatalf("response round trip failed: got %#v, want %#v", roundTripResponse, *newResponse)
	}
}

func TestFetcherDSLTokenRegistration(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "disabled", true: "enabled"}[enabled], func(t *testing.T) {
			var got, fieldPresent bool
			config := &FetcherConfig{
				DSLTokenRegistration:         enabled,
				DSLTokenRegistrationResponse: func(string) error { return nil },
				RoundTripper: func(_ context.Context, payload []byte) ([]byte, error) {
					var relayedRequest RelayedRequest
					if err := cbor.Unmarshal(payload, &relayedRequest); err != nil {
						return nil, err
					}

					var request DiscoverServerEntriesRequest
					if err := cbor.Unmarshal(relayedRequest.Request, &request); err != nil {
						return nil, err
					}
					got = request.DSLTokenRegistration
					var requestFields map[uint64]cbor.RawMessage
					if err := cbor.Unmarshal(relayedRequest.Request, &requestFields); err != nil {
						return nil, err
					}
					_, fieldPresent = requestFields[5]

					response, err := protocol.CBOREncoding.Marshal(&DiscoverServerEntriesResponse{})
					if err != nil {
						return nil, err
					}
					return protocol.CBOREncoding.Marshal(&RelayedResponse{Response: response})
				},
			}

			fetcher, err := NewFetcher(config)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := fetcher.doDiscoverServerEntriesRequest(
				context.Background(), nil, 1, 1, enabled); err != nil {

				t.Fatal(err)
			}
			if got != enabled {
				t.Fatalf("got DSL token registration %t, want %t", got, enabled)
			}
			if fieldPresent != enabled {
				t.Fatalf("DSL token registration field present: got %t, want %t", fieldPresent, enabled)
			}
		})
	}
}

func TestFetcherDSLTokenRegistrationOrdering(t *testing.T) {
	var events []string
	token := "b3BhcXVlLXRva2Vu"

	config := &FetcherConfig{
		Logger:               testutils.NewTestLoggerWithComponent("fetcher"),
		DSLTokenRegistration: true,
		DSLTokenRegistrationResponse: func(got string) error {
			if got != token {
				t.Fatal("unexpected token")
			}
			events = append(events, "token")
			return nil
		},
		RoundTripper: func(_ context.Context, payload []byte) ([]byte, error) {
			var request RelayedRequest
			if err := cbor.Unmarshal(payload, &request); err != nil {
				return nil, err
			}
			if request.RequestType != requestTypeDiscoverServerEntries {
				return nil, errors.TraceNew("unexpected request type")
			}

			var discoverRequest DiscoverServerEntriesRequest
			if err := cbor.Unmarshal(request.Request, &discoverRequest); err != nil {
				return nil, err
			}
			if !discoverRequest.DSLTokenRegistration {
				return nil, errors.TraceNew("registration not requested")
			}
			events = append(events, "request")

			response, err := protocol.CBOREncoding.Marshal(&DiscoverServerEntriesResponse{
				DSLToken: token,
				VersionedServerEntryTags: []*VersionedServerEntryTag{{
					Tag:     []byte{1},
					Version: 1,
				}},
			})
			if err != nil {
				return nil, err
			}
			return protocol.CBOREncoding.Marshal(&RelayedResponse{Response: response})
		},
		DatastoreGetLastFetchTime: func() (time.Time, error) { return time.Time{}, nil },
		DatastoreSetLastFetchTime: func(time.Time) error { return nil },
		DatastoreGetLastActiveOSLsTime: func() (time.Time, error) {
			return time.Now(), nil
		},
		DatastoreKnownOSLIDs: func() ([]OSLID, error) { return nil, nil },
		DatastoreHasServerEntry: func(
			ServerEntryTag, int, bool, string, string) bool {

			events = append(events, "entries")
			return true
		},
		DatastoreFatalError:           func(error) {},
		FetchTTL:                      0,
		DiscoverServerEntriesMinCount: 1,
		DiscoverServerEntriesMaxCount: 1,
		DiscoverLightProxyMinCount:    0,
		DiscoverLightProxyMaxCount:    0,
		GetLastActiveOSLsTTL:          time.Hour,
		DoGarbageCollection:           func() {},
	}

	fetcher, err := NewFetcher(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := fetcher.Run(context.Background()); err != nil {
		t.Fatal(err)
	}

	want := []string{"request", "token", "entries"}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("unexpected event order: got %v, want %v", events, want)
	}
}

func TestFetcherDSLTokenRegistrationProceedsAfterOSLFailure(t *testing.T) {
	registrationRequested := false
	responseHandled := false
	token := "b3BhcXVlLXRva2Vu"

	config := &FetcherConfig{
		Logger:               testutils.NewTestLoggerWithComponent("fetcher"),
		DSLTokenRegistration: true,
		DSLTokenRegistrationResponse: func(got string) error {
			if got != token {
				t.Fatal("unexpected token")
			}
			responseHandled = true
			return nil
		},
		RoundTripper: func(_ context.Context, payload []byte) ([]byte, error) {
			var request RelayedRequest
			if err := cbor.Unmarshal(payload, &request); err != nil {
				return nil, err
			}
			var discoverRequest DiscoverServerEntriesRequest
			if err := cbor.Unmarshal(request.Request, &discoverRequest); err != nil {
				return nil, err
			}
			registrationRequested = discoverRequest.DSLTokenRegistration

			response, err := protocol.CBOREncoding.Marshal(
				&DiscoverServerEntriesResponse{DSLToken: token})
			if err != nil {
				return nil, err
			}
			return protocol.CBOREncoding.Marshal(&RelayedResponse{Response: response})
		},
		DatastoreGetLastFetchTime: func() (time.Time, error) { return time.Time{}, nil },
		DatastoreSetLastFetchTime: func(time.Time) error { return nil },
		DatastoreGetLastActiveOSLsTime: func() (time.Time, error) {
			return time.Time{}, errors.TraceNew("OSL failure")
		},
		DatastoreFatalError:           func(error) {},
		FetchTTL:                      0,
		DiscoverServerEntriesMinCount: 1,
		DiscoverServerEntriesMaxCount: 1,
		DiscoverLightProxyMinCount:    0,
		DiscoverLightProxyMaxCount:    0,
		DoGarbageCollection:           func() {},
	}

	fetcher, err := NewFetcher(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := fetcher.Run(context.Background()); err == nil {
		t.Fatal("expected OSL failure")
	}
	if !registrationRequested || !responseHandled {
		t.Fatal("registration not completed after OSL processing failed")
	}
}

func TestFetcherDSLTokenRegistrationRejectsInvalidEncoding(t *testing.T) {
	for _, token := range []string{"YWJj=", "not+base64url", "A"} {
		t.Run(token, func(t *testing.T) {
			callbackInvoked := false
			config := &FetcherConfig{
				Logger:                       testutils.NewTestLoggerWithComponent("fetcher"),
				DSLTokenRegistration:         true,
				DSLTokenRegistrationResponse: func(string) error { callbackInvoked = true; return nil },
				RoundTripper: func(_ context.Context, _ []byte) ([]byte, error) {
					response, err := protocol.CBOREncoding.Marshal(&DiscoverServerEntriesResponse{DSLToken: token})
					if err != nil {
						return nil, err
					}
					return protocol.CBOREncoding.Marshal(&RelayedResponse{Response: response})
				},
				DatastoreGetLastFetchTime: func() (time.Time, error) { return time.Time{}, nil },
				DatastoreSetLastFetchTime: func(time.Time) error { return nil },
				DatastoreGetLastActiveOSLsTime: func() (time.Time, error) {
					return time.Now(), nil
				},
				DatastoreKnownOSLIDs:          func() ([]OSLID, error) { return nil, nil },
				DatastoreFatalError:           func(error) {},
				FetchTTL:                      0,
				DiscoverServerEntriesMinCount: 0,
				DiscoverServerEntriesMaxCount: 0,
				DiscoverLightProxyMinCount:    0,
				DiscoverLightProxyMaxCount:    0,
				GetLastActiveOSLsTTL:          time.Hour,
				DoGarbageCollection:           func() {},
			}
			fetcher, err := NewFetcher(config)
			if err != nil {
				t.Fatal(err)
			}
			if err := fetcher.Run(context.Background()); err != nil {
				t.Fatal(err)
			}
			if callbackInvoked {
				t.Fatal("invalid token encoding reached persistence callback")
			}
		})
	}
}

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
	cacheOSLFileSpecs  bool
	testLightProxy     bool
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
		{
			name: "cache OSL file specs",

			requireOSLKeys:     true,
			interruptDownloads: true,
			enableRetries:      true,
			cacheOSLFileSpecs:  true,
		},
		{
			name: "cache both",

			requireOSLKeys:     true,
			interruptDownloads: true,
			enableRetries:      true,
			cacheServerEntries: true,
			cacheOSLFileSpecs:  true,
		},
		{
			name: "light proxy entries",

			testLightProxy: true,
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

	// Initialize light proxy entries. These are opaque bytes here; the dsl
	// fetcher does not decode or validate them (validation happens in the
	// client's StoreLightProxy at import time).

	var backendLightProxyEntries []*struct {
		ProxyEntry        []byte
		ProxyEntryTracker int64
	}
	if testConfig.testLightProxy {
		backendLightProxyEntries = []*struct {
			ProxyEntry        []byte
			ProxyEntryTracker int64
		}{
			{
				ProxyEntry:        []byte("test-light-proxy-entry"),
				ProxyEntryTracker: 0x0102030405060708,
			},
		}
		backend.SetLightProxyEntries(backendLightProxyEntries)
	}

	var lightProxyMutex sync.Mutex
	var storedLightProxyEntries []*struct {
		ProxyEntry        []byte
		ProxyEntryTracker int64
	}
	storeLightProxy := func(proxyEntry []byte, proxyEntryTracker int64) error {
		lightProxyMutex.Lock()
		defer lightProxyMutex.Unlock()
		storedLightProxyEntries = append(
			storedLightProxyEntries,
			&struct {
				ProxyEntry        []byte
				ProxyEntryTracker int64
			}{append([]byte(nil), proxyEntry...), proxyEntryTracker})
		return nil
	}

	// Initialize relay

	expectValidMetric := false
	metricsValidator := func(metric string, fields common.LogFields) bool { return false }
	if testConfig.cacheServerEntries || testConfig.cacheOSLFileSpecs {
		expectValidMetric = true
		metricsValidator = func(metric string, fields common.LogFields) bool {
			// TODO: in "both" test case, check that both events are logged
			return (testConfig.cacheServerEntries && metric == "dsl_relay_get_server_entries") ||
				(testConfig.cacheOSLFileSpecs && metric == "dsl_relay_get_osl_file_specs")
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

	serverEntryCacheTTL := defaultServerEntryCacheTTL
	serverEntryCacheMaxSize := defaultServerEntryCacheMaxSize
	oslFileSpecCacheTTL := defaultOSLFileSpecCacheTTL
	oslFileSpecCacheMaxSize := defaultOSLFileSpecCacheMaxSize

	if !testConfig.cacheServerEntries {
		serverEntryCacheTTL = 0
		serverEntryCacheMaxSize = 0
	}
	if !testConfig.cacheOSLFileSpecs {
		oslFileSpecCacheTTL = 0
		oslFileSpecCacheMaxSize = 0
	}
	relay.SetCacheParameters(
		serverEntryCacheTTL,
		serverEntryCacheMaxSize,
		oslFileSpecCacheTTL,
		oslFileSpecCacheMaxSize)

	// Initialize client fetcher

	// Set transfer targets that will exercise various scenarios, including
	// requiring request size backoff (e.g. see Fetcher.doGetServerEntriesRequest)
	// to succeed.

	discoverCount := 128
	getCount := 64
	oslCount := 1
	lightProxyCount := 0
	if testConfig.testLightProxy {
		lightProxyCount = 1
	}
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
		prioritizeDial bool,
		prioritizeReason string,
		prioritizeTunnelProtocol string) bool {

		_, expectedPrioritizeDial, expectedPrioritizeReason,
			expectedPrioritizeTunnelProtocol, err :=
			backend.GetServerEntryProperties(tag.String())
		if err != nil ||
			prioritizeDial != expectedPrioritizeDial ||
			prioritizeReason != expectedPrioritizeReason ||
			prioritizeTunnelProtocol != expectedPrioritizeTunnelProtocol {
			unexpectedServerEntryPrioritizeDial.Store(1)
		}
		return dslClient.DatastoreHasServerEntry(tag, version)
	}

	datastoreStoreServerEntryWithCheck := func(
		packedServerEntryFields protocol.PackedServerEntryFields,
		source string,
		prioritizeDial bool,
		prioritizeReason string,
		prioritizeTunnelProtocol string) error {

		serverEntryFields, _ := protocol.DecodePackedServerEntryFields(packedServerEntryFields)
		tag := serverEntryFields.GetTag()

		expectedSource, expectedPrioritizeDial, expectedPrioritizeReason,
			expectedPrioritizeTunnelProtocol, err :=
			backend.GetServerEntryProperties(tag)
		if err != nil ||
			prioritizeDial != expectedPrioritizeDial ||
			prioritizeReason != expectedPrioritizeReason ||
			prioritizeTunnelProtocol != expectedPrioritizeTunnelProtocol {
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
		DatastoreStoreLightProxy:       storeLightProxy,
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
		DiscoverLightProxyMinCount:    lightProxyCount,
		DiscoverLightProxyMaxCount:    lightProxyCount,
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

	if testConfig.cacheOSLFileSpecs {
		if !testConfig.requireOSLKeys {
			return errors.TraceNew("invalid test config")
		}

		// Refetch OSL file specs.

		dslClient.lastFetchTime = time.Time{}
		dslClient.lastActiveOSLsTime = time.Time{}
		dslClient.oslStates = make(map[string][]byte)

		err = fetcher.Run(ctx)
		if err != nil {
			return errors.Trace(err)
		}
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

	if testConfig.testLightProxy {
		lightProxyMutex.Lock()
		defer lightProxyMutex.Unlock()

		// At least one light proxy entry should have been imported (exactly
		// one per Discover request, selected at random from the configured
		// set).
		if len(storedLightProxyEntries) < 1 {
			return errors.TraceNew("expected light proxy entry import")
		}

		// Every imported light proxy entry must match a configured entry,
		// confirming the bytes and tracker round-trip correctly.
		for _, stored := range storedLightProxyEntries {
			matched := false
			for _, expected := range backendLightProxyEntries {
				if bytes.Equal(stored.ProxyEntry, expected.ProxyEntry) &&
					stored.ProxyEntryTracker == expected.ProxyEntryTracker {
					matched = true
					break
				}
			}
			if !matched {
				return errors.TraceNew("unexpected light proxy entry")
			}
		}
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
