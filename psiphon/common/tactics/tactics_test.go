/*
 * Copyright (c) 2018, Psiphon Inc.
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

package tactics

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/parameters"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/internal/testutils"
)

func TestTactics(t *testing.T) {

	// Server tactics configuration

	// Long and short region lists test both map and slice lookups.
	//
	// Repeated median aggregation tests aggregation memoization.
	//
	// The test-packetman-spec tests a reference between a filter tactics
	// and default tactics.

	tacticsConfigTemplate := `
    {
      "RequestPublicKey" : "%s",
      "RequestPrivateKey" : "%s",
      "RequestObfuscatedKey" : "%s",
      "DefaultTactics" : {
        "TTL" : "1s",
        "Parameters" : {
          "NetworkLatencyMultiplier" : %0.1f,
          "ServerPacketManipulationSpecs" : [{"Name": "test-packetman-spec", "PacketSpecs": [["TCP-flags S"]]}]
        }
      },
      "FilteredTactics" : [
        {
          "Filter" : {
            "Regions": ["R1", "R2", "R3", "R4", "R5", "R6"],
            "APIParameters" : {"client_platform" : ["P1"]},
            "SpeedTestRTTMilliseconds" : {
              "Aggregation" : "Median",
              "AtLeast" : 1
            }
          },
          "Tactics" : {
            "Parameters" : {
              "ConnectionWorkerPoolSize" : %d
            }
          }
        },
        {
          "Filter" : {
            "Regions": ["R1"],
            "ASNs": ["1"],
            "APIParameters" : {"client_platform" : ["P1"], "client_version": ["V1"]},
            "SpeedTestRTTMilliseconds" : {
              "Aggregation" : "Median",
              "AtLeast" : 1
            }
          },
          "Tactics" : {
            "Parameters" : {
              %s
            }
          }
        },
        {
          "Filter" : {
            "APIParameters" : {"client_platform" : ["P2"], "client_version": ["V2"]}
          },
          "Tactics" : {
            "Parameters" : {
              "ConnectionWorkerPoolSize" : 1
            }
          }
        },
        {
          "Filter" : {
            "Regions": ["R2"]
          },
          "Tactics" : {
            "Parameters" : {
              "ConnectionWorkerPoolSize" : %d
            }
          }
        },
        {
          "Filter" : {
            "Regions": ["R7"]
          },
          "Tactics" : {
            "Parameters" : {
              "ServerProtocolPacketManipulations": {"All" : ["test-packetman-spec"]}
            }
          }
        }
      ]
    }
    `
	if stringLookupThreshold != 5 {
		t.Fatalf("unexpected stringLookupThreshold")
	}

	encodedRequestPublicKey, encodedRequestPrivateKey, encodedObfuscatedKey, err := GenerateKeys()
	if err != nil {
		t.Fatalf("GenerateKeys failed: %s", err)
	}

	tacticsNetworkLatencyMultiplier := 2.0
	tacticsConnectionWorkerPoolSize := 5
	tacticsLimitTunnelProtocols := protocol.TunnelProtocols{"OSSH", "SSH"}
	jsonTacticsLimitTunnelProtocols := `"LimitTunnelProtocols" : ["OSSH", "SSH"]`

	expectedApplyCount := 3

	tacticsConfig := fmt.Sprintf(
		tacticsConfigTemplate,
		encodedRequestPublicKey,
		encodedRequestPrivateKey,
		encodedObfuscatedKey,
		tacticsNetworkLatencyMultiplier,
		tacticsConnectionWorkerPoolSize,
		jsonTacticsLimitTunnelProtocols,
		tacticsConnectionWorkerPoolSize+1)

	file, err := ioutil.TempFile("", "tactics.config")
	if err != nil {
		t.Fatalf("TempFile create failed: %s", err)
	}
	_, err = file.Write([]byte(tacticsConfig))
	if err != nil {
		t.Fatalf("TempFile write failed: %s", err)
	}
	file.Close()

	configFileName := file.Name()
	defer os.Remove(configFileName)

	// Configure and run server

	// Mock server uses an insecure HTTP transport that exposes endpoint names

	clientGeoIPData := common.GeoIPData{Country: "R1", ASN: "1"}

	logger := testutils.NewTestLogger()

	validator := func(
		apiParams common.APIParameters) error {

		expectedParams := []string{"client_platform", "client_version"}
		for _, name := range expectedParams {
			value, ok := apiParams[name]
			if !ok {
				return fmt.Errorf("missing param: %s", name)
			}
			_, ok = value.(string)
			if !ok {
				return fmt.Errorf("invalid param type: %s", name)
			}
		}
		return nil
	}

	formatter := func(
		_ string,
		_ common.GeoIPData,
		apiParams common.APIParameters) common.LogFields {

		return common.LogFields(apiParams)
	}

	server, err := NewServer(
		logger,
		formatter,
		validator,
		configFileName,
		"",
		"",
		"")
	if err != nil {
		t.Fatalf("NewServer failed: %s", err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %s", err)
	}

	serverAddress := listener.Addr().String()

	go func() {
		serveMux := http.NewServeMux()
		serveMux.HandleFunc(
			"/",
			func(w http.ResponseWriter, r *http.Request) {
				// Ensure RTT takes at least 1 millisecond for speed test
				time.Sleep(1 * time.Millisecond)
				endPoint := strings.Trim(r.URL.Path, "/")
				if !server.HandleEndPoint(endPoint, clientGeoIPData, w, r) {
					http.NotFound(w, r)
				}
			})
		httpServer := &http.Server{
			Addr:    serverAddress,
			Handler: serveMux,
		}
		httpServer.Serve(listener)
	}()

	// Configure client

	params, err := parameters.NewParameters(
		func(err error) {
			t.Fatalf("Parameters getValue failed: %s", err)
		})
	if err != nil {
		t.Fatalf("NewParameters failed: %s", err)
	}

	networkID := "NETWORK1"

	getNetworkID := func() string { return networkID }

	apiParams := common.APIParameters{
		"client_platform": "P1",
		"client_version":  "V1"}

	storer := newTestStorer()

	endPointRegion := "R0"
	endPointProtocol := "OSSH"
	differentEndPointProtocol := "SSH"

	obfuscatedRoundTripper := func(
		ctx context.Context,
		endPoint string,
		requestBody []byte) ([]byte, error) {

		// This mock ObfuscatedRoundTripper does not actually obfuscate the endpoint
		// value.

		request, err := http.NewRequest(
			"POST",
			fmt.Sprintf("http://%s/%s", serverAddress, endPoint),
			bytes.NewReader(requestBody))
		if err != nil {
			return nil, err
		}
		request = request.WithContext(ctx)
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			return nil, err
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("HTTP request failed: %d", response.StatusCode)
		}
		body, err := ioutil.ReadAll(response.Body)
		if err != nil {
			return nil, err
		}
		return body, nil
	}

	// There should be no local tactics

	tacticsRecord, err := UseStoredTactics(storer, networkID)
	if err != nil {
		t.Fatalf("UseStoredTactics failed: %s", err)
	}

	if tacticsRecord != nil {
		t.Fatalf("unexpected tactics record")
	}

	// Helper to check that expected tactics parameters are returned

	checkParameters := func(r *Record) {

		p, err := parameters.NewParameters(nil)
		if err != nil {
			t.Fatalf("NewParameters failed: %s", err)
		}

		// ValidationSkipOnError is set for Psiphon clients
		counts, err := p.Set(r.Tag, parameters.ValidationSkipOnError, r.Tactics.Parameters)
		if err != nil {
			t.Fatalf("Apply failed: %s", err)
		}

		if counts[0] != expectedApplyCount {
			t.Fatalf("Unexpected apply count: %d", counts[0])
		}

		multipler := p.Get().Float(parameters.NetworkLatencyMultiplier)
		if multipler != tacticsNetworkLatencyMultiplier {
			t.Fatalf("Unexpected NetworkLatencyMultiplier: %v", multipler)
		}

		connectionWorkerPoolSize := p.Get().Int(parameters.ConnectionWorkerPoolSize)
		if connectionWorkerPoolSize != tacticsConnectionWorkerPoolSize {
			t.Fatalf("Unexpected ConnectionWorkerPoolSize: %v", connectionWorkerPoolSize)
		}

		limitTunnelProtocols := p.Get().TunnelProtocols(parameters.LimitTunnelProtocols)
		if !reflect.DeepEqual(limitTunnelProtocols, tacticsLimitTunnelProtocols) {
			t.Fatalf("Unexpected LimitTunnelProtocols: %v", limitTunnelProtocols)
		}
	}

	// Helper to check server-side cachedTacticsData state

	checkServerCache := func(cacheEntryFilterMatches ...[]bool) {

		cacheItems := server.cachedTacticsData.Items()
		if len(cacheItems) != len(cacheEntryFilterMatches) {
			t.Fatalf("Unexpected cachedTacticsData size: %v", len(cacheItems))
		}

		for _, filterMatches := range cacheEntryFilterMatches {
			includeServerSizeOnly := false
			hasFilterMatches := true
			cacheKey := getCacheKey(includeServerSizeOnly, hasFilterMatches, filterMatches)
			_, ok := server.cachedTacticsData.Get(cacheKey)
			if !ok {
				t.Fatalf("Unexpected missing cachedTacticsData entry: %v", filterMatches)
			}
		}
	}

	// Initial tactics request; will also run a speed test

	// Request should complete in < 1 second
	ctx, cancelFunc := context.WithTimeout(context.Background(), 1*time.Second)

	initialFetchTacticsRecord, err := FetchTactics(
		ctx,
		params,
		storer,
		getNetworkID,
		apiParams,
		endPointProtocol,
		endPointRegion,
		encodedRequestPublicKey,
		encodedObfuscatedKey,
		obfuscatedRoundTripper)

	cancelFunc()

	if err != nil {
		t.Fatalf("FetchTactics failed: %s", err)
	}

	if initialFetchTacticsRecord == nil {
		t.Fatalf("expected tactics record")
	}

	checkParameters(initialFetchTacticsRecord)

	// Server should be caching tactics data for tactics matching first two
	// filters.
	checkServerCache([]bool{true, true, false, false, false})

	// There should now be cached local tactics

	storedTacticsRecord, err := UseStoredTactics(storer, networkID)
	if err != nil {
		t.Fatalf("UseStoredTactics failed: %s", err)
	}

	if storedTacticsRecord == nil {
		t.Fatalf("expected stored tactics record")
	}

	// Strip monotonic component so comparisons will work
	initialFetchTacticsRecord.Expiry = initialFetchTacticsRecord.Expiry.Round(0)

	if !reflect.DeepEqual(initialFetchTacticsRecord, storedTacticsRecord) {
		t.Fatalf("tactics records are not identical:\n\n%#v\n\n%#v\n\n",
			initialFetchTacticsRecord, storedTacticsRecord)
	}

	checkParameters(storedTacticsRecord)

	// There should now be a speed test sample

	speedTestSamples, err := getSpeedTestSamples(storer, networkID)
	if err != nil {
		t.Fatalf("getSpeedTestSamples failed: %s", err)
	}

	if len(speedTestSamples) != 1 {
		t.Fatalf("unexpected speed test samples count")
	}

	// Wait for tactics to expire

	time.Sleep(1 * time.Second)

	storedTacticsRecord, err = UseStoredTactics(storer, networkID)
	if err != nil {
		t.Fatalf("UseStoredTactics failed: %s", err)
	}

	if storedTacticsRecord != nil {
		t.Fatalf("unexpected stored tactics record")
	}

	// Next fetch should merge empty payload as tag matches
	// TODO: inspect tactics response payload

	fetchTacticsRecord, err := FetchTactics(
		context.Background(),
		params,
		storer,
		getNetworkID,
		apiParams,
		endPointProtocol,
		endPointRegion,
		encodedRequestPublicKey,
		encodedObfuscatedKey,
		obfuscatedRoundTripper)
	if err != nil {
		t.Fatalf("FetchTactics failed: %s", err)
	}

	if fetchTacticsRecord == nil {
		t.Fatalf("expected tactics record")
	}

	if initialFetchTacticsRecord.Tag != fetchTacticsRecord.Tag {
		t.Fatalf("tags are not identical")
	}

	if initialFetchTacticsRecord.Expiry.Equal(fetchTacticsRecord.Expiry) {
		t.Fatalf("expiries unexpectedly identical")
	}

	if !reflect.DeepEqual(initialFetchTacticsRecord.Tactics, fetchTacticsRecord.Tactics) {
		t.Fatalf("tactics are not identical:\n\n%#v\n\n%#v\n\n",
			initialFetchTacticsRecord.Tactics, fetchTacticsRecord.Tactics)
	}

	checkParameters(fetchTacticsRecord)

	// Server cache should be the same
	checkServerCache([]bool{true, true, false, false, false})

	// Modify tactics configuration to change payload

	tacticsConnectionWorkerPoolSize = 6

	tacticsLimitTunnelProtocols = protocol.TunnelProtocols{}
	jsonTacticsLimitTunnelProtocols = ``
	expectedApplyCount = 2

	// Omitting LimitTunnelProtocols entirely tests this bug fix: When a new
	// tactics payload is obtained, all previous parameters should be cleared.
	//
	// In the bug, any previous parameters not in the new tactics were
	// incorrectly retained. In this test case, LimitTunnelProtocols is
	// omitted in the new tactics; if FetchTactics fails to clear the old
	// LimitTunnelProtocols then the test will fail.

	tacticsConfig = fmt.Sprintf(
		tacticsConfigTemplate,
		encodedRequestPublicKey,
		encodedRequestPrivateKey,
		encodedObfuscatedKey,
		tacticsNetworkLatencyMultiplier,
		tacticsConnectionWorkerPoolSize,
		jsonTacticsLimitTunnelProtocols,
		tacticsConnectionWorkerPoolSize+1)

	err = ioutil.WriteFile(configFileName, []byte(tacticsConfig), 0600)
	if err != nil {
		t.Fatalf("WriteFile failed: %s", err)
	}

	reloaded, err := server.Reload()
	if err != nil {
		t.Fatalf("Reload failed: %s", err)
	}

	if !reloaded {
		t.Fatalf("Server config failed to reload")
	}

	// Server cache should be flushed
	checkServerCache()

	// Next fetch should return a different payload

	fetchTacticsRecord, err = FetchTactics(
		context.Background(),
		params,
		storer,
		getNetworkID,
		apiParams,
		endPointProtocol,
		endPointRegion,
		encodedRequestPublicKey,
		encodedObfuscatedKey,
		obfuscatedRoundTripper)
	if err != nil {
		t.Fatalf("FetchTactics failed: %s", err)
	}

	if fetchTacticsRecord == nil {
		t.Fatalf("expected tactics record")
	}

	if initialFetchTacticsRecord.Tag == fetchTacticsRecord.Tag {
		t.Fatalf("tags unexpectedly identical")
	}

	if initialFetchTacticsRecord.Expiry.Equal(fetchTacticsRecord.Expiry) {
		t.Fatalf("expires unexpectedly identical")
	}

	if reflect.DeepEqual(initialFetchTacticsRecord.Tactics, fetchTacticsRecord.Tactics) {
		t.Fatalf("tactics unexpectedly identical")
	}

	checkParameters(fetchTacticsRecord)

	checkServerCache([]bool{true, true, false, false, false})

	// Exercise handshake transport of tactics

	// Wait for tactics to expire; handshake should renew
	time.Sleep(1 * time.Second)

	handshakeParams := common.APIParameters{
		"client_platform": "P1",
		"client_version":  "V1"}

	err = SetTacticsAPIParameters(storer, networkID, handshakeParams)
	if err != nil {
		t.Fatalf("SetTacticsAPIParameters failed: %s", err)
	}

	// FetchTactics will exercise the compression case.
	compressPayload := false

	tacticsPayload, err := server.GetTacticsPayload(clientGeoIPData, handshakeParams, compressPayload)
	if err != nil {
		t.Fatalf("GetTacticsPayload failed: %s", err)
	}

	handshakeTacticsRecord, err := HandleTacticsPayload(storer, networkID, tacticsPayload)
	if err != nil {
		t.Fatalf("HandleTacticsPayload failed: %s", err)
	}

	// When tactic parameters are unchanged, HandleTacticsPayload returns nil,
	// so that callers do not apply tactics unnecessarily.
	//
	// Check that nil is returned, but then directly load the record stored by
	// HandleTacticsPayload in order to check metadata including the updated
	// TTL.

	if handshakeTacticsRecord != nil {
		t.Fatalf("unexpected tactics record")
	}
	handshakeTacticsRecord, err = getStoredTacticsRecord(storer, networkID)
	if err != nil {
		t.Fatalf("getStoredTacticsRecord failed: %s", err)
	}

	if fetchTacticsRecord.Tag != handshakeTacticsRecord.Tag {
		t.Fatalf("tags are not identical")
	}

	if fetchTacticsRecord.Expiry.Equal(handshakeTacticsRecord.Expiry) {
		t.Fatalf("expiries unexpectedly identical")
	}

	if !reflect.DeepEqual(fetchTacticsRecord.Tactics, handshakeTacticsRecord.Tactics) {
		t.Fatalf("tactics are not identical:\n\n%#v\n\n%#v\n\n",
			fetchTacticsRecord.Tactics, handshakeTacticsRecord.Tactics)
	}

	checkParameters(handshakeTacticsRecord)

	checkServerCache([]bool{true, true, false, false, false})

	// Now there should be stored tactics

	storedTacticsRecord, err = UseStoredTactics(storer, networkID)
	if err != nil {
		t.Fatalf("UseStoredTactics failed: %s", err)
	}

	if storedTacticsRecord == nil {
		t.Fatalf("expected stored tactics record")
	}

	handshakeTacticsRecord.Expiry = handshakeTacticsRecord.Expiry.Round(0)

	if !reflect.DeepEqual(handshakeTacticsRecord, storedTacticsRecord) {
		t.Fatalf("tactics records are not identical:\n\n%#v\n\n%#v\n\n",
			handshakeTacticsRecord, storedTacticsRecord)
	}

	checkParameters(storedTacticsRecord)

	// Change network ID, should be no stored tactics

	networkID = "NETWORK2"

	storedTacticsRecord, err = UseStoredTactics(storer, networkID)
	if err != nil {
		t.Fatalf("UseStoredTactics failed: %s", err)
	}

	if storedTacticsRecord != nil {
		t.Fatalf("unexpected stored tactics record")
	}

	// Server should cache a new entry for different filter matches

	apiParams2 := common.APIParameters{
		"client_platform": "P2",
		"client_version":  "V2"}

	fetchTacticsRecord, err = FetchTactics(
		context.Background(),
		params,
		storer,
		getNetworkID,
		apiParams2,
		endPointProtocol,
		endPointRegion,
		encodedRequestPublicKey,
		encodedObfuscatedKey,
		obfuscatedRoundTripper)
	if err != nil {
		t.Fatalf("FetchTactics failed: %s", err)
	}

	if fetchTacticsRecord == nil {
		t.Fatalf("expected tactics record")
	}

	checkServerCache(
		[]bool{true, true, false, false, false},
		[]bool{false, false, true, false, false})

	// Exercise speed test sample truncation

	maxSamples := params.Get().Int(parameters.SpeedTestMaxSampleCount)

	for i := 0; i < maxSamples*2; i++ {

		response, err := MakeSpeedTestResponse(0, 0)
		if err != nil {
			t.Fatalf("MakeSpeedTestResponse failed: %s", err)
		}

		err = AddSpeedTestSample(
			params,
			storer,
			networkID,
			"",
			differentEndPointProtocol,
			100*time.Millisecond,
			nil,
			response)
		if err != nil {
			t.Fatalf("AddSpeedTestSample failed: %s", err)
		}
	}

	speedTestSamples, err = getSpeedTestSamples(storer, networkID)
	if err != nil {
		t.Fatalf("getSpeedTestSamples failed: %s", err)
	}

	if len(speedTestSamples) != maxSamples {
		t.Fatalf("unexpected speed test samples count")
	}

	for _, sample := range speedTestSamples {
		if sample.EndPointProtocol == endPointProtocol {
			t.Fatalf("unexpected old speed test sample")
		}
	}

	// Fetch should fail when using incorrect keys

	encodedIncorrectRequestPublicKey, _, encodedIncorrectObfuscatedKey, err := GenerateKeys()
	if err != nil {
		t.Fatalf("GenerateKeys failed: %s", err)
	}

	_, err = FetchTactics(
		context.Background(),
		params,
		storer,
		getNetworkID,
		apiParams,
		endPointProtocol,
		endPointRegion,
		encodedIncorrectRequestPublicKey,
		encodedObfuscatedKey,
		obfuscatedRoundTripper)
	if err == nil {
		t.Fatalf("FetchTactics succeeded unexpectedly with incorrect request key")
	}

	_, err = FetchTactics(
		context.Background(),
		params,
		storer,
		getNetworkID,
		apiParams,
		endPointProtocol,
		endPointRegion,
		encodedRequestPublicKey,
		encodedIncorrectObfuscatedKey,
		obfuscatedRoundTripper)
	if err == nil {
		t.Fatalf("FetchTactics succeeded unexpectedly with incorrect obfuscated key")
	}

	// When no keys are supplied, untunneled tactics requests are not supported, but
	// handshake tactics (GetTacticsPayload) should still work.

	tacticsConfig = fmt.Sprintf(
		tacticsConfigTemplate,
		"",
		"",
		"",
		tacticsNetworkLatencyMultiplier,
		tacticsConnectionWorkerPoolSize,
		jsonTacticsLimitTunnelProtocols,
		tacticsConnectionWorkerPoolSize+1)

	err = ioutil.WriteFile(configFileName, []byte(tacticsConfig), 0600)
	if err != nil {
		t.Fatalf("WriteFile failed: %s", err)
	}

	reloaded, err = server.Reload()
	if err != nil {
		t.Fatalf("Reload failed: %s", err)
	}

	if !reloaded {
		t.Fatalf("Server config failed to reload")
	}

	_, err = server.GetTacticsPayload(clientGeoIPData, handshakeParams, compressPayload)
	if err != nil {
		t.Fatalf("GetTacticsPayload failed: %s", err)
	}

	handled := server.HandleEndPoint(TACTICS_END_POINT, clientGeoIPData, nil, nil)
	if handled {
		t.Fatalf("HandleEndPoint unexpectedly handled request")
	}

	handled = server.HandleEndPoint(SPEED_TEST_END_POINT, clientGeoIPData, nil, nil)
	if handled {
		t.Fatalf("HandleEndPoint unexpectedly handled request")
	}

	// TODO: test replay attack defence
	// TODO: test Server.Validate with invalid tactics configurations
}

func TestTacticsFilterGeoIPScope(t *testing.T) {

	encodedRequestPublicKey, encodedRequestPrivateKey, encodedObfuscatedKey, err := GenerateKeys()
	if err != nil {
		t.Fatalf("GenerateKeys failed: %s", err)
	}

	// Exercise specifying keys in NewServer instead of config file.

	tacticsConfigTemplate := `
    {
      "DefaultTactics" : {
        "TTL" : "60s"
      },
      %s
    }
    `

	// Test: region-only scope

	filteredTactics := `
      "FilteredTactics" : [
        {
          "Filter" : {
            "Regions": ["R1", "R2", "R3"]
          }
        },
        {
          "Filter" : {
            "Regions": ["R4", "R5", "R6"]
          }
        }
      ]
	`

	tacticsConfig := fmt.Sprintf(tacticsConfigTemplate, filteredTactics)

	file, err := ioutil.TempFile("", "tactics.config")
	if err != nil {
		t.Fatalf("TempFile create failed: %s", err)
	}
	_, err = file.Write([]byte(tacticsConfig))
	if err != nil {
		t.Fatalf("TempFile write failed: %s", err)
	}
	file.Close()

	configFileName := file.Name()
	defer os.Remove(configFileName)

	server, err := NewServer(
		nil,
		nil,
		nil,
		configFileName,
		encodedRequestPublicKey,
		encodedRequestPrivateKey,
		encodedObfuscatedKey)
	if err != nil {
		t.Fatalf("NewServer failed: %s", err)
	}

	reload := func() {
		tacticsConfig = fmt.Sprintf(tacticsConfigTemplate, filteredTactics)

		err = ioutil.WriteFile(configFileName, []byte(tacticsConfig), 0600)
		if err != nil {
			t.Fatalf("WriteFile failed: %s", err)
		}

		reloaded, err := server.Reload()
		if err != nil {
			t.Fatalf("Reload failed: %s", err)
		}

		if !reloaded {
			t.Fatalf("Server config failed to reload")
		}
	}

	geoIPData := common.GeoIPData{
		Country: "R0",
		ISP:     "I0",
		ASN:     "0",
		City:    "C0",
	}

	scope := server.GetFilterGeoIPScope(geoIPData)

	if scope != GeoIPScopeRegion {
		t.Fatalf("unexpected scope: %b", scope)
	}

	// Test: ISP-only scope

	filteredTactics = `
      "FilteredTactics" : [
        {
          "Filter" : {
            "ISPs": ["I1", "I2", "I3"]
          }
        },
        {
          "Filter" : {
            "ISPs": ["I4", "I5", "I6"]
          }
        }
      ]
	`

	reload()

	scope = server.GetFilterGeoIPScope(geoIPData)

	if scope != GeoIPScopeISP {
		t.Fatalf("unexpected scope: %b", scope)
	}

	// Test: ASN-only scope

	filteredTactics = `
      "FilteredTactics" : [
        {
          "Filter" : {
            "ASNs": ["1", "2", "3"]
          }
        },
        {
          "Filter" : {
            "ASNs": ["4", "5", "6"]
          }
        }
      ]
	`

	reload()

	scope = server.GetFilterGeoIPScope(geoIPData)

	if scope != GeoIPScopeASN {
		t.Fatalf("unexpected scope: %b", scope)
	}

	// Test: City-only scope

	filteredTactics = `
      "FilteredTactics" : [
        {
          "Filter" : {
            "Cities": ["C1", "C2", "C3"]
          }
        },
        {
          "Filter" : {
            "Cities": ["C4", "C5", "C6"]
          }
        }
      ]
	`

	reload()

	scope = server.GetFilterGeoIPScope(geoIPData)

	if scope != GeoIPScopeCity {
		t.Fatalf("unexpected scope: %b", scope)
	}

	// Test: full scope

	filteredTactics = `
      "FilteredTactics" : [
        {
          "Filter" : {
            "Regions": ["R1", "R2", "R3"]
          }
        },
        {
          "Filter" : {
            "ISPs": ["I1", "I2", "I3"]
          }
        },
        {
          "Filter" : {
            "ASNs": ["1", "2", "3"]
          }
        },
        {
          "Filter" : {
            "Cities": ["C4", "C5", "C6"]
          }
        }
      ]
	`

	reload()

	scope = server.GetFilterGeoIPScope(geoIPData)

	if scope != GeoIPScopeRegion|GeoIPScopeISP|GeoIPScopeASN|GeoIPScopeCity {
		t.Fatalf("unexpected scope: %b", scope)
	}

	// Test: conditional scopes

	filteredTactics = `
      "FilteredTactics" : [
        {
          "Filter" : {
            "Regions": ["R1"]
          }
        },
        {
          "Filter" : {
            "Regions": ["R2"],
            "ISPs": ["I2a"]
          }
        },
        {
          "Filter" : {
            "Regions": ["R2"],
            "ISPs": ["I2b"]
          }
        },
        {
          "Filter" : {
            "Regions": ["R3"],
            "ISPs": ["I3a"],
            "Cities": ["C3a"]
          }
        },
        {
          "Filter" : {
            "Regions": ["R3"],
            "ISPs": ["I3b"],
            "Cities": ["C3b"]
          }
        },
        {
          "Filter" : {
            "Regions": ["R4"],
            "ASNs": ["4"]
          }
        },
        {
          "Filter" : {
            "Regions": ["R4"],
            "ASNs": ["4"]
          }
        },
        {
          "Filter" : {
            "Regions": ["R5"],
            "ASNs": ["5"],
            "Cities": ["C3a"]
          }
        },
        {
          "Filter" : {
            "Regions": ["R5"],
            "ASNs": ["5"],
            "Cities": ["C3b"]
          }
        }
      ]
	`

	reload()

	scope = server.GetFilterGeoIPScope(common.GeoIPData{Country: "R0"})

	if scope != GeoIPScopeRegion {
		t.Fatalf("unexpected scope: %b", scope)
	}

	scope = server.GetFilterGeoIPScope(common.GeoIPData{Country: "R1"})

	if scope != GeoIPScopeRegion {
		t.Fatalf("unexpected scope: %b", scope)
	}

	scope = server.GetFilterGeoIPScope(common.GeoIPData{Country: "R2"})

	if scope != GeoIPScopeRegion|GeoIPScopeISP {
		t.Fatalf("unexpected scope: %b", scope)
	}

	scope = server.GetFilterGeoIPScope(common.GeoIPData{Country: "R3"})

	if scope != GeoIPScopeRegion|GeoIPScopeISP|GeoIPScopeCity {
		t.Fatalf("unexpected scope: %b", scope)
	}

	scope = server.GetFilterGeoIPScope(common.GeoIPData{Country: "R4"})

	if scope != GeoIPScopeRegion|GeoIPScopeASN {
		t.Fatalf("unexpected scope: %b", scope)
	}

	scope = server.GetFilterGeoIPScope(common.GeoIPData{Country: "R5"})

	if scope != GeoIPScopeRegion|GeoIPScopeASN|GeoIPScopeCity {
		t.Fatalf("unexpected scope: %b", scope)
	}

	// Test: reset regional map optimization

	filteredTactics = `
      "FilteredTactics" : [
        {
          "Filter" : {
            "Regions": ["R1"],
            "ISPs": ["I1"]
          }
        },
        {
          "Filter" : {
            "Cities": ["C1"]
          }
        }
      ]
	`

	reload()

	scope = server.GetFilterGeoIPScope(common.GeoIPData{Country: "R0"})

	if scope != GeoIPScopeRegion|GeoIPScopeISP|GeoIPScopeCity {
		t.Fatalf("unexpected scope: %b", scope)
	}

	filteredTactics = `
      "FilteredTactics" : [
        {
          "Filter" : {
            "Regions": ["R1"],
            "Cities": ["C1"]
          }
        },
        {
          "Filter" : {
            "ISPs": ["I1"]
          }
        }
      ]
	`

	reload()

	scope = server.GetFilterGeoIPScope(common.GeoIPData{Country: "R0"})

	if scope != GeoIPScopeRegion|GeoIPScopeISP|GeoIPScopeCity {
		t.Fatalf("unexpected scope: %b", scope)
	}
}

type testStorer struct {
	tacticsRecords         map[string][]byte
	speedTestSampleRecords map[string][]byte
}

func newTestStorer() *testStorer {
	return &testStorer{
		tacticsRecords:         make(map[string][]byte),
		speedTestSampleRecords: make(map[string][]byte),
	}
}

func (s *testStorer) SetTacticsRecord(networkID string, record []byte) error {
	s.tacticsRecords[networkID] = record
	return nil
}

func (s *testStorer) GetTacticsRecord(networkID string) ([]byte, error) {
	return s.tacticsRecords[networkID], nil
}

func (s *testStorer) SetSpeedTestSamplesRecord(networkID string, record []byte) error {
	s.speedTestSampleRecords[networkID] = record
	return nil
}

func (s *testStorer) GetSpeedTestSamplesRecord(networkID string) ([]byte, error) {
	return s.speedTestSampleRecords[networkID], nil
}
