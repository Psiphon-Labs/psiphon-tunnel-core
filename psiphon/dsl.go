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

package psiphon

import (
	"context"
	"sync/atomic"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/dsl"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/inproxy"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/parameters"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
)

func runUntunneledDSLFetcher(
	ctx context.Context,
	config *Config,
	brokerClientManager *InproxyBrokerClientManager,
	signal <-chan struct{}) {

	NoticeInfo("running untunneled DSL fetcher")

fetcherLoop:
	for !disableDSLFetches.Load() {

		select {
		case <-signal:
		case <-ctx.Done():
			break fetcherLoop
		}

		isTunneled := false

		err := func() error {

			brokerClient, _, err := brokerClientManager.GetBrokerClient(config.GetNetworkID())
			if err != nil {
				return errors.Trace(err)
			}

			roundTripper := func(
				ctx context.Context,
				requestPayload []byte) ([]byte, error) {

				response, err := brokerClient.ClientDSL(
					ctx,
					&inproxy.ClientDSLRequest{
						RequestPayload: requestPayload,
					})
				if err != nil {
					return nil, errors.Trace(err)
				}
				return response.ResponsePayload, nil
			}

			// Detailed logging, retries, last request times, and
			// WaitForNetworkConnectivity are all handled inside dsl.Fetcher.

			// There is no equivilent to RecordRemoteServerListStat or
			// remote_server_list, since the DSL backend will log DSL request events.
			//
			// TODO: add a failed_dsl_request log, similar to failed_tunnel,
			// to record and report failures?

			err = doDSLFetch(ctx, config, isTunneled, roundTripper)
			if err != nil {
				return errors.Trace(err)
			}

			return nil
		}()

		if err != nil {
			NoticeError("untunneled DSL fetch failed: %v", errors.Trace(err))
			// No cooldown pause, since controller.triggerFetches isn't be
			// called in a tight loop.
		}
	}

	NoticeInfo("exiting untunneled DSL fetcher")
}

func runTunneledDSLFetcher(
	ctx context.Context,
	config *Config,
	getActiveTunnel func() *Tunnel,
	signal <-chan struct{}) {

	NoticeInfo("running tunneled DSL fetcher")

fetcherLoop:
	for !disableDSLFetches.Load() {

		select {
		case <-signal:
		case <-ctx.Done():
			break fetcherLoop
		}

		tunnel := getActiveTunnel()
		if tunnel == nil {
			continue
		}

		isTunneled := true

		roundTripper := func(
			ctx context.Context,
			requestPayload []byte) ([]byte, error) {

			// The request ctx is ignored; tunnel.SendAPIRequest does not
			// support a request context. In practise, the input ctx is
			// controller.runCtx which includes the full lifetime of the
			// tunnel. When a tunnel closes, any in-flight SendAPIRequest
			// will be interrupted and not block.

			responsePayload, err := tunnel.SendAPIRequest(
				protocol.PSIPHON_API_DSL_REQUEST_NAME, requestPayload)
			return responsePayload, errors.Trace(err)
		}

		// Detailed logging, retries, last request times, and
		// WaitForNetworkConnectivity are all handled inside dsl.Fetcher.

		err := doDSLFetch(ctx, config, isTunneled, roundTripper)
		if err != nil {
			NoticeError("tunneled DSL fetch failed: %v", errors.Trace(err))
			// No cooldown pause, since runTunneledDSLFetcher is called only
			// once after fully connecting.
		}
	}

	NoticeInfo("exiting tunneled DSL fetcher")
}

func doDSLFetch(
	ctx context.Context,
	config *Config,
	isTunneled bool,
	roundTripper dsl.FetcherRoundTripper) error {

	var paddingPRNG *prng.PRNG
	if isTunneled {

		// For a tunneled request, padding is added via the params since
		// there's no random padding at the SSH request layer. The PRNG seed
		// is not replayed.
		paddingPRNG = prng.DefaultPRNG()
	}

	includeSessionID := true
	baseAPIParams := getBaseAPIParameters(
		baseParametersNoDialParameters,
		paddingPRNG,
		includeSessionID,
		config,
		nil)

	// Copied from FetchObfuscatedServerLists.
	//
	// Prevent excessive notice noise in cases such as a general database
	// failure, as GetSLOK may be called thousands of times per fetch.
	emittedGetSLOKAlert := int32(0)
	lookupSLOKs := func(slokID []byte) []byte {
		key, err := GetSLOK(slokID)
		if err != nil && atomic.CompareAndSwapInt32(&emittedGetSLOKAlert, 0, 1) {
			NoticeWarning("GetSLOK failed: %s", err)
		}
		return key
	}

	c := &dsl.FetcherConfig{
		Logger:            NoticeCommonLogger(false),
		BaseAPIParameters: baseAPIParams,
		RoundTripper:      roundTripper,

		DatastoreHasServerEntry:        DSLHasServerEntry,
		DatastoreStoreServerEntry:      DSLStoreServerEntry,
		DatastoreGetLastActiveOSLsTime: DSLGetLastActiveOSLsTime,
		DatastoreSetLastActiveOSLsTime: DSLSetLastActiveOSLsTime,
		DatastoreKnownOSLIDs:           DSLKnownOSLIDs,
		DatastoreGetOSLState:           DSLGetOSLState,
		DatastoreStoreOSLState:         DSLStoreOSLState,
		DatastoreDeleteOSLState:        DSLDeleteOSLState,
		DatastoreSLOKLookup:            lookupSLOKs,
		DatastoreFatalError:            onDSLDatastoreFatalError,

		DoGarbageCollection: DoGarbageCollection,
	}

	p := config.GetParameters().Get()
	if isTunneled {

		c.DatastoreGetLastFetchTime = DSLGetLastTunneledFetchTime
		c.DatastoreSetLastFetchTime = DSLSetLastTunneledFetchTime

		c.RequestTimeout = p.Duration(parameters.DSLFetcherTunneledRequestTimeout)
		c.RequestRetryCount = p.Int(parameters.DSLFetcherTunneledRequestRetryCount)
		c.RequestRetryDelay = p.Duration(parameters.DSLFetcherTunneledRequestRetryDelay)
		c.RequestRetryDelayJitter = p.Float(parameters.DSLFetcherTunneledRequestRetryDelayJitter)
		c.FetchTTL = p.Duration(parameters.DSLFetcherTunneledFetchTTL)
		c.DiscoverServerEntriesMinCount = p.Int(parameters.DSLFetcherTunneledDiscoverServerEntriesMinCount)
		c.DiscoverServerEntriesMaxCount = p.Int(parameters.DSLFetcherTunneledDiscoverServerEntriesMaxCount)
		c.GetServerEntriesMinCount = p.Int(parameters.DSLFetcherTunneledGetServerEntriesMinCount)
		c.GetServerEntriesMaxCount = p.Int(parameters.DSLFetcherTunneledGetServerEntriesMaxCount)

		// WaitForNetworkConnectivity is not wired up in this case since
		// tunnel must be connected. If the tunnel becomes disconnected due
		// to loss of network connectivity, prefer to fail this request and
		// try again, with a new tunnel, after reconnecting.

	} else {

		c.DatastoreGetLastFetchTime = DSLGetLastUntunneledFetchTime
		c.DatastoreSetLastFetchTime = DSLSetLastUntunneledFetchTime

		c.RequestTimeout = p.Duration(parameters.DSLFetcherUntunneledRequestTimeout)
		c.RequestRetryCount = p.Int(parameters.DSLFetcherUntunneledRequestRetryCount)
		c.RequestRetryDelay = p.Duration(parameters.DSLFetcherUntunneledRequestRetryDelay)
		c.RequestRetryDelayJitter = p.Float(parameters.DSLFetcherUntunneledRequestRetryDelayJitter)
		c.FetchTTL = p.Duration(parameters.DSLFetcherUntunneledFetchTTL)
		c.DiscoverServerEntriesMinCount = p.Int(parameters.DSLFetcherUntunneledDiscoverServerEntriesMinCount)
		c.DiscoverServerEntriesMaxCount = p.Int(parameters.DSLFetcherUntunneledDiscoverServerEntriesMaxCount)
		c.GetServerEntriesMinCount = p.Int(parameters.DSLFetcherUntunneledGetServerEntriesMinCount)
		c.GetServerEntriesMaxCount = p.Int(parameters.DSLFetcherUntunneledGetServerEntriesMaxCount)

		c.WaitForNetworkConnectivity = func() bool {
			return WaitForNetworkConnectivity(ctx, config.NetworkConnectivityChecker, nil)
		}

	}
	c.GetLastActiveOSLsTTL = p.Duration(parameters.DSLFetcherGetLastActiveOSLsTTL)
	c.GetOSLFileSpecsMinCount = p.Int(parameters.DSLFetcherGetOSLFileSpecsMinCount)
	c.GetOSLFileSpecsMaxCount = p.Int(parameters.DSLFetcherGetOSLFileSpecsMaxCount)
	p.Close()

	fetcher, err := dsl.NewFetcher(c)
	if err != nil {
		return errors.Trace(err)
	}

	err = fetcher.Run(ctx)
	if err != nil {
		return errors.Trace(err)
	}

	return nil
}

var disableDSLFetches atomic.Bool

func onDSLDatastoreFatalError(_ error) {

	// Halt all DSL requests for the duration of the process on a
	// DatastoreFatalError, which includes failure to set the last request
	// time. This avoids continuous DSL request in this scenario.

	disableDSLFetches.Store(true)
}
