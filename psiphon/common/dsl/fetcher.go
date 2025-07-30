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
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/osl"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	"github.com/fxamacker/cbor/v2"
)

// FetcherRoundTripper is a pluggable round trip transport that sends requests
// to a relay and returns the corresponding response. The FetcherRoundTripper
// connection to a relay typically provides obfuscation and blocking
// resistance, enabling the client to reach the DSL backend via the relay.
//
// Round trippers include in-proxy broker clients, where the broker is a
// relay; and SSH tunnel requests, where the Psiphon server is the relay.
type FetcherRoundTripper func(
	ctx context.Context,
	requestPayload []byte) (responsePayload []byte, err error)

// FetcherConfig specifies the configuration for a Fetcher.
type FetcherConfig struct {
	Logger common.Logger

	BaseAPIParameters common.APIParameters

	RoundTripper FetcherRoundTripper

	DatastoreGetLastDiscoverTime func() (time.Time, error)
	DatastoreSetLastDiscoverTime func(time time.Time) error
	DatastoreHasServerEntry      func(tag ServerEntryTag, version int) bool
	DatastoreStoreServerEntry    func(
		serverEntryFields protocol.PackedServerEntryFields,
		source string) error

	DatastoreGetLastActiveOSLsTime func() (time.Time, error)
	DatastoreSetLastActiveOSLsTime func(time time.Time) error
	DatastoreKnownOSLIDs           func() (IDs []OSLID, err error)
	DatastoreGetOSLState           func(ID OSLID) (state []byte, notFound bool, err error)
	DatastoreStoreOSLState         func(ID OSLID, state []byte) error
	DatastoreDeleteOSLState        func(ID OSLID) error
	DatastoreSLOKLookup            osl.SLOKLookup
	DatastoreFatalError            func(error)

	RequestTimeout          time.Duration
	RequestRetryCount       int
	RequestRetryDelay       time.Duration
	RequestRetryDelayJitter float64

	DiscoverServerEntriesTTL      time.Duration
	DiscoverServerEntriesMinCount int
	DiscoverServerEntriesMaxCount int
	GetServerEntriesMinCount      int
	GetServerEntriesMaxCount      int
	GetLastActiveOSLsTTL          time.Duration
	GetOSLFileSpecsMinCount       int
	GetOSLFileSpecsMaxCount       int

	DoGarbageCollection func()
}

const (
	oslStateNoFileSpec  = 1
	oslStateHasFileSpec = 2
	oslStateHasKey      = 3
)

// fetcherOSLState is OSL state that's persisted to the datastore. For each
// active OSL, the Fetcher will progressively download and persist the
// corresponding FileSpec, and then attempt to reassemble the OSL key using
// the FileSpec, persist any reassembled keys, and ultimately prune old OSL
// state.
type fetcherOSLState struct {
	ID       OSLID       `cbor:"1,keyasint,omitempty"`
	State    int32       `cbor:"2,keyasint,omitempty"`
	FileSpec OSLFileSpec `cbor:"3,keyasint,omitempty"`
	Key      OSLKey      `cbor:"4,keyasint,omitempty"`
}

// Fetcher orchestrates discovering and downloading server entries from a DSL
// backend, via a relay. A Fetcher also synchronizes active OSL state and
// reassembles OSL keys to be used as discovery inputs.
type Fetcher struct {
	config              *FetcherConfig
	packedAPIParameters protocol.PackedAPIParameters
}

// NewFetcher creates a new Fetcher.
func NewFetcher(config *FetcherConfig) (*Fetcher, error) {

	packedAPIParameters, err := protocol.EncodePackedAPIParameters(
		config.BaseAPIParameters)
	if err != nil {
		return nil, errors.Trace(err)
	}

	return &Fetcher{
		config:              config,
		packedAPIParameters: packedAPIParameters,
	}, nil
}

// Run performs a server entry discovery/download and OSL synchronization
// sequence.
//
// Run supports two modes:
//   - Frequent, intended for fetching via an established SSH tunnel, and
//     discovering only a small number of servers. Frequent fetches can be
//     repeated often.
//   - Non-frequent, intended for fetching via an untunneled relay, and invoked
//     after a client is unable to connect with its known servers. This fetch
//     mode is intended for discovering a larger number of servers, and is
//     subject to the DiscoverServerEntriesTTL, which skips repeated runs.
//
// Each Run may make incremental progress. New OSL state or new server entries
// may be downloaded and persisted even when Run ultimately fails and returns
// an error.
//
// Run will stop and return immediately when the input ctx is done.
//
// Data is processed incrementally and DoGarbageCollection is invoked
// periodically in order to limit the overall memory footprint of the Run.
//
// The caller MUST:
//
//   - Schedule Fetcher runs when appropriate: when the client is unable to
//     connect, a full, non-frequent, untunneled fetcher run should be
//     triggered to potentially discover a large selection of servers; when the
//     client connects, a frequent fetcher run should be triggered to discover
//     a small number of servers.
//
//   - Configure DiscoverServerEntriesMin/MaxCount using appropriate parameters
//     for the frequence/non-frequent mode.
//
//   - Provide a cooldown time or delay between repeated Run calls when Run
//     returns an error.
//
//   - Cease all Run invocations if the DatastoreFatalError callback is invoked.
//     In this case, a set-last-time datastore operation required for the
//     DiscoverServerEntriesTTL/GetLastActiveOSLsTTL mechanism has failed. The
//     calling client should not invoke Run again until after a Stop/Start
//     cycle.
//
//   - Ensure that there's only one concurrent fetcher run. The datastore
//     operations are intended for incremental, persistent progress and
//     multiple concurrent runs may interleave conflicting datastore calls.
//     This requirement means that if there's an ongoing untunneled fetcher run
//     and a tunnel is established, any post-connected, frequent fetcher run
//     must be skipped or postponed.
func (f *Fetcher) Run(ctx context.Context, isFrequent bool) error {

	if !isFrequent {

		lastTime, err := f.config.DatastoreGetLastDiscoverTime()
		if err != nil {
			return errors.Trace(err)
		}

		if time.Now().Before(lastTime.Add(f.config.DiscoverServerEntriesTTL)) {
			return nil
		}
	}

	// processOSLs will:
	//
	// - check for new active OSLs, subject to GetLastActiveOSLsTTL
	// - download any OSL FileSpecs for known, active OSL IDs
	// - attempt to reassemble OSL keys for any unassembled OSLs
	// - return the list of assembled, active OSL keys

	OSLKeys, oslErr := f.processOSLs(ctx)
	if oslErr != nil {
		f.config.Logger.WithTraceFields(common.LogFields{
			"error": oslErr.Error(),
		}).Warning("DSL: process OSLs failed")
		// Proceed without OSL keys
	}

	// Discover server entries, identified by tag.

	// Vary the size of the requested response to avoid a trivial traffic
	// fingerprint.
	discoverCount := prng.Range(
		f.config.DiscoverServerEntriesMinCount,
		f.config.DiscoverServerEntriesMaxCount)

	versionedTags, err := f.doDiscoverServerEntriesRequest(
		ctx,
		OSLKeys,
		discoverCount)
	if err != nil {
		return errors.Trace(err)
	}

	// Check each discovered server entry tag and version. Skip when the
	// tag/version is already in the local datastore. Fetch the unknown or
	// updated server entries in batches.
	//
	// Datastore transactions are per server entry, to allow for incremental
	// progress in case of an error.

	storeServerEntriesCount := 0
	knownServerEntriesCount := 0
	defer func() {
		// Emit log even if not all fetches succeed.
		f.config.Logger.WithTraceFields(common.LogFields{
			"tags":    len(versionedTags),
			"updated": storeServerEntriesCount,
			"known":   knownServerEntriesCount,
		}).Info("DSL: fetched server entries")
	}()

	var getTags []ServerEntryTag
	for _, v := range versionedTags {
		if f.config.DatastoreHasServerEntry(v.Tag, int(v.Version)) {
			knownServerEntriesCount += 1
			continue
		}
		getTags = append(getTags, v.Tag)
	}

	for len(getTags) > 0 {

		// Vary the size of the request and response.
		getCount := prng.Range(
			f.config.GetServerEntriesMinCount,
			f.config.GetServerEntriesMaxCount)

		getBatch := getTags
		if len(getBatch) > getCount {
			getBatch = getBatch[:getCount]
		}

		sourcedServerEntries, err := f.doGetServerEntriesRequest(ctx, getBatch)
		if err != nil {
			return errors.Trace(err)
		}

		for _, sourcedEntry := range sourcedServerEntries {

			if sourcedEntry == nil {
				// The requested server entry is no longer distributable or
				// doesn't exist.
				continue
			}

			err := f.config.DatastoreStoreServerEntry(
				sourcedEntry.ServerEntryFields,
				sourcedEntry.Source)
			if err != nil {
				return errors.Trace(err)
			}
			storeServerEntriesCount += 1
		}

		// doGetServerEntriesRequest will retry failed requests and reduces
		// the number of requested server entries in each retry. Adjust
		// getTags in case less than the initial getBatch were fetched.
		// Unfetched server entries will be added to the next batch.

		getTags = getTags[len(sourcedServerEntries):]

		f.config.DoGarbageCollection()
	}

	if !isFrequent {
		err = f.config.DatastoreSetLastDiscoverTime(time.Now())
		if err != nil {
			err = errors.Trace(err)

			// Signal a fatal datastore error. The caller should not run any
			// Fetcher again, for the duration of its process, since the
			// LastDiscoverTime mechanism won't prevent excess repeats.

			f.config.DatastoreFatalError(err)
			f.config.Logger.WithTraceFields(common.LogFields{
				"error": err.Error(),
			}).Warning("DSL: datastore failed")
			// Proceed with this one run
		}
	}

	if oslErr != nil {
		return errors.Trace(oslErr)
	}

	return nil
}

func (f *Fetcher) processOSLs(ctx context.Context) ([]OSLKey, error) {

	lastTime, err := f.config.DatastoreGetLastActiveOSLsTime()
	if err != nil {
		// TODO: proceed, but skip GetActiveOSLsRequest?
		return nil, errors.Trace(err)
	}

	now := time.Now()

	if now.After(lastTime.Add(f.config.GetLastActiveOSLsTTL)) {

		// When the last GetActiveOSLsRequest fetch expires, request the
		// current active OSLs again. Prune any locally stored OSL states for
		// OSLs that are no longer active. Add new OSL states for previously
		// unknown OSLs. These new OSLs states will trigger OSL FileSpec
		// fetches in the next step.

		// The size of the request and response is not varied in this case. In
		// practise, the number of active OSL IDs is expected to be
		// relatively small. The obfuscation hops to the relay should add a
		// small amount of random padding.
		activeOSLIDs, err := f.doGetActiveOSLsRequest(ctx)
		if err != nil {
			return nil, errors.Trace(err)
		}

		// Load known OSL states without attempting to reassemble OSL keys.

		knownOSLStates, err := f.loadOSLStates(ctx, false)
		if err != nil {
			return nil, errors.Trace(err)
		}

		addedCount := 0
		removedCount := 0

		for _, activeID := range activeOSLIDs {
			isKnown := false
			for _, knownState := range knownOSLStates {
				if bytes.Equal(activeID, knownState.ID) {
					isKnown = true
					break
				}
			}
			if !isKnown {
				err := f.storeOSLState(
					activeID,
					&fetcherOSLState{
						ID:    activeID,
						State: oslStateNoFileSpec,
					})
				if err != nil {
					return nil, errors.Trace(err)
				}
				addedCount += 1
			}
		}

		for _, knownState := range knownOSLStates {
			isActive := false
			for _, activeID := range activeOSLIDs {
				if bytes.Equal(activeID, knownState.ID) {
					isActive = true
					break
				}
			}
			if !isActive {
				err := f.config.DatastoreDeleteOSLState(knownState.ID)
				if err != nil {
					return nil, errors.Trace(err)
				}
				removedCount += 1
			}
		}

		f.config.DoGarbageCollection()

		f.config.Logger.WithTraceFields(common.LogFields{
			"total":   len(activeOSLIDs),
			"added":   addedCount,
			"removed": removedCount,
		}).Info("DSL: fetched active OSL IDs")

		err = f.config.DatastoreSetLastActiveOSLsTime(now)
		if err != nil {
			err = errors.Trace(err)

			// Signal a fatal datastore error. The caller should not run any
			// Fetcher again, for the duration of its process, since the
			// LastActiveOSLsTime mechanism won't prevent excess repeats.

			f.config.DatastoreFatalError(errors.Trace(err))

			f.config.Logger.WithTraceFields(common.LogFields{
				"error": err.Error(),
			}).Warning("DSL: datastore failed")
			// Proceed with this one run
		}
	}

	// Load known OSL states, attempting to reassemble OSL keys. Any newly
	// assembled keys will be stored back to the datastore, caching the
	// assembly. For OSLs in the no-FileSpec state, the missing FileSpecs
	// will be fetched.

	knownOSLStates, err := f.loadOSLStates(ctx, true)
	if err != nil {
		return nil, errors.Trace(err)
	}

	addedSpecCount := 0
	removedSpecCount := 0
	defer func() {
		// Emit log even if not all fetches succeed.
		if addedSpecCount > 0 || removedSpecCount > 0 {
			f.config.Logger.WithTraceFields(common.LogFields{
				"added":   addedSpecCount,
				"removed": removedSpecCount,
			}).Info("DSL: fetched OSL FileSpecs")
		}
	}()

	var getFileSpecs []OSLID
	for _, knownState := range knownOSLStates {
		if knownState.State == oslStateHasFileSpec ||
			knownState.State == oslStateHasKey {
			continue
		}
		getFileSpecs = append(getFileSpecs, knownState.ID)
	}

	for len(getFileSpecs) > 0 {

		// Vary the size of the request and response.
		getCount := prng.Range(
			f.config.GetOSLFileSpecsMinCount,
			f.config.GetOSLFileSpecsMaxCount)

		getBatch := getFileSpecs
		if len(getBatch) > getCount {
			getBatch = getBatch[:getCount]
		}

		fileSpecs, err := f.doGetOSLFileSpecsRequest(ctx, getBatch)
		if err != nil {
			return nil, errors.Trace(err)
		}

		for i, fileSpec := range fileSpecs {

			if len(fileSpec) > 0 {

				err := f.storeOSLState(
					getFileSpecs[i],
					&fetcherOSLState{
						ID:       getFileSpecs[i],
						State:    oslStateHasFileSpec,
						FileSpec: fileSpec})
				if err != nil {
					return nil, errors.Trace(err)
				}
				addedSpecCount += 1

			} else {

				// A nil/empty FileSpec in the response indicates that the
				// requested OSL ID is invalid or no longer active. Prune the OSL state.
				err := f.config.DatastoreDeleteOSLState(getBatch[i])
				if err != nil {
					return nil, errors.Trace(err)
				}
				removedSpecCount += 1
			}
		}

		// doGetOSLFileSpecsRequest will retry failed requests and reduces
		// the number of requested OSL FileSpecs in each retry. Adjust
		// getFileSpecs in case less than the initial getBatch were fetched.
		// Unfetched FileSpecs will be added to the next batch.

		getFileSpecs = getFileSpecs[len(fileSpecs):]

		f.config.DoGarbageCollection()
	}

	if addedSpecCount > 0 || removedSpecCount > 0 {

		// Repeat attempting to reassemble OSL keys, since new FileSpecs were
		// downloaded. This case also prunes any now-removed OSLs so their keys
		// will not be included in the return value.

		knownOSLStates, err = f.loadOSLStates(ctx, true)
		if err != nil {
			return nil, errors.Trace(err)
		}
	}

	var keys []OSLKey
	for _, knownState := range knownOSLStates {
		if knownState.State == oslStateHasKey {
			keys = append(keys, knownState.Key)
		}
	}

	return keys, nil
}

func (f *Fetcher) doDiscoverServerEntriesRequest(
	ctx context.Context,
	keys []OSLKey,
	discoverCount int) ([]VersionedServerEntryTag, error) {

	// Perform the request with retries. On each retry, reduce the requested
	// response size to mitigate blocking or performance issues with larger
	// responses.

	for i := 0; ; i++ {

		// All known OSL keys are sent in the request. In practise, the number
		// of active OSL IDs is expected to be relatively small.

		request := &DiscoverServerEntriesRequest{
			BaseAPIParameters: f.packedAPIParameters,
			OSLKeys:           keys,
			DiscoverCount:     int32(discoverCount),
		}

		var response *DiscoverServerEntriesResponse
		doRetry, err := f.doRelayedRequest(
			ctx, requestTypeDiscoverServerEntries, request, &response)

		if err == nil {
			return response.VersionedServerEntryTags, nil
		}

		if i >= f.config.RequestRetryCount || !doRetry || ctx.Err() != nil {
			return nil, errors.Trace(err)
		}

		f.config.Logger.WithTraceFields(common.LogFields{
			"discoverCount": discoverCount,
			"error":         err.Error(),
		}).Warning("DSL: doDiscoverServerEntriesRequest failed")

		common.SleepWithContext(
			ctx,
			prng.JitterDuration(
				f.config.RequestRetryDelay,
				f.config.RequestRetryDelayJitter))

		if discoverCount > 1 {
			discoverCount /= 2
		}
	}
}

func (f *Fetcher) doGetServerEntriesRequest(
	ctx context.Context,
	tags []ServerEntryTag) ([]*SourcedServerEntry, error) {

	// Perform the request with retries. On each retry, reduce the requested
	// response size to mitigate blocking or performance issues with larger
	// responses.

	for i := 0; ; i++ {

		request := &GetServerEntriesRequest{
			BaseAPIParameters: f.packedAPIParameters,
			ServerEntryTags:   tags,
		}

		var response *GetServerEntriesResponse
		doRetry, err := f.doRelayedRequest(
			ctx, requestTypeGetServerEntries, request, &response)

		if err == nil && len(tags) != len(response.SourcedServerEntries) {
			err = errors.TraceNew("unexpected server entry count")
		}

		if err == nil {
			return response.SourcedServerEntries, nil
		}

		if i >= f.config.RequestRetryCount || !doRetry || ctx.Err() != nil {
			return nil, errors.Trace(err)
		}

		f.config.Logger.WithTraceFields(common.LogFields{
			"attempt":  i,
			"tagCount": len(tags),
			"error":    err.Error(),
		}).Warning("DSL: doGetServerEntriesRequest attempt failed")

		common.SleepWithContext(
			ctx,
			prng.JitterDuration(
				f.config.RequestRetryDelay,
				f.config.RequestRetryDelayJitter))

		if len(tags) > 1 {
			n := len(tags) / 2
			tags = tags[:n]
		}
	}
}

func (f *Fetcher) doGetActiveOSLsRequest(ctx context.Context) ([]OSLID, error) {

	// Perform the request with retries. The response always includes all
	// current, active OSL IDs and is not reduced on retry.

	for i := 0; ; i++ {

		request := &GetActiveOSLsRequest{
			BaseAPIParameters: f.packedAPIParameters,
		}

		var response *GetActiveOSLsResponse
		doRetry, err := f.doRelayedRequest(
			ctx, requestTypeGetActiveOSLs, request, &response)
		if err == nil {
			return response.ActiveOSLIDs, nil
		}

		if i >= f.config.RequestRetryCount || !doRetry || ctx.Err() != nil {
			return nil, errors.Trace(err)
		}

		f.config.Logger.WithTraceFields(common.LogFields{
			"attempt": i,
			"error":   err.Error(),
		}).Warning("DSL: doGetActiveOSLsRequest attempt failed")

		common.SleepWithContext(
			ctx,
			prng.JitterDuration(
				f.config.RequestRetryDelay,
				f.config.RequestRetryDelayJitter))
	}
}

func (f *Fetcher) doGetOSLFileSpecsRequest(
	ctx context.Context, IDs []OSLID) ([]OSLFileSpec, error) {

	// Perform the request with retries. On each retry, reduce the requested
	// response size to mitigate blocking or performance issues with larger
	// responses.

	for i := 0; ; i++ {

		request := &GetOSLFileSpecsRequest{
			BaseAPIParameters: f.packedAPIParameters,
			OSLIDs:            IDs,
		}

		var response *GetOSLFileSpecsResponse
		doRetry, err := f.doRelayedRequest(
			ctx, requestTypeGetOSLFileSpecs, request, &response)

		if err == nil && len(IDs) != len(response.OSLFileSpecs) {
			err = errors.TraceNew("unexpected OSL file spec count")
		}

		if err == nil {
			return response.OSLFileSpecs, nil
		}

		if i >= f.config.RequestRetryCount || !doRetry || ctx.Err() != nil {
			return nil, errors.Trace(err)
		}

		f.config.Logger.WithTraceFields(common.LogFields{
			"attempt":    i,
			"OSLIDCount": len(IDs),
			"error":      err.Error(),
		}).Warning("DSL: doGetOSLFileSpecsRequest attempt failed")

		common.SleepWithContext(
			ctx,
			prng.JitterDuration(
				f.config.RequestRetryDelay,
				f.config.RequestRetryDelayJitter))

		if len(IDs) > 1 {
			n := len(IDs) / 2
			IDs = IDs[:n]
		}
	}
}

func (f *Fetcher) doRelayedRequest(
	ctx context.Context,
	requestType int32,
	request any,
	response any) (retRetry bool, retErr error) {

	// Add the relay wrapping.

	cborRequest, err := protocol.CBOREncoding.Marshal(request)
	if err != nil {
		return false, errors.Trace(err)
	}

	cborRelayedRequest, err := protocol.CBOREncoding.Marshal(
		&RelayedRequest{
			RequestType: requestType,
			Version:     requestVersion,
			Request:     cborRequest,
		})
	if err != nil {
		return false, errors.Trace(err)
	}

	if len(cborRelayedRequest) > MaxRelayPayloadSize {
		return false, errors.Tracef(
			"request size %d exceeds limit %d", len(cborRelayedRequest), MaxRelayPayloadSize)
	}

	// Relay the request via the supplied RoundTripper.

	requestCtx := ctx
	if f.config.RequestTimeout > 0 {
		var requestCancelFunc context.CancelFunc
		requestCtx, requestCancelFunc = context.WithTimeout(ctx, f.config.RequestTimeout)
		defer requestCancelFunc()
	}

	cborRelayedResponse, err := f.config.RoundTripper(requestCtx, cborRelayedRequest)
	if err != nil {
		// Allow retries for in case of intermittent network failures or
		// potential blocking.
		//
		// TODO: check for specific retry-eligible errors from the RoundTripper?
		return true, errors.Trace(err)
	}

	// Remove the relay wrapping.

	var relayedResponse *RelayedResponse
	err = cbor.Unmarshal(cborRelayedResponse, &relayedResponse)
	if err != nil {
		return false, errors.Trace(err)
	}

	if relayedResponse.Error != 0 {
		// No retries if a response was received from the DSL backend.
		return false, errors.Tracef(
			"RelayedResponse.Error: %d", relayedResponse.Error)
	}

	err = cbor.Unmarshal(relayedResponse.Response, response)
	if err != nil {
		return false, errors.Trace(err)
	}

	return false, nil
}

func (f *Fetcher) loadOSLStates(ctx context.Context, reassembleKeys bool) ([]*fetcherOSLState, error) {

	// Load just the set of known OSL IDs, and then process each OSL state one
	// at a time, to avoid loading all states into memory at once.

	activeIDs, err := f.config.DatastoreKnownOSLIDs()
	if err != nil {
		return nil, errors.Trace(err)
	}

	var states []*fetcherOSLState

	for _, ID := range activeIDs {

		cborState, found, err := f.config.DatastoreGetOSLState(ID)
		if err != nil {
			return nil, errors.Trace(err)
		}

		if !found {
			// This case is not expected since DatastoreKnownOSLIDs returns
			// only known IDs.
			continue
		}

		var state *fetcherOSLState
		err = cbor.Unmarshal(cborState, &state)
		if err != nil {
			return nil, errors.Trace(err)
		}

		if !bytes.Equal(ID, state.ID) {
			return nil, errors.TraceNew("unexpected OSL ID")
		}
		// TODO: sanity check FileSpec/Key fields match State?

		if state.State == oslStateHasFileSpec {

			// When we have the FileSpec, but not the reassembled key, attempt
			// reassembly from SLOKs. A reassembled key is stored back to the
			// datastore.

			if reassembleKeys {

				var fileSpec *osl.OSLFileSpec
				err = cbor.Unmarshal(state.FileSpec, &fileSpec)
				if err != nil {
					return nil, errors.Trace(err)
				}

				ok, key, err := osl.ReassembleOSLKey(fileSpec, f.config.DatastoreSLOKLookup)
				if err != nil {
					return nil, errors.Trace(err)
				}
				if ok {

					// Without the guarantee that there's only one concurrent
					// fetcher run, it's possible, with two concurrent
					// fetchers, that one prunes an OSL state after
					// GetActiveOSLsRequest, while the other calls
					// storeOSLState and incorrectly restores the pruned state.

					state.State = oslStateHasKey
					state.Key = key
					state.FileSpec = nil
					err = f.storeOSLState(ID, state)
					if err != nil {
						return nil, errors.Trace(err)
					}
				}
				f.config.Logger.WithTrace().Info("DSL: reassembled OSL key")
			}

			// Allow state.FileSpec to be garbage collected.
			state.FileSpec = nil

			f.config.DoGarbageCollection()
		}

		states = append(states, state)
	}

	return states, nil
}

func (f *Fetcher) storeOSLState(ID OSLID, state *fetcherOSLState) error {

	cborState, err := protocol.CBOREncoding.Marshal(state)
	if err != nil {
		return errors.Trace(err)
	}

	err = f.config.DatastoreStoreOSLState(ID, cborState)
	if err != nil {
		return errors.Trace(err)
	}

	return nil
}
