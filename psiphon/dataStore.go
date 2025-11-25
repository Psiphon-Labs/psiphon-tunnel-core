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

package psiphon

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/dsl"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/parameters"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
)

var (
	datastoreServerEntriesBucket                = []byte("serverEntries")
	datastoreServerEntryTagsBucket              = []byte("serverEntryTags")
	datastoreServerEntryTombstoneTagsBucket     = []byte("serverEntryTombstoneTags")
	datastoreUrlETagsBucket                     = []byte("urlETags")
	datastoreKeyValueBucket                     = []byte("keyValues")
	datastoreRemoteServerListStatsBucket        = []byte("remoteServerListStats")
	datastoreFailedTunnelStatsBucket            = []byte("failedTunnelStats")
	datastoreSLOKsBucket                        = []byte("SLOKs")
	datastoreTacticsBucket                      = []byte("tactics")
	datastoreSpeedTestSamplesBucket             = []byte("speedTestSamples")
	datastoreDialParametersBucket               = []byte("dialParameters")
	datastoreNetworkReplayParametersBucket      = []byte("networkReplayParameters")
	datastoreDSLOSLStatesBucket                 = []byte("dslOSLStates")
	datastoreLastConnectedKey                   = "lastConnected"
	datastoreLastServerEntryFilterKey           = []byte("lastServerEntryFilter")
	datastoreAffinityServerEntryIDKey           = []byte("affinityServerEntryID")
	datastoreInproxyCommonCompartmentIDsKey     = []byte("inproxyCommonCompartmentIDs")
	datastorePersistentStatTypeRemoteServerList = string(datastoreRemoteServerListStatsBucket)
	datastorePersistentStatTypeFailedTunnel     = string(datastoreFailedTunnelStatsBucket)
	datastoreCheckServerEntryTagsEndTimeKey     = "checkServerEntryTagsEndTime"
	datastoreDSLLastUntunneledFetchTimeKey      = "dslLastUntunneledDiscoverTime"
	datastoreDSLLastTunneledFetchTimeKey        = "dslLastTunneledDiscoverTime"
	datastoreDSLLastActiveOSLsTimeKey           = "dslLastActiveOSLsTime"

	datastoreServerEntryFetchGCThreshold = 10

	datastoreReferenceCountMutex  sync.RWMutex
	datastoreReferenceCount       int64
	datastoreMutex                sync.RWMutex
	activeDatastoreDB             *datastoreDB
	disableCheckServerEntryTags   atomic.Bool
	datastoreLastServerEntryCount atomic.Int64
)

func init() {
	datastoreLastServerEntryCount.Store(-1)
}

// OpenDataStore opens and initializes the singleton datastore instance.
//
// Nested Open/CloseDataStore calls are supported: OpenDataStore will succeed
// when called when the datastore is initialized. Every call to OpenDataStore
// must be paired with a corresponding call to CloseDataStore to ensure the
// datastore is closed.
func OpenDataStore(config *Config) error {
	return openDataStore(config, true)
}

// OpenDataStoreWithoutRetry performs an OpenDataStore but does not retry or
// reset the datastore file in case of failures. Use
// OpenDataStoreWithoutRetry when the datastore is expected to be locked by
// another process and faster failure is preferred.
func OpenDataStoreWithoutRetry(config *Config) error {
	return openDataStore(config, false)
}

func openDataStore(config *Config, retryAndReset bool) error {

	// The datastoreReferenceCountMutex/datastoreMutex mutex pair allow for:
	//
	// _Nested_ OpenDataStore/CloseDataStore calls to not block when a
	// datastoreView is in progress (for example, a GetDialParameters call while
	// a slow ScanServerEntries is running). In this case the nested
	// OpenDataStore/CloseDataStore calls will lock only
	// datastoreReferenceCountMutex and not datastoreMutex.
	//
	// Synchronized access, for OpenDataStore/CloseDataStore, to
	// activeDatastoreDB based on a consistent view of datastoreReferenceCount
	// via locking first datastoreReferenceCount and then datastoreMutex while
	// holding datastoreReferenceCount.
	//
	// Concurrent access, for datastoreView/datastoreUpdate, to activeDatastoreDB
	// via datastoreMutex read locks.
	//
	// Exclusive access, for OpenDataStore/CloseDataStore, to activeDatastoreDB,
	// with no running datastoreView/datastoreUpdate, by aquiring a
	// datastoreMutex write lock.

	datastoreReferenceCountMutex.Lock()

	if datastoreReferenceCount < 0 || datastoreReferenceCount == math.MaxInt64 {
		datastoreReferenceCountMutex.Unlock()
		return errors.Tracef(
			"invalid datastore reference count: %d", datastoreReferenceCount)
	}

	if datastoreReferenceCount > 0 {

		// For this sanity check, we need only the read-only lock; and must use the
		// read-only lock to allow concurrent datastoreView calls.

		datastoreMutex.RLock()
		isNil := activeDatastoreDB == nil
		datastoreMutex.RUnlock()
		if isNil {
			return errors.TraceNew("datastore unexpectedly closed")
		}

		// Add a reference to the open datastore.

		datastoreReferenceCount += 1
		datastoreReferenceCountMutex.Unlock()
		return nil
	}

	// Only lock datastoreMutex now that it's necessary.
	// datastoreReferenceCountMutex remains locked.
	datastoreMutex.Lock()

	if activeDatastoreDB != nil {
		datastoreMutex.Unlock()
		datastoreReferenceCountMutex.Unlock()
		return errors.TraceNew("datastore unexpectedly open")
	}

	// datastoreReferenceCount is 0, so open the datastore.

	newDB, err := datastoreOpenDB(
		config.GetDataStoreDirectory(), retryAndReset)
	if err != nil {
		datastoreMutex.Unlock()
		datastoreReferenceCountMutex.Unlock()
		return errors.Trace(err)
	}

	datastoreReferenceCount = 1
	activeDatastoreDB = newDB
	datastoreMutex.Unlock()
	datastoreReferenceCountMutex.Unlock()

	_ = resetAllPersistentStatsToUnreported()

	return nil
}

// CloseDataStore closes the singleton datastore instance, if open.
func CloseDataStore() {

	datastoreReferenceCountMutex.Lock()
	defer datastoreReferenceCountMutex.Unlock()

	if datastoreReferenceCount <= 0 {
		NoticeWarning(
			"invalid datastore reference count: %d", datastoreReferenceCount)
		return
	}
	datastoreReferenceCount -= 1
	if datastoreReferenceCount > 0 {
		return
	}

	// Only lock datastoreMutex now that it's necessary.
	// datastoreReferenceCountMutex remains locked.
	datastoreMutex.Lock()
	defer datastoreMutex.Unlock()

	if activeDatastoreDB == nil {
		return
	}

	err := activeDatastoreDB.close()
	if err != nil {
		NoticeWarning("failed to close datastore: %s", errors.Trace(err))
	}

	activeDatastoreDB = nil
}

// GetDataStoreMetrics returns a string logging datastore metrics.
func GetDataStoreMetrics() string {
	datastoreMutex.RLock()
	defer datastoreMutex.RUnlock()

	if activeDatastoreDB == nil {
		return ""
	}

	return activeDatastoreDB.getDataStoreMetrics()
}

// datastoreView runs a read-only transaction, making datastore buckets and
// values available to the supplied function.
//
// Bucket value slices are only valid for the duration of the transaction and
// _must_ not be referenced directly outside the transaction.
func datastoreView(fn func(tx *datastoreTx) error) error {

	datastoreMutex.RLock()
	defer datastoreMutex.RUnlock()

	if activeDatastoreDB == nil {
		return errors.TraceNew("datastore not open")
	}

	err := activeDatastoreDB.view(fn)
	if err != nil {
		err = errors.Trace(err)
	}
	return err
}

// datastoreUpdate runs a read-write transaction, making datastore buckets and
// values available to the supplied function.
//
// Bucket value slices are only valid for the duration of the transaction and
// _must_ not be referenced directly outside the transaction.
func datastoreUpdate(fn func(tx *datastoreTx) error) error {

	datastoreMutex.RLock()
	defer datastoreMutex.RUnlock()

	if activeDatastoreDB == nil {
		return errors.TraceNew("database not open")
	}

	err := activeDatastoreDB.update(fn)
	if err != nil {
		err = errors.Trace(err)
	}
	return err
}

// StoreServerEntry adds the server entry to the datastore.
//
// When a server entry already exists for a given server, it will be
// replaced only if replaceIfExists is set or if the the ConfigurationVersion
// field of the new entry is strictly higher than the existing entry.
//
// If the server entry data is malformed, an alert notice is issued and
// the entry is skipped; no error is returned.
func StoreServerEntry(serverEntryFields protocol.ServerEntryFields, replaceIfExists bool) error {

	// TODO: call serverEntryFields.VerifySignature. At this time, we do not do
	// this as not all server entries have an individual signature field. All
	// StoreServerEntry callers either call VerifySignature or obtain server
	// entries from a trusted source (embedded in a signed client, or in a signed
	// authenticated package).

	// Server entries should already be validated before this point,
	// so instead of skipping we fail with an error.
	err := protocol.ValidateServerEntryFields(serverEntryFields)
	if err != nil {
		return errors.Tracef("invalid server entry: %s", err)
	}

	// BoltDB implementation note:
	// For simplicity, we don't maintain indexes on server entry
	// region or supported protocols. Instead, we perform full-bucket
	// scans with a filter. With a small enough database (thousands or
	// even tens of thousand of server entries) and common enough
	// values (e.g., many servers support all protocols), performance
	// is expected to be acceptable.

	err = datastoreUpdate(func(tx *datastoreTx) error {

		serverEntries := tx.bucket(datastoreServerEntriesBucket)
		serverEntryTags := tx.bucket(datastoreServerEntryTagsBucket)
		serverEntryTombstoneTags := tx.bucket(datastoreServerEntryTombstoneTagsBucket)

		serverEntryID := []byte(serverEntryFields.GetIPAddress())

		// Check not only that the entry exists, but is valid. This
		// will replace in the rare case where the data is corrupt.
		existingConfigurationVersion := -1
		existingData := serverEntries.get(serverEntryID)
		if existingData != nil {
			var existingServerEntry *protocol.ServerEntry
			err := json.Unmarshal(existingData, &existingServerEntry)
			if err == nil {
				existingConfigurationVersion = existingServerEntry.ConfigurationVersion
			}
		}

		configurationVersion := serverEntryFields.GetConfigurationVersion()

		exists := existingConfigurationVersion > -1
		newer := exists && existingConfigurationVersion < configurationVersion
		update := !exists || replaceIfExists || newer

		if !update {
			return nil
		}

		serverEntryTag := serverEntryFields.GetTag()

		// Generate a derived tag when the server entry has no tag.
		if serverEntryTag == "" {

			serverEntryTag = protocol.GenerateServerEntryTag(
				serverEntryFields.GetIPAddress(),
				serverEntryFields.GetWebServerSecret())

			serverEntryFields.SetTag(serverEntryTag)
		}

		serverEntryTagBytes := []byte(serverEntryTag)

		// Ignore the server entry if it was previously pruned and a tombstone is
		// set.
		//
		// This logic is enforced only for embedded server entries, as all other
		// sources are considered to be definitive and non-stale. These exceptions
		// intentionally allow the scenario where a server is temporarily deleted
		// and then restored; in this case, it's desired for pruned server entries
		// to be restored.
		if serverEntryFields.GetLocalSource() == protocol.SERVER_ENTRY_SOURCE_EMBEDDED {
			if serverEntryTombstoneTags.get(serverEntryTagBytes) != nil {
				return nil
			}
		}

		data, err := json.Marshal(serverEntryFields)
		if err != nil {
			return errors.Trace(err)
		}

		err = serverEntries.put(serverEntryID, data)
		if err != nil {
			return errors.Trace(err)
		}

		serverEntryTagRecord, err := setServerEntryTagRecord(
			serverEntryID, configurationVersion)
		if err != nil {
			return errors.Trace(err)
		}

		err = serverEntryTags.put(serverEntryTagBytes, serverEntryTagRecord)
		if err != nil {
			return errors.Trace(err)
		}

		NoticeInfo("updated server %s", serverEntryFields.GetDiagnosticID())

		return nil
	})
	if err != nil {
		return errors.Trace(err)
	}

	return nil
}

// StoreServerEntries stores a list of server entries.
// There is an independent transaction for each entry insert/update.
func StoreServerEntries(
	config *Config,
	serverEntries []protocol.ServerEntryFields,
	replaceIfExists bool) error {

	for _, serverEntryFields := range serverEntries {
		err := StoreServerEntry(serverEntryFields, replaceIfExists)
		if err != nil {
			return errors.Trace(err)
		}
	}

	return nil
}

// StreamingStoreServerEntries stores a list of server entries. There is an
// independent transaction for each entry insert/update.
// StreamingStoreServerEntries stops early and returns an error if ctx becomes
// done; any server entries stored up to that point are retained.
func StreamingStoreServerEntries(
	ctx context.Context,
	config *Config,
	serverEntries *protocol.StreamingServerEntryDecoder,
	replaceIfExists bool) error {

	// Note: both StreamingServerEntryDecoder.Next and StoreServerEntry
	// allocate temporary memory buffers for hex/JSON decoding/encoding,
	// so this isn't true constant-memory streaming (it depends on garbage
	// collection).

	n := 0
	for {

		select {
		case <-ctx.Done():
			return errors.Trace(ctx.Err())
		default:
		}

		serverEntry, err := serverEntries.Next()
		if err != nil {
			return errors.Trace(err)
		}

		if serverEntry == nil {
			// No more server entries
			return nil
		}

		err = StoreServerEntry(serverEntry, replaceIfExists)
		if err != nil {
			return errors.Trace(err)
		}

		n += 1
		if n == datastoreServerEntryFetchGCThreshold {
			DoGarbageCollection()
			n = 0
		}
	}
}

// ImportEmbeddedServerEntries loads, decodes, and stores a list of server
// entries. If embeddedServerEntryListFilename is not empty,
// embeddedServerEntryList will be ignored and the encoded server entry list
// will be loaded from the specified file. The import process stops early if
// ctx becomes done; any server entries imported up to that point are
// retained.
func ImportEmbeddedServerEntries(
	ctx context.Context,
	config *Config,
	embeddedServerEntryListFilename string,
	embeddedServerEntryList string) error {

	var reader io.Reader

	if embeddedServerEntryListFilename != "" {

		file, err := os.Open(embeddedServerEntryListFilename)
		if err != nil {
			return errors.Trace(err)
		}
		defer file.Close()

		reader = file

	} else {

		reader = strings.NewReader(embeddedServerEntryList)
	}

	err := StreamingStoreServerEntries(
		ctx,
		config,
		protocol.NewStreamingServerEntryDecoder(
			reader,
			common.TruncateTimestampToHour(common.GetCurrentTimestamp()),
			protocol.SERVER_ENTRY_SOURCE_EMBEDDED),
		false)
	if err != nil {
		return errors.Trace(err)
	}

	return nil
}

// PromoteServerEntry sets the server affinity server entry ID to the
// specified server entry IP address.
func PromoteServerEntry(config *Config, ipAddress string) error {
	err := datastoreUpdate(func(tx *datastoreTx) error {

		serverEntryID := []byte(ipAddress)

		// Ensure the corresponding server entry exists before
		// setting server affinity.
		bucket := tx.bucket(datastoreServerEntriesBucket)
		data := bucket.get(serverEntryID)
		if data == nil {
			NoticeWarning(
				"PromoteServerEntry: ignoring unknown server entry: %s",
				ipAddress)
			return nil
		}

		bucket = tx.bucket(datastoreKeyValueBucket)
		err := bucket.put(datastoreAffinityServerEntryIDKey, serverEntryID)
		if err != nil {
			return errors.Trace(err)
		}

		// Store the current server entry filter (e.g, region, etc.) that
		// was in use when the entry was promoted. This is used to detect
		// when the top ranked server entry was promoted under a different
		// filter.

		currentFilter, err := makeServerEntryFilterValue(config)
		if err != nil {
			return errors.Trace(err)
		}

		err = bucket.put(datastoreLastServerEntryFilterKey, currentFilter)
		if err != nil {
			return errors.Trace(err)
		}

		return nil
	})

	if err != nil {
		return errors.Trace(err)
	}
	return nil
}

// DeleteServerEntryAffinity clears server affinity if set to the specified
// server.
func DeleteServerEntryAffinity(ipAddress string) error {
	err := datastoreUpdate(func(tx *datastoreTx) error {

		serverEntryID := []byte(ipAddress)

		bucket := tx.bucket(datastoreKeyValueBucket)

		affinityServerEntryID := bucket.get(datastoreAffinityServerEntryIDKey)

		if bytes.Equal(affinityServerEntryID, serverEntryID) {
			err := bucket.delete(datastoreAffinityServerEntryIDKey)
			if err != nil {
				return errors.Trace(err)
			}
			err = bucket.delete(datastoreLastServerEntryFilterKey)
			if err != nil {
				return errors.Trace(err)
			}
		}

		return nil
	})

	if err != nil {
		return errors.Trace(err)
	}
	return nil
}

// GetLastServerEntryCount returns a generalized number of server entries in
// the datastore recorded by the last ServerEntryIterator New/Reset call.
// Similar to last_connected and persistent stats timestamps, the count is
// rounded to avoid a potentially unique client fingerprint. The return value
// is -1 if no count has been recorded.
func GetLastServerEntryCount() int {
	count := int(datastoreLastServerEntryCount.Load())

	if count <= 0 {
		// Return -1 (no count) and 0 (no server entries) as-is.
		return count
	}

	n := protocol.ServerEntryCountRoundingIncrement

	// Round up to the nearest ServerEntryCountRoundingIncrement.
	return ((count + (n - 1)) / n) * n
}

func makeServerEntryFilterValue(config *Config) ([]byte, error) {

	// Currently, only a change of EgressRegion will "break" server affinity.
	// If the tunnel protocol filter changes, any existing affinity server
	// either passes the new filter, or it will be skipped anyway.

	return []byte(config.EgressRegion), nil
}

func hasServerEntryFilterChanged(config *Config) (bool, error) {

	currentFilter, err := makeServerEntryFilterValue(config)
	if err != nil {
		return false, errors.Trace(err)
	}

	changed := false
	err = datastoreView(func(tx *datastoreTx) error {

		bucket := tx.bucket(datastoreKeyValueBucket)
		previousFilter := bucket.get(datastoreLastServerEntryFilterKey)

		// When not found, previousFilter will be nil; ensures this
		// results in "changed", even if currentFilter is len(0).
		if previousFilter == nil ||
			!bytes.Equal(previousFilter, currentFilter) {
			changed = true
		}
		return nil
	})
	if err != nil {
		return false, errors.Trace(err)
	}

	return changed, nil
}

// ServerEntryIterator is used to iterate over
// stored server entries in rank order.
type ServerEntryIterator struct {
	config                       *Config
	applyServerAffinity          bool
	serverEntryIDs               [][]byte
	serverEntryIndex             int
	isTacticsServerEntryIterator bool
	isTargetServerEntryIterator  bool
	isPruneServerEntryIterator   bool
	hasNextTargetServerEntry     bool
	targetServerEntry            *protocol.ServerEntry
}

// NewServerEntryIterator creates a new ServerEntryIterator.
//
// The boolean return value indicates whether to treat the first server(s)
// as affinity servers or not. When the server entry selection filter changes
// such as from a specific region to any region, or when there was no previous
// filter/iterator, the the first server(s) are arbitrary and should not be
// given affinity treatment.
//
// NewServerEntryIterator and any returned ServerEntryIterator are not
// designed for concurrent use as not all related datastore operations are
// performed in a single transaction.
func NewServerEntryIterator(config *Config) (bool, *ServerEntryIterator, error) {

	// When configured, this target server entry is the only candidate
	if config.TargetServerEntry != "" {
		return newTargetServerEntryIterator(config, false)
	}

	filterChanged, err := hasServerEntryFilterChanged(config)
	if err != nil {
		return false, nil, errors.Trace(err)
	}

	applyServerAffinity := !filterChanged

	iterator := &ServerEntryIterator{
		config:              config,
		applyServerAffinity: applyServerAffinity,
	}

	err = iterator.reset(true)
	if err != nil {
		return false, nil, errors.Trace(err)
	}

	return applyServerAffinity, iterator, nil
}

func NewTacticsServerEntryIterator(config *Config) (*ServerEntryIterator, error) {

	// When configured, this target server entry is the only candidate
	if config.TargetServerEntry != "" {
		_, iterator, err := newTargetServerEntryIterator(config, true)
		return iterator, err
	}

	iterator := &ServerEntryIterator{
		config:                       config,
		isTacticsServerEntryIterator: true,
	}

	err := iterator.reset(true)
	if err != nil {
		return nil, errors.Trace(err)
	}

	return iterator, nil
}

func NewPruneServerEntryIterator(config *Config) (*ServerEntryIterator, error) {

	// There is no TargetServerEntry case when pruning.

	iterator := &ServerEntryIterator{
		config:                     config,
		isPruneServerEntryIterator: true,
	}

	err := iterator.reset(true)
	if err != nil {
		return nil, errors.Trace(err)
	}

	return iterator, nil
}

// newTargetServerEntryIterator is a helper for initializing the TargetServerEntry case
func newTargetServerEntryIterator(config *Config, isTactics bool) (bool, *ServerEntryIterator, error) {

	serverEntry, err := protocol.DecodeServerEntry(
		config.TargetServerEntry, config.loadTimestamp, protocol.SERVER_ENTRY_SOURCE_TARGET)
	if err != nil {
		return false, nil, errors.Trace(err)
	}

	if serverEntry.Tag == "" {
		serverEntry.Tag = protocol.GenerateServerEntryTag(
			serverEntry.IpAddress, serverEntry.WebServerSecret)
	}

	if isTactics {

		if len(serverEntry.GetSupportedTacticsProtocols()) == 0 {
			return false, nil, errors.TraceNew("TargetServerEntry does not support tactics protocols")
		}

	} else {

		if config.EgressRegion != "" && serverEntry.Region != config.EgressRegion {
			return false, nil, errors.TraceNew("TargetServerEntry does not support EgressRegion")
		}

		p := config.GetParameters().Get()
		limitTunnelProtocols := p.TunnelProtocols(parameters.LimitTunnelProtocols)
		limitTunnelDialPortNumbers := protocol.TunnelProtocolPortLists(
			p.TunnelProtocolPortLists(parameters.LimitTunnelDialPortNumbers))
		limitQUICVersions := p.QUICVersions(parameters.LimitQUICVersions)

		if len(limitTunnelProtocols) > 0 {
			// At the ServerEntryIterator level, only limitTunnelProtocols is applied;
			// excludeIntensive and excludeInproxt are handled higher up.
			if len(serverEntry.GetSupportedProtocols(
				conditionallyEnabledComponents{},
				config.UseUpstreamProxy(),
				limitTunnelProtocols,
				limitTunnelDialPortNumbers,
				limitQUICVersions,
				false)) == 0 {
				return false, nil, errors.Tracef(
					"TargetServerEntry does not support LimitTunnelProtocols: %v", limitTunnelProtocols)
			}
		}
	}

	iterator := &ServerEntryIterator{
		isTacticsServerEntryIterator: isTactics,
		isTargetServerEntryIterator:  true,
		hasNextTargetServerEntry:     true,
		targetServerEntry:            serverEntry,
	}

	err = iterator.reset(true)
	if err != nil {
		return false, nil, errors.Trace(err)
	}

	NoticeInfo("using TargetServerEntry: %s", serverEntry.GetDiagnosticID())

	return false, iterator, nil
}

// Reset a NewServerEntryIterator to the start of its cycle. The next
// call to Next will return the first server entry.
func (iterator *ServerEntryIterator) Reset() error {
	return iterator.reset(false)
}

func (iterator *ServerEntryIterator) reset(isInitialRound bool) error {
	iterator.Close()

	if iterator.isTargetServerEntryIterator {
		iterator.hasNextTargetServerEntry = true

		// Provide the GetLastServerEntryCount implementation. See comment below.
		count := 0
		err := getBucketKeys(datastoreServerEntriesBucket, func(_ []byte) { count += 1 })
		if err != nil {
			return errors.Trace(err)
		}
		datastoreLastServerEntryCount.Store(int64(count))

		return nil
	}

	// Support stand-alone GetTactics operation. See TacticsStorer for more
	// details.
	if iterator.isTacticsServerEntryIterator {
		err := OpenDataStoreWithoutRetry(iterator.config)
		if err != nil {
			return errors.Trace(err)
		}
		defer CloseDataStore()
	}

	// BoltDB implementation note:
	// We don't keep a transaction open for the duration of the iterator
	// because this would expose the following semantics to consumer code:
	//
	//     Read-only transactions and read-write transactions ... generally
	//     shouldn't be opened simultaneously in the same goroutine. This can
	//     cause a deadlock as the read-write transaction needs to periodically
	//     re-map the data file but it cannot do so while a read-only
	//     transaction is open.
	//     (https://github.com/boltdb/bolt)
	//
	// So the underlying serverEntriesBucket could change after the serverEntryIDs
	// list is built.

	var serverEntryIDs [][]byte

	err := datastoreView(func(tx *datastoreTx) error {

		bucket := tx.bucket(datastoreKeyValueBucket)

		serverEntryIDs = make([][]byte, 0)
		shuffleHead := 0

		// The prune case, isPruneServerEntryIterator, skips all
		// move-to-front operations and uses a pure random shuffle in order
		// to uniformly select server entries to prune check. There may be a
		// benefit to inverting the move and move affinity and potential
		// replay servers to the _back_ if they're less likely to be pruned;
		// however, the replay logic here doesn't check the replay TTL and
		// even potential replay servers might be pruned.

		var affinityServerEntryID []byte

		// In the first round only, move any server affinity candiate to the
		// very first position.

		if !iterator.isPruneServerEntryIterator &&
			isInitialRound &&
			iterator.applyServerAffinity {

			affinityServerEntryID = bucket.get(datastoreAffinityServerEntryIDKey)
			if affinityServerEntryID != nil {
				serverEntryIDs = append(serverEntryIDs, append([]byte(nil), affinityServerEntryID...))
				shuffleHead = 1
			}
		}

		bucket = tx.bucket(datastoreServerEntriesBucket)
		cursor := bucket.cursor()
		for key := cursor.firstKey(); key != nil; key = cursor.nextKey() {
			if affinityServerEntryID != nil {
				if bytes.Equal(affinityServerEntryID, key) {
					continue
				}
			}
			serverEntryIDs = append(serverEntryIDs, append([]byte(nil), key...))
		}
		cursor.close()

		// Provide the GetLastServerEntryCount implementation. This snapshot
		// of the number of server entries in the datastore is used for
		// metrics; a snapshot is recorded here to avoid the overhead of
		// datastore scans or operations when the metric is logged.

		datastoreLastServerEntryCount.Store(int64(len(serverEntryIDs)))

		// Randomly shuffle the entire list of server IDs, excluding the
		// server affinity candidate.

		for i := len(serverEntryIDs) - 1; i > shuffleHead-1; i-- {
			j := prng.Intn(i+1-shuffleHead) + shuffleHead
			serverEntryIDs[i], serverEntryIDs[j] = serverEntryIDs[j], serverEntryIDs[i]
		}

		// In the first round, or with some probability, move _potential_ replay
		// candidates to the front of the list (excepting the server affinity slot,
		// if any). This move is post-shuffle so the order is still randomized. To
		// save the memory overhead of unmarshalling all dial parameters, this
		// operation just moves any server with a dial parameter record to the
		// front. Whether the dial parameter remains valid for replay -- TTL,
		// tactics/config unchanged, etc. --- is checked later.
		//
		// TODO: move only up to parameters.ReplayCandidateCount to front?

		p := iterator.config.GetParameters().Get()

		if !iterator.isPruneServerEntryIterator &&
			(isInitialRound || p.WeightedCoinFlip(parameters.ReplayLaterRoundMoveToFrontProbability)) &&
			p.Int(parameters.ReplayCandidateCount) != 0 {

			networkID := []byte(iterator.config.GetNetworkID())

			dialParamsBucket := tx.bucket(datastoreDialParametersBucket)
			i := shuffleHead
			j := len(serverEntryIDs) - 1
			for {
				for ; i < j; i++ {
					key := makeDialParametersKey(serverEntryIDs[i], networkID)
					if dialParamsBucket.get(key) == nil {
						break
					}
				}
				for ; i < j; j-- {
					key := makeDialParametersKey(serverEntryIDs[j], networkID)
					if dialParamsBucket.get(key) != nil {
						break
					}
				}
				if i < j {
					serverEntryIDs[i], serverEntryIDs[j] = serverEntryIDs[j], serverEntryIDs[i]
					i++
					j--
				} else {
					break
				}
			}
		}

		return nil
	})
	if err != nil {
		return errors.Trace(err)
	}

	iterator.serverEntryIDs = serverEntryIDs
	iterator.serverEntryIndex = 0

	return nil
}

// Close cleans up resources associated with a ServerEntryIterator.
func (iterator *ServerEntryIterator) Close() {
	iterator.serverEntryIDs = nil
	iterator.serverEntryIndex = 0
}

// Next returns the next server entry, by rank, for a ServerEntryIterator.
// Returns nil with no error when there is no next item.
func (iterator *ServerEntryIterator) Next() (*protocol.ServerEntry, error) {

	var serverEntry *protocol.ServerEntry
	var err error

	defer func() {
		if err != nil {
			iterator.Close()
		}
	}()

	if iterator.isTargetServerEntryIterator {
		if iterator.hasNextTargetServerEntry {
			iterator.hasNextTargetServerEntry = false
			return MakeCompatibleServerEntry(iterator.targetServerEntry), nil
		}
		return nil, nil
	}

	// Support stand-alone GetTactics operation. See TacticsStorer for more
	// details.
	if iterator.isTacticsServerEntryIterator {
		err := OpenDataStoreWithoutRetry(iterator.config)
		if err != nil {
			return nil, errors.Trace(err)
		}
		defer CloseDataStore()
	}

	// There are no region/protocol indexes for the server entries bucket.
	// Loop until we have the next server entry that matches the iterator
	// filter requirements.
	for {
		if iterator.serverEntryIndex >= len(iterator.serverEntryIDs) {
			// There is no next item
			return nil, nil
		}

		serverEntryID := iterator.serverEntryIDs[iterator.serverEntryIndex]
		iterator.serverEntryIndex += 1

		serverEntry = nil
		doDeleteServerEntry := false

		err = datastoreView(func(tx *datastoreTx) error {
			serverEntries := tx.bucket(datastoreServerEntriesBucket)
			value := serverEntries.get(serverEntryID)
			if value == nil {
				return nil
			}

			// When the server entry has a signature and the signature verification
			// public key is configured, perform a signature verification, which will
			// detect data corruption of most server entry fields. When the check
			// fails, the server entry is deleted and skipped and iteration continues.
			//
			// This prevents wasteful, time-consuming dials in cases where the server
			// entry is intact except for a bit flip in the obfuscation key, for
			// example. A delete is triggered also in the case where the server entry
			// record fails to unmarshal.

			if iterator.config.ServerEntrySignaturePublicKey != "" {

				var serverEntryFields protocol.ServerEntryFields
				err = json.Unmarshal(value, &serverEntryFields)
				if err != nil {
					doDeleteServerEntry = true
					NoticeWarning(
						"ServerEntryIterator.Next: unmarshal failed: %s",
						errors.Trace(err))

					// Do not stop iterating.
					return nil
				}

				if serverEntryFields.HasSignature() {
					err = serverEntryFields.VerifySignature(
						iterator.config.ServerEntrySignaturePublicKey)
					if err != nil {
						doDeleteServerEntry = true
						NoticeWarning(
							"ServerEntryIterator.Next: verify signature failed: %s",
							errors.Trace(err))

						// Do not stop iterating.
						return nil
					}
				}
			}

			// Must unmarshal here as slice is only valid within transaction.
			err = json.Unmarshal(value, &serverEntry)

			if err != nil {
				serverEntry = nil
				doDeleteServerEntry = true
				NoticeWarning(
					"ServerEntryIterator.Next: unmarshal failed: %s",
					errors.Trace(err))

				// Do not stop iterating.
				return nil
			}

			return nil
		})
		if err != nil {
			return nil, errors.Trace(err)
		}

		if doDeleteServerEntry {
			err := deleteServerEntry(iterator.config, serverEntryID)
			if err != nil {
				NoticeWarning(
					"ServerEntryIterator.Next: deleteServerEntry failed: %s",
					errors.Trace(err))
			}
			continue
		}

		if serverEntry == nil {
			// In case of data corruption or a bug causing this condition,
			// do not stop iterating.
			NoticeWarning("ServerEntryIterator.Next: unexpected missing server entry")
			continue
		}

		// Generate a derived server entry tag for server entries with no tag. Store
		// back the updated server entry so that (a) the tag doesn't need to be
		// regenerated; (b) the server entry can be looked up by tag (currently used
		// in the status request prune case).
		//
		// This is a distinct transaction so as to avoid the overhead of regular
		// write transactions in the iterator; once tags have been stored back, most
		// iterator transactions will remain read-only.
		if serverEntry.Tag == "" {

			serverEntry.Tag = protocol.GenerateServerEntryTag(
				serverEntry.IpAddress, serverEntry.WebServerSecret)

			err = datastoreUpdate(func(tx *datastoreTx) error {

				serverEntries := tx.bucket(datastoreServerEntriesBucket)
				serverEntryTags := tx.bucket(datastoreServerEntryTagsBucket)

				// We must reload and store back the server entry _fields_ to preserve any
				// currently unrecognized fields, for future compatibility.

				value := serverEntries.get(serverEntryID)
				if value == nil {
					return nil
				}

				var serverEntryFields protocol.ServerEntryFields
				err := json.Unmarshal(value, &serverEntryFields)
				if err != nil {
					return errors.Trace(err)
				}

				// As there is minor race condition between loading/checking serverEntry
				// and reloading/modifying serverEntryFields, this transaction references
				// only the freshly loaded fields when checking and setting the tag.

				serverEntryTag := serverEntryFields.GetTag()

				if serverEntryTag != "" {
					return nil
				}

				serverEntryTag = protocol.GenerateServerEntryTag(
					serverEntryFields.GetIPAddress(),
					serverEntryFields.GetWebServerSecret())

				serverEntryFields.SetTag(serverEntryTag)

				jsonServerEntryFields, err := json.Marshal(serverEntryFields)
				if err != nil {
					return errors.Trace(err)
				}

				err = serverEntries.put(serverEntryID, jsonServerEntryFields)
				if err != nil {
					return errors.Trace(err)
				}

				serverEntryTagRecord, err := setServerEntryTagRecord(
					[]byte(serverEntryTag),
					serverEntryFields.GetConfigurationVersion())
				if err != nil {
					return errors.Trace(err)
				}

				err = serverEntryTags.put([]byte(serverEntryTag), serverEntryTagRecord)
				if err != nil {
					return errors.Trace(err)
				}

				return nil
			})

			if err != nil {
				// Do not stop.
				NoticeWarning(
					"ServerEntryIterator.Next: update server entry failed: %s",
					errors.Trace(err))
			}
		}

		if iterator.serverEntryIndex%datastoreServerEntryFetchGCThreshold == 0 {
			DoGarbageCollection()
		}

		// Check filter requirements

		if iterator.isPruneServerEntryIterator {
			// No region filter for the prune case.
			break

		} else if iterator.isTacticsServerEntryIterator {

			// Tactics doesn't filter by egress region.
			if len(serverEntry.GetSupportedTacticsProtocols()) > 0 {
				break
			}

		} else {

			if iterator.config.EgressRegion == "" ||
				serverEntry.Region == iterator.config.EgressRegion {
				break
			}
		}
	}

	return MakeCompatibleServerEntry(serverEntry), nil
}

// MakeCompatibleServerEntry provides backwards compatibility with old server entries
// which have a single meekFrontingDomain and not a meekFrontingAddresses array.
// By copying this one meekFrontingDomain into meekFrontingAddresses, this client effectively
// uses that single value as legacy clients do.
func MakeCompatibleServerEntry(serverEntry *protocol.ServerEntry) *protocol.ServerEntry {
	if len(serverEntry.MeekFrontingAddresses) == 0 && serverEntry.MeekFrontingDomain != "" {
		serverEntry.MeekFrontingAddresses =
			append(serverEntry.MeekFrontingAddresses, serverEntry.MeekFrontingDomain)
	}

	return serverEntry
}

// PruneServerEntry deletes the server entry, along with associated data,
// corresponding to the specified server entry tag. Pruning is subject to an
// age check. In the case of an error, a notice is emitted.
func PruneServerEntry(config *Config, serverEntryTag string) bool {
	pruned, err := pruneServerEntry(config, serverEntryTag)
	if err != nil {
		NoticeWarning(
			"PruneServerEntry failed: %s: %s",
			serverEntryTag, errors.Trace(err))
		return false
	}
	if pruned {
		NoticePruneServerEntry(serverEntryTag)
	}
	return pruned
}

func pruneServerEntry(config *Config, serverEntryTag string) (bool, error) {

	minimumAgeForPruning := config.GetParameters().Get().Duration(
		parameters.ServerEntryMinimumAgeForPruning)

	pruned := false

	err := datastoreUpdate(func(tx *datastoreTx) error {

		serverEntries := tx.bucket(datastoreServerEntriesBucket)
		serverEntryTags := tx.bucket(datastoreServerEntryTagsBucket)
		serverEntryTombstoneTags := tx.bucket(datastoreServerEntryTombstoneTagsBucket)
		keyValues := tx.bucket(datastoreKeyValueBucket)
		dialParameters := tx.bucket(datastoreDialParametersBucket)

		serverEntryTagBytes := []byte(serverEntryTag)

		serverEntryTagRecord := serverEntryTags.get(serverEntryTagBytes)
		if serverEntryTagRecord == nil {
			return errors.TraceNew("server entry tag not found")
		}

		serverEntryID, _, err := getServerEntryTagRecord(serverEntryTagRecord)
		if err != nil {
			return errors.Trace(err)
		}

		serverEntryJson := serverEntries.get(serverEntryID)
		if serverEntryJson == nil {
			return errors.TraceNew("server entry not found")
		}

		var serverEntry *protocol.ServerEntry
		err = json.Unmarshal(serverEntryJson, &serverEntry)
		if err != nil {
			return errors.Trace(err)
		}

		// Only prune sufficiently old server entries. This mitigates the case where
		// stale data in psiphond will incorrectly identify brand new servers as
		// being invalid/deleted.
		serverEntryLocalTimestamp, err := time.Parse(time.RFC3339, serverEntry.LocalTimestamp)
		if err != nil {
			return errors.Trace(err)
		}
		if serverEntryLocalTimestamp.Add(minimumAgeForPruning).After(time.Now()) {
			return nil
		}

		// Handle the server IP recycle case where multiple serverEntryTags records
		// refer to the same server IP. Only delete the server entry record when its
		// tag matches the pruned tag. Otherwise, the server entry record is
		// associated with another tag. The pruned tag is still deleted.
		doDeleteServerEntry := (serverEntry.Tag == serverEntryTag)

		err = serverEntryTags.delete(serverEntryTagBytes)
		if err != nil {
			return errors.Trace(err)
		}

		if doDeleteServerEntry {

			err = deleteServerEntryHelper(
				config,
				serverEntryID,
				serverEntries,
				keyValues,
				dialParameters)
			if err != nil {
				return errors.Trace(err)
			}
		}

		// Tombstones prevent reimporting pruned server entries. Tombstone
		// identifiers are tags, which are derived from the web server secret in
		// addition to the server IP, so tombstones will not clobber recycled server
		// IPs as long as new web server secrets are generated in the recycle case.
		//
		// Tombstones are set only for embedded server entries, as all other sources
		// are expected to provide valid server entries; this also provides a fail-
		// safe mechanism to restore pruned server entries through all non-embedded
		// sources.
		if serverEntry.LocalSource == protocol.SERVER_ENTRY_SOURCE_EMBEDDED {
			err = serverEntryTombstoneTags.put(serverEntryTagBytes, []byte{1})
			if err != nil {
				return errors.Trace(err)
			}
		}

		pruned = true

		return nil
	})

	return pruned, errors.Trace(err)
}

// DeleteServerEntry deletes the specified server entry and associated data.
func DeleteServerEntry(config *Config, ipAddress string) {

	serverEntryID := []byte(ipAddress)

	// For notices, we cannot assume we have a valid server entry tag value to
	// log, as DeleteServerEntry is called when a server entry fails to unmarshal
	// or fails signature verification.

	err := deleteServerEntry(config, serverEntryID)
	if err != nil {
		NoticeWarning("DeleteServerEntry failed: %s", errors.Trace(err))
		return
	}
	NoticeInfo("Server entry deleted")
}

func deleteServerEntry(config *Config, serverEntryID []byte) error {

	return datastoreUpdate(func(tx *datastoreTx) error {

		serverEntries := tx.bucket(datastoreServerEntriesBucket)
		serverEntryTags := tx.bucket(datastoreServerEntryTagsBucket)
		keyValues := tx.bucket(datastoreKeyValueBucket)
		dialParameters := tx.bucket(datastoreDialParametersBucket)

		err := deleteServerEntryHelper(
			config,
			serverEntryID,
			serverEntries,
			keyValues,
			dialParameters)
		if err != nil {
			return errors.Trace(err)
		}

		// Remove any tags pointing to the deleted server entry.
		var deleteKeys [][]byte
		cursor := serverEntryTags.cursor()
		for key, value := cursor.first(); key != nil; key, value = cursor.next() {
			if bytes.Equal(value, serverEntryID) {
				deleteKeys = append(deleteKeys, key)
			}
		}
		cursor.close()

		// Mutate bucket only after cursor is closed.
		//
		// TODO: expose boltdb Cursor.Delete to allow for safe mutation
		// within cursor loop.
		for _, deleteKey := range deleteKeys {
			err := serverEntryTags.delete(deleteKey)
			if err != nil {
				return errors.Trace(err)
			}
		}

		return nil
	})
}

func deleteServerEntryHelper(
	config *Config,
	serverEntryID []byte,
	serverEntries *datastoreBucket,
	keyValues *datastoreBucket,
	dialParameters *datastoreBucket) error {

	err := serverEntries.delete(serverEntryID)
	if err != nil {
		return errors.Trace(err)
	}

	affinityServerEntryID := keyValues.get(datastoreAffinityServerEntryIDKey)
	if bytes.Equal(affinityServerEntryID, serverEntryID) {
		err = keyValues.delete(datastoreAffinityServerEntryIDKey)
		if err != nil {
			return errors.Trace(err)
		}
		err = keyValues.delete(datastoreLastServerEntryFilterKey)
		if err != nil {
			return errors.Trace(err)
		}
	}

	// Each dial parameters key has serverID as a prefix; see
	// makeDialParametersKey. There may be multiple keys with the
	// serverEntryID prefix; they will be grouped together, so the loop can
	// exit as soon as a previously found prefix is no longer found.
	foundFirstMatch := false

	// TODO: expose boltdb Seek functionality to skip to first matching record.
	var deleteKeys [][]byte
	cursor := dialParameters.cursor()
	for key, _ := cursor.first(); key != nil; key, _ = cursor.next() {
		if bytes.HasPrefix(key, serverEntryID) {
			foundFirstMatch = true
			deleteKeys = append(deleteKeys, key)
		} else if foundFirstMatch {
			break
		}
	}
	cursor.close()

	// Mutate bucket only after cursor is closed.
	//
	// TODO: expose boltdb Cursor.Delete to allow for safe mutation
	// within cursor loop.
	for _, deleteKey := range deleteKeys {
		err := dialParameters.delete(deleteKey)
		if err != nil {
			return errors.Trace(err)
		}
	}

	return nil
}

// ScanServerEntries iterates over all stored server entries, unmarshals each,
// and passes it to callback for processing. If callback returns false, the
// iteration is cancelled and an error is returned.
//
// ScanServerEntries may be slow to execute, particularly for older devices
// and/or very large server lists. Callers should avoid blocking on
// ScanServerEntries where possible; and use the cancel option to interrupt
// scans that are no longer required.
func ScanServerEntries(callback func(*protocol.ServerEntry) bool) error {

	// TODO: this operation can be sped up (by a factor of ~2x, in one test
	// scenario) by using a faster JSON implementation
	// (https://github.com/json-iterator/go) and increasing
	// datastoreServerEntryFetchGCThreshold.
	//
	// json-iterator increases the binary code size significantly, which affects
	// memory limit accounting on some platforms, so it's not clear we can use it
	// universally. Similarly, tuning datastoreServerEntryFetchGCThreshold has a
	// memory limit tradeoff.
	//
	// Since ScanServerEntries is now called asynchronously and doesn't block
	// establishment at all, we can tolerate its slower performance. Other
	// bulk-JSON operations such as [Streaming]StoreServerEntries also benefit
	// from using a faster JSON implementation, but the relative performance
	// increase is far smaller as import times are dominated by data store write
	// transaction overhead. Other operations such as ServerEntryIterator
	// amortize the cost of JSON unmarshalling over many other operations.

	err := datastoreView(func(tx *datastoreTx) error {

		bucket := tx.bucket(datastoreServerEntriesBucket)
		cursor := bucket.cursor()
		n := 0

		for key, value := cursor.first(); key != nil; key, value = cursor.next() {

			var serverEntry *protocol.ServerEntry
			err := json.Unmarshal(value, &serverEntry)
			if err != nil {
				// In case of data corruption or a bug causing this condition,
				// do not stop iterating.
				NoticeWarning("ScanServerEntries: %s", errors.Trace(err))
				continue
			}

			if !callback(serverEntry) {
				cursor.close()
				return errors.TraceNew("scan cancelled")
			}

			n += 1
			if n == datastoreServerEntryFetchGCThreshold {
				DoGarbageCollection()
				n = 0
			}
		}
		cursor.close()
		return nil
	})

	if err != nil {
		return errors.Trace(err)
	}

	return nil
}

// HasServerEntries returns a bool indicating if the data store contains at
// least one server entry. This is a faster operation than CountServerEntries.
// On failure, HasServerEntries returns false.
func HasServerEntries() bool {

	hasServerEntries := false

	err := datastoreView(func(tx *datastoreTx) error {
		bucket := tx.bucket(datastoreServerEntriesBucket)
		cursor := bucket.cursor()
		key, _ := cursor.first()
		hasServerEntries = (key != nil)
		cursor.close()
		return nil
	})

	if err != nil {
		NoticeWarning("HasServerEntries failed: %s", errors.Trace(err))
		return false
	}

	return hasServerEntries
}

// CountServerEntries returns a count of stored server entries. On failure,
// CountServerEntries returns 0.
func CountServerEntries() int {

	count := 0

	err := datastoreView(func(tx *datastoreTx) error {
		bucket := tx.bucket(datastoreServerEntriesBucket)
		cursor := bucket.cursor()
		for key, _ := cursor.first(); key != nil; key, _ = cursor.next() {
			count += 1
		}
		cursor.close()
		return nil
	})

	if err != nil {
		NoticeWarning("CountServerEntries failed: %s", err)
		return 0
	}

	return count
}

// SetUrlETag stores an ETag for the specfied URL.
// Note: input URL is treated as a string, and is not
// encoded or decoded or otherwise canonicalized.
func SetUrlETag(url, etag string) error {

	err := datastoreUpdate(func(tx *datastoreTx) error {
		bucket := tx.bucket(datastoreUrlETagsBucket)
		err := bucket.put([]byte(url), []byte(etag))
		if err != nil {
			return errors.Trace(err)
		}
		return nil
	})

	if err != nil {
		return errors.Trace(err)
	}
	return nil
}

// GetUrlETag retrieves a previously stored an ETag for the
// specfied URL. If not found, it returns an empty string value.
func GetUrlETag(url string) (string, error) {

	var etag string

	err := datastoreView(func(tx *datastoreTx) error {
		bucket := tx.bucket(datastoreUrlETagsBucket)
		etag = string(bucket.get([]byte(url)))
		return nil
	})

	if err != nil {
		return "", errors.Trace(err)
	}
	return etag, nil
}

// SetKeyValue stores a key/value pair.
func SetKeyValue(key, value string) error {

	err := datastoreUpdate(func(tx *datastoreTx) error {
		bucket := tx.bucket(datastoreKeyValueBucket)
		err := bucket.put([]byte(key), []byte(value))
		if err != nil {
			return errors.Trace(err)
		}
		return nil
	})

	if err != nil {
		return errors.Trace(err)
	}
	return nil
}

// GetKeyValue retrieves the value for a given key. If not found,
// it returns an empty string value.
func GetKeyValue(key string) (string, error) {

	var value string

	err := datastoreView(func(tx *datastoreTx) error {
		bucket := tx.bucket(datastoreKeyValueBucket)
		value = string(bucket.get([]byte(key)))
		return nil
	})

	if err != nil {
		return "", errors.Trace(err)
	}
	return value, nil
}

// Persistent stat records in the persistentStatStateUnreported
// state are available for take out.
//
// Records in the persistentStatStateReporting have been taken
// out and are pending either deletion (for a successful request)
// or change to StateUnreported (for a failed request).
//
// All persistent stat records are reverted to StateUnreported
// when the datastore is initialized at start up.

var persistentStatStateUnreported = []byte("0")
var persistentStatStateReporting = []byte("1")

var persistentStatTypes = []string{
	datastorePersistentStatTypeRemoteServerList,
	datastorePersistentStatTypeFailedTunnel,
}

// StorePersistentStat adds a new persistent stat record, which
// is set to StateUnreported and is an immediate candidate for
// reporting.
//
// The stat is a JSON byte array containing fields as
// required by the Psiphon server API. It's assumed that the
// JSON value contains enough unique information for the value to
// function as a key in the key/value datastore.
//
// Only up to PersistentStatsMaxStoreRecords are stored. Once this
// limit is reached, new records are discarded.
func StorePersistentStat(config *Config, statType string, stat []byte) error {

	if !common.Contains(persistentStatTypes, statType) {
		return errors.Tracef("invalid persistent stat type: %s", statType)
	}

	maxStoreRecords := config.GetParameters().Get().Int(
		parameters.PersistentStatsMaxStoreRecords)

	err := datastoreUpdate(func(tx *datastoreTx) error {
		bucket := tx.bucket([]byte(statType))

		count := 0
		cursor := bucket.cursor()
		for key, _ := cursor.first(); key != nil; key, _ = cursor.next() {
			count++
		}
		cursor.close()

		// TODO: assuming newer metrics are more useful, replace oldest record
		// instead of discarding?

		if count >= maxStoreRecords {
			// Silently discard.
			return nil
		}

		err := bucket.put(stat, persistentStatStateUnreported)
		if err != nil {
			return errors.Trace(err)
		}

		return nil
	})

	if err != nil {
		return errors.Trace(err)
	}

	return nil
}

// CountUnreportedPersistentStats returns the number of persistent
// stat records in StateUnreported.
func CountUnreportedPersistentStats() int {

	unreported := 0

	err := datastoreView(func(tx *datastoreTx) error {

		for _, statType := range persistentStatTypes {

			bucket := tx.bucket([]byte(statType))
			cursor := bucket.cursor()
			for key, value := cursor.first(); key != nil; key, value = cursor.next() {
				if bytes.Equal(value, persistentStatStateUnreported) {
					unreported++
				}
			}
			cursor.close()
		}
		return nil
	})

	if err != nil {
		NoticeWarning("CountUnreportedPersistentStats failed: %s", err)
		return 0
	}

	return unreported
}

// TakeOutUnreportedPersistentStats returns persistent stats records that are
// in StateUnreported. At least one record, if present, will be returned and
// then additional records up to PersistentStatsMaxSendBytes. The records are
// set to StateReporting. If the records are successfully reported, clear them
// with ClearReportedPersistentStats. If the records are not successfully
// reported, restore them with PutBackUnreportedPersistentStats.
func TakeOutUnreportedPersistentStats(
	config *Config,
	adjustMaxSendBytes int) (map[string][][]byte, int, error) {

	// TODO: add a failsafe like disableCheckServerEntryTags, to avoid repeatedly resending
	// persistent stats in the case of a local error? Also consider just dropping persistent stats
	// which fail to send due to a network disconnection, rather than invoking
	// PutBackUnreportedPersistentStats -- especially if it's likely that the server received the
	// stats and the disconnection occurs just before the request is acknowledged.

	stats := make(map[string][][]byte)

	maxSendBytes := config.GetParameters().Get().Int(
		parameters.PersistentStatsMaxSendBytes)

	maxSendBytes -= adjustMaxSendBytes

	sendBytes := 0

	err := datastoreUpdate(func(tx *datastoreTx) error {

		for _, statType := range persistentStatTypes {

			bucket := tx.bucket([]byte(statType))

			var deleteKeys [][]byte
			cursor := bucket.cursor()
			for key, value := cursor.first(); key != nil; key, value = cursor.next() {

				// Perform a test JSON unmarshaling. In case of data corruption or a bug,
				// attempt to delete and skip the record.
				var jsonData interface{}
				err := json.Unmarshal(key, &jsonData)
				if err != nil {
					NoticeWarning(
						"Invalid key in TakeOutUnreportedPersistentStats: %s: %s",
						string(key), err)
					deleteKeys = append(deleteKeys, key)
					continue
				}

				if bytes.Equal(value, persistentStatStateUnreported) {
					// Must make a copy as slice is only valid within transaction.
					data := make([]byte, len(key))
					copy(data, key)

					if stats[statType] == nil {
						stats[statType] = make([][]byte, 0)
					}

					stats[statType] = append(stats[statType], data)

					sendBytes += len(data)
					if sendBytes >= maxSendBytes {
						break
					}
				}

			}
			cursor.close()

			// Mutate bucket only after cursor is closed.
			for _, deleteKey := range deleteKeys {
				_ = bucket.delete(deleteKey)
			}

			for _, key := range stats[statType] {
				err := bucket.put(key, persistentStatStateReporting)
				if err != nil {
					return errors.Trace(err)
				}
			}

		}
		return nil
	})

	if err != nil {
		return nil, 0, errors.Trace(err)
	}

	return stats, sendBytes, nil
}

// PutBackUnreportedPersistentStats restores a list of persistent
// stat records to StateUnreported.
func PutBackUnreportedPersistentStats(stats map[string][][]byte) error {

	err := datastoreUpdate(func(tx *datastoreTx) error {

		for _, statType := range persistentStatTypes {

			bucket := tx.bucket([]byte(statType))
			for _, key := range stats[statType] {
				err := bucket.put(key, persistentStatStateUnreported)
				if err != nil {
					return errors.Trace(err)
				}
			}
		}

		return nil
	})

	if err != nil {
		return errors.Trace(err)
	}

	return nil
}

// ClearReportedPersistentStats deletes a list of persistent
// stat records that were successfully reported.
func ClearReportedPersistentStats(stats map[string][][]byte) error {

	err := datastoreUpdate(func(tx *datastoreTx) error {

		for _, statType := range persistentStatTypes {

			bucket := tx.bucket([]byte(statType))
			for _, key := range stats[statType] {
				err := bucket.delete(key)
				if err != nil {
					return err
				}
			}
		}

		return nil
	})

	if err != nil {
		return errors.Trace(err)
	}

	return nil
}

// resetAllPersistentStatsToUnreported sets all persistent stat
// records to StateUnreported. This reset is called when the
// datastore is initialized at start up, as we do not know if
// persistent records in StateReporting were reported or not.
func resetAllPersistentStatsToUnreported() error {

	err := datastoreUpdate(func(tx *datastoreTx) error {

		for _, statType := range persistentStatTypes {

			bucket := tx.bucket([]byte(statType))
			resetKeys := make([][]byte, 0)
			cursor := bucket.cursor()
			for key := cursor.firstKey(); key != nil; key = cursor.nextKey() {
				resetKeys = append(resetKeys, key)
			}
			cursor.close()
			// TODO: data mutation is done outside cursor. Is this
			// strictly necessary in this case? As is, this means
			// all stats need to be loaded into memory at once.
			// https://godoc.org/github.com/boltdb/bolt#Cursor
			for _, key := range resetKeys {
				err := bucket.put(key, persistentStatStateUnreported)
				if err != nil {
					return errors.Trace(err)
				}
			}
		}

		return nil
	})

	if err != nil {
		return errors.Trace(err)
	}

	return nil
}

// IsCheckServerEntryTagsDue indicates that a new prune check is due, based on
// the time of the previous check ending.
func IsCheckServerEntryTagsDue(config *Config) bool {

	// disableCheckServerEntryTags is a failsafe, enabled in error cases below
	// and in UpdateCheckServerEntryTagsEndTime to prevent constantly
	// resending prune check payloads if the scheduling mechanism fails.
	if disableCheckServerEntryTags.Load() {
		return false
	}

	// Whether the next check is due is based on time elapsed since the time
	// of the previous check ending, with the elapsed time set in tactics.
	// The previous end time, rather the next due time, is stored, to allow
	// changes to this tactic to have immediate effect.

	p := config.GetParameters().Get()
	enabled := p.Bool(parameters.CheckServerEntryTagsEnabled)
	checkPeriod := p.Duration(parameters.CheckServerEntryTagsPeriod)
	p.Close()

	if !enabled {
		return false
	}

	lastEndTime, err := getTimeKeyValue(datastoreCheckServerEntryTagsEndTimeKey)
	if err != nil {
		NoticeWarning("IsCheckServerEntryTagsDue getTimeKeyValue failed: %s", errors.Trace(err))
		disableCheckServerEntryTags.Store(true)
		return false
	}

	return lastEndTime.IsZero() || time.Now().After(lastEndTime.Add(checkPeriod))
}

// UpdateCheckServerEntryTagsEndTime should be called after a prune check is
// complete. The end time is set, extending the time until the next check,
// unless there's a sufficiently high ratio of pruned servers from the last
// check.
func UpdateCheckServerEntryTagsEndTime(config *Config, checkCount int, pruneCount int) {

	p := config.GetParameters().Get()
	ratio := p.Float(parameters.CheckServerEntryTagsRepeatRatio)
	minimum := p.Int(parameters.CheckServerEntryTagsRepeatMinimum)
	p.Close()

	// When there's a sufficiently high ratio of pruned/checked from
	// the _previous_ check operation, don't mark the check as ended. This
	// will result in the next status request performing another check. It's
	// assumed that the ratio will decrease over the course of repeated
	// checks as more server entries are pruned, and random selection for
	// checking will include fewer and fewer invalid server entry tags.
	//
	// The rate of repeated checking is also limited by the status request
	// schedule, where PsiphonAPIStatusRequestPeriodMin/Max defaults to 5-10
	// minutes.

	if pruneCount >= minimum && ratio > 0 && float64(pruneCount)/float64(checkCount) >= ratio {
		NoticeInfo("UpdateCheckServerEntryTagsEndTime: %d/%d: repeat", pruneCount, checkCount)
		return
	}

	err := setTimeKeyValue(datastoreCheckServerEntryTagsEndTimeKey, time.Now())
	if err != nil {
		NoticeWarning("UpdateCheckServerEntryTagsEndTime setTimeKeyValue failed: %s", errors.Trace(err))
		disableCheckServerEntryTags.Store(true)
		return
	}

	NoticeInfo("UpdateCheckServerEntryTagsEndTime: %d/%d: done", pruneCount, checkCount)
}

// GetCheckServerEntryTags returns a random selection of server entry tags to
// be checked for pruning. An empty list is returned if a check is not yet
// due.
func GetCheckServerEntryTags(config *Config) ([]string, int, error) {

	if disableCheckServerEntryTags.Load() {
		return nil, 0, nil
	}

	if !IsCheckServerEntryTagsDue(config) {
		return nil, 0, nil
	}

	// maxSendBytes is intended to limit the request memory overhead and
	// network size. maxWorkTime ensures that slow devices -- with datastore
	// operations and JSON unmarshaling particularly slow -- will launch a
	// request in a timely fashion.

	p := config.GetParameters().Get()
	maxSendBytes := p.Int(parameters.CheckServerEntryTagsMaxSendBytes)
	maxWorkTime := p.Duration(parameters.CheckServerEntryTagsMaxWorkTime)
	minimumAgeForPruning := p.Duration(parameters.ServerEntryMinimumAgeForPruning)
	p.Close()

	iterator, err := NewPruneServerEntryIterator(config)
	if err != nil {
		return nil, 0, errors.Trace(err)
	}

	var checkTags []string
	bytes := 0
	startWork := time.Now()

	for {

		serverEntry, err := iterator.Next()
		if err != nil {
			return nil, 0, errors.Trace(err)
		}

		if serverEntry == nil {
			break
		}

		// Skip checking the server entry if PruneServerEntry won't prune it
		// anyway, due to ServerEntryMinimumAgeForPruning.
		serverEntryLocalTimestamp, err := time.Parse(time.RFC3339, serverEntry.LocalTimestamp)
		if err != nil {
			return nil, 0, errors.Trace(err)
		}
		if serverEntryLocalTimestamp.Add(minimumAgeForPruning).After(time.Now()) {
			continue
		}

		// Server entries with replay records are not skipped. It's possible that replay records are
		// retained, due to ReplayRetainFailedProbability, even if the server entry is no longer
		// valid. Inspecting replay would also require an additional JSON unmarshal of the
		// DialParameters, in order to check the replay TTL.
		//
		// A potential future enhancement could be to add and check a new index that tracks how
		// recently a server entry connection got as far as completing the SSH handshake, which
		// verifies the Psiphon server running at that server entry network address. This would
		// exclude from prune checking all recently known-valid servers regardless of whether they
		// ultimately pass the liveness test, establish a tunnel, or reach the replay data transfer
		// targets.

		checkTags = append(checkTags, serverEntry.Tag)

		// Approximate the size of the JSON encoding of the string array,
		// including quotes and commas.
		bytes += len(serverEntry.Tag) + 3

		if bytes >= maxSendBytes || (maxWorkTime > 0 && time.Since(startWork) > maxWorkTime) {
			break
		}
	}

	return checkTags, bytes, nil
}

// CountSLOKs returns the total number of SLOK records.
func CountSLOKs() int {

	count := 0

	err := datastoreView(func(tx *datastoreTx) error {
		bucket := tx.bucket(datastoreSLOKsBucket)
		cursor := bucket.cursor()
		for key := cursor.firstKey(); key != nil; key = cursor.nextKey() {
			count++
		}
		cursor.close()
		return nil
	})

	if err != nil {
		NoticeWarning("CountSLOKs failed: %s", err)
		return 0
	}

	return count
}

// DeleteSLOKs deletes all SLOK records.
func DeleteSLOKs() error {

	err := datastoreUpdate(func(tx *datastoreTx) error {
		return tx.clearBucket(datastoreSLOKsBucket)
	})

	if err != nil {
		return errors.Trace(err)
	}

	return nil
}

// SetSLOK stores a SLOK key, referenced by its ID. The bool
// return value indicates whether the SLOK was already stored.
func SetSLOK(id, slok []byte) (bool, error) {

	var duplicate bool

	err := datastoreUpdate(func(tx *datastoreTx) error {
		bucket := tx.bucket(datastoreSLOKsBucket)
		duplicate = bucket.get(id) != nil
		err := bucket.put(id, slok)
		if err != nil {
			return errors.Trace(err)
		}
		return nil
	})

	if err != nil {
		return false, errors.Trace(err)
	}

	return duplicate, nil
}

// GetSLOK returns a SLOK key for the specified ID. The return
// value is nil if the SLOK is not found.
func GetSLOK(id []byte) ([]byte, error) {

	var slok []byte

	err := datastoreView(func(tx *datastoreTx) error {
		bucket := tx.bucket(datastoreSLOKsBucket)
		value := bucket.get(id)
		if value != nil {
			// Must make a copy as slice is only valid within transaction.
			slok = make([]byte, len(value))
			copy(slok, value)
		}
		return nil
	})

	if err != nil {
		return nil, errors.Trace(err)
	}

	return slok, nil
}

func makeDialParametersKey(serverIPAddress, networkID []byte) []byte {
	// TODO: structured key?
	return append(append([]byte(nil), serverIPAddress...), networkID...)
}

// SetDialParameters stores dial parameters associated with the specified
// server/network ID.
func SetDialParameters(serverIPAddress, networkID string, dialParams *DialParameters) error {

	key := makeDialParametersKey([]byte(serverIPAddress), []byte(networkID))

	data, err := json.Marshal(dialParams)
	if err != nil {
		return errors.Trace(err)
	}

	return setBucketValue(datastoreDialParametersBucket, key, data)
}

// GetDialParameters fetches any dial parameters associated with the specified
// server/network ID. Returns nil, nil when no record is found.
func GetDialParameters(
	config *Config, serverIPAddress, networkID string) (*DialParameters, error) {

	// Support stand-alone GetTactics operation. See TacticsStorer for more
	// details.
	err := OpenDataStoreWithoutRetry(config)
	if err != nil {
		return nil, errors.Trace(err)
	}
	defer CloseDataStore()

	key := makeDialParametersKey([]byte(serverIPAddress), []byte(networkID))

	var dialParams *DialParameters

	err = getBucketValue(
		datastoreDialParametersBucket,
		key,
		func(value []byte) error {
			if value == nil {
				return nil
			}

			// Note: unlike with server entries, this record is not deleted when the
			// unmarshal fails, as the caller should proceed with the dial without dial
			// parameters; and when when the dial succeeds, new dial parameters will be
			// written over this record.

			err := json.Unmarshal(value, &dialParams)
			if err != nil {
				return errors.Trace(err)
			}

			return nil
		})
	if err != nil {
		return nil, errors.Trace(err)
	}

	return dialParams, nil
}

// DeleteDialParameters clears any dial parameters associated with the
// specified server/network ID.
func DeleteDialParameters(serverIPAddress, networkID string) error {

	key := makeDialParametersKey([]byte(serverIPAddress), []byte(networkID))

	return deleteBucketValue(datastoreDialParametersBucket, key)
}

// TacticsStorer implements tactics.Storer.
//
// Each TacticsStorer datastore operation is wrapped with
// OpenDataStoreWithoutRetry/CloseDataStore, which enables a limited degree of
// multiprocess datastore synchronization:
//
// One process runs a Controller. Another process runs a stand-alone operation
// which accesses tactics via GetTactics. For example, SendFeedback.
//
// When the Controller is running, it holds an exclusive lock on the datastore
// and TacticsStorer operations in GetTactics in another process will fail.
// The stand-alone operation should proceed without tactics. In many cases,
// this is acceptable since any stand-alone operation network traffic will be
// tunneled.
//
// When the Controller is not running, the TacticsStorer operations in
// GetTactics in another process will succeed, with no operation holding a
// datastore lock for longer than the handful of milliseconds required to
// perform a single datastore operation.
//
// If the Controller is started while the stand-alone operation is in
// progress, the Controller start will not be blocked for long by the brief
// TacticsStorer datastore locks; the bolt Open call, in particular, has a 1
// second lock aquisition timeout and OpenDataStore will retry when the
// datastore file is locked.
//
// In this scheme, no attempt is made to detect interleaving datastore writes;
// that is, if a different process writes tactics in between GetTactics calls
// to GetTacticsRecord and then SetTacticsRecord. This is because all tactics
// writes are considered fresh and valid.
//
// Using OpenDataStoreWithoutRetry ensures that the GetTactics attempt in the
// non-Controller operation will quickly fail if the datastore is locked.
type TacticsStorer struct {
	config *Config
}

func (t *TacticsStorer) SetTacticsRecord(networkID string, record []byte) error {
	err := OpenDataStoreWithoutRetry(t.config)
	if err != nil {
		return errors.Trace(err)
	}
	defer CloseDataStore()
	err = setBucketValue(datastoreTacticsBucket, []byte(networkID), record)
	if err != nil {
		return errors.Trace(err)
	}
	return nil
}

func (t *TacticsStorer) GetTacticsRecord(networkID string) ([]byte, error) {
	err := OpenDataStoreWithoutRetry(t.config)
	if err != nil {
		return nil, errors.Trace(err)
	}
	defer CloseDataStore()
	value, err := copyBucketValue(datastoreTacticsBucket, []byte(networkID))
	if err != nil {
		return nil, errors.Trace(err)
	}
	return value, nil
}

func (t *TacticsStorer) SetSpeedTestSamplesRecord(networkID string, record []byte) error {
	err := OpenDataStoreWithoutRetry(t.config)
	if err != nil {
		return errors.Trace(err)
	}
	defer CloseDataStore()
	err = setBucketValue(datastoreSpeedTestSamplesBucket, []byte(networkID), record)
	if err != nil {
		return errors.Trace(err)
	}
	return nil
}

func (t *TacticsStorer) GetSpeedTestSamplesRecord(networkID string) ([]byte, error) {
	err := OpenDataStoreWithoutRetry(t.config)
	if err != nil {
		return nil, errors.Trace(err)
	}
	defer CloseDataStore()
	value, err := copyBucketValue(datastoreSpeedTestSamplesBucket, []byte(networkID))
	if err != nil {
		return nil, errors.Trace(err)
	}
	return value, nil
}

// GetTacticsStorer creates a TacticsStorer.
func GetTacticsStorer(config *Config) *TacticsStorer {
	return &TacticsStorer{config: config}
}

// GetAffinityServerEntryAndDialParameters fetches the current affinity server
// entry value and any corresponding dial parameters for the specified network
// ID. An error is returned when no affinity server is available. The
// DialParameter output may be nil when a server entry is found but has no
// dial parameters.
func GetAffinityServerEntryAndDialParameters(
	networkID string) (protocol.ServerEntryFields, *DialParameters, error) {

	var serverEntryFields protocol.ServerEntryFields
	var dialParams *DialParameters

	err := datastoreView(func(tx *datastoreTx) error {

		keyValues := tx.bucket(datastoreKeyValueBucket)
		serverEntries := tx.bucket(datastoreServerEntriesBucket)
		dialParameters := tx.bucket(datastoreDialParametersBucket)

		affinityServerEntryID := keyValues.get(datastoreAffinityServerEntryIDKey)
		if affinityServerEntryID == nil {
			return errors.TraceNew("no affinity server available")
		}

		serverEntryRecord := serverEntries.get(affinityServerEntryID)
		if serverEntryRecord == nil {
			return errors.TraceNew("affinity server entry not found")
		}

		err := json.Unmarshal(
			serverEntryRecord,
			&serverEntryFields)
		if err != nil {
			return errors.Trace(err)
		}

		dialParamsKey := makeDialParametersKey(
			[]byte(serverEntryFields.GetIPAddress()),
			[]byte(networkID))

		dialParamsRecord := dialParameters.get(dialParamsKey)
		if dialParamsRecord != nil {
			err := json.Unmarshal(dialParamsRecord, &dialParams)
			if err != nil {
				return errors.Trace(err)
			}
		}

		return nil
	})
	if err != nil {
		return nil, nil, errors.Trace(err)
	}

	return serverEntryFields, dialParams, nil
}

// GetSignedServerEntryFields loads, from the datastore, the raw JSON server
// entry fields for the specified server entry.
//
// The protocol.ServerEntryFields returned by GetSignedServerEntryFields will
// include all fields required to verify the server entry signature,
// including new fields added after the current client version, which do not
// get unmarshaled into protocol.ServerEntry.
func GetSignedServerEntryFields(ipAddress string) (protocol.ServerEntryFields, error) {

	var serverEntryFields protocol.ServerEntryFields

	err := datastoreView(func(tx *datastoreTx) error {

		serverEntries := tx.bucket(datastoreServerEntriesBucket)

		key := []byte(ipAddress)

		serverEntryRecord := serverEntries.get(key)
		if serverEntryRecord == nil {
			return errors.TraceNew("server entry not found")
		}

		err := json.Unmarshal(
			serverEntryRecord,
			&serverEntryFields)
		if err != nil {
			return errors.Trace(err)
		}

		return nil
	})
	if err != nil {
		return nil, errors.Trace(err)
	}

	err = serverEntryFields.ToSignedFields()
	if err != nil {
		return nil, errors.Trace(err)
	}

	return serverEntryFields, nil
}

// StoreInproxyCommonCompartmentIDs stores a list of in-proxy common
// compartment IDs. Clients obtain common compartment IDs from tactics;
// persisting the IDs enables a scheme whereby existing clients may continue
// to use common compartment IDs, and access the related in-proxy proxy
// matches, even after the compartment IDs are de-listed from tactics.
//
// The caller is responsible for merging new and existing compartment IDs into
// the input list, and trimming the length of the list appropriately.
func StoreInproxyCommonCompartmentIDs(compartmentIDs []string) error {

	value, err := json.Marshal(compartmentIDs)
	if err != nil {
		return errors.Trace(err)
	}

	err = setBucketValue(
		datastoreKeyValueBucket,
		datastoreInproxyCommonCompartmentIDsKey,
		value)
	return errors.Trace(err)
}

// LoadInproxyCommonCompartmentIDs returns the list of known, persisted
// in-proxy common compartment IDs. LoadInproxyCommonCompartmentIDs will
// return nil, nil when there is no stored list.
func LoadInproxyCommonCompartmentIDs() ([]string, error) {

	var compartmentIDs []string

	err := getBucketValue(
		datastoreKeyValueBucket,
		datastoreInproxyCommonCompartmentIDsKey,
		func(value []byte) error {
			if value == nil {
				return nil
			}

			// Note: unlike with server entries, this record is not deleted
			// when the unmarshal fails, as the caller should proceed with
			// any common compartment IDs available with tactics; and
			// subsequently call StoreInproxyCommonCompartmentIDs, writing
			// over this record.

			err := json.Unmarshal(value, &compartmentIDs)
			if err != nil {
				return errors.Trace(err)
			}

			return nil
		})
	if err != nil {
		return nil, errors.Trace(err)
	}

	return compartmentIDs, nil
}

// makeNetworkReplayParametersKey creates a unique key for the replay
// parameters which reflects the network ID context; the replay data type, R;
// and the replay ID, which uniquely identifies the object that is replayed
// (for example, am in-proxy broker public key, uniquely identifying a
// broker).
func makeNetworkReplayParametersKey[R any](networkID, replayID string) []byte {

	// A pointer to an R is used instead of stack (or heap) allocating a full
	// R object. As a result, the %T will include a '*' prefix, and this is
	// removed by the [1:].
	//
	// Fields are delimited using 0 bytes, which aren't expected to occur in
	// the field string values.

	var t *R
	key := append(append([]byte(nil), []byte(networkID)...), 0)
	key = append(append(key, []byte(fmt.Sprintf("%T", t)[1:])...), 0)
	key = append(key, []byte(replayID)...)
	return key
}

// SetNetworkReplayParameters stores replay parameters associated with the
// specified context and object.
//
// Limitation: unlike server dial parameters, the datastore does not prune
// replay records.
func SetNetworkReplayParameters[R any](networkID, replayID string, replayParams *R) error {

	key := makeNetworkReplayParametersKey[R](networkID, replayID)

	data, err := json.Marshal(replayParams)
	if err != nil {
		return errors.Trace(err)
	}

	return setBucketValue(datastoreNetworkReplayParametersBucket, key, data)
}

// SelectCandidateWithNetworkReplayParameters takes a list of candidate
// objects and selects one. The candidates are considered in the specified
// order. The first candidate with a valid replay record is returned, along
// with its replay parameters.
//
// The caller provides isValidReplay which should indicate if replay
// parameters remain valid; the caller should check for expiry and changes to
// the underlhying tactics.
//
// When no candidates with valid replay parameters are found,
// SelectCandidateWithNetworkReplayParameters returns the first candidate and
// nil replay parameters.
//
// When selectFirstCandidate is specified,
// SelectCandidateWithNetworkReplayParameters will check for valid replay
// parameters for the first candidate only, and then select the first
// candidate.
func SelectCandidateWithNetworkReplayParameters[C, R any](
	networkID string,
	selectFirstCandidate bool,
	candidates []*C,
	getReplayID func(*C) string,
	isValidReplay func(*C, *R) bool) (*C, *R, error) {

	if len(candidates) < 1 {
		return nil, nil, errors.TraceNew("no candidates")
	}

	candidate := candidates[0]
	var replay *R

	err := datastoreUpdate(func(tx *datastoreTx) error {

		bucket := tx.bucket(datastoreNetworkReplayParametersBucket)

		for _, c := range candidates {
			key := makeNetworkReplayParametersKey[R](networkID, getReplayID(c))
			value := bucket.get(key)
			if value == nil {
				continue
			}
			var r *R
			err := json.Unmarshal(value, &r)
			if err != nil {

				// Delete the record. This avoids continually checking it.
				// Note that the deletes performed here won't prune records
				// for old candidates which are no longer passed in to
				// SelectCandidateWithNetworkReplayParameters.
				NoticeWarning(
					"SelectCandidateWithNetworkReplayParameters: unmarshal failed: %s",
					errors.Trace(err))
				_ = bucket.delete(key)
				continue
			}
			if isValidReplay(c, r) {
				candidate = c
				replay = r
				return nil
			} else if selectFirstCandidate {
				return nil
			} else {

				// Delete the record if it's no longer valid due to expiry or
				// tactics changes. This avoids continually checking it.
				_ = bucket.delete(key)
				continue
			}
		}

		// No valid replay parameters were found, so candidates[0] and a nil
		// replay will be returned.
		return nil
	})
	if err != nil {
		return nil, nil, errors.Trace(err)
	}

	return candidate, replay, nil

}

// DeleteNetworkReplayParameters deletes the replay record associated with the
// specified context and object.
func DeleteNetworkReplayParameters[R any](networkID, replayID string) error {

	key := makeNetworkReplayParametersKey[R](networkID, replayID)

	return deleteBucketValue(datastoreNetworkReplayParametersBucket, key)
}

// DSLGetLastUntunneledFetchTime returns the timestamp of the last
// successfully completed untunneled DSL fetch.
func DSLGetLastUntunneledFetchTime() (time.Time, error) {
	value, err := getTimeKeyValue(datastoreDSLLastUntunneledFetchTimeKey)
	return value, errors.Trace(err)
}

// DSLSetLastUntunneledFetchTime sets the timestamp of the most recent
// successfully completed untunneled DSL fetch.
func DSLSetLastUntunneledFetchTime(time time.Time) error {
	err := setTimeKeyValue(datastoreDSLLastUntunneledFetchTimeKey, time)
	return errors.Trace(err)
}

// DSLGetLastUntunneledFetchTime returns the timestamp of the last
// successfully completed tunneled DSL fetch.
func DSLGetLastTunneledFetchTime() (time.Time, error) {
	value, err := getTimeKeyValue(datastoreDSLLastTunneledFetchTimeKey)
	return value, errors.Trace(err)
}

// DSLSetLastTunneledFetchTime sets the timestamp of the most recent
// successfully completed untunneled DSL fetch.
func DSLSetLastTunneledFetchTime(time time.Time) error {
	err := setTimeKeyValue(datastoreDSLLastTunneledFetchTimeKey, time)
	return errors.Trace(err)
}

// DSLHasServerEntry returns whether the datastore contains the server entry
// with the specified tag and version. DSLHasServerEntry uses a fast lookup
// which avoids unmarshaling server entries.
func DSLHasServerEntry(tag dsl.ServerEntryTag, version int) bool {

	hasServerEntry := false

	err := datastoreView(func(tx *datastoreTx) error {

		serverEntryTags := tx.bucket(datastoreServerEntryTagsBucket)

		serverEntryTagRecord := serverEntryTags.get(tag)

		if serverEntryTagRecord == nil {
			hasServerEntry = false
			return nil
		}

		_, configurationVersion, err := getServerEntryTagRecord(
			serverEntryTagRecord)
		if err != nil {
			return errors.Trace(err)
		}

		hasServerEntry = (configurationVersion == version)
		return nil
	})

	if err != nil {
		NoticeWarning("DSLHasServerEntry failed: %s", errors.Trace(err))
		return false
	}

	return hasServerEntry
}

// DSLStoreServerEntry adds the server entry to the datastore using
// StoreServerEntry and populating LocalSource and LocalTimestamp.
func DSLStoreServerEntry(
	serverEntrySignaturePublicKey string,
	packedServerEntryFields protocol.PackedServerEntryFields,
	source string) error {

	serverEntryFields, err := protocol.DecodePackedServerEntryFields(packedServerEntryFields)
	if err != nil {
		return errors.Trace(err)
	}

	err = serverEntryFields.VerifySignature(serverEntrySignaturePublicKey)
	if err != nil {
		return errors.Trace(err)
	}

	// See protocol.DecodeServerEntryFields and ImportEmbeddedServerEntries
	// for other code paths that populate SetLocalSource and SetLocalTimestamp.

	serverEntryFields.SetLocalSource(source)
	serverEntryFields.SetLocalTimestamp(common.TruncateTimestampToHour(common.GetCurrentTimestamp()))

	err = protocol.ValidateServerEntryFields(serverEntryFields)
	if err != nil {
		return errors.Trace(err)
	}

	err = StoreServerEntry(serverEntryFields, true)
	if err != nil {
		return errors.Trace(err)
	}

	return nil
}

// DSLGetLastActiveOSLsTime returns the timestamp of the last
// successfully completed active OSL check.
func DSLGetLastActiveOSLsTime() (time.Time, error) {
	value, err := getTimeKeyValue(datastoreDSLLastActiveOSLsTimeKey)
	return value, errors.Trace(err)
}

// DSLSetLastActiveOSLsTime sets the timestamp of the most recent
// successfully completed active OSL check.
func DSLSetLastActiveOSLsTime(time time.Time) error {
	err := setTimeKeyValue(datastoreDSLLastActiveOSLsTimeKey, time)
	return errors.Trace(err)
}

// DSLKnownOSLIDs returns the set of known OSL IDs retrieved from the active
// OSL DSL request.
func DSLKnownOSLIDs() ([]dsl.OSLID, error) {

	IDs := []dsl.OSLID{}

	err := getBucketKeys(datastoreDSLOSLStatesBucket, func(key []byte) {
		// Must make a copy as slice is only valid within transaction.
		IDs = append(IDs, append([]byte(nil), key...))
	})
	if err != nil {
		return nil, errors.Trace(err)
	}
	return IDs, nil
}

// DSLGetOSLState gets the current OSL state associated with an active OSL. A
// nil state is returned when no state is found for the specified ID. See
// dsl.Fetcher for more details on OSL states.
func DSLGetOSLState(ID dsl.OSLID) ([]byte, error) {
	state, err := copyBucketValue(datastoreDSLOSLStatesBucket, ID)
	if err != nil {
		return nil, errors.Trace(err)
	}

	return state, nil
}

// DSLStoreOSLState sets the OSL state associated with an active OSL.
func DSLStoreOSLState(ID dsl.OSLID, state []byte) error {
	err := setBucketValue(datastoreDSLOSLStatesBucket, ID, state)
	return errors.Trace(err)
}

// DSLDeleteOSLState deletes the specified OSL state.
func DSLDeleteOSLState(ID dsl.OSLID) error {
	err := deleteBucketValue(datastoreDSLOSLStatesBucket, ID)
	return errors.Trace(err)
}

func setTimeKeyValue(key string, timevalue time.Time) error {
	err := SetKeyValue(key, timevalue.Format(time.RFC3339))
	return errors.Trace(err)
}

func getTimeKeyValue(key string) (time.Time, error) {

	value, err := GetKeyValue(key)
	if err != nil {
		return time.Time{}, errors.Trace(err)
	}

	if value == "" {
		return time.Time{}, nil
	}

	timeValue, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, errors.Trace(err)
	}

	return timeValue, nil
}

func setBucketValue(bucket, key, value []byte) error {

	err := datastoreUpdate(func(tx *datastoreTx) error {
		bucket := tx.bucket(bucket)
		err := bucket.put(key, value)
		if err != nil {
			return errors.Trace(err)
		}
		return nil
	})

	if err != nil {
		return errors.Trace(err)
	}

	return nil
}

func getBucketValue(bucket, key []byte, valueCallback func([]byte) error) error {

	err := datastoreView(func(tx *datastoreTx) error {
		bucket := tx.bucket(bucket)
		value := bucket.get(key)
		return valueCallback(value)
	})

	if err != nil {
		return errors.Trace(err)
	}

	return nil
}

func deleteBucketValue(bucket, key []byte) error {

	err := datastoreUpdate(func(tx *datastoreTx) error {
		bucket := tx.bucket(bucket)
		return bucket.delete(key)
	})

	if err != nil {
		return errors.Trace(err)
	}

	return nil
}

func copyBucketValue(bucket, key []byte) ([]byte, error) {
	var valueCopy []byte
	err := getBucketValue(bucket, key, func(value []byte) error {
		if value != nil {
			// Must make a copy as slice is only valid within transaction.
			valueCopy = make([]byte, len(value))
			copy(valueCopy, value)
		}
		return nil
	})
	return valueCopy, err
}

func getBucketKeys(bucket []byte, keyCallback func([]byte)) error {

	err := datastoreView(func(tx *datastoreTx) error {
		bucket := tx.bucket(bucket)
		cursor := bucket.cursor()
		for key := cursor.firstKey(); key != nil; key = cursor.nextKey() {
			keyCallback(key)
		}
		cursor.close()
		return nil
	})

	if err != nil {
		return errors.Trace(err)
	}

	return nil
}

func setServerEntryTagRecord(
	serverEntryID []byte, configurationVersion int) ([]byte, error) {

	var delimiter = [1]byte{0}

	if bytes.Contains(serverEntryID, delimiter[:]) {
		// Not expected, since serverEntryID is an IP address string.
		return nil, errors.TraceNew("invalid serverEntryID")
	}

	if configurationVersion < 0 || configurationVersion >= math.MaxInt32 {
		return nil, errors.TraceNew("invalid configurationVersion")
	}

	var version [4]byte
	binary.LittleEndian.PutUint32(version[:], uint32(configurationVersion))

	return append(append(serverEntryID, delimiter[:]...), version[:]...), nil
}

func getServerEntryTagRecord(
	record []byte) ([]byte, int, error) {

	var delimiter = [1]byte{0}

	i := bytes.Index(record, delimiter[:])
	if i == -1 {
		// Backwards compatibility: assume version 0
		return record, 0, nil
	}
	i += 1

	if len(record)-i != 4 {
		return nil, 0, errors.TraceNew("invalid configurationVersion")
	}

	configurationVersion := binary.LittleEndian.Uint32(record[i:])

	return record[:i-1], int(configurationVersion), nil
}
