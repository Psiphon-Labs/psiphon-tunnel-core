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
	"encoding/json"
	"sync"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/parameters"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
)

var (
	datastoreServerEntriesBucket                = []byte("serverEntries")
	datastoreServerEntryTagsBucket              = []byte("serverEntryTags")
	datastoreServerEntryTombstoneTagsBucket     = []byte("serverEntryTombstoneTags")
	datastoreSplitTunnelRouteETagsBucket        = []byte("splitTunnelRouteETags")
	datastoreSplitTunnelRouteDataBucket         = []byte("splitTunnelRouteData")
	datastoreUrlETagsBucket                     = []byte("urlETags")
	datastoreKeyValueBucket                     = []byte("keyValues")
	datastoreRemoteServerListStatsBucket        = []byte("remoteServerListStats")
	datastoreFailedTunnelStatsBucket            = []byte("failedTunnelStats")
	datastoreSLOKsBucket                        = []byte("SLOKs")
	datastoreTacticsBucket                      = []byte("tactics")
	datastoreSpeedTestSamplesBucket             = []byte("speedTestSamples")
	datastoreDialParametersBucket               = []byte("dialParameters")
	datastoreLastConnectedKey                   = "lastConnected"
	datastoreLastServerEntryFilterKey           = []byte("lastServerEntryFilter")
	datastoreAffinityServerEntryIDKey           = []byte("affinityServerEntryID")
	datastorePersistentStatTypeRemoteServerList = string(datastoreRemoteServerListStatsBucket)
	datastorePersistentStatTypeFailedTunnel     = string(datastoreFailedTunnelStatsBucket)
	datastoreServerEntryFetchGCThreshold        = 10

	datastoreMutex    sync.RWMutex
	activeDatastoreDB *datastoreDB
)

// OpenDataStore opens and initializes the singleton data store instance.
func OpenDataStore(config *Config) error {

	datastoreMutex.Lock()

	existingDB := activeDatastoreDB

	if existingDB != nil {
		datastoreMutex.Unlock()
		return errors.TraceNew("db already open")
	}

	newDB, err := datastoreOpenDB(config.GetDataStoreDirectory())
	if err != nil {
		datastoreMutex.Unlock()
		return errors.Trace(err)
	}

	activeDatastoreDB = newDB

	datastoreMutex.Unlock()

	_ = resetAllPersistentStatsToUnreported()

	return nil
}

// CloseDataStore closes the singleton data store instance, if open.
func CloseDataStore() {

	datastoreMutex.Lock()
	defer datastoreMutex.Unlock()

	if activeDatastoreDB == nil {
		return
	}

	err := activeDatastoreDB.close()
	if err != nil {
		NoticeWarning("failed to close database: %s", errors.Trace(err))
	}

	activeDatastoreDB = nil
}

func datastoreView(fn func(tx *datastoreTx) error) error {

	datastoreMutex.RLock()
	defer datastoreMutex.RUnlock()

	if activeDatastoreDB == nil {
		return errors.TraceNew("database not open")
	}

	err := activeDatastoreDB.view(fn)
	if err != nil {
		err = errors.Trace(err)
	}
	return err
}

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

// StoreServerEntry adds the server entry to the data store.
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

		exists := existingConfigurationVersion > -1
		newer := exists && existingConfigurationVersion < serverEntryFields.GetConfigurationVersion()
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

		err = serverEntryTags.put(serverEntryTagBytes, serverEntryID)
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

// StreamingStoreServerEntries stores a list of server entries.
// There is an independent transaction for each entry insert/update.
func StreamingStoreServerEntries(
	config *Config,
	serverEntries *protocol.StreamingServerEntryDecoder,
	replaceIfExists bool) error {

	// Note: both StreamingServerEntryDecoder.Next and StoreServerEntry
	// allocate temporary memory buffers for hex/JSON decoding/encoding,
	// so this isn't true constant-memory streaming (it depends on garbage
	// collection).

	n := 0
	for {
		serverEntry, err := serverEntries.Next()
		if err != nil {
			return errors.Trace(err)
		}

		if serverEntry == nil {
			// No more server entries
			break
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
//
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

		limitTunnelProtocols := config.GetClientParameters().Get().TunnelProtocols(parameters.LimitTunnelProtocols)
		if len(limitTunnelProtocols) > 0 {
			// At the ServerEntryIterator level, only limitTunnelProtocols is applied;
			// excludeIntensive is handled higher up.
			if len(serverEntry.GetSupportedProtocols(
				conditionallyEnabledComponents{},
				config.UseUpstreamProxy(),
				limitTunnelProtocols,
				false)) == 0 {
				return false, nil, errors.TraceNew("TargetServerEntry does not support LimitTunnelProtocols")
			}
		}
	}

	iterator := &ServerEntryIterator{
		isTacticsServerEntryIterator: isTactics,
		isTargetServerEntryIterator:  true,
		hasNextTargetServerEntry:     true,
		targetServerEntry:            serverEntry,
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
		return nil
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

		var affinityServerEntryID []byte

		// In the first round only, move any server affinity candiate to the
		// very first position.

		if isInitialRound &&
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

		p := iterator.config.GetClientParameters().Get()

		if (isInitialRound || p.WeightedCoinFlip(parameters.ReplayLaterRoundMoveToFrontProbability)) &&
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
			deleteServerEntry(iterator.config, serverEntryID)
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

				serverEntries.put(serverEntryID, jsonServerEntryFields)
				if err != nil {
					return errors.Trace(err)
				}

				serverEntryTags.put([]byte(serverEntryTag), serverEntryID)
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

		if iterator.isTacticsServerEntryIterator {

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
func PruneServerEntry(config *Config, serverEntryTag string) {
	err := pruneServerEntry(config, serverEntryTag)
	if err != nil {
		NoticeWarning(
			"PruneServerEntry failed: %s: %s",
			serverEntryTag, errors.Trace(err))
		return
	}
	NoticePruneServerEntry(serverEntryTag)
}

func pruneServerEntry(config *Config, serverEntryTag string) error {

	minimumAgeForPruning := config.GetClientParameters().Get().Duration(
		parameters.ServerEntryMinimumAgeForPruning)

	return datastoreUpdate(func(tx *datastoreTx) error {

		serverEntries := tx.bucket(datastoreServerEntriesBucket)
		serverEntryTags := tx.bucket(datastoreServerEntryTagsBucket)
		serverEntryTombstoneTags := tx.bucket(datastoreServerEntryTombstoneTagsBucket)
		keyValues := tx.bucket(datastoreKeyValueBucket)
		dialParameters := tx.bucket(datastoreDialParametersBucket)

		serverEntryTagBytes := []byte(serverEntryTag)

		serverEntryID := serverEntryTags.get(serverEntryTagBytes)
		if serverEntryID == nil {
			return errors.TraceNew("server entry tag not found")
		}

		serverEntryJson := serverEntries.get(serverEntryID)
		if serverEntryJson == nil {
			return errors.TraceNew("server entry not found")
		}

		var serverEntry *protocol.ServerEntry
		err := json.Unmarshal(serverEntryJson, &serverEntry)
		if err != nil {
			errors.Trace(err)
		}

		// Only prune sufficiently old server entries. This mitigates the case where
		// stale data in psiphond will incorrectly identify brand new servers as
		// being invalid/deleted.
		serverEntryLocalTimestamp, err := time.Parse(time.RFC3339, serverEntry.LocalTimestamp)
		if err != nil {
			errors.Trace(err)
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
			errors.Trace(err)
		}

		if doDeleteServerEntry {

			err = deleteServerEntryHelper(
				config,
				serverEntryID,
				serverEntries,
				keyValues,
				dialParameters)
			if err != nil {
				errors.Trace(err)
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

		return nil
	})
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
			errors.Trace(err)
		}

		// Remove any tags pointing to the deleted server entry.
		cursor := serverEntryTags.cursor()
		defer cursor.close()
		for key, value := cursor.first(); key != nil; key, value = cursor.next() {
			if bytes.Equal(value, serverEntryID) {
				err := serverEntryTags.delete(key)
				if err != nil {
					return errors.Trace(err)
				}
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
		errors.Trace(err)
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

	// TODO: expose boltdb Seek functionality to skip to first matching record.
	cursor := dialParameters.cursor()
	defer cursor.close()
	foundFirstMatch := false
	for key, _ := cursor.first(); key != nil; key, _ = cursor.next() {
		// Dial parameters key has serverID as a prefix; see makeDialParametersKey.
		if bytes.HasPrefix(key, serverEntryID) {
			foundFirstMatch = true
			err := dialParameters.delete(key)
			if err != nil {
				return errors.Trace(err)
			}
		} else if foundFirstMatch {
			break
		}
	}

	return nil
}

func scanServerEntries(scanner func(*protocol.ServerEntry)) error {
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
				NoticeWarning("scanServerEntries: %s", errors.Trace(err))
				continue
			}
			scanner(serverEntry)

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

// CountServerEntries returns a count of stored server entries.
func CountServerEntries() int {
	count := 0
	err := scanServerEntries(func(_ *protocol.ServerEntry) {
		count += 1
	})

	if err != nil {
		NoticeWarning("CountServerEntries failed: %s", err)
		return 0
	}

	return count
}

// CountServerEntriesWithConstraints returns a count of stored server entries for
// the specified region and tunnel protocol limits.
func CountServerEntriesWithConstraints(
	useUpstreamProxy bool,
	region string,
	constraints *protocolSelectionConstraints) (int, int) {

	// When CountServerEntriesWithConstraints is called only
	// limitTunnelProtocolState is fixed; excludeIntensive is transitory.
	excludeIntensive := false

	initialCount := 0
	count := 0
	err := scanServerEntries(func(serverEntry *protocol.ServerEntry) {
		if region == "" || serverEntry.Region == region {

			if constraints.isInitialCandidate(excludeIntensive, serverEntry) {
				initialCount += 1
			}

			if constraints.isCandidate(excludeIntensive, serverEntry) {
				count += 1
			}

		}
	})

	if err != nil {
		NoticeWarning("CountServerEntriesWithConstraints failed: %s", err)
		return 0, 0
	}

	return initialCount, count
}

// ReportAvailableRegions prints a notice with the available egress regions.
// When limitState has initial protocols, the available regions are limited
// to those available for the initial protocols; or if limitState has general
// limited protocols, the available regions are similarly limited.
func ReportAvailableRegions(config *Config, constraints *protocolSelectionConstraints) {

	// When ReportAvailableRegions is called only limitTunnelProtocolState is
	// fixed; excludeIntensive is transitory.
	excludeIntensive := false

	regions := make(map[string]bool)
	err := scanServerEntries(func(serverEntry *protocol.ServerEntry) {

		isCandidate := false
		if constraints.hasInitialProtocols() {
			isCandidate = constraints.isInitialCandidate(excludeIntensive, serverEntry)
		} else {
			isCandidate = constraints.isCandidate(excludeIntensive, serverEntry)
		}

		if isCandidate {
			regions[serverEntry.Region] = true
		}
	})

	if err != nil {
		NoticeWarning("ReportAvailableRegions failed: %s", err)
		return
	}

	regionList := make([]string, 0, len(regions))
	for region := range regions {
		// Some server entries do not have a region, but it makes no sense to return
		// an empty string as an "available region".
		if region != "" {
			regionList = append(regionList, region)
		}
	}

	NoticeAvailableEgressRegions(regionList)
}

// SetSplitTunnelRoutes updates the cached routes data for
// the given region. The associated etag is also stored and
// used to make efficient web requests for updates to the data.
func SetSplitTunnelRoutes(region, etag string, data []byte) error {

	err := datastoreUpdate(func(tx *datastoreTx) error {
		bucket := tx.bucket(datastoreSplitTunnelRouteETagsBucket)
		err := bucket.put([]byte(region), []byte(etag))
		if err != nil {
			return errors.Trace(err)
		}

		bucket = tx.bucket(datastoreSplitTunnelRouteDataBucket)
		err = bucket.put([]byte(region), data)
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

// GetSplitTunnelRoutesETag retrieves the etag for cached routes
// data for the specified region. If not found, it returns an empty string value.
func GetSplitTunnelRoutesETag(region string) (string, error) {

	var etag string

	err := datastoreView(func(tx *datastoreTx) error {
		bucket := tx.bucket(datastoreSplitTunnelRouteETagsBucket)
		etag = string(bucket.get([]byte(region)))
		return nil
	})

	if err != nil {
		return "", errors.Trace(err)
	}
	return etag, nil
}

// GetSplitTunnelRoutesData retrieves the cached routes data
// for the specified region. If not found, it returns a nil value.
func GetSplitTunnelRoutesData(region string) ([]byte, error) {

	var data []byte

	err := datastoreView(func(tx *datastoreTx) error {
		bucket := tx.bucket(datastoreSplitTunnelRouteDataBucket)
		value := bucket.get([]byte(region))
		if value != nil {
			// Must make a copy as slice is only valid within transaction.
			data = make([]byte, len(value))
			copy(data, value)
		}
		return nil
	})

	if err != nil {
		return nil, errors.Trace(err)
	}
	return data, nil
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

	maxStoreRecords := config.GetClientParameters().Get().Int(
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
func TakeOutUnreportedPersistentStats(config *Config) (map[string][][]byte, error) {

	stats := make(map[string][][]byte)

	maxSendBytes := config.GetClientParameters().Get().Int(
		parameters.PersistentStatsMaxSendBytes)

	err := datastoreUpdate(func(tx *datastoreTx) error {

		sendBytes := 0

		for _, statType := range persistentStatTypes {

			bucket := tx.bucket([]byte(statType))
			cursor := bucket.cursor()
			for key, value := cursor.first(); key != nil; key, value = cursor.next() {

				// Perform a test JSON unmarshaling. In case of data corruption or a bug,
				// delete and skip the record.
				var jsonData interface{}
				err := json.Unmarshal(key, &jsonData)
				if err != nil {
					NoticeWarning(
						"Invalid key in TakeOutUnreportedPersistentStats: %s: %s",
						string(key), err)
					bucket.delete(key)
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
		return nil, errors.Trace(err)
	}

	return stats, nil
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
func SetSLOK(id, key []byte) (bool, error) {

	var duplicate bool

	err := datastoreUpdate(func(tx *datastoreTx) error {
		bucket := tx.bucket(datastoreSLOKsBucket)
		duplicate = bucket.get(id) != nil
		err := bucket.put([]byte(id), []byte(key))
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

	var key []byte

	err := datastoreView(func(tx *datastoreTx) error {
		bucket := tx.bucket(datastoreSLOKsBucket)
		key = bucket.get(id)
		return nil
	})

	if err != nil {
		return nil, errors.Trace(err)
	}

	return key, nil
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
func GetDialParameters(serverIPAddress, networkID string) (*DialParameters, error) {

	key := makeDialParametersKey([]byte(serverIPAddress), []byte(networkID))

	data, err := getBucketValue(datastoreDialParametersBucket, key)
	if err != nil {
		return nil, errors.Trace(err)
	}

	if data == nil {
		return nil, nil
	}

	// Note: unlike with server entries, this record is not deleted when the
	// unmarshal fails, as the caller should proceed with the dial without dial
	// parameters; and when when the dial succeeds, new dial parameters will be
	// written over this record.

	var dialParams *DialParameters
	err = json.Unmarshal(data, &dialParams)
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
type TacticsStorer struct {
}

func (t *TacticsStorer) SetTacticsRecord(networkID string, record []byte) error {
	return setBucketValue(datastoreTacticsBucket, []byte(networkID), record)
}

func (t *TacticsStorer) GetTacticsRecord(networkID string) ([]byte, error) {
	return getBucketValue(datastoreTacticsBucket, []byte(networkID))
}

func (t *TacticsStorer) SetSpeedTestSamplesRecord(networkID string, record []byte) error {
	return setBucketValue(datastoreSpeedTestSamplesBucket, []byte(networkID), record)
}

func (t *TacticsStorer) GetSpeedTestSamplesRecord(networkID string) ([]byte, error) {
	return getBucketValue(datastoreSpeedTestSamplesBucket, []byte(networkID))
}

// GetTacticsStorer creates a TacticsStorer.
func GetTacticsStorer() *TacticsStorer {
	return &TacticsStorer{}
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

func getBucketValue(bucket, key []byte) ([]byte, error) {

	var value []byte

	err := datastoreView(func(tx *datastoreTx) error {
		bucket := tx.bucket(bucket)
		value = bucket.get(key)
		return nil
	})

	if err != nil {
		return nil, errors.Trace(err)
	}

	return value, nil
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
