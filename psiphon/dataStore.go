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
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Psiphon-Inc/bolt"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
)

// The BoltDB dataStore implementation is an alternative to the sqlite3-based
// implementation in dataStore.go. Both implementations have the same interface.
//
// BoltDB is pure Go, and is intended to be used in cases where we have trouble
// building sqlite3/CGO (e.g., currently go mobile due to
// https://github.com/mattn/go-sqlite3/issues/201), and perhaps ultimately as
// the primary dataStore implementation.
//
type dataStore struct {
	init sync.Once
	db   *bolt.DB
}

const (
	serverEntriesBucket         = "serverEntries"
	rankedServerEntriesBucket   = "rankedServerEntries"
	rankedServerEntriesKey      = "rankedServerEntries"
	splitTunnelRouteETagsBucket = "splitTunnelRouteETags"
	splitTunnelRouteDataBucket  = "splitTunnelRouteData"
	urlETagsBucket              = "urlETags"
	keyValueBucket              = "keyValues"
	tunnelStatsBucket           = "tunnelStats"
	rankedServerEntryCount      = 100
)

var singleton dataStore

// InitDataStore initializes the singleton instance of dataStore. This
// function uses a sync.Once and is safe for use by concurrent goroutines.
// The underlying sql.DB connection pool is also safe.
//
// Note: the sync.Once was more useful when initDataStore was private and
// called on-demand by the public functions below. Now we require an explicit
// InitDataStore() call with the filename passed in. The on-demand calls
// have been replaced by checkInitDataStore() to assert that Init was called.
func InitDataStore(config *Config) (err error) {
	singleton.init.Do(func() {
		// Need to gather the list of migratable server entries before
		// initializing the boltdb store (as prepareMigrationEntries
		// checks for the existence of the bolt db file)
		migratableServerEntries := prepareMigrationEntries(config)

		filename := filepath.Join(config.DataStoreDirectory, DATA_STORE_FILENAME)
		var db *bolt.DB
		db, err = bolt.Open(filename, 0600, &bolt.Options{Timeout: 1 * time.Second})

		// The datastore file may be corrupt, so attempt to delete and try again
		if err != nil {
			NoticeAlert("retry on initDataStore error: %s", err)
			os.Remove(filename)
			db, err = bolt.Open(filename, 0600, &bolt.Options{Timeout: 1 * time.Second})
		}

		if err != nil {
			// Note: intending to set the err return value for InitDataStore
			err = fmt.Errorf("initDataStore failed to open database: %s", err)
			return
		}

		err = db.Update(func(tx *bolt.Tx) error {
			requiredBuckets := []string{
				serverEntriesBucket,
				rankedServerEntriesBucket,
				splitTunnelRouteETagsBucket,
				splitTunnelRouteDataBucket,
				urlETagsBucket,
				keyValueBucket,
				tunnelStatsBucket,
			}
			for _, bucket := range requiredBuckets {
				_, err := tx.CreateBucketIfNotExists([]byte(bucket))
				if err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			err = fmt.Errorf("initDataStore failed to create buckets: %s", err)
			return
		}

		// Run consistency checks on datastore and emit errors for diagnostics purposes
		// We assume this will complete quickly for typical size Psiphon datastores.
		db.View(func(tx *bolt.Tx) error {
			err := <-tx.Check()
			if err != nil {
				NoticeAlert("boltdb Check(): %s", err)
			}
			return nil
		})

		singleton.db = db

		// The migrateServerEntries function requires the data store is
		// initialized prior to execution so that migrated entries can be stored

		if len(migratableServerEntries) > 0 {
			migrateEntries(migratableServerEntries, filepath.Join(config.DataStoreDirectory, LEGACY_DATA_STORE_FILENAME))
		}

		resetAllTunnelStatsToUnreported()
	})

	return err
}

func checkInitDataStore() {
	if singleton.db == nil {
		panic("checkInitDataStore: datastore not initialized")
	}
}

// StoreServerEntry adds the server entry to the data store.
// A newly stored (or re-stored) server entry is assigned the next-to-top
// rank for iteration order (the previous top ranked entry is promoted). The
// purpose of inserting at next-to-top is to keep the last selected server
// as the top ranked server.
// When replaceIfExists is true, an existing server entry record is
// overwritten; otherwise, the existing record is unchanged.
// If the server entry data is malformed, an alert notice is issued and
// the entry is skipped; no error is returned.
func StoreServerEntry(serverEntry *ServerEntry, replaceIfExists bool) error {
	checkInitDataStore()

	// Server entries should already be validated before this point,
	// so instead of skipping we fail with an error.
	err := ValidateServerEntry(serverEntry)
	if err != nil {
		return common.ContextError(errors.New("invalid server entry"))
	}

	// BoltDB implementation note:
	// For simplicity, we don't maintain indexes on server entry
	// region or supported protocols. Instead, we perform full-bucket
	// scans with a filter. With a small enough database (thousands or
	// even tens of thousand of server entries) and common enough
	// values (e.g., many servers support all protocols), performance
	// is expected to be acceptable.

	err = singleton.db.Update(func(tx *bolt.Tx) error {

		serverEntries := tx.Bucket([]byte(serverEntriesBucket))

		// Check not only that the entry exists, but is valid. This
		// will replace in the rare case where the data is corrupt.
		existingServerEntryValid := false
		existingData := serverEntries.Get([]byte(serverEntry.IpAddress))
		if existingData != nil {
			existingServerEntry := new(ServerEntry)
			if json.Unmarshal(existingData, existingServerEntry) == nil {
				existingServerEntryValid = true
			}
		}

		if existingServerEntryValid && !replaceIfExists {
			// Disabling this notice, for now, as it generates too much noise
			// in diagnostics with clients that always submit embedded servers
			// to the core on each run.
			// NoticeInfo("ignored update for server %s", serverEntry.IpAddress)
			return nil
		}

		data, err := json.Marshal(serverEntry)
		if err != nil {
			return common.ContextError(err)
		}
		err = serverEntries.Put([]byte(serverEntry.IpAddress), data)
		if err != nil {
			return common.ContextError(err)
		}

		err = insertRankedServerEntry(tx, serverEntry.IpAddress, 1)
		if err != nil {
			return common.ContextError(err)
		}

		NoticeInfo("updated server %s", serverEntry.IpAddress)

		return nil
	})
	if err != nil {
		return common.ContextError(err)
	}

	return nil
}

// StoreServerEntries shuffles and stores a list of server entries.
// Shuffling is performed on imported server entrues as part of client-side
// load balancing.
// There is an independent transaction for each entry insert/update.
func StoreServerEntries(serverEntries []*ServerEntry, replaceIfExists bool) error {
	checkInitDataStore()

	for index := len(serverEntries) - 1; index > 0; index-- {
		swapIndex := rand.Intn(index + 1)
		serverEntries[index], serverEntries[swapIndex] = serverEntries[swapIndex], serverEntries[index]
	}

	for _, serverEntry := range serverEntries {
		err := StoreServerEntry(serverEntry, replaceIfExists)
		if err != nil {
			return common.ContextError(err)
		}
	}

	// Since there has possibly been a significant change in the server entries,
	// take this opportunity to update the available egress regions.
	ReportAvailableRegions()

	return nil
}

// PromoteServerEntry assigns the top rank (one more than current
// max rank) to the specified server entry. Server candidates are
// iterated in decending rank order, so this server entry will be
// the first candidate in a subsequent tunnel establishment.
func PromoteServerEntry(ipAddress string) error {
	checkInitDataStore()

	err := singleton.db.Update(func(tx *bolt.Tx) error {

		// Ensure the corresponding entry exists before
		// inserting into rank.
		bucket := tx.Bucket([]byte(serverEntriesBucket))
		data := bucket.Get([]byte(ipAddress))
		if data == nil {
			NoticeAlert(
				"PromoteServerEntry: ignoring unknown server entry: %s",
				ipAddress)
			return nil
		}

		return insertRankedServerEntry(tx, ipAddress, 0)
	})

	if err != nil {
		return common.ContextError(err)
	}
	return nil
}

func getRankedServerEntries(tx *bolt.Tx) ([]string, error) {
	bucket := tx.Bucket([]byte(rankedServerEntriesBucket))
	data := bucket.Get([]byte(rankedServerEntriesKey))

	if data == nil {
		return []string{}, nil
	}

	rankedServerEntries := make([]string, 0)
	err := json.Unmarshal(data, &rankedServerEntries)
	if err != nil {
		return nil, common.ContextError(err)
	}
	return rankedServerEntries, nil
}

func setRankedServerEntries(tx *bolt.Tx, rankedServerEntries []string) error {
	data, err := json.Marshal(rankedServerEntries)
	if err != nil {
		return common.ContextError(err)
	}

	bucket := tx.Bucket([]byte(rankedServerEntriesBucket))
	err = bucket.Put([]byte(rankedServerEntriesKey), data)
	if err != nil {
		return common.ContextError(err)
	}

	return nil
}

func insertRankedServerEntry(tx *bolt.Tx, serverEntryId string, position int) error {
	rankedServerEntries, err := getRankedServerEntries(tx)
	if err != nil {
		return common.ContextError(err)
	}

	// BoltDB implementation note:
	// For simplicity, we store the ranked server ids in an array serialized to
	// a single key value. To ensure this value doesn't grow without bound,
	// it's capped at rankedServerEntryCount. For now, this cap should be large
	// enough to meet the shuffleHeadLength = config.TunnelPoolSize criteria, for
	// any reasonable configuration of config.TunnelPoolSize.

	// Using: https://github.com/golang/go/wiki/SliceTricks

	// When serverEntryId is already ranked, remove it first to avoid duplicates

	for i, rankedServerEntryId := range rankedServerEntries {
		if rankedServerEntryId == serverEntryId {
			rankedServerEntries = append(
				rankedServerEntries[:i], rankedServerEntries[i+1:]...)
			break
		}
	}

	// SliceTricks insert, with length cap enforced

	if len(rankedServerEntries) < rankedServerEntryCount {
		rankedServerEntries = append(rankedServerEntries, "")
	}
	if position >= len(rankedServerEntries) {
		position = len(rankedServerEntries) - 1
	}
	copy(rankedServerEntries[position+1:], rankedServerEntries[position:])
	rankedServerEntries[position] = serverEntryId

	err = setRankedServerEntries(tx, rankedServerEntries)
	if err != nil {
		return common.ContextError(err)
	}

	return nil
}

func serverEntrySupportsProtocol(serverEntry *ServerEntry, protocol string) bool {
	// Note: for meek, the capabilities are FRONTED-MEEK and UNFRONTED-MEEK
	// and the additonal OSSH service is assumed to be available internally.
	requiredCapability := strings.TrimSuffix(protocol, "-OSSH")
	return common.Contains(serverEntry.Capabilities, requiredCapability)
}

// ServerEntryIterator is used to iterate over
// stored server entries in rank order.
type ServerEntryIterator struct {
	region                      string
	protocol                    string
	shuffleHeadLength           int
	serverEntryIds              []string
	serverEntryIndex            int
	isTargetServerEntryIterator bool
	hasNextTargetServerEntry    bool
	targetServerEntry           *ServerEntry
}

// NewServerEntryIterator creates a new ServerEntryIterator
func NewServerEntryIterator(config *Config) (iterator *ServerEntryIterator, err error) {

	// When configured, this target server entry is the only candidate
	if config.TargetServerEntry != "" {
		return newTargetServerEntryIterator(config)
	}

	checkInitDataStore()
	iterator = &ServerEntryIterator{
		region:                      config.EgressRegion,
		protocol:                    config.TunnelProtocol,
		shuffleHeadLength:           config.TunnelPoolSize,
		isTargetServerEntryIterator: false,
	}
	err = iterator.Reset()
	if err != nil {
		return nil, err
	}
	return iterator, nil
}

// newTargetServerEntryIterator is a helper for initializing the TargetServerEntry case
func newTargetServerEntryIterator(config *Config) (iterator *ServerEntryIterator, err error) {
	serverEntry, err := DecodeServerEntry(
		config.TargetServerEntry, common.GetCurrentTimestamp(), common.SERVER_ENTRY_SOURCE_TARGET)
	if err != nil {
		return nil, err
	}
	if config.EgressRegion != "" && serverEntry.Region != config.EgressRegion {
		return nil, errors.New("TargetServerEntry does not support EgressRegion")
	}
	if config.TunnelProtocol != "" {
		// Note: same capability/protocol mapping as in StoreServerEntry
		requiredCapability := strings.TrimSuffix(config.TunnelProtocol, "-OSSH")
		if !common.Contains(serverEntry.Capabilities, requiredCapability) {
			return nil, errors.New("TargetServerEntry does not support TunnelProtocol")
		}
	}
	iterator = &ServerEntryIterator{
		isTargetServerEntryIterator: true,
		hasNextTargetServerEntry:    true,
		targetServerEntry:           serverEntry,
	}
	NoticeInfo("using TargetServerEntry: %s", serverEntry.IpAddress)
	return iterator, nil
}

// Reset a NewServerEntryIterator to the start of its cycle. The next
// call to Next will return the first server entry.
func (iterator *ServerEntryIterator) Reset() error {
	iterator.Close()

	if iterator.isTargetServerEntryIterator {
		iterator.hasNextTargetServerEntry = true
		return nil
	}

	count := CountServerEntries(iterator.region, iterator.protocol)
	NoticeCandidateServers(iterator.region, iterator.protocol, count)

	// This query implements the Psiphon server candidate selection
	// algorithm: the first TunnelPoolSize server candidates are in rank
	// (priority) order, to favor previously successful servers; then the
	// remaining long tail is shuffled to raise up less recent candidates.

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
	// So the underlying serverEntriesBucket could change after the serverEntryIds
	// list is built.

	var serverEntryIds []string

	err := singleton.db.View(func(tx *bolt.Tx) error {
		var err error
		serverEntryIds, err = getRankedServerEntries(tx)
		if err != nil {
			return err
		}

		skipServerEntryIds := make(map[string]bool)
		for _, serverEntryId := range serverEntryIds {
			skipServerEntryIds[serverEntryId] = true
		}

		bucket := tx.Bucket([]byte(serverEntriesBucket))
		cursor := bucket.Cursor()
		for key, _ := cursor.Last(); key != nil; key, _ = cursor.Prev() {
			serverEntryId := string(key)
			if _, ok := skipServerEntryIds[serverEntryId]; ok {
				continue
			}
			serverEntryIds = append(serverEntryIds, serverEntryId)
		}
		return nil
	})
	if err != nil {
		return common.ContextError(err)
	}

	for i := len(serverEntryIds) - 1; i > iterator.shuffleHeadLength-1; i-- {
		j := rand.Intn(i+1-iterator.shuffleHeadLength) + iterator.shuffleHeadLength
		serverEntryIds[i], serverEntryIds[j] = serverEntryIds[j], serverEntryIds[i]
	}

	iterator.serverEntryIds = serverEntryIds
	iterator.serverEntryIndex = 0

	return nil
}

// Close cleans up resources associated with a ServerEntryIterator.
func (iterator *ServerEntryIterator) Close() {
	iterator.serverEntryIds = nil
	iterator.serverEntryIndex = 0
}

// Next returns the next server entry, by rank, for a ServerEntryIterator.
// Returns nil with no error when there is no next item.
func (iterator *ServerEntryIterator) Next() (serverEntry *ServerEntry, err error) {
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
		if iterator.serverEntryIndex >= len(iterator.serverEntryIds) {
			// There is no next item
			return nil, nil
		}

		serverEntryId := iterator.serverEntryIds[iterator.serverEntryIndex]
		iterator.serverEntryIndex += 1

		var data []byte
		err = singleton.db.View(func(tx *bolt.Tx) error {
			bucket := tx.Bucket([]byte(serverEntriesBucket))
			value := bucket.Get([]byte(serverEntryId))
			if value != nil {
				// Must make a copy as slice is only valid within transaction.
				data = make([]byte, len(value))
				copy(data, value)
			}
			return nil
		})
		if err != nil {
			return nil, common.ContextError(err)
		}

		if data == nil {
			// In case of data corruption or a bug causing this condition,
			// do not stop iterating.
			NoticeAlert("ServerEntryIterator.Next: unexpected missing server entry: %s", serverEntryId)
			continue
		}

		serverEntry = new(ServerEntry)
		err = json.Unmarshal(data, serverEntry)
		if err != nil {
			// In case of data corruption or a bug causing this condition,
			// do not stop iterating.
			NoticeAlert("ServerEntryIterator.Next: %s", common.ContextError(err))
			continue
		}

		// Check filter requirements
		if (iterator.region == "" || serverEntry.Region == iterator.region) &&
			(iterator.protocol == "" || serverEntrySupportsProtocol(serverEntry, iterator.protocol)) {

			break
		}
	}

	return MakeCompatibleServerEntry(serverEntry), nil
}

// MakeCompatibleServerEntry provides backwards compatibility with old server entries
// which have a single meekFrontingDomain and not a meekFrontingAddresses array.
// By copying this one meekFrontingDomain into meekFrontingAddresses, this client effectively
// uses that single value as legacy clients do.
func MakeCompatibleServerEntry(serverEntry *ServerEntry) *ServerEntry {
	if len(serverEntry.MeekFrontingAddresses) == 0 && serverEntry.MeekFrontingDomain != "" {
		serverEntry.MeekFrontingAddresses =
			append(serverEntry.MeekFrontingAddresses, serverEntry.MeekFrontingDomain)
	}

	return serverEntry
}

func scanServerEntries(scanner func(*ServerEntry)) error {
	err := singleton.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(serverEntriesBucket))
		cursor := bucket.Cursor()

		for key, value := cursor.First(); key != nil; key, value = cursor.Next() {
			serverEntry := new(ServerEntry)
			err := json.Unmarshal(value, serverEntry)
			if err != nil {
				// In case of data corruption or a bug causing this condition,
				// do not stop iterating.
				NoticeAlert("scanServerEntries: %s", common.ContextError(err))
				continue
			}
			scanner(serverEntry)
		}

		return nil
	})

	if err != nil {
		return common.ContextError(err)
	}

	return nil
}

// CountServerEntries returns a count of stored servers for the
// specified region and protocol.
func CountServerEntries(region, protocol string) int {
	checkInitDataStore()

	count := 0
	err := scanServerEntries(func(serverEntry *ServerEntry) {
		if (region == "" || serverEntry.Region == region) &&
			(protocol == "" || serverEntrySupportsProtocol(serverEntry, protocol)) {
			count += 1
		}
	})

	if err != nil {
		NoticeAlert("CountServerEntries failed: %s", err)
		return 0
	}

	return count
}

// ReportAvailableRegions prints a notice with the available egress regions.
// Note that this report ignores config.TunnelProtocol.
func ReportAvailableRegions() {
	checkInitDataStore()

	regions := make(map[string]bool)
	err := scanServerEntries(func(serverEntry *ServerEntry) {
		regions[serverEntry.Region] = true
	})

	if err != nil {
		NoticeAlert("ReportAvailableRegions failed: %s", err)
		return
	}

	regionList := make([]string, 0, len(regions))
	for region, _ := range regions {
		// Some server entries do not have a region, but it makes no sense to return
		// an empty string as an "available region".
		if region != "" {
			regionList = append(regionList, region)
		}
	}

	NoticeAvailableEgressRegions(regionList)
}

// GetServerEntryIpAddresses returns an array containing
// all stored server IP addresses.
func GetServerEntryIpAddresses() (ipAddresses []string, err error) {
	checkInitDataStore()

	ipAddresses = make([]string, 0)
	err = scanServerEntries(func(serverEntry *ServerEntry) {
		ipAddresses = append(ipAddresses, serverEntry.IpAddress)
	})

	if err != nil {
		return nil, common.ContextError(err)
	}

	return ipAddresses, nil
}

// SetSplitTunnelRoutes updates the cached routes data for
// the given region. The associated etag is also stored and
// used to make efficient web requests for updates to the data.
func SetSplitTunnelRoutes(region, etag string, data []byte) error {
	checkInitDataStore()

	err := singleton.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(splitTunnelRouteETagsBucket))
		err := bucket.Put([]byte(region), []byte(etag))

		bucket = tx.Bucket([]byte(splitTunnelRouteDataBucket))
		err = bucket.Put([]byte(region), data)
		return err
	})

	if err != nil {
		return common.ContextError(err)
	}
	return nil
}

// GetSplitTunnelRoutesETag retrieves the etag for cached routes
// data for the specified region. If not found, it returns an empty string value.
func GetSplitTunnelRoutesETag(region string) (etag string, err error) {
	checkInitDataStore()

	err = singleton.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(splitTunnelRouteETagsBucket))
		etag = string(bucket.Get([]byte(region)))
		return nil
	})

	if err != nil {
		return "", common.ContextError(err)
	}
	return etag, nil
}

// GetSplitTunnelRoutesData retrieves the cached routes data
// for the specified region. If not found, it returns a nil value.
func GetSplitTunnelRoutesData(region string) (data []byte, err error) {
	checkInitDataStore()

	err = singleton.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(splitTunnelRouteDataBucket))
		value := bucket.Get([]byte(region))
		if value != nil {
			// Must make a copy as slice is only valid within transaction.
			data = make([]byte, len(value))
			copy(data, value)
		}
		return nil
	})

	if err != nil {
		return nil, common.ContextError(err)
	}
	return data, nil
}

// SetUrlETag stores an ETag for the specfied URL.
// Note: input URL is treated as a string, and is not
// encoded or decoded or otherwise canonicalized.
func SetUrlETag(url, etag string) error {
	checkInitDataStore()

	err := singleton.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(urlETagsBucket))
		err := bucket.Put([]byte(url), []byte(etag))
		return err
	})

	if err != nil {
		return common.ContextError(err)
	}
	return nil
}

// GetUrlETag retrieves a previously stored an ETag for the
// specfied URL. If not found, it returns an empty string value.
func GetUrlETag(url string) (etag string, err error) {
	checkInitDataStore()

	err = singleton.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(urlETagsBucket))
		etag = string(bucket.Get([]byte(url)))
		return nil
	})

	if err != nil {
		return "", common.ContextError(err)
	}
	return etag, nil
}

// SetKeyValue stores a key/value pair.
func SetKeyValue(key, value string) error {
	checkInitDataStore()

	err := singleton.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(keyValueBucket))
		err := bucket.Put([]byte(key), []byte(value))
		return err
	})

	if err != nil {
		return common.ContextError(err)
	}
	return nil
}

// GetKeyValue retrieves the value for a given key. If not found,
// it returns an empty string value.
func GetKeyValue(key string) (value string, err error) {
	checkInitDataStore()

	err = singleton.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(keyValueBucket))
		value = string(bucket.Get([]byte(key)))
		return nil
	})

	if err != nil {
		return "", common.ContextError(err)
	}
	return value, nil
}

// Tunnel stats records in the tunnelStatsStateUnreported
// state are available for take out.
// Records in the tunnelStatsStateReporting have been
// taken out and are pending either deleting (for a
// successful request) or change to StateUnreported (for
// a failed request).
// All tunnel stats records are reverted to StateUnreported
// when the datastore is initialized at start up.

var tunnelStatsStateUnreported = []byte("0")
var tunnelStatsStateReporting = []byte("1")

// StoreTunnelStats adds a new tunnel stats record, which is
// set to StateUnreported and is an immediate candidate for
// reporting.
// tunnelStats is a JSON byte array containing fields as
// required by the Psiphon server API (see RecordTunnelStats).
// It's assumed that the JSON value contains enough unique
// information for the value to function as a key in the
// key/value datastore. This assumption is currently satisfied
// by the fields sessionId + tunnelNumber.
func StoreTunnelStats(tunnelStats []byte) error {
	checkInitDataStore()

	err := singleton.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(tunnelStatsBucket))
		err := bucket.Put(tunnelStats, tunnelStatsStateUnreported)
		return err
	})

	if err != nil {
		return common.ContextError(err)
	}
	return nil
}

// CountUnreportedTunnelStats returns the number of tunnel
// stats records in StateUnreported.
func CountUnreportedTunnelStats() int {
	checkInitDataStore()

	unreported := 0

	err := singleton.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(tunnelStatsBucket))
		cursor := bucket.Cursor()
		for key, value := cursor.First(); key != nil; key, value = cursor.Next() {
			if 0 == bytes.Compare(value, tunnelStatsStateUnreported) {
				unreported++
				break
			}
		}
		return nil
	})

	if err != nil {
		NoticeAlert("CountUnreportedTunnelStats failed: %s", err)
		return 0
	}

	return unreported
}

// TakeOutUnreportedTunnelStats returns up to maxCount tunnel
// stats records that are in StateUnreported. The records are set
// to StateReporting. If the records are successfully reported,
// clear them with ClearReportedTunnelStats. If the records are
// not successfully reported, restore them with
// PutBackUnreportedTunnelStats.
func TakeOutUnreportedTunnelStats(maxCount int) ([][]byte, error) {
	checkInitDataStore()

	tunnelStats := make([][]byte, 0)

	err := singleton.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(tunnelStatsBucket))
		cursor := bucket.Cursor()
		for key, value := cursor.First(); key != nil; key, value = cursor.Next() {

			// Perform a test JSON unmarshaling. In case of data corruption or a bug,
			// skip the record.
			var jsonData interface{}
			err := json.Unmarshal(key, &jsonData)
			if err != nil {
				NoticeAlert(
					"Invalid key in TakeOutUnreportedTunnelStats: %s: %s",
					string(key), err)
				continue
			}

			if 0 == bytes.Compare(value, tunnelStatsStateUnreported) {
				// Must make a copy as slice is only valid within transaction.
				data := make([]byte, len(key))
				copy(data, key)
				tunnelStats = append(tunnelStats, data)
				if len(tunnelStats) >= maxCount {
					break
				}
			}
		}
		for _, key := range tunnelStats {
			err := bucket.Put(key, tunnelStatsStateReporting)
			if err != nil {
				return err
			}
		}

		return nil
	})

	if err != nil {
		return nil, common.ContextError(err)
	}
	return tunnelStats, nil
}

// PutBackUnreportedTunnelStats restores a list of tunnel
// stats records to StateUnreported.
func PutBackUnreportedTunnelStats(tunnelStats [][]byte) error {
	checkInitDataStore()

	err := singleton.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(tunnelStatsBucket))
		for _, key := range tunnelStats {
			err := bucket.Put(key, tunnelStatsStateUnreported)
			if err != nil {
				return err
			}
		}
		return nil
	})

	if err != nil {
		return common.ContextError(err)
	}
	return nil
}

// ClearReportedTunnelStats deletes a list of tunnel
// stats records that were succesdfully reported.
func ClearReportedTunnelStats(tunnelStats [][]byte) error {
	checkInitDataStore()

	err := singleton.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(tunnelStatsBucket))
		for _, key := range tunnelStats {
			err := bucket.Delete(key)
			if err != nil {
				return err
			}
		}
		return nil
	})

	if err != nil {
		return common.ContextError(err)
	}
	return nil
}

// resetAllTunnelStatsToUnreported sets all tunnel
// stats records to StateUnreported. This reset is called
// when the datastore is initialized at start up, as we do
// not know if tunnel records in StateReporting were reported
// or not.
func resetAllTunnelStatsToUnreported() error {
	checkInitDataStore()

	err := singleton.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(tunnelStatsBucket))
		resetKeys := make([][]byte, 0)
		cursor := bucket.Cursor()
		for key, _ := cursor.First(); key != nil; key, _ = cursor.Next() {
			resetKeys = append(resetKeys, key)
		}
		// TODO: data mutation is done outside cursor. Is this
		// strictly necessary in this case?
		// https://godoc.org/github.com/boltdb/bolt#Cursor
		for _, key := range resetKeys {
			err := bucket.Put(key, tunnelStatsStateUnreported)
			if err != nil {
				return err
			}
		}
		return nil
	})

	if err != nil {
		return common.ContextError(err)
	}
	return nil
}
