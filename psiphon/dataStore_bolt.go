//go:build !PSIPHON_USE_BADGER_DB && !PSIPHON_USE_FILES_DB
// +build !PSIPHON_USE_BADGER_DB,!PSIPHON_USE_FILES_DB

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

package psiphon

import (
	std_errors "errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"sync/atomic"
	"time"

	"github.com/Psiphon-Labs/bolt"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
)

const (
	OPEN_DB_RETRIES = 2
)

type datastoreDB struct {
	boltDB   *bolt.DB
	filename string
	isFailed int32
}

type datastoreTx struct {
	db     *datastoreDB
	boltTx *bolt.Tx
}

type datastoreBucket struct {
	db         *datastoreDB
	boltBucket *bolt.Bucket
}

type datastoreCursor struct {
	db         *datastoreDB
	boltCursor *bolt.Cursor
}

func datastoreOpenDB(
	rootDataDirectory string, retryAndReset bool) (*datastoreDB, error) {

	var db *datastoreDB
	var err error

	attempts := 1
	if retryAndReset {
		attempts += OPEN_DB_RETRIES
	}

	reset := false

	for attempt := 0; attempt < attempts; attempt++ {

		db, err = tryDatastoreOpenDB(rootDataDirectory, reset)
		if err == nil {
			break
		}

		NoticeWarning("tryDatastoreOpenDB failed: %s", err)

		// The datastore file may be corrupt, so, in subsequent iterations,
		// set the "reset" flag and attempt to delete the file and try again.
		//
		// Don't reset the datastore when open failed due to timeout obtaining
		// the file lock, as the datastore is simply locked by another
		// process and not corrupt. As the file lock is advisory, deleting
		// the file would succeed despite the lock. In this case, still retry
		// in case the the lock is released.

		reset = !std_errors.Is(err, bolt.ErrTimeout)
	}

	return db, err
}

func tryDatastoreOpenDB(
	rootDataDirectory string, reset bool) (retdb *datastoreDB, reterr error) {

	// Testing indicates that the bolt Check function can raise SIGSEGV due to
	// invalid mmap buffer accesses in cases such as opening a valid but
	// truncated datastore file.
	//
	// To handle this, we temporarily set SetPanicOnFault in order to treat the
	// fault as a panic, recover any panic, and return an error which will result
	// in a retry with reset.
	//
	// Limitation: another potential crash case is "fatal error: out of
	// memory" due to bolt.freelist.read attempting to allocate a slice using
	// a corrupted size value on disk. There is no way to recover from this
	// fatal.

	// Begin recovery preamble
	panicOnFault := debug.SetPanicOnFault(true)
	defer debug.SetPanicOnFault(panicOnFault)

	defer func() {
		if r := recover(); r != nil {
			retdb = nil
			reterr = errors.Tracef("panic: %v", r)
		}
	}()
	// End recovery preamble

	filename := filepath.Join(rootDataDirectory, "psiphon.boltdb")

	if reset {
		NoticeWarning("tryDatastoreOpenDB: reset")
		os.Remove(filename)
	}

	// A typical Psiphon datastore will not have a large, fragmented freelist.
	// For this reason, we're not setting FreelistType to FreelistMapType or
	// enabling NoFreelistSync. The latter option has a trade-off of slower
	// start up time.
	//
	// Monitor freelist stats in DataStoreMetrics in diagnostics and consider
	// setting these options if necessary.

	newDB, err := bolt.Open(filename, 0600, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		return nil, errors.Trace(err)
	}

	// Run consistency checks on datastore and emit errors for diagnostics
	// purposes. We assume this will complete quickly for typical size Psiphon
	// datastores and wait for the check to complete before proceeding.
	err = newDB.View(func(tx *bolt.Tx) error {
		return tx.SynchronousCheck()
	})
	if err != nil {
		return nil, errors.Trace(err)
	}

	err = newDB.Update(func(tx *bolt.Tx) error {
		requiredBuckets := [][]byte{
			datastoreServerEntriesBucket,
			datastoreServerEntryTagsBucket,
			datastoreServerEntryTombstoneTagsBucket,
			datastoreUrlETagsBucket,
			datastoreKeyValueBucket,
			datastoreRemoteServerListStatsBucket,
			datastoreFailedTunnelStatsBucket,
			datastoreSLOKsBucket,
			datastoreTacticsBucket,
			datastoreSpeedTestSamplesBucket,
			datastoreDialParametersBucket,
			datastoreNetworkReplayParametersBucket,
			datastoreDSLOSLStatesBucket,
		}
		for _, bucket := range requiredBuckets {
			_, err := tx.CreateBucketIfNotExists(bucket)
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, errors.Trace(err)
	}

	// Cleanup obsolete buckets

	err = newDB.Update(func(tx *bolt.Tx) error {
		obsoleteBuckets := [][]byte{
			[]byte("tunnelStats"),
			[]byte("rankedServerEntries"),
			[]byte("splitTunnelRouteETags"),
			[]byte("splitTunnelRouteData"),
		}
		for _, obsoleteBucket := range obsoleteBuckets {
			if tx.Bucket(obsoleteBucket) != nil {
				err := tx.DeleteBucket(obsoleteBucket)
				if err != nil {
					NoticeWarning("DeleteBucket %s error: %s", obsoleteBucket, err)
					// Continue, since this is not fatal
				}
			}
		}
		return nil
	})
	if err != nil {
		return nil, errors.Trace(err)
	}

	return &datastoreDB{
		boltDB:   newDB,
		filename: filename,
	}, nil
}

var errDatastoreFailed = std_errors.New("datastore has failed")

func (db *datastoreDB) isDatastoreFailed() bool {
	return atomic.LoadInt32(&db.isFailed) == 1
}

func (db *datastoreDB) setDatastoreFailed(r interface{}) {
	atomic.StoreInt32(&db.isFailed, 1)
	NoticeWarning("%s: %s", errDatastoreFailed.Error(), errors.Tracef("panic: %v", r))
}

func (db *datastoreDB) close() error {

	// Limitation: there is no panic recover in this case. We assume boltDB.Close
	// does not make  mmap accesses and prefer to not continue with the datastore
	// file in a locked or open state. We also assume that any locks aquired by
	// boltDB.Close, held by transactions, will be released even if the
	// transaction panics and the database is in the failed state.

	return db.boltDB.Close()
}

func (db *datastoreDB) getDataStoreMetrics() string {
	fileSize := int64(0)
	fileInfo, err := os.Stat(db.filename)
	if err == nil {
		fileSize = fileInfo.Size()
	}
	stats := db.boltDB.Stats()
	return fmt.Sprintf("filesize %s | freepages %d | freealloc %s | txcount %d | writes %d | writetime %s",
		common.FormatByteCount(uint64(fileSize)),
		stats.FreePageN,
		common.FormatByteCount(uint64(stats.FreeAlloc)),
		stats.TxN,
		stats.TxStats.Write,
		stats.TxStats.WriteTime)
}

func (db *datastoreDB) view(fn func(tx *datastoreTx) error) (reterr error) {

	// Any bolt function that performs mmap buffer accesses can raise SIGBUS due
	// to underlying storage changes, such as a truncation of the datastore file
	// or removal or network attached storage, etc.
	//
	// To handle this, we temporarily set SetPanicOnFault in order to treat the
	// fault as a panic, recover any panic to avoid crashing the process, and
	// putting this datastoreDB instance into a failed state. All subsequent
	// calls to this datastoreDBinstance or its related datastoreTx and
	// datastoreBucket instances will fail.

	// Begin recovery preamble
	if db.isDatastoreFailed() {
		return errDatastoreFailed
	}
	panicOnFault := debug.SetPanicOnFault(true)
	defer debug.SetPanicOnFault(panicOnFault)
	defer func() {
		if r := recover(); r != nil {
			db.setDatastoreFailed(r)
			reterr = errDatastoreFailed
		}
	}()
	// End recovery preamble

	return db.boltDB.View(
		func(tx *bolt.Tx) error {
			err := fn(&datastoreTx{db: db, boltTx: tx})
			if err != nil {
				return errors.Trace(err)
			}
			return nil
		})
}

func (db *datastoreDB) update(fn func(tx *datastoreTx) error) (reterr error) {

	// Begin recovery preamble
	if db.isDatastoreFailed() {
		return errDatastoreFailed
	}
	panicOnFault := debug.SetPanicOnFault(true)
	defer debug.SetPanicOnFault(panicOnFault)
	defer func() {
		if r := recover(); r != nil {
			db.setDatastoreFailed(r)
			reterr = errDatastoreFailed
		}
	}()
	// End recovery preamble

	return db.boltDB.Update(
		func(tx *bolt.Tx) error {
			err := fn(&datastoreTx{db: db, boltTx: tx})
			if err != nil {
				return errors.Trace(err)
			}
			return nil
		})
}

func (tx *datastoreTx) bucket(name []byte) (retbucket *datastoreBucket) {

	// Begin recovery preamble
	if tx.db.isDatastoreFailed() {
		return &datastoreBucket{db: tx.db, boltBucket: nil}
	}
	panicOnFault := debug.SetPanicOnFault(true)
	defer debug.SetPanicOnFault(panicOnFault)
	defer func() {
		if r := recover(); r != nil {
			tx.db.setDatastoreFailed(r)
			retbucket = &datastoreBucket{db: tx.db, boltBucket: nil}
		}
	}()
	// End recovery preamble

	return &datastoreBucket{db: tx.db, boltBucket: tx.boltTx.Bucket(name)}
}

func (tx *datastoreTx) clearBucket(name []byte) (reterr error) {

	// Begin recovery preamble
	if tx.db.isDatastoreFailed() {
		return errDatastoreFailed
	}
	panicOnFault := debug.SetPanicOnFault(true)
	defer debug.SetPanicOnFault(panicOnFault)
	defer func() {
		if r := recover(); r != nil {
			tx.db.setDatastoreFailed(r)
			reterr = errDatastoreFailed
		}
	}()
	// End recovery preamble

	err := tx.boltTx.DeleteBucket(name)
	if err != nil {
		return errors.Trace(err)
	}
	_, err = tx.boltTx.CreateBucket(name)
	if err != nil {
		return errors.Trace(err)
	}
	return nil
}

func (b *datastoreBucket) get(key []byte) (retvalue []byte) {

	// Begin recovery preamble
	if b.db.isDatastoreFailed() {
		return nil
	}
	panicOnFault := debug.SetPanicOnFault(true)
	defer debug.SetPanicOnFault(panicOnFault)
	defer func() {
		if r := recover(); r != nil {
			b.db.setDatastoreFailed(r)
			retvalue = nil
		}
	}()
	// End recovery preamble

	return b.boltBucket.Get(key)
}

func (b *datastoreBucket) put(key, value []byte) (reterr error) {

	// Begin recovery preamble
	if b.db.isDatastoreFailed() {
		return errDatastoreFailed
	}
	panicOnFault := debug.SetPanicOnFault(true)
	defer debug.SetPanicOnFault(panicOnFault)
	defer func() {
		if r := recover(); r != nil {
			b.db.setDatastoreFailed(r)
			reterr = errDatastoreFailed
		}
	}()
	// End recovery preamble

	err := b.boltBucket.Put(key, value)
	if err != nil {
		return errors.Trace(err)
	}
	return nil
}

func (b *datastoreBucket) delete(key []byte) (reterr error) {

	// Begin recovery preamble
	if b.db.isDatastoreFailed() {
		return errDatastoreFailed
	}
	panicOnFault := debug.SetPanicOnFault(true)
	defer debug.SetPanicOnFault(panicOnFault)
	defer func() {
		if r := recover(); r != nil {
			b.db.setDatastoreFailed(r)
			reterr = errDatastoreFailed
		}
	}()
	// End recovery preamble

	err := b.boltBucket.Delete(key)
	if err != nil {
		return errors.Trace(err)
	}
	return nil
}

func (b *datastoreBucket) cursor() (retcursor datastoreCursor) {

	// Begin recovery preamble
	if b.db.isDatastoreFailed() {
		return datastoreCursor{db: b.db, boltCursor: nil}
	}
	panicOnFault := debug.SetPanicOnFault(true)
	defer debug.SetPanicOnFault(panicOnFault)
	defer func() {
		if r := recover(); r != nil {
			b.db.setDatastoreFailed(r)
			retcursor = datastoreCursor{db: b.db, boltCursor: nil}
		}
	}()
	// End recovery preamble

	return datastoreCursor{db: b.db, boltCursor: b.boltBucket.Cursor()}
}

func (c *datastoreCursor) firstKey() (retkey []byte) {

	// Begin recovery preamble
	if c.db.isDatastoreFailed() {
		return nil
	}
	panicOnFault := debug.SetPanicOnFault(true)
	defer debug.SetPanicOnFault(panicOnFault)
	defer func() {
		if r := recover(); r != nil {
			c.db.setDatastoreFailed(r)
			retkey = nil
		}
	}()
	// End recovery preamble

	key, _ := c.boltCursor.First()
	return key
}

func (c *datastoreCursor) nextKey() (retkey []byte) {

	// Begin recovery preamble
	if c.db.isDatastoreFailed() {
		return nil
	}
	panicOnFault := debug.SetPanicOnFault(true)
	defer debug.SetPanicOnFault(panicOnFault)
	defer func() {
		if r := recover(); r != nil {
			c.db.setDatastoreFailed(r)
			retkey = nil
		}
	}()
	// End recovery preamble

	key, _ := c.boltCursor.Next()
	return key
}

func (c *datastoreCursor) first() (retkey, retvalue []byte) {

	// Begin recovery preamble
	if c.db.isDatastoreFailed() {
		return nil, nil
	}
	panicOnFault := debug.SetPanicOnFault(true)
	defer debug.SetPanicOnFault(panicOnFault)
	defer func() {
		if r := recover(); r != nil {
			c.db.setDatastoreFailed(r)
			retkey = nil
			retvalue = nil
		}
	}()
	// End recovery preamble

	return c.boltCursor.First()
}

func (c *datastoreCursor) next() (retkey, retvalue []byte) {

	// Begin recovery preamble
	if c.db.isDatastoreFailed() {
		return nil, nil
	}
	panicOnFault := debug.SetPanicOnFault(true)
	defer debug.SetPanicOnFault(panicOnFault)
	defer func() {
		if r := recover(); r != nil {
			c.db.setDatastoreFailed(r)
			retkey = nil
			retvalue = nil
		}
	}()
	// End recovery preamble

	return c.boltCursor.Next()
}

func (c *datastoreCursor) close() {
	// BoltDB doesn't close cursors.
}
