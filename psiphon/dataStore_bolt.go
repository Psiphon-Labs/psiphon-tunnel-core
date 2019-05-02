// +build !BADGER_DB,!FILES_DB

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
	"os"
	"path/filepath"
	"time"

	"github.com/Psiphon-Labs/bolt"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
)

type datastoreDB struct {
	boltDB *bolt.DB
}

type datastoreTx struct {
	boltTx *bolt.Tx
}

type datastoreBucket struct {
	boltBucket *bolt.Bucket
}

type datastoreCursor struct {
	boltCursor *bolt.Cursor
}

func datastoreOpenDB(rootDataDirectory string) (*datastoreDB, error) {

	filename := filepath.Join(rootDataDirectory, "psiphon.boltdb")

	var newDB *bolt.DB
	var err error

	for retry := 0; retry < 3; retry++ {

		if retry > 0 {
			NoticeAlert("datastoreOpenDB retry: %d", retry)
		}

		newDB, err = bolt.Open(filename, 0600, &bolt.Options{Timeout: 1 * time.Second})

		// The datastore file may be corrupt, so attempt to delete and try again
		if err != nil {
			NoticeAlert("bolt.Open error: %s", err)
			os.Remove(filename)
			continue
		}

		// Run consistency checks on datastore and emit errors for diagnostics purposes
		// We assume this will complete quickly for typical size Psiphon datastores.
		err = newDB.View(func(tx *bolt.Tx) error {
			return tx.SynchronousCheck()
		})

		// The datastore file may be corrupt, so attempt to delete and try again
		if err != nil {
			NoticeAlert("bolt.SynchronousCheck error: %s", err)
			newDB.Close()
			os.Remove(filename)
			continue
		}

		break
	}

	if err != nil {
		return nil, common.ContextError(err)
	}

	err = newDB.Update(func(tx *bolt.Tx) error {
		requiredBuckets := [][]byte{
			datastoreServerEntriesBucket,
			datastoreServerEntryTagsBucket,
			datastoreServerEntryTombstoneTagsBucket,
			datastoreSplitTunnelRouteETagsBucket,
			datastoreSplitTunnelRouteDataBucket,
			datastoreUrlETagsBucket,
			datastoreKeyValueBucket,
			datastoreRemoteServerListStatsBucket,
			datastoreFailedTunnelStatsBucket,
			datastoreSLOKsBucket,
			datastoreTacticsBucket,
			datastoreSpeedTestSamplesBucket,
			datastoreDialParametersBucket,
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
		return nil, common.ContextError(err)
	}

	// Cleanup obsolete buckets

	err = newDB.Update(func(tx *bolt.Tx) error {
		obsoleteBuckets := [][]byte{
			[]byte("tunnelStats"),
			[]byte("rankedServerEntries"),
		}
		for _, obsoleteBucket := range obsoleteBuckets {
			if tx.Bucket(obsoleteBucket) != nil {
				err := tx.DeleteBucket(obsoleteBucket)
				if err != nil {
					NoticeAlert("DeleteBucket %s error: %s", obsoleteBucket, err)
					// Continue, since this is not fatal
				}
			}
		}
		return nil
	})
	if err != nil {
		return nil, common.ContextError(err)
	}

	return &datastoreDB{boltDB: newDB}, nil
}

func (db *datastoreDB) close() error {
	return db.boltDB.Close()
}

func (db *datastoreDB) view(fn func(tx *datastoreTx) error) error {
	return db.boltDB.View(
		func(tx *bolt.Tx) error {
			err := fn(&datastoreTx{boltTx: tx})
			if err != nil {
				return common.ContextError(err)
			}
			return nil
		})
}

func (db *datastoreDB) update(fn func(tx *datastoreTx) error) error {
	return db.boltDB.Update(
		func(tx *bolt.Tx) error {
			err := fn(&datastoreTx{boltTx: tx})
			if err != nil {
				return common.ContextError(err)
			}
			return nil
		})
}

func (tx *datastoreTx) bucket(name []byte) *datastoreBucket {
	return &datastoreBucket{boltBucket: tx.boltTx.Bucket(name)}
}

func (tx *datastoreTx) clearBucket(name []byte) error {
	err := tx.boltTx.DeleteBucket(name)
	if err != nil {
		return common.ContextError(err)
	}
	_, err = tx.boltTx.CreateBucket(name)
	if err != nil {
		return common.ContextError(err)
	}
	return nil
}

func (b *datastoreBucket) get(key []byte) []byte {
	return b.boltBucket.Get(key)
}

func (b *datastoreBucket) put(key, value []byte) error {
	err := b.boltBucket.Put(key, value)
	if err != nil {
		return common.ContextError(err)
	}
	return nil
}

func (b *datastoreBucket) delete(key []byte) error {
	err := b.boltBucket.Delete(key)
	if err != nil {
		return common.ContextError(err)
	}
	return nil
}

func (b *datastoreBucket) cursor() datastoreCursor {
	return datastoreCursor{boltCursor: b.boltBucket.Cursor()}
}

func (c *datastoreCursor) firstKey() []byte {
	key, _ := c.boltCursor.First()
	return key
}

func (c *datastoreCursor) nextKey() []byte {
	key, _ := c.boltCursor.Next()
	return key
}

func (c *datastoreCursor) first() ([]byte, []byte) {
	return c.boltCursor.First()
}

func (c *datastoreCursor) next() ([]byte, []byte) {
	return c.boltCursor.Next()
}

func (c *datastoreCursor) close() {
	// BoltDB doesn't close cursors.
}
