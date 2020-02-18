// +build BADGER_DB

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

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/dgraph-io/badger"
	"github.com/dgraph-io/badger/options"
)

const (
	DATA_STORE_DIRECTORY = "psiphon.badgerdb"
)

type datastoreDB struct {
	badgerDB *badger.DB
}

type datastoreTx struct {
	badgerTx *badger.Txn
}

type datastoreBucket struct {
	name []byte
	tx   *datastoreTx
}

type datastoreCursor struct {
	badgerIterator *badger.Iterator
	prefix         []byte
}

func datastoreOpenDB(rootDataDirectory string) (*datastoreDB, error) {

	dbDirectory := filepath.Join(rootDataDirectory, "psiphon.badgerdb")

	err := os.MkdirAll(dbDirectory, 0700)
	if err != nil {
		return nil, errors.Trace(err)
	}

	opts := badger.DefaultOptions

	opts.Dir = dbDirectory
	opts.ValueDir = dbDirectory

	opts.TableLoadingMode = options.FileIO
	opts.ValueLogLoadingMode = options.FileIO
	opts.MaxTableSize = 1 << 16
	opts.ValueLogFileSize = 1 << 20
	opts.NumMemtables = 1
	opts.NumLevelZeroTables = 1
	opts.NumLevelZeroTablesStall = 2
	opts.NumCompactors = 1

	db, err := badger.Open(opts)
	if err != nil {
		return nil, errors.Trace(err)
	}

	for {
		if db.RunValueLogGC(0.5) != nil {
			break
		}
	}

	return &datastoreDB{badgerDB: db}, nil
}

func (db *datastoreDB) close() error {
	return db.badgerDB.Close()
}

func (db *datastoreDB) view(fn func(tx *datastoreTx) error) error {
	return db.badgerDB.View(
		func(tx *badger.Txn) error {
			err := fn(&datastoreTx{badgerTx: tx})
			if err != nil {
				return errors.Trace(err)
			}
			return nil
		})
}

func (db *datastoreDB) update(fn func(tx *datastoreTx) error) error {
	return db.badgerDB.Update(
		func(tx *badger.Txn) error {
			err := fn(&datastoreTx{badgerTx: tx})
			if err != nil {
				return errors.Trace(err)
			}
			return nil
		})
}

func (tx *datastoreTx) bucket(name []byte) *datastoreBucket {
	return &datastoreBucket{
		name: name,
		tx:   tx,
	}
}

func (tx *datastoreTx) clearBucket(name []byte) error {
	b := tx.bucket(name)
	c := b.cursor()
	for key := c.firstKey(); key != nil; key = c.nextKey() {
		err := tx.badgerTx.Delete(key)
		if err != nil {
			return errors.Trace(err)
		}
	}
	return nil
}

func (b *datastoreBucket) get(key []byte) []byte {
	keyWithPrefix := append(b.name, key...)
	item, err := b.tx.badgerTx.Get(keyWithPrefix)
	if err != nil {
		if err != badger.ErrKeyNotFound {
			// The original datastore interface does not return an error from
			// Get, so emit notice.
			NoticeWarning("get failed: %s: %s",
				string(keyWithPrefix), errors.Trace(err))
		}
		return nil
	}
	value, err := item.Value()
	if err != nil {
		NoticeWarning("get failed: %s: %s",
			string(keyWithPrefix), errors.Trace(err))
		return nil
	}
	return value
}

func (b *datastoreBucket) put(key, value []byte) error {
	keyWithPrefix := append(b.name, key...)
	err := b.tx.badgerTx.Set(keyWithPrefix, value)
	if err != nil {
		return errors.Trace(err)
	}
	return nil
}

func (b *datastoreBucket) delete(key []byte) error {
	keyWithPrefix := append(b.name, key...)
	err := b.tx.badgerTx.Delete(keyWithPrefix)
	if err != nil {
		return errors.Trace(err)
	}
	return nil
}

func (b *datastoreBucket) cursor() *datastoreCursor {
	opts := badger.DefaultIteratorOptions
	opts.PrefetchValues = false
	iterator := b.tx.badgerTx.NewIterator(opts)
	return &datastoreCursor{badgerIterator: iterator, prefix: b.name}
}

func (c *datastoreCursor) firstKey() []byte {
	c.badgerIterator.Seek(c.prefix)
	return c.currentKey()
}

func (c *datastoreCursor) currentKey() []byte {
	if !c.badgerIterator.ValidForPrefix(c.prefix) {
		return nil
	}
	item := c.badgerIterator.Item()
	return item.Key()[len(c.prefix):]
}

func (c *datastoreCursor) nextKey() []byte {
	c.badgerIterator.Next()
	return c.currentKey()
}

func (c *datastoreCursor) first() ([]byte, []byte) {
	c.badgerIterator.Seek(c.prefix)
	return c.current()
}

func (c *datastoreCursor) current() ([]byte, []byte) {
	if !c.badgerIterator.ValidForPrefix(c.prefix) {
		return nil, nil
	}
	item := c.badgerIterator.Item()
	value, err := item.Value()
	if err != nil {
		return nil, nil
	}
	return item.Key()[len(c.prefix):], value
}

func (c *datastoreCursor) next() ([]byte, []byte) {
	c.badgerIterator.Next()
	return c.current()
}

func (c *datastoreCursor) close() {
	c.badgerIterator.Close()
}
