// +build FILES_DB

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
	"bytes"
	"encoding/hex"
	std_errors "errors"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
)

// datastoreDB is a simple filesystem-backed key/value store that implements
// the datastore interface.
//
// The current implementation is intended only for experimentation.
//
// Buckets are subdirectories, keys are file names (hex-encoded), and values
// are file contents. Unlike other datastores, update transactions are neither
// atomic not isolcated; only each put is individually atomic.
//
// A buffer pool is used to reduce memory allocation/GC churn from loading
// file values into memory. Transactions and cursors track and release shared
// buffers.
//
// As with the original datastore interface, value slices are only valid
// within a transaction; for cursors, there's a further limitation that the
// value slices are only valid until the next iteration.
type datastoreDB struct {
	dataDirectory string
	bufferPool    sync.Pool
	lock          sync.RWMutex
	closed        bool
}

type datastoreTx struct {
	db        *datastoreDB
	canUpdate bool
	buffers   []*bytes.Buffer
}

type datastoreBucket struct {
	bucketDirectory string
	tx              *datastoreTx
}

type datastoreCursor struct {
	bucket     *datastoreBucket
	fileInfos  []os.FileInfo
	index      int
	lastBuffer *bytes.Buffer
}

func datastoreOpenDB(rootDataDirectory string) (*datastoreDB, error) {

	dataDirectory := filepath.Join(rootDataDirectory, "psiphon.filesdb")
	err := os.MkdirAll(dataDirectory, 0700)
	if err != nil {
		return nil, errors.Trace(err)
	}

	return &datastoreDB{
		dataDirectory: dataDirectory,
		bufferPool: sync.Pool{
			New: func() interface{} {
				return new(bytes.Buffer)
			},
		},
	}, nil
}

func (db *datastoreDB) getBuffer() *bytes.Buffer {
	return db.bufferPool.Get().(*bytes.Buffer)
}

func (db *datastoreDB) putBuffer(buffer *bytes.Buffer) {
	buffer.Truncate(0)
	db.bufferPool.Put(buffer)
}

func (db *datastoreDB) readBuffer(filename string) (*bytes.Buffer, error) {
	// Complete any partial put commit.
	err := datastoreApplyCommit(filename)
	if err != nil {
		return nil, errors.Trace(err)
	}
	file, err := os.Open(filename)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, errors.Trace(err)
	}
	defer file.Close()
	buffer := db.getBuffer()
	_, err = buffer.ReadFrom(file)
	if err != nil {
		return nil, errors.Trace(err)
	}
	return buffer, nil
}

func (db *datastoreDB) close() error {
	// close will await any active view and update transactions via this lock.
	db.lock.Lock()
	defer db.lock.Unlock()
	db.closed = true
	return nil
}

func (db *datastoreDB) view(fn func(tx *datastoreTx) error) error {
	db.lock.RLock()
	defer db.lock.RUnlock()
	if db.closed {
		return errors.TraceNew("closed")
	}
	tx := &datastoreTx{db: db}
	defer tx.releaseBuffers()
	err := fn(tx)
	if err != nil {
		return errors.Trace(err)
	}
	return nil
}

func (db *datastoreDB) update(fn func(tx *datastoreTx) error) error {
	db.lock.Lock()
	defer db.lock.Unlock()
	if db.closed {
		return errors.TraceNew("closed")
	}
	tx := &datastoreTx{db: db, canUpdate: true}
	defer tx.releaseBuffers()
	err := fn(tx)
	if err != nil {
		return errors.Trace(err)
	}
	return nil
}

func (tx *datastoreTx) bucket(name []byte) *datastoreBucket {
	bucketDirectory := filepath.Join(tx.db.dataDirectory, hex.EncodeToString(name))
	err := os.MkdirAll(bucketDirectory, 0700)
	if err != nil {
		// The original datastore interface does not return an error from Bucket,
		// so emit notice, and return zero-value bucket for which all
		// operations will fail.
		NoticeWarning("bucket failed: %s", errors.Trace(err))
		return &datastoreBucket{}
	}
	return &datastoreBucket{
		bucketDirectory: bucketDirectory,
		tx:              tx,
	}
}

func (tx *datastoreTx) clearBucket(name []byte) error {
	bucketDirectory := filepath.Join(tx.db.dataDirectory, hex.EncodeToString(name))
	err := os.RemoveAll(bucketDirectory)
	if err != nil {
		return errors.Trace(err)
	}
	return nil
}

func (tx *datastoreTx) releaseBuffers() {
	for _, buffer := range tx.buffers {
		tx.db.putBuffer(buffer)
	}
	tx.buffers = nil
}

func (b *datastoreBucket) get(key []byte) []byte {
	if b.tx == nil {
		return nil
	}
	filename := filepath.Join(b.bucketDirectory, hex.EncodeToString(key))
	valueBuffer, err := b.tx.db.readBuffer(filename)
	if err != nil {
		// The original datastore interface does not return an error from Get,
		// so emit notice.
		NoticeWarning("get failed: %s", errors.Trace(err))
		return nil
	}
	if valueBuffer == nil {
		return nil
	}
	b.tx.buffers = append(b.tx.buffers, valueBuffer)
	return valueBuffer.Bytes()
}

func (b *datastoreBucket) put(key, value []byte) error {
	if b.tx == nil {
		return errors.TraceNew("bucket not found")
	}
	if !b.tx.canUpdate {
		return errors.TraceNew("non-update transaction")
	}

	filename := filepath.Join(b.bucketDirectory, hex.EncodeToString(key))

	// Complete any partial put commit.
	err := datastoreApplyCommit(filename)
	if err != nil {
		return errors.Trace(err)
	}

	putFilename := filename + ".put"
	err = ioutil.WriteFile(putFilename, value, 0600)
	if err != nil {
		return errors.Trace(err)
	}

	commitFilename := filename + ".commit"
	err = os.Rename(putFilename, commitFilename)
	if err != nil {
		return errors.Trace(err)
	}

	err = datastoreApplyCommit(filename)
	if err != nil {
		return errors.Trace(err)
	}

	return nil
}

func datastoreApplyCommit(filename string) error {
	commitFilename := filename + ".commit"
	if _, err := os.Stat(commitFilename); err != nil && os.IsNotExist(err) {
		return nil
	}
	// TODO: may not be sufficient atomic
	err := os.Rename(commitFilename, filename)
	if err != nil {
		return errors.Trace(err)
	}
	return nil
}

func (b *datastoreBucket) delete(key []byte) error {
	if b.tx == nil {
		return errors.TraceNew("bucket not found")
	}
	filename := filepath.Join(b.bucketDirectory, hex.EncodeToString(key))
	filenames := []string{filename + ".put", filename + ".commit", filename}
	for _, filename := range filenames {
		err := os.Remove(filename)
		if err != nil && !os.IsNotExist(err) {
			return errors.Trace(err)
		}
	}
	return nil
}

func (b *datastoreBucket) cursor() *datastoreCursor {
	if b.tx == nil {
		// The original datastore interface does not return an error from
		// Cursor, so emit notice, and return zero-value cursor for which all
		// operations will fail.
		return &datastoreCursor{}
	}
	fileInfos, err := ioutil.ReadDir(b.bucketDirectory)
	if err != nil {
		NoticeWarning("cursor failed: %s", errors.Trace(err))
		return &datastoreCursor{}
	}
	return &datastoreCursor{
		bucket:    b,
		fileInfos: fileInfos,
	}
}

func (c *datastoreCursor) advance() {
	if c.bucket == nil {
		return
	}
	for {
		c.index += 1
		if c.index <= len(c.fileInfos) {
			break
		}
		// Skip any .put or .commit files
		if strings.Contains(c.fileInfos[c.index].Name(), ".") {
			continue
		}
	}
}

func (c *datastoreCursor) firstKey() []byte {
	if c.bucket == nil {
		return nil
	}
	c.index = 0
	return c.currentKey()
}

func (c *datastoreCursor) currentKey() []byte {
	if c.bucket == nil {
		return nil
	}
	if c.index >= len(c.fileInfos) {
		return nil
	}
	info := c.fileInfos[c.index]
	if info.IsDir() {
		NoticeWarning("cursor failed: unexpected dir")
		return nil
	}
	key, err := hex.DecodeString(info.Name())
	if err != nil {
		NoticeWarning("cursor failed: %s", errors.Trace(err))
		return nil
	}
	return key
}

func (c *datastoreCursor) nextKey() []byte {
	if c.bucket == nil {
		return nil
	}
	c.advance()
	return c.currentKey()
}

func (c *datastoreCursor) first() ([]byte, []byte) {
	if c.bucket == nil {
		return nil, nil
	}
	c.index = 0
	return c.current()
}

func (c *datastoreCursor) current() ([]byte, []byte) {
	key := c.currentKey()
	if key == nil {
		return nil, nil
	}

	if c.lastBuffer != nil {
		c.bucket.tx.db.putBuffer(c.lastBuffer)
	}
	c.lastBuffer = nil

	filename := filepath.Join(c.bucket.bucketDirectory, hex.EncodeToString(key))
	valueBuffer, err := c.bucket.tx.db.readBuffer(filename)
	if valueBuffer == nil {
		err = std_errors.New("unexpected nil value")
	}
	if err != nil {
		NoticeWarning("cursor failed: %s", errors.Trace(err))
		return nil, nil
	}
	c.lastBuffer = valueBuffer
	return key, valueBuffer.Bytes()
}

func (c *datastoreCursor) next() ([]byte, []byte) {
	if c.bucket == nil {
		return nil, nil
	}
	c.advance()
	return c.current()
}

func (c *datastoreCursor) close() {
	if c.lastBuffer != nil {
		c.bucket.tx.db.putBuffer(c.lastBuffer)
		c.lastBuffer = nil
	}
}
