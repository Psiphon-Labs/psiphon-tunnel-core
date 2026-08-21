//go:build PSIPHON_USE_SQLITE_DB
// +build PSIPHON_USE_SQLITE_DB

/*
 * Copyright (c) 2026, Psiphon Inc.
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
	"database/sql"
	std_errors "errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Psiphon-Labs/bolt"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	sqlite3 "github.com/mattn/go-sqlite3"
)

const (
	sqliteDatastoreFilename = "psiphon.sqlite3"
	sqliteDriverName        = "psiphon_sqlite3"

	// Version 0 is SQLite's default and means the datastore schema is
	// uninitialized.
	sqliteDatastoreVersionUninitialized = 0

	// Version 1 means the schema is initialized and legacy datastore import
	// has not been attempted.
	sqliteDatastoreVersionSchema = 1

	// Version 2 means legacy datastore import was completed (success or not).
	sqliteDatastoreVersionPostImport = 2

	sqliteOpenRetries        = 2
	sqliteImportRetries      = 2
	sqliteOperationRetries   = 5
	sqliteCommitRetries      = 10
	sqliteInitBeginRetries   = 20
	sqliteRetryDelay         = 10 * time.Millisecond
	sqliteBusyTimeout        = 2500
	sqliteConnAcquireTimeout = 60 * time.Second

	// Tune cache/allocations for lower memory environments, including 512kib
	// cache per db conn.
	sqliteCacheSize     = -512
	sqliteSoftHeapLimit = 2 * 1024 * 1024
	sqliteMaxOpenConns  = 2
	sqliteMaxIdleConns  = 1
)

var datastoreServerEntryKeyValue = []byte{}
var datastoreDialParameterKeyValue = []byte{}

var errDatastoreFailed = std_errors.New("datastore has failed")
var errSQLiteCorruptSchema = std_errors.New("SQLite datastore schema is missing")

type datastoreDB struct {
	sqlDB    *sql.DB
	filename string
	isFailed int32
	isReset  int32
	mutex    sync.RWMutex
}

type datastoreTx struct {
	db        *datastoreDB
	conn      *sql.Conn
	canUpdate bool
	err       error
	cursors   map[*datastoreCursor]struct{}
}

type datastoreBucket struct {
	name []byte
	tx   *datastoreTx
}

type datastoreCursor struct {
	tx        *datastoreTx
	bucket    []byte
	rows      *sql.Rows
	withValue bool
	key       []byte
	value     []byte
}

func init() {
	sql.Register(sqliteDriverName, &sqlite3.SQLiteDriver{
		ConnectHook: func(conn *sqlite3.SQLiteConn) error {
			pragmas := []string{
				"PRAGMA locking_mode=NORMAL",
				"PRAGMA synchronous=FULL",
				// mmap_size currently defaults to 0; keep it disabled to avoid
				// mmap-related SIGBUS faults on database corruption.
				"PRAGMA mmap_size=0",
				fmt.Sprintf("PRAGMA cache_size=%d", sqliteCacheSize),
				fmt.Sprintf("PRAGMA soft_heap_limit=%d", sqliteSoftHeapLimit),
				fmt.Sprintf("PRAGMA busy_timeout=%d", sqliteBusyTimeout),
			}
			for _, pragma := range pragmas {
				_, err := conn.Exec(pragma, nil)
				if err != nil {
					return err
				}
			}
			return nil
		},
	})
}

func datastoreOpenDB(
	rootDataDirectory string, retryAndReset bool) (*datastoreDB, error) {

	filename := filepath.Join(rootDataDirectory, sqliteDatastoreFilename)
	attempts := 1
	if retryAndReset {
		attempts += sqliteOpenRetries
	}

	var err error
	for attempt := 0; attempt < attempts; attempt++ {
		db, openErr := tryDatastoreOpenSQLiteDB(filename)
		if openErr == nil {
			return db, nil
		}
		err = openErr
		NoticeWarning("tryDatastoreOpenSQLiteDB failed: %s", err)

		if !retryAndReset || !isSQLiteCorruption(err) {
			break
		}
		removeErr := removeSQLiteDatastore(filename)
		if removeErr != nil {
			err = removeErr
			break
		}
	}

	return nil, errors.Trace(err)
}

func tryDatastoreOpenSQLiteDB(filename string) (*datastoreDB, error) {

	file, err := os.OpenFile(filename, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, errors.Trace(err)
	}
	err = file.Close()
	if err != nil {
		return nil, errors.Trace(err)
	}

	// The URI path must begin with "/" -- including Windows paths, as
	// "/C:/path" -- or else url.URL.String emits "file://<first-segment>/...",
	// which SQLite rejects as an invalid URI authority.
	absFilename, err := filepath.Abs(filename)
	if err != nil {
		return nil, errors.Trace(err)
	}
	urlPath := filepath.ToSlash(absFilename)
	if !strings.HasPrefix(urlPath, "/") {
		urlPath = "/" + urlPath
	}

	query := url.Values{}
	query.Set("cache", "private")
	query.Set("mode", "rwc")
	dsn := (&url.URL{
		Scheme:   "file",
		Path:     urlPath,
		RawQuery: query.Encode(),
	}).String()

	sqlDB, err := sql.Open(sqliteDriverName, dsn)
	if err != nil {
		return nil, errors.Trace(err)
	}
	sqlDB.SetMaxOpenConns(sqliteMaxOpenConns)
	sqlDB.SetMaxIdleConns(sqliteMaxIdleConns)

	db := &datastoreDB{sqlDB: sqlDB, filename: filename}
	err = db.initialize()
	if err != nil {
		closeErr := sqlDB.Close()
		if closeErr != nil {
			NoticeWarning("failed to close SQLite datastore: %s", errors.Trace(closeErr))
		}
		return nil, errors.Trace(err)
	}

	return db, nil
}

func (db *datastoreDB) initialize() error {
	ctx := context.Background()
	conn, err := db.sqlDB.Conn(ctx)
	if err != nil {
		return errors.Trace(err)
	}
	defer conn.Close()

	// The SQLite datastore adapter is intended to support cases that require
	// (a) no locks held when idle; and (b) multi-process writers. The WAL
	// mode doesn't support these requirements.
	//
	// DELETE journal mode and NORMAL locking release all file locks when a
	// transaction ends, and allow for multi-process writers (serialized).
	// https://www.sqlite.org/pragma.html#pragma_journal_mode
	// https://www.sqlite.org/pragma.html#pragma_locking_mode
	var journalMode string
	err = conn.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&journalMode)
	if err != nil {
		return errors.Trace(err)
	}
	if !strings.EqualFold(journalMode, "delete") {
		err = conn.QueryRowContext(
			ctx, "PRAGMA journal_mode=DELETE").Scan(&journalMode)
		if err != nil {
			return errors.Trace(err)
		}
		if !strings.EqualFold(journalMode, "delete") {
			return errors.Tracef("unexpected SQLite journal mode: %s", journalMode)
		}
	}

	var version int
	err = conn.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version)
	if err != nil {
		return errors.Trace(err)
	}
	if version == sqliteDatastoreVersionUninitialized {
		err = initializeSQLiteSchema(ctx, conn)
		if err != nil {
			return errors.Trace(err)
		}
	} else if version != sqliteDatastoreVersionSchema &&
		version != sqliteDatastoreVersionPostImport {

		return errors.Tracef("unsupported SQLite datastore version: %d", version)
	}

	var tableCount int
	err = conn.QueryRowContext(ctx, `
		SELECT count(*) FROM sqlite_master
		WHERE type='table' AND name='bucket_entries'`).Scan(&tableCount)
	if err != nil {
		return errors.Trace(err)
	}
	if tableCount != 1 {
		return errSQLiteCorruptSchema
	}

	if version != sqliteDatastoreVersionPostImport {
		err = initializeImportBoltDatastore(ctx, conn, db.filename)
		if err != nil {
			return errors.Trace(err)
		}
	}
	return nil
}

func initializeSQLiteSchema(ctx context.Context, conn *sql.Conn) error {
	err := sqliteExecWithRetry(
		ctx, conn, "BEGIN IMMEDIATE", sqliteInitBeginRetries)
	if err != nil {
		return errors.Trace(err)
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(ctx, "ROLLBACK")
		}
	}()

	var version int
	err = conn.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version)
	if err != nil {
		return errors.Trace(err)
	}
	if version == sqliteDatastoreVersionUninitialized {
		_, err = conn.ExecContext(ctx, `
			CREATE TABLE IF NOT EXISTS bucket_entries (
				bucket BLOB NOT NULL,
				key BLOB NOT NULL,
				value BLOB NOT NULL,
				PRIMARY KEY (bucket, key)
			) WITHOUT ROWID`)
		if err != nil {
			return errors.Trace(err)
		}
		_, err = conn.ExecContext(ctx, fmt.Sprintf(
			"PRAGMA user_version=%d", sqliteDatastoreVersionSchema))
		if err != nil {
			return errors.Trace(err)
		}
	} else if version != sqliteDatastoreVersionSchema &&
		version != sqliteDatastoreVersionPostImport {

		return errors.Tracef("unsupported SQLite datastore version: %d", version)
	}

	_, err = conn.ExecContext(ctx, "COMMIT")
	if err != nil {
		return errors.Trace(err)
	}
	committed = true
	return nil
}

func isSQLiteBusy(err error) bool {
	var sqliteErr sqlite3.Error
	return std_errors.As(err, &sqliteErr) &&
		(sqliteErr.Code == sqlite3.ErrBusy || sqliteErr.Code == sqlite3.ErrLocked)
}

func isSQLiteCorruption(err error) bool {
	if std_errors.Is(err, errSQLiteCorruptSchema) {
		return true
	}
	var sqliteErr sqlite3.Error
	return std_errors.As(err, &sqliteErr) &&
		(sqliteErr.Code == sqlite3.ErrCorrupt || sqliteErr.Code == sqlite3.ErrNotADB)
}

func removeSQLiteDatastore(filename string) error {
	for _, suffix := range []string{"", "-journal", "-shm", "-wal"} {
		err := os.Remove(filename + suffix)
		if err != nil && !os.IsNotExist(err) {
			return errors.Trace(err)
		}
	}
	return nil
}

func (db *datastoreDB) isDatastoreFailed() bool {
	return atomic.LoadInt32(&db.isFailed) == 1
}

func (db *datastoreDB) setDatastoreFailed(err error) {
	atomic.StoreInt32(&db.isFailed, 1)
	NoticeWarning("%s: %s", errDatastoreFailed.Error(), errors.Trace(err))
}

func (db *datastoreDB) resetFailedDatastore() {
	if !db.isDatastoreFailed() ||
		!atomic.CompareAndSwapInt32(&db.isReset, 0, 1) {
		return
	}
	db.mutex.Lock()
	defer db.mutex.Unlock()

	err := db.close()
	if err != nil {
		NoticeWarning("failed to close SQLite datastore: %s", errors.Trace(err))
		return
	}
	err = removeSQLiteDatastore(db.filename)
	if err != nil {
		NoticeWarning("failed to reset SQLite datastore: %s", errors.Trace(err))
		return
	}
	NoticeWarning("reset failed datastore")
}

func (db *datastoreDB) handleError(err error) error {
	if err == nil {
		return nil
	}
	if isSQLiteCorruption(err) {
		db.setDatastoreFailed(err)
		db.resetFailedDatastore()
		return errDatastoreFailed
	}
	return errors.Trace(err)
}

func (db *datastoreDB) close() error {
	return db.sqlDB.Close()
}

func (db *datastoreDB) getDataStoreMetrics() string {
	fileSize := int64(0)
	fileInfo, err := os.Stat(db.filename)
	if err == nil {
		fileSize = fileInfo.Size()
	}
	stats := db.sqlDB.Stats()
	return fmt.Sprintf(
		"filesize %s | openconnections %d | inuse %d | idle %d | waitcount %d | waittime %s",
		common.FormatByteCount(uint64(fileSize)), stats.OpenConnections,
		stats.InUse, stats.Idle, stats.WaitCount, stats.WaitDuration)
}

func (db *datastoreDB) view(fn func(tx *datastoreTx) error) error {
	return db.transaction(false, fn)
}

func (db *datastoreDB) update(fn func(tx *datastoreTx) error) error {
	return db.transaction(true, fn)
}

func (db *datastoreDB) transaction(
	canUpdate bool, fn func(tx *datastoreTx) error) (retErr error) {

	db.mutex.RLock()
	defer func() {
		db.mutex.RUnlock()
		retErr = db.handleError(retErr)
	}()

	if db.isDatastoreFailed() {
		return errDatastoreFailed
	}

	// This timeout guards against deadlocks from nested transactions.
	ctx := context.Background()
	acquireCtx, cancel := context.WithTimeout(ctx, sqliteConnAcquireTimeout)
	conn, err := db.sqlDB.Conn(acquireCtx)
	cancel()
	if err != nil {
		return errors.Trace(err)
	}
	defer func() {
		err := conn.Close()
		if retErr == nil {
			retErr = errors.Trace(err)
		}
	}()

	if canUpdate {
		err = sqliteExecWithRetry(
			ctx, conn, "BEGIN IMMEDIATE", sqliteOperationRetries)
	} else {
		// No explicit retries: plain BEGIN acquires no lock. For reads,
		// busy_timeout remains in effect.
		_, err = conn.ExecContext(ctx, "BEGIN")
	}
	if err != nil {
		_, _ = conn.ExecContext(ctx, "ROLLBACK")
		return errors.Trace(err)
	}

	tx := &datastoreTx{
		db:        db,
		conn:      conn,
		canUpdate: canUpdate,
		cursors:   make(map[*datastoreCursor]struct{}),
	}
	err = fn(tx)
	tx.closeCursors()
	if err == nil {
		err = tx.err
	}
	if err != nil {
		_, _ = conn.ExecContext(ctx, "ROLLBACK")
		return errors.Trace(err)
	}

	if canUpdate {
		err = sqliteExecWithRetry(ctx, conn, "COMMIT", sqliteCommitRetries)
	} else {
		_, err = conn.ExecContext(ctx, "ROLLBACK")
	}
	if err != nil {
		_, _ = conn.ExecContext(ctx, "ROLLBACK")
		return errors.Trace(err)
	}
	return nil
}

func sqliteExecWithRetry(
	ctx context.Context, conn *sql.Conn, query string, retries int) error {

	var err error
	for attempt := 0; attempt < retries; attempt++ {
		_, err = conn.ExecContext(ctx, query)
		if err == nil {
			return nil
		}
		if !isSQLiteBusy(err) {
			return errors.Trace(err)
		}
		time.Sleep(time.Duration(attempt+1) * sqliteRetryDelay)
	}
	NoticeWarning(
		"sqliteExecWithRetry: %s failed after %d attempts: %v",
		query, retries, err)
	return errors.Trace(err)
}

func (tx *datastoreTx) setError(err error) error {
	if err == nil {
		return nil
	}
	err = errors.Trace(err)
	if tx.err == nil {
		tx.err = err
	}
	return err
}

func (tx *datastoreTx) bucket(name []byte) *datastoreBucket {
	return &datastoreBucket{name: name, tx: tx}
}

func (tx *datastoreTx) clearBucket(name []byte) error {
	if !tx.canUpdate {
		return tx.setError(errors.TraceNew("non-update transaction"))
	}
	_, err := tx.conn.ExecContext(
		context.Background(), "DELETE FROM bucket_entries WHERE bucket=?", name)
	return tx.setError(err)
}

func (tx *datastoreTx) closeCursors() {
	for cursor := range tx.cursors {
		cursor.close()
	}
}

func (b *datastoreBucket) get(key []byte) []byte {
	if b.tx.err != nil {
		return nil
	}
	var value []byte
	err := b.tx.conn.QueryRowContext(context.Background(),
		"SELECT value FROM bucket_entries WHERE bucket=? AND key=?",
		b.name, key).Scan(&value)
	if err == sql.ErrNoRows {
		return nil
	}
	if err != nil {
		b.tx.setError(err)
		return nil
	}
	return value
}

func (b *datastoreBucket) put(key, value []byte) error {
	if !b.tx.canUpdate {
		return b.tx.setError(errors.TraceNew("non-update transaction"))
	}
	if value == nil {
		// Store nil values as empty, as the bolt adapter does; a nil
		// []byte violates the NOT NULL constraint.
		value = []byte{}
	}
	_, err := b.tx.conn.ExecContext(context.Background(), `
		INSERT INTO bucket_entries (bucket, key, value) VALUES (?, ?, ?)
		ON CONFLICT (bucket, key) DO UPDATE SET value=excluded.value`,
		b.name, key, value)
	return b.tx.setError(err)
}

func (b *datastoreBucket) delete(key []byte) error {
	if !b.tx.canUpdate {
		return b.tx.setError(errors.TraceNew("non-update transaction"))
	}
	_, err := b.tx.conn.ExecContext(context.Background(),
		"DELETE FROM bucket_entries WHERE bucket=? AND key=?", b.name, key)
	return b.tx.setError(err)
}

func (b *datastoreBucket) cursor() *datastoreCursor {
	cursor := &datastoreCursor{tx: b.tx, bucket: b.name}
	b.tx.cursors[cursor] = struct{}{}
	return cursor
}

func (c *datastoreCursor) start(withValue bool) bool {
	c.closeRows()
	if c.tx.err != nil {
		return false
	}

	query := "SELECT key FROM bucket_entries WHERE bucket=? ORDER BY key"
	if withValue {
		query = "SELECT key, value FROM bucket_entries WHERE bucket=? ORDER BY key"
	}
	rows, err := c.tx.conn.QueryContext(context.Background(), query, c.bucket)
	if err != nil {
		c.tx.setError(err)
		return false
	}
	c.rows = rows
	c.withValue = withValue
	return c.advance()
}

func (c *datastoreCursor) advance() bool {
	if c.rows == nil || !c.rows.Next() {
		if c.rows != nil {
			err := c.rows.Err()
			if err != nil {
				c.tx.setError(err)
			}
		}
		c.closeRows()
		return false
	}

	var err error
	if c.withValue {
		err = c.rows.Scan(&c.key, &c.value)
	} else {
		err = c.rows.Scan(&c.key)
		c.value = nil
	}
	if err != nil {
		c.tx.setError(err)
		c.closeRows()
		return false
	}
	return true
}

func (c *datastoreCursor) firstKey() []byte {
	if !c.start(false) {
		return nil
	}
	return c.key
}

func (c *datastoreCursor) nextKey() []byte {
	if c.withValue || !c.advance() {
		return nil
	}
	return c.key
}

func (c *datastoreCursor) first() ([]byte, []byte) {
	if !c.start(true) {
		return nil, nil
	}
	return c.key, c.value
}

func (c *datastoreCursor) next() ([]byte, []byte) {
	if !c.withValue || !c.advance() {
		return nil, nil
	}
	return c.key, c.value
}

func (c *datastoreCursor) closeRows() {
	if c.rows != nil {
		err := c.rows.Close()
		if err != nil {
			c.tx.setError(err)
		}
	}
	c.rows = nil
	c.key = nil
	c.value = nil
}

func (c *datastoreCursor) close() {
	c.closeRows()
	delete(c.tx.cursors, c)
}

func initializeImportBoltDatastore(
	ctx context.Context, conn *sql.Conn, sqliteFilename string) error {

	// TODO: remove bolt file after import, to save disk space. Currently it's
	// left in place to allow for testing to easily switch back and forth.

	const boltDatastoreFilename = "psiphon.boltdb"

	startTime := time.Now()

	err := sqliteExecWithRetry(
		ctx, conn, "BEGIN IMMEDIATE", sqliteInitBeginRetries)
	if err != nil {
		return errors.Trace(err)
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(ctx, "ROLLBACK")
		}
	}()

	var version int
	err = conn.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version)
	if err != nil {
		return errors.Trace(err)
	}
	if version == sqliteDatastoreVersionPostImport {
		_, err = conn.ExecContext(ctx, "COMMIT")
		if err != nil {
			return errors.Trace(err)
		}
		committed = true
		return nil
	}
	if version != sqliteDatastoreVersionSchema {
		return errors.Tracef("unsupported SQLite datastore version: %d", version)
	}

	// Once the import is completed, skipped, or abandoned, the datastore
	// version is updated to sqliteDatastoreVersionPostImport, and imports
	// are no longer attempted. This is set even on failures, so as to not
	// keep attempting imports on every open when the source datastore is
	// corrupt, or other scenarios.
	//
	// A savepoint is used to roll back all imported data in the case of any
	// import error, keeping the write transaction open to still atomically
	// update to sqliteDatastoreVersionPostImport.

	finish := func(outcome string) error {
		_, err := conn.ExecContext(ctx, fmt.Sprintf(
			"PRAGMA user_version=%d", sqliteDatastoreVersionPostImport))
		if err != nil {
			return errors.Trace(err)
		}
		_, err = conn.ExecContext(ctx, "COMMIT")
		if err != nil {
			return errors.Trace(err)
		}
		committed = true
		NoticeInfo(
			"Bolt datastore import %s (%s)",
			outcome, time.Since(startTime))
		return nil
	}

	var hasEntries int
	err = conn.QueryRowContext(
		ctx, "SELECT EXISTS(SELECT 1 FROM bucket_entries)").Scan(&hasEntries)
	if err != nil {
		return errors.Trace(err)
	}
	if hasEntries != 0 {
		return finish("skipped: SQLite datastore is not empty")
	}

	boltFilename := filepath.Join(filepath.Dir(sqliteFilename), boltDatastoreFilename)
	_, err = os.Stat(boltFilename)
	if os.IsNotExist(err) {
		return finish("skipped: Bolt datastore does not exist")
	}
	if err != nil {
		return finish(fmt.Sprintf("abandoned: %s", errors.Trace(err)))
	}

	_, err = conn.ExecContext(ctx, "SAVEPOINT bolt_import")
	if err != nil {
		return errors.Trace(err)
	}

	var bucketCount, keyValueCount int64

	importErr := func() (retErr error) {

		panicOnFault := debug.SetPanicOnFault(true)
		defer debug.SetPanicOnFault(panicOnFault)
		defer func() {
			if value := recover(); value != nil {
				retErr = errors.Tracef("panic: %v", value)
			}
		}()

		var boltDB *bolt.DB
		var err error
		defer func() {
			if boltDB != nil {
				err := boltDB.Close()
				if retErr == nil {
					retErr = errors.Trace(err)
				}
			}
		}()

		for attempt := 0; attempt <= sqliteImportRetries; attempt++ {
			boltDB, err = bolt.Open(boltFilename, 0600, &bolt.Options{
				ReadOnly: true,
				Timeout:  1 * time.Second,
				OpenFile: func(filename string, _ int, _ os.FileMode) (*os.File, error) {
					return os.Open(filename)
				},
			})
			if err == nil {
				break
			}
			if !std_errors.Is(err, bolt.ErrTimeout) ||
				attempt == sqliteImportRetries {

				return errors.Trace(err)
			}
		}

		stmt, err := conn.PrepareContext(ctx,
			"INSERT INTO bucket_entries (bucket, key, value) VALUES (?, ?, ?)")
		if err != nil {
			return errors.Trace(err)
		}
		defer func() {
			err := stmt.Close()
			if retErr == nil {
				retErr = errors.Trace(err)
			}
		}()

		// The serverEntryKeys/dialParameterKeys special cases allow import of
		// bolt datastores that have not yet applied the key-only buckets upgrade.

		var serverEntryKeysFound, dialParameterKeysFound bool

		err = boltDB.View(func(tx *bolt.Tx) error {
			rootCursor := tx.Cursor()
			for bucketName, _ := rootCursor.First(); bucketName != nil; bucketName, _ = rootCursor.Next() {

				bucket := tx.Bucket(bucketName)
				if bucket == nil {
					return errors.TraceNew("invalid Bolt bucket")
				}
				bucketCount++
				if string(bucketName) == string(datastoreServerEntryKeysBucket) {
					serverEntryKeysFound = true
				}
				if string(bucketName) == string(datastoreDialParameterKeysBucket) {
					dialParameterKeysFound = true
				}

				cursor := bucket.Cursor()
				for key, value := cursor.First(); key != nil; key, value = cursor.Next() {
					if value == nil {
						return errors.TraceNew("nested Bolt bucket is not supported")
					}
					_, err := stmt.ExecContext(ctx, bucketName, key, value)
					if err != nil {
						return errors.Trace(err)
					}
					keyValueCount++
				}
			}
			return nil
		})
		if err != nil {
			return errors.Trace(err)
		}

		if !serverEntryKeysFound {
			result, err := conn.ExecContext(ctx, `
				INSERT INTO bucket_entries (bucket, key, value)
				SELECT ?, key, ? FROM bucket_entries WHERE bucket=?`,
				datastoreServerEntryKeysBucket, datastoreServerEntryKeyValue,
				datastoreServerEntriesBucket)
			if err != nil {
				return errors.Trace(err)
			}
			count, err := result.RowsAffected()
			if err != nil {
				return errors.Trace(err)
			}
			keyValueCount += count
			if count > 0 {
				bucketCount++
			}
		}
		if !dialParameterKeysFound {
			result, err := conn.ExecContext(ctx, `
				INSERT INTO bucket_entries (bucket, key, value)
				SELECT ?, key, ? FROM bucket_entries WHERE bucket=?`,
				datastoreDialParameterKeysBucket, datastoreDialParameterKeyValue,
				datastoreDialParametersBucket)
			if err != nil {
				return errors.Trace(err)
			}
			count, err := result.RowsAffected()
			if err != nil {
				return errors.Trace(err)
			}
			keyValueCount += count
			if count > 0 {
				bucketCount++
			}
		}

		return nil
	}()

	if importErr != nil {
		_, err = conn.ExecContext(ctx, "ROLLBACK TO bolt_import")
		if err != nil {
			return errors.Trace(err)
		}
	}
	_, err = conn.ExecContext(ctx, "RELEASE bolt_import")
	if err != nil {
		return errors.Trace(err)
	}

	if importErr != nil {
		return finish(fmt.Sprintf(
			"abandoned: %s", errors.Trace(importErr)))
	}

	return finish(fmt.Sprintf(
		"succeeded: %d buckets, %d key/value records",
		bucketCount, keyValueCount))
}
