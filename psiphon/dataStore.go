/*
 * Copyright (c) 2014, Psiphon Inc.
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
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	sqlite3 "github.com/mattn/go-sqlite3"
	"log"
	"sync"
	"time"
)

type dataStore struct {
	init sync.Once
	db   *sql.DB
}

var singleton dataStore

// initDataStore initializes the singleton instance of dataStore. This
// function uses a sync.Once and is safe for use by concurrent goroutines.
// The underlying sql.DB connection pool is also safe.
func initDataStore() {
	singleton.init.Do(func() {
		const schema = `
        create table if not exists serverEntry
            (id text not null primary key,
             rank integer not null unique,
             region text not null,
             data blob not null);
        create table if not exists keyValue
            (key text not null,
             value text not null);
		pragma journal_mode=WAL;
        `
		db, err := sql.Open(
			"sqlite3",
			fmt.Sprintf("file:%s?cache=private&mode=rwc", DATA_STORE_FILENAME))
		if err != nil {
			log.Fatal("initDataStore failed to open database: %s", err)
		}
		_, err = db.Exec(schema)
		if err != nil {
			log.Fatal("initDataStore failed to initialize schema: %s", err)
		}
		singleton.db = db
	})
}

func canRetry(err error) bool {
	sqlError, ok := err.(sqlite3.Error)
	return ok && (sqlError.Code == sqlite3.ErrBusy ||
		sqlError.Code == sqlite3.ErrLocked ||
		sqlError.ExtendedCode == sqlite3.ErrLockedSharedCache ||
		sqlError.ExtendedCode == sqlite3.ErrBusySnapshot)
}

// transactionWithRetry will retry a write transaction if sqlite3
// reports a table is locked by another writer.
func transactionWithRetry(updater func(*sql.Tx) error) error {
	initDataStore()
	for i := 0; i < 10; i++ {
		if i > 0 {
			// Delay on retry
			time.Sleep(100)
		}
		transaction, err := singleton.db.Begin()
		if err != nil {
			return ContextError(err)
		}
		err = updater(transaction)
		if err != nil {
			transaction.Rollback()
			if canRetry(err) {
				continue
			}
			return ContextError(err)
		}
		err = transaction.Commit()
		if err != nil {
			transaction.Rollback()
			if canRetry(err) {
				continue
			}
			return ContextError(err)
		}
		return nil
	}
	return ContextError(errors.New("retries exhausted"))
}

// serverEntryExists returns true if a serverEntry with the
// given ipAddress id already exists.
func serverEntryExists(transaction *sql.Tx, ipAddress string) bool {
	query := "select count(*) from serverEntry where id  = ?;"
	var count int
	err := singleton.db.QueryRow(query, ipAddress).Scan(&count)
	return err == nil && count > 0
}

// StoreServerEntry adds the server entry to the data store. A newly
// stored (or re-stored) server entry is assigned the next-to-top rank
// for cycle order (the previous top ranked entry is promoted). The
// purpose of this is to keep the last selected server as the top
// ranked server.
// When replaceIfExists is true, an existing server entry record is
// overwritten; otherwise, the existing record is unchanged.
func StoreServerEntry(serverEntry *ServerEntry, replaceIfExists bool) error {
	return transactionWithRetry(func(transaction *sql.Tx) error {
		serverEntryExists := serverEntryExists(transaction, serverEntry.IpAddress)
		if serverEntryExists && !replaceIfExists {
			return nil
		}
		// TODO: also skip updates if replaceIfExists but 'data' has not changed
		_, err := transaction.Exec(`
            update serverEntry set rank = rank + 1
                where id = (select id from serverEntry order by rank desc limit 1);
            `)
		if err != nil {
			// Note: ContextError() would break canRetry()
			return err
		}
		data, err := json.Marshal(serverEntry)
		if err != nil {
			return ContextError(err)
		}
		_, err = transaction.Exec(`
            insert or replace into serverEntry (id, rank, region, data)
            values (?, (select coalesce(max(rank)-1, 0) from serverEntry), ?, ?);
            `, serverEntry.IpAddress, serverEntry.Region, data)
		if err != nil {
			return err
		}
		// TODO: log after commit
		if !serverEntryExists {
			log.Printf("stored server %s", serverEntry.IpAddress)
		}
		return nil
	})
}

// PromoteServerEntry assigns the top cycle rank to the specified
// server entry. This server entry will be the first candidate in
// a subsequent tunnel establishment.
func PromoteServerEntry(ipAddress string) error {
	return transactionWithRetry(func(transaction *sql.Tx) error {
		_, err := transaction.Exec(`
            update serverEntry
            set rank = (select MAX(rank)+1 from serverEntry)
            where id = ?;
            `, ipAddress)
		if err != nil {
			// Note: ContextError() would break canRetry()
			return err
		}
		return nil
	})
}

// ServerEntryCycler is used to continuously iterate over
// stored server entries in rank order.
type ServerEntryCycler struct {
	region      string
	transaction *sql.Tx
	cursor      *sql.Rows
	isReset     bool
}

// NewServerEntryCycler creates a new ServerEntryCycler
func NewServerEntryCycler(region string) (cycler *ServerEntryCycler, err error) {
	initDataStore()
	cycler = &ServerEntryCycler{region: region}
	err = cycler.Reset()
	if err != nil {
		return nil, err
	}
	return cycler, nil
}

// Reset a ServerEntryCycler to the start of its cycle. The next
// call to Next will return the first server entry.
func (cycler *ServerEntryCycler) Reset() error {
	cycler.Close()
	transaction, err := singleton.db.Begin()
	if err != nil {
		return ContextError(err)
	}
	var cursor *sql.Rows
	if cycler.region == "" {
		cursor, err = transaction.Query(
			"select data from serverEntry order by rank desc;")
	} else {
		cursor, err = transaction.Query(
			"select data from serverEntry where region = ? order by rank desc;",
			cycler.region)
	}
	if err != nil {
		transaction.Rollback()
		return ContextError(err)
	}
	cycler.isReset = true
	cycler.transaction = transaction
	cycler.cursor = cursor
	return nil
}

// Close cleans up resources associated with a ServerEntryCycler.
func (cycler *ServerEntryCycler) Close() {
	if cycler.cursor != nil {
		cycler.cursor.Close()
	}
	cycler.cursor = nil
	if cycler.transaction != nil {
		cycler.transaction.Rollback()
	}
	cycler.transaction = nil
}

// Next returns the next server entry, by rank, for a ServerEntryCycler. When
// the ServerEntryCycler has worked through all known server entries, Next will
// call Reset and start over and return the first server entry again.
func (cycler *ServerEntryCycler) Next() (serverEntry *ServerEntry, err error) {
	defer func() {
		if err != nil {
			cycler.Close()
		}
	}()
	for !cycler.cursor.Next() {
		err = cycler.cursor.Err()
		if err != nil {
			return nil, ContextError(err)
		}
		if cycler.isReset {
			return nil, ContextError(errors.New("no server entries"))
		}
		err = cycler.Reset()
		if err != nil {
			return nil, ContextError(err)
		}
	}
	cycler.isReset = false
	var data []byte
	err = cycler.cursor.Scan(&data)
	if err != nil {
		return nil, ContextError(err)
	}
	serverEntry = new(ServerEntry)
	err = json.Unmarshal(data, serverEntry)
	if err != nil {
		return nil, ContextError(err)
	}
	return serverEntry, nil
}

// HasServerEntries returns true if the data store contains at
// least one server entry (for the specified region, in not blank).
func HasServerEntries(region string) bool {
	initDataStore()
	var err error
	var count int
	if region == "" {
		err = singleton.db.QueryRow("select count(*) from serverEntry;").Scan(&count)
		if err == nil {
			log.Printf("servers: %d", count)
		}
	} else {
		err = singleton.db.QueryRow(
			"select count(*) from serverEntry where region = ?;", region).Scan(&count)
		if err == nil {
			log.Printf("servers for region %s: %d", region, count)
		}
	}
	return err == nil && count > 0
}

// GetServerEntryIpAddresses returns an array containing
// all stored server IP addresses.
func GetServerEntryIpAddresses() (ipAddresses []string, err error) {
	initDataStore()
	ipAddresses = make([]string, 0)
	rows, err := singleton.db.Query("select id from serverEntry;")
	if err != nil {
		return nil, ContextError(err)
	}
	defer rows.Close()
	for rows.Next() {
		var ipAddress string
		err = rows.Scan(&ipAddress)
		if err != nil {
			return nil, ContextError(err)
		}
		ipAddresses = append(ipAddresses, ipAddress)
	}
	if err = rows.Err(); err != nil {
		return nil, ContextError(err)
	}
	return ipAddresses, nil
}

// SetKeyValue stores a key/value pair.
func SetKeyValue(key, value string) error {
	return transactionWithRetry(func(transaction *sql.Tx) error {
		_, err := transaction.Exec(`
            insert or replace into keyValue (key, value)
            values (?, ?);
            `, key, value)
		if err != nil {
			// Note: ContextError() would break canRetry()
			return err
		}
		return nil
	})
}

// GetLastConnected retrieves a key/value pair. If not found,
// it returns an empty string value.
func GetKeyValue(key string) (value string, err error) {
	initDataStore()
	rows := singleton.db.QueryRow("select value from keyValue where key = ?;", key)
	err = rows.Scan(&value)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", ContextError(err)
	}
	return value, nil
}
