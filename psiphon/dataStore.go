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
             data blob not null,
             rank integer not null unique);
        `
		db, err := sql.Open("sqlite3", DATA_STORE_FILENAME)
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

// transactionWithRetry will retry a write transaction if sqlite3
// reports ErrBusy or ErrBusySnapshot -- i.e., if the XXXXX
func transactionWithRetry(updater func(*sql.Tx) error) error {
	initDataStore()
	for i := 0; i < 10; i++ {
		transaction, err := singleton.db.Begin()
		if err != nil {
			return ContextError(err)
		}
		err = updater(transaction)
		if err != nil {
			transaction.Rollback()
			if sqlError, ok := err.(sqlite3.Error); ok &&
				(sqlError.Code == sqlite3.ErrBusy ||
					sqlError.ExtendedCode == sqlite3.ErrBusySnapshot) {
				time.Sleep(100)
				continue
			}
			return ContextError(err)
		}
		err = transaction.Commit()
		if err != nil {
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
			return ContextError(err)
		}
		data, err := json.Marshal(serverEntry)
		if err != nil {
			return ContextError(err)
		}
		_, err = transaction.Exec(`
            insert or replace into serverEntry (id, data, rank)
            values (?, ?, (select coalesce(max(rank)-1, 0) from serverEntry));
            `, serverEntry.IpAddress, data)
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
			return ContextError(err)
		}
		return nil
	})
}

// ServerEntryCycler is used to continuously iterate over
// stored server entries in rank order.
type ServerEntryCycler struct {
	transaction *sql.Tx
	cursor      *sql.Rows
	isReset     bool
}

// NewServerEntryCycler creates a new ServerEntryCycler
func NewServerEntryCycler() (cycler *ServerEntryCycler, err error) {
	initDataStore()
	cycler = new(ServerEntryCycler)
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
	cursor, err := transaction.Query("select * from serverEntry order by rank desc;")
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
	var id string
	var data []byte
	var rank int64
	err = cycler.cursor.Scan(&id, &data, &rank)
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
// least one server entry.
func HasServerEntries() bool {
	initDataStore()
	var count int
	err := singleton.db.QueryRow("select count(*) from serverEntry;").Scan(&count)
	if err == nil {
		log.Printf("stored servers: %d", count)
	}
	return err == nil && count > 0
}
