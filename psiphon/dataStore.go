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
	sqlite3 "github.com/Psiphon-Inc/go-sqlite3"
	"strings"
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
	    create table if not exists serverEntryProtocol
	        (serverEntryId text not null,
	         protocol text not null,
	         primary key (serverEntryId, protocol));
        create table if not exists keyValue
            (key text not null primary key,
             value text not null);
		pragma journal_mode=WAL;
        `
		db, err := sql.Open(
			"sqlite3",
			fmt.Sprintf("file:%s?cache=private&mode=rwc", DATA_STORE_FILENAME))
		if err != nil {
			Fatal("initDataStore failed to open database: %s", err)
		}
		_, err = db.Exec(schema)
		if err != nil {
			Fatal("initDataStore failed to initialize schema: %s", err)
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
		_, err = transaction.Exec(`
            delete from serverEntryProtocol where serverEntryId = ?;
            `, serverEntry.IpAddress)
		if err != nil {
			return err
		}
		for _, protocol := range SupportedTunnelProtocols {
			// Note: for meek, the capabilities are FRONTED-MEEK and UNFRONTED-MEEK
			// and the additonal OSSH service is assumed to be available internally.
			requiredCapability := strings.TrimSuffix(protocol, "-OSSH")
			if Contains(serverEntry.Capabilities, requiredCapability) {
				_, err = transaction.Exec(`
                    insert into serverEntryProtocol (serverEntryId, protocol)
                    values (?, ?);
                    `, serverEntry.IpAddress, protocol)
				if err != nil {
					return err
				}
			}
		}
		// TODO: post notice after commit
		if !serverEntryExists {
			Notice(NOTICE_INFO, "stored server %s", serverEntry.IpAddress)
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

// ServerEntryIterator is used to iterate over
// stored server entries in rank order.
type ServerEntryIterator struct {
	region      string
	protocol    string
	excludeIds  []string
	transaction *sql.Tx
	cursor      *sql.Rows
}

// NewServerEntryIterator creates a new NewServerEntryIterator
func NewServerEntryIterator(region, protocol string) (iterator *ServerEntryIterator, err error) {
	initDataStore()
	iterator = &ServerEntryIterator{
		region:   region,
		protocol: protocol,
	}
	err = iterator.Reset()
	if err != nil {
		return nil, err
	}
	return iterator, nil
}

// Reset a NewServerEntryIterator to the start of its cycle. The next
// call to Next will return the first server entry.
func (iterator *ServerEntryIterator) Reset() error {
	iterator.Close()
	transaction, err := singleton.db.Begin()
	if err != nil {
		return ContextError(err)
	}
	var cursor *sql.Rows
	whereClause, whereParams := makeServerEntryWhereClause(
		iterator.region, iterator.protocol, nil)
	query := "select data from serverEntry" + whereClause + " order by rank desc;"
	cursor, err = transaction.Query(query, whereParams...)
	if err != nil {
		transaction.Rollback()
		return ContextError(err)
	}
	iterator.transaction = transaction
	iterator.cursor = cursor
	return nil
}

// Close cleans up resources associated with a ServerEntryIterator.
func (iterator *ServerEntryIterator) Close() {
	if iterator.cursor != nil {
		iterator.cursor.Close()
	}
	iterator.cursor = nil
	if iterator.transaction != nil {
		iterator.transaction.Rollback()
	}
	iterator.transaction = nil
}

// Next returns the next server entry, by rank, for a ServerEntryIterator.
// Returns nil with no error when there is no next item.
func (iterator *ServerEntryIterator) Next() (serverEntry *ServerEntry, err error) {
	defer func() {
		if err != nil {
			iterator.Close()
		}
	}()
	if !iterator.cursor.Next() {
		err = iterator.cursor.Err()
		if err != nil {
			return nil, ContextError(err)
		}
		// There is no next item
		return nil, nil
	}

	var data []byte
	err = iterator.cursor.Scan(&data)
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

func makeServerEntryWhereClause(
	region, protocol string, excludeIds []string) (whereClause string, whereParams []interface{}) {
	whereClause = ""
	whereParams = make([]interface{}, 0)
	if region != "" {
		whereClause += " where region = ?"
		whereParams = append(whereParams, region)
	}
	if protocol != "" {
		if len(whereClause) > 0 {
			whereClause += " and"
		} else {
			whereClause += " where"
		}
		whereClause +=
			" exists (select 1 from serverEntryProtocol where protocol = ? and serverEntryId = serverEntry.id)"
		whereParams = append(whereParams, protocol)
	}
	if len(excludeIds) > 0 {
		if len(whereClause) > 0 {
			whereClause += " and"
		} else {
			whereClause += " where"
		}
		whereClause += " id in ("
		for index, id := range excludeIds {
			if index > 0 {
				whereClause += ", "
			}
			whereClause += "?"
			whereParams = append(whereParams, id)
		}
		whereClause += ")"
	}
	return whereClause, whereParams
}

// HasServerEntries returns true if the data store contains at
// least one server entry (for the specified region and/or protocol,
// when not blank).
func HasServerEntries(region, protocol string) bool {
	initDataStore()
	var count int
	whereClause, whereParams := makeServerEntryWhereClause(region, protocol, nil)
	query := "select count(*) from serverEntry" + whereClause
	err := singleton.db.QueryRow(query, whereParams...).Scan(&count)

	if region == "" {
		region = "(any)"
	}
	if protocol == "" {
		protocol = "(any)"
	}
	Notice(NOTICE_INFO, "servers for region %s and protocol %s: %d",
		region, protocol, count)

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
