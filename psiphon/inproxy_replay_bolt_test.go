//go:build !PSIPHON_USE_BADGER_DB && !PSIPHON_USE_FILES_DB && !PSIPHON_USE_SQLITE_DB
// +build !PSIPHON_USE_BADGER_DB,!PSIPHON_USE_FILES_DB,!PSIPHON_USE_SQLITE_DB

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

// The replay lookup transaction tests count writable commits through the
// Bolt transaction ID, so they build only with the Bolt datastore.

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/Psiphon-Labs/bolt"
)

// countBrokerReplayCommits returns the datastore's committed writable
// transaction ID, which increments once per writable commit. Read-only
// transactions do not change it.
func countBrokerReplayCommits(t *testing.T) int {
	t.Helper()
	datastoreMutex.RLock()
	defer datastoreMutex.RUnlock()
	var id int
	err := activeDatastoreDB.boltDB.View(func(tx *bolt.Tx) error {
		id = tx.ID()
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// TestInproxyBrokerReplayLookupTransactions verifies the replay lookup's
// transaction policy: absent and valid records are read without a writable
// commit; an invalid record costs one writable commit, which deletes it; and
// when another broker client stores a valid record between the read-only
// check and the writable cleanup, the lookup returns that record and does
// not delete it.
func TestInproxyBrokerReplayLookupTransactions(t *testing.T) {
	spec := newProviderTestBroker(t, "A", "B")
	m := newProviderTestManager(t, 1, spec)

	t.Run("absent", func(t *testing.T) {
		before := countBrokerReplayCommits(t)
		if loadBrokerReplayTestParameters(t, spec) != nil {
			t.Fatal("loaded a record that was never stored")
		}
		if got := countBrokerReplayCommits(t) - before; got != 0 {
			t.Fatalf("absent lookup made %d writable commits", got)
		}
	})

	valid := makeBrokerReplayTestParameters(t, m, spec, "A")
	if err := storeInproxyBrokerReplayParameters("TEST", valid); err != nil {
		t.Fatal(err)
	}

	t.Run("valid", func(t *testing.T) {
		before := countBrokerReplayCommits(t)
		loaded := loadBrokerReplayTestParameters(t, spec)
		if loaded == nil || !bytes.Equal(loaded.replayRecordHash, valid.replayRecordHash) {
			t.Fatal("valid lookup did not return the stored record")
		}
		if got := countBrokerReplayCommits(t) - before; got != 0 {
			t.Fatalf("valid lookup made %d writable commits", got)
		}
	})

	expired := makeBrokerReplayTestParameters(t, m, spec, "A")
	expired.LastUsedTimestamp = time.Now().Add(-2 * time.Hour)

	t.Run("invalid", func(t *testing.T) {
		if err := SetNetworkReplayParameters("TEST", spec.BrokerPublicKey, expired); err != nil {
			t.Fatal(err)
		}
		before := countBrokerReplayCommits(t)
		if loadBrokerReplayTestParameters(t, spec) != nil {
			t.Fatal("accepted an expired record")
		}
		if got := countBrokerReplayCommits(t) - before; got != 1 {
			t.Fatalf("invalid lookup made %d writable commits, want 1", got)
		}
		// The deletion is durable: the next lookup finds nothing and
		// commits nothing.
		before = countBrokerReplayCommits(t)
		if loadBrokerReplayTestParameters(t, spec) != nil {
			t.Fatal("expired record was not deleted")
		}
		if got := countBrokerReplayCommits(t) - before; got != 0 {
			t.Fatalf("lookup after deletion made %d writable commits", got)
		}
	})

	t.Run("concurrent-replacement", func(t *testing.T) {
		if err := SetNetworkReplayParameters("TEST", spec.BrokerPublicKey, expired); err != nil {
			t.Fatal(err)
		}
		// A writer holds the writable transaction open while the lookup's
		// read-only check observes the expired record. Read-only
		// transactions do not wait for the writer, so the check completes
		// before the writer replaces the record and commits. The lookup's
		// writable cleanup then serializes after that commit, re-reads
		// the valid replacement, and must return it rather than delete it.
		writerOpen := make(chan struct{})
		viewDone := make(chan struct{})
		replacement := makeBrokerReplayTestParameters(t, m, spec, "B")
		value, err := json.Marshal(replacement)
		if err != nil {
			t.Fatal(err)
		}
		key := makeNetworkReplayParametersKey[InproxyBrokerDialParameters]("TEST", spec.BrokerPublicKey)
		before := countBrokerReplayCommits(t)
		writerErr := make(chan error, 1)
		go func() {
			writerErr <- datastoreUpdate(func(tx *datastoreTx) error {
				close(writerOpen)
				<-viewDone
				return tx.bucket(datastoreNetworkReplayParametersBucket).put(key, value)
			})
		}()
		<-writerOpen
		// Confirm the read-only path sees the expired record while the
		// writer is open, then release the writer before the lookup's
		// cleanup transaction can start.
		var observed []byte
		err = datastoreView(func(tx *datastoreTx) error {
			observed = append([]byte(nil),
				tx.bucket(datastoreNetworkReplayParametersBucket).get(key)...)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(observed) == 0 {
			t.Fatal("read-only check did not observe the expired record")
		}
		resultCh := make(chan *InproxyBrokerDialParameters, 1)
		go func() {
			// This lookup's read-only check runs while the writer is still
			// open and observes the expired record; its writable cleanup
			// blocks until the writer commits.
			params, err := loadInproxyBrokerReplayParameters("TEST", spec, time.Hour)
			if err != nil {
				t.Error(err)
			}
			resultCh <- params
		}()
		// Give the lookup's read-only check time to run before releasing
		// the writer. Bolt serializes writable transactions, so even if
		// the lookup reaches its cleanup first it waits for the writer.
		time.Sleep(50 * time.Millisecond)
		close(viewDone)
		if err := <-writerErr; err != nil {
			t.Fatal(err)
		}
		got := <-resultCh
		if got == nil || !bytes.Equal(got.replayRecordHash, hashInproxyBrokerReplayRecord(value)) {
			t.Fatal("lookup did not return the concurrently stored valid record")
		}
		stored := loadBrokerReplayTestParameters(t, spec)
		if stored == nil || !bytes.Equal(stored.replayRecordHash, hashInproxyBrokerReplayRecord(value)) {
			t.Fatal("lookup deleted the concurrently stored valid record")
		}
		// Exactly two writable commits: the writer's and the lookup's
		// cleanup. One would mean the lookup's read-only check ran after
		// the writer committed and the view-then-update path was never
		// exercised, which the assertions above cannot distinguish.
		if got := countBrokerReplayCommits(t) - before; got != 2 {
			t.Fatalf("concurrent replacement made %d writable commits, want 2 (view-then-update not exercised)", got)
		}
	})
}
