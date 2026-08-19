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

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Psiphon-Labs/bolt"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
)

func TestDatastoreKeyOnlyBuckets(t *testing.T) {
	if err := runTestDatastoreKeyOnlyBuckets(); err != nil {
		t.Fatal(err.Error())
	}
}

func runTestDatastoreKeyOnlyBuckets() error {

	testDataDirName, err := os.MkdirTemp(
		"", "psiphon-datastore-key-only-buckets-test")
	if err != nil {
		return errors.Trace(err)
	}
	defer os.RemoveAll(testDataDirName)

	clientConfigJSON := `
    {
        "ClientPlatform" : "",
        "ClientVersion" : "0000000000000000",
        "SponsorId" : "0000000000000000",
        "PropagationChannelId" : "0",
        "DisableTactics" : true
    }`

	clientConfig, err := LoadConfig([]byte(clientConfigJSON))
	if err != nil {
		return errors.Trace(err)
	}
	clientConfig.DataRootDirectory = testDataDirName
	err = clientConfig.Commit(false)
	if err != nil {
		return errors.Trace(err)
	}

	serverEntryCount := 100
	dialParametersCount := 50
	networkID := clientConfig.GetNetworkID()

	// Pave a datastore with server entries and dial parameters using the
	// public API.

	err = OpenDataStore(clientConfig)
	if err != nil {
		return errors.Trace(err)
	}

	for i := 0; i < serverEntryCount; i++ {
		n := 16
		fields := make(protocol.ServerEntryFields)
		fields["ipAddress"] = fmt.Sprintf("127.0.0.%d", i+1)
		fields["sshPort"] = 2222
		fields["sshUsername"] = prng.HexString(n)
		fields["sshPassword"] = prng.HexString(n)
		fields["sshHostKey"] = prng.HexString(n)
		fields["capabilities"] = []string{"SSH", "ssh-api-requests"}
		fields["region"] = "US"
		fields["configurationVersion"] = 1
		fields.SetLocalSource(protocol.SERVER_ENTRY_SOURCE_EMBEDDED)
		fields.SetLocalTimestamp(
			common.TruncateTimestampToHour(common.GetCurrentTimestamp()))
		err = StoreServerEntry(fields, true)
		if err != nil {
			return errors.Trace(err)
		}
	}

	for i := 0; i < dialParametersCount; i++ {
		err := SetDialParameters(
			fmt.Sprintf("127.0.0.%d", i+1), networkID, &DialParameters{})
		if err != nil {
			return errors.Trace(err)
		}
	}

	// checkKeyBucket checks that a key-only index bucket contains exactly
	// the keys of its source bucket.
	checkKeyBucket := func(sourceBucket, keyBucket []byte, expectedCount int) error {
		return errors.Trace(datastoreView(func(tx *datastoreTx) error {
			var sourceKeys, indexKeys [][]byte
			for _, b := range [][]byte{sourceBucket, keyBucket} {
				keys := &sourceKeys
				if bytes.Equal(b, keyBucket) {
					keys = &indexKeys
				}
				cursor := tx.bucket(b).cursor()
				for key := cursor.firstKey(); key != nil; key = cursor.nextKey() {
					*keys = append(*keys, append([]byte(nil), key...))
				}
				cursor.close()
			}
			if len(sourceKeys) != expectedCount {
				return errors.Tracef(
					"unexpected source key count: %d", len(sourceKeys))
			}
			if len(indexKeys) != expectedCount {
				return errors.Tracef(
					"unexpected index key count: %d", len(indexKeys))
			}
			for i := range sourceKeys {
				if !bytes.Equal(sourceKeys[i], indexKeys[i]) {
					return errors.TraceNew("key mismatch")
				}
			}
			return nil
		}))
	}

	checkDataStore := func() error {
		if !HasServerEntries() {
			return errors.TraceNew("unexpected HasServerEntries")
		}
		if count := CountServerEntries(); count != serverEntryCount {
			return errors.Tracef("unexpected server entry count: %d", count)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_, iterator, err := NewServerEntryIterator(ctx, clientConfig)
		if err != nil {
			return errors.Trace(err)
		}
		defer iterator.Close()
		iteratedServerEntries := 0
		for {
			serverEntry, err := iterator.Next(ctx)
			if err != nil {
				return errors.Trace(err)
			}
			if serverEntry == nil {
				break
			}
			iteratedServerEntries += 1
		}
		if iteratedServerEntries != serverEntryCount {
			return errors.Tracef("unexpected iterated count: %d", iteratedServerEntries)
		}

		// PromoteServerEntry checks existence in the server entry key
		// bucket, silently ignoring unknown entries; a successful
		// GetAffinityServerEntryAndDialParameters confirms the promotion.
		promoteIPAddress := "127.0.0.1"
		err = PromoteServerEntry(clientConfig, promoteIPAddress)
		if err != nil {
			return errors.Trace(err)
		}
		serverEntryFields, _, err := GetAffinityServerEntryAndDialParameters(networkID)
		if err != nil {
			return errors.Trace(err)
		}
		if serverEntryFields.GetIPAddress() != promoteIPAddress {
			return errors.TraceNew("unexpected affinity server entry")
		}

		err = checkKeyBucket(
			datastoreServerEntriesBucket,
			datastoreServerEntryKeysBucket,
			serverEntryCount)
		if err != nil {
			return errors.Trace(err)
		}
		err = checkKeyBucket(
			datastoreDialParametersBucket,
			datastoreDialParameterKeysBucket,
			dialParametersCount)
		return errors.Trace(err)
	}

	err = checkDataStore()
	if err != nil {
		return errors.Trace(err)
	}
	CloseDataStore()

	// Simulate a datastore created by a client version which predates the
	// key-only index buckets by deleting them from the closed datastore
	// file; then reopen, which runs the upgrade, and check that both
	// indexes are rebuilt.

	filename := filepath.Join(
		testDataDirName, "ca.psiphon.PsiphonTunnel.tunnel-core",
		"datastore", "psiphon.boltdb")
	db, err := bolt.Open(filename, 0600, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		return errors.Trace(err)
	}
	err = db.Update(func(tx *bolt.Tx) error {
		err := tx.DeleteBucket(datastoreServerEntryKeysBucket)
		if err != nil {
			return err
		}
		return tx.DeleteBucket(datastoreDialParameterKeysBucket)
	})
	if err != nil {
		_ = db.Close()
		return errors.Trace(err)
	}
	err = db.Close()
	if err != nil {
		return errors.Trace(err)
	}

	err = OpenDataStore(clientConfig)
	if err != nil {
		return errors.Trace(err)
	}
	err = checkDataStore()
	if err != nil {
		CloseDataStore()
		return errors.Trace(err)
	}
	CloseDataStore()

	// Check that reopening an already upgraded datastore preserves the
	// indexes.

	err = OpenDataStore(clientConfig)
	if err != nil {
		return errors.Trace(err)
	}
	defer CloseDataStore()

	return errors.Trace(checkDataStore())
}
