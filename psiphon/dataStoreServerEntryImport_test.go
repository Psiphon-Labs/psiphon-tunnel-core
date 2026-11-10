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
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
)

// When the datastore is empty, the import blocks starting tunnel
// establishment. Each write transaction costs a durable flush, which is slow
// on some devices, so the import must not use a transaction per server entry.
func TestImportEmbeddedServerEntriesBatchesWhenDatastoreIsEmpty(t *testing.T) {

	const count = 500
	const batchSize = 10

	config := openServerEntryImportTestDatastore(t)

	commitsBefore := serverEntryImportTestWriteTxCount(t)

	err := ImportEmbeddedServerEntries(
		context.Background(), config, "",
		encodeServerEntryImportTestList(t, 0, count, 1))
	if err != nil {
		t.Fatalf("ImportEmbeddedServerEntries failed: %v", err)
	}

	commits := serverEntryImportTestWriteTxCount(t) - commitsBefore

	if stored := len(serverEntryImportTestStoredVersions(t)); stored != count {
		t.Fatalf("unexpected stored server entry count: %d", stored)
	}
	if expectedCommits := count / batchSize; commits != expectedCommits {
		t.Fatalf("import used %d write transactions, expected %d",
			commits, expectedCommits)
	}
}

// When the datastore has server entries, the import doesn't block starting
// tunnel establishment. Each server entry is stored in its own transaction, so
// that other writes can run between server entries.
func TestImportEmbeddedServerEntriesStoresIndividuallyWhenDatastoreHasEntries(t *testing.T) {

	const count = 100

	config := openServerEntryImportTestDatastore(t)

	err := StoreServerEntry(newStorableServerEntryImportTestFields(0, 1), false)
	if err != nil {
		t.Fatalf("StoreServerEntry failed: %v", err)
	}

	commitsBefore := serverEntryImportTestWriteTxCount(t)

	err = ImportEmbeddedServerEntries(
		context.Background(), config, "",
		encodeServerEntryImportTestList(t, 0, count, 1))
	if err != nil {
		t.Fatalf("ImportEmbeddedServerEntries failed: %v", err)
	}

	commits := serverEntryImportTestWriteTxCount(t) - commitsBefore

	if stored := len(serverEntryImportTestStoredVersions(t)); stored != count {
		t.Fatalf("unexpected stored server entry count: %d", stored)
	}
	if commits != count {
		t.Fatalf("import used %d write transactions, expected %d", commits, count)
	}
}

// Entries already decoded when the stream fails must be retained, as when
// each entry was committed on its own.
func TestImportEmbeddedServerEntriesRetainsStoredEntriesOnDecodeError(t *testing.T) {

	config := openServerEntryImportTestDatastore(t)

	// Not a multiple of the batch size, so some entries are pending when the
	// error occurs.
	const validBeforeError = 25
	list := encodeServerEntryImportTestList(t, 0, validBeforeError, 1) +
		"\nnot-a-hex-encoded-server-entry\n" +
		encodeServerEntryImportTestList(t, validBeforeError, 20, 1)

	err := ImportEmbeddedServerEntries(context.Background(), config, "", list)
	if err == nil {
		t.Fatalf("expected ImportEmbeddedServerEntries to fail")
	}

	if stored := len(serverEntryImportTestStoredVersions(t)); stored != validBeforeError {
		t.Fatalf("unexpected stored server entry count: %d", stored)
	}
}

// Entries already decoded when the context is cancelled must be retained, as
// documented on StreamingStoreServerEntries.
func TestStreamingStoreServerEntriesRetainsStoredEntriesOnCancel(t *testing.T) {

	config := openServerEntryImportTestDatastore(t)

	// The reader hands the decoder one line per Read, and cancels the context
	// while serving the cancelAtLine-th line. That entry is decoded and then
	// the next loop iteration observes the cancellation. All of these entries
	// are pending, as this is less than the batch size.
	const cancelAtLine = 7

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reader := &serverEntryImportTestLineReader{
		lines: strings.Split(
			encodeServerEntryImportTestList(t, 0, 100, 1), "\n"),
		onLineServed: func(line int) {
			if line == cancelAtLine {
				cancel()
			}
		},
	}

	err := StreamingStoreServerEntries(
		ctx,
		config,
		protocol.NewStreamingServerEntryDecoder(
			reader,
			common.TruncateTimestampToHour(common.GetCurrentTimestamp()),
			protocol.SERVER_ENTRY_SOURCE_EMBEDDED),
		false)
	if err == nil {
		t.Fatalf("expected StreamingStoreServerEntries to fail")
	}

	if stored := len(serverEntryImportTestStoredVersions(t)); stored != cancelAtLine {
		t.Fatalf("unexpected stored server entry count: %d", stored)
	}
}

// Server entries for the same server within one batch are applied in order.
func TestImportEmbeddedServerEntriesAppliesConfigurationVersionsInBatch(t *testing.T) {

	config := openServerEntryImportTestDatastore(t)

	// Server 0 is first stored, then replaced by a newer version, then offered
	// an older version again.
	list := strings.Join([]string{
		encodeServerEntryImportTestList(t, 0, 1, 1),
		encodeServerEntryImportTestList(t, 0, 1, 3),
		encodeServerEntryImportTestList(t, 0, 1, 2),
		encodeServerEntryImportTestList(t, 1, 1, 1),
	}, "\n")

	err := ImportEmbeddedServerEntries(context.Background(), config, "", list)
	if err != nil {
		t.Fatalf("ImportEmbeddedServerEntries failed: %v", err)
	}

	stored := serverEntryImportTestStoredVersions(t)
	if len(stored) != 2 ||
		stored[serverEntryImportTestIPAddress(0)] != 3 ||
		stored[serverEntryImportTestIPAddress(1)] != 1 {
		t.Fatalf("unexpected stored server entries: %v", stored)
	}
}

// A server entry is reported as updated only once it is stored. When a later
// entry in a batch fails, the whole batch is rolled back.
func TestStoreServerEntriesNoticesOnlyStoredEntries(t *testing.T) {

	openServerEntryImportTestDatastore(t)

	// Restore the previous setting; other tests rely on it.
	emitDiagnostics := GetEmitDiagnosticNotices()
	emitNetworkParameters := GetEmitNetworkParameters()
	SetEmitDiagnosticNotices(true, false)
	defer SetEmitDiagnosticNotices(emitDiagnostics, emitNetworkParameters)

	var updatedNotices int
	err := SetNoticeWriter(NewNoticeReceiver(
		func(notice []byte) {
			var n struct {
				NoticeType string `json:"noticeType"`
				Data       struct {
					Message string `json:"message"`
				} `json:"data"`
			}
			if json.Unmarshal(notice, &n) == nil &&
				n.NoticeType == "Info" &&
				strings.HasPrefix(n.Data.Message, "updated server ") {
				updatedNotices += 1
			}
		}))
	if err != nil {
		t.Fatalf("SetNoticeWriter failed: %v", err)
	}
	defer ResetNoticeWriter()

	newEntries := func(first int) []protocol.ServerEntryFields {
		return []protocol.ServerEntryFields{
			newStorableServerEntryImportTestFields(first, 1),
			newStorableServerEntryImportTestFields(first+1, 1),
		}
	}

	err = storeServerEntries(newEntries(0), false, nil)
	if err != nil {
		t.Fatalf("storeServerEntries failed: %v", err)
	}
	if updatedNotices != 2 {
		t.Fatalf("unexpected updated server notice count: %d", updatedNotices)
	}

	// The second entry fails after the first has been written.
	err = storeServerEntries(
		newEntries(2), false,
		func(tx *datastoreTx, serverEntryID []byte) error {
			if string(serverEntryID) == serverEntryImportTestIPAddress(3) {
				return fmt.Errorf("test failure")
			}
			return nil
		})
	if err == nil {
		t.Fatalf("expected storeServerEntries to fail")
	}

	if stored := len(serverEntryImportTestStoredVersions(t)); stored != 2 {
		t.Fatalf("unexpected stored server entry count: %d", stored)
	}
	if updatedNotices != 2 {
		t.Fatalf("unexpected updated server notice count: %d", updatedNotices)
	}
}

func openServerEntryImportTestDatastore(t *testing.T) *Config {

	config, err := LoadConfig([]byte(`
    {
        "ClientPlatform" : "",
        "ClientVersion" : "0000000000000000",
        "SponsorId" : "0000000000000000",
        "PropagationChannelId" : "0",
        "DisableTactics" : true
    }`))
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}
	config.DataRootDirectory = t.TempDir()
	err = config.Commit(false)
	if err != nil {
		t.Fatalf("Commit failed: %v", err)
	}

	err = OpenDataStore(config)
	if err != nil {
		t.Fatalf("OpenDataStore failed: %v", err)
	}
	t.Cleanup(CloseDataStore)

	return config
}

func serverEntryImportTestIPAddress(index int) string {
	return fmt.Sprintf("10.0.%d.%d", index/250, index%250+1)
}

func newServerEntryImportTestFields(
	index, configurationVersion int) protocol.ServerEntryFields {

	fields := make(protocol.ServerEntryFields)
	fields["ipAddress"] = serverEntryImportTestIPAddress(index)
	fields["sshPort"] = 2222
	fields["sshUsername"] = "username"
	fields["sshPassword"] = "password"
	fields["sshHostKey"] = "hostkey"
	fields["capabilities"] = []string{"SSH", "ssh-api-requests"}
	fields["region"] = "US"
	fields["configurationVersion"] = configurationVersion
	return fields
}

// newStorableServerEntryImportTestFields returns server entry fields with the
// local fields that are otherwise set when decoding, and which are required
// to store the server entry.
func newStorableServerEntryImportTestFields(
	index, configurationVersion int) protocol.ServerEntryFields {

	fields := newServerEntryImportTestFields(index, configurationVersion)
	fields.SetLocalSource(protocol.SERVER_ENTRY_SOURCE_EMBEDDED)
	fields.SetLocalTimestamp(
		common.TruncateTimestampToHour(common.GetCurrentTimestamp()))
	return fields
}

// encodeServerEntryImportTestList returns an encoded server entry list, with
// one line per server, for servers [firstIndex, firstIndex+count).
func encodeServerEntryImportTestList(
	t *testing.T, firstIndex, count, configurationVersion int) string {

	lines := make([]string, count)
	for i := range lines {
		encoded, err := protocol.EncodeServerEntryFields(
			newServerEntryImportTestFields(
				firstIndex+i, configurationVersion))
		if err != nil {
			t.Fatalf("EncodeServerEntryFields failed: %v", err)
		}
		lines[i] = encoded
	}
	return strings.Join(lines, "\n")
}

// serverEntryImportTestWriteTxCount returns the number of write transactions
// committed to the datastore so far. A bolt read transaction's ID is the ID
// of the last committed write transaction.
func serverEntryImportTestWriteTxCount(t *testing.T) int {

	var txID int
	err := datastoreView(func(tx *datastoreTx) error {
		txID = int(tx.boltTx.ID())
		return nil
	})
	if err != nil {
		t.Fatalf("datastoreView failed: %v", err)
	}
	return txID
}

// serverEntryImportTestStoredVersions returns the configuration version of
// every stored server entry, by IP address.
func serverEntryImportTestStoredVersions(t *testing.T) map[string]int {

	versions := make(map[string]int)
	err := datastoreView(func(tx *datastoreTx) error {
		cursor := tx.bucket(datastoreServerEntriesBucket).cursor()
		defer cursor.close()
		for key, value := cursor.first(); key != nil; key, value = cursor.next() {
			var serverEntry protocol.ServerEntry
			if err := json.Unmarshal(value, &serverEntry); err != nil {
				return err
			}
			versions[string(key)] = serverEntry.ConfigurationVersion
		}
		return nil
	})
	if err != nil {
		t.Fatalf("datastoreView failed: %v", err)
	}
	return versions
}

// serverEntryImportTestLineReader serves one line per Read call.
type serverEntryImportTestLineReader struct {
	lines        []string
	served       int
	onLineServed func(line int)
}

func (r *serverEntryImportTestLineReader) Read(p []byte) (int, error) {
	if r.served >= len(r.lines) {
		return 0, io.EOF
	}
	line := r.lines[r.served] + "\n"
	r.served += 1
	if r.onLineServed != nil {
		r.onLineServed(r.served)
	}
	return copy(p, line), nil
}
