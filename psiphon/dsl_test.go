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
 */

package psiphon

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"
)

func TestDSLAccessTokenRegistrationScheduling(t *testing.T) {
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	refreshTTL := 24 * time.Hour

	emptyRecord := new(dslAccessTokenRegistrationRecord)
	if !isDSLAccessTokenRegistrationDue(emptyRecord, now, refreshTTL) {
		t.Fatal("first registration is not due")
	}

	record := &dslAccessTokenRegistrationRecord{
		DSLAccessToken: "dG9rZW4",
		LastSuccessfulDSLAccessTokenRegistrationTime: now,
	}
	refreshDeadline := now.Add(
		jitterDSLAccessTokenRegistrationRefreshTTL(refreshTTL, record.DSLAccessToken))

	if isDSLAccessTokenRegistrationDue(record, now, refreshTTL) {
		t.Fatal("registration is due immediately after success")
	}
	if isDSLAccessTokenRegistrationDue(
		record, refreshDeadline.Add(-time.Nanosecond), refreshTTL) {

		t.Fatal("registration is due before jittered refresh TTL")
	}
	if !isDSLAccessTokenRegistrationDue(record, refreshDeadline, refreshTTL) {
		t.Fatal("registration is not due at jittered refresh TTL")
	}
}

func TestDSLAccessTokenRegistrationRefreshTTLJitter(t *testing.T) {
	refreshTTL := 24 * time.Hour
	first := jitterDSLAccessTokenRegistrationRefreshTTL(refreshTTL, "dG9rZW4")
	second := jitterDSLAccessTokenRegistrationRefreshTTL(refreshTTL, "dG9rZW4")
	other := jitterDSLAccessTokenRegistrationRefreshTTL(refreshTTL, "b3RoZXItdG9rZW4")

	if first != second {
		t.Fatalf("jitter is not deterministic: %s != %s", first, second)
	}
	if first == other {
		t.Fatal("jitter does not vary by access token")
	}
	minimum := time.Duration(float64(refreshTTL) * (1 - dslAccessTokenRegistrationRefreshTTLJitter))
	maximum := time.Duration(float64(refreshTTL) * (1 + dslAccessTokenRegistrationRefreshTTLJitter))
	if first < minimum || first > maximum || other < minimum || other > maximum {
		t.Fatal("jitter is outside the configured range")
	}
}

func TestDSLAccessTokenRegistrationPersistence(t *testing.T) {
	config := newDSLAccessTokenTestConfig(t)
	if err := OpenDataStore(config); err != nil {
		t.Fatal(err)
	}
	datastoreOpen := true
	defer func() {
		if datastoreOpen {
			CloseDataStore()
		}
	}()

	token := "b3BhcXVlLXRva2Vu"
	successTime := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	changed, err := storeDSLAccessTokenRegistration(token, successTime)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("first token was not reported as changed")
	}

	got, err := GetDSLAccessToken()
	if err != nil {
		t.Fatal(err)
	}
	if got != token {
		t.Fatal("unexpected stored token")
	}

	failedRefreshTime := successTime.Add(time.Hour)
	if _, err := storeDSLAccessTokenRegistration("", failedRefreshTime); err == nil {
		t.Fatal("empty token registration succeeded")
	}
	record, err := loadDSLAccessTokenRegistrationRecord()
	if err != nil {
		t.Fatal(err)
	}
	if record.DSLAccessToken != token ||
		!record.LastSuccessfulDSLAccessTokenRegistrationTime.Equal(successTime) {

		t.Fatal("failed refresh did not preserve the successful record")
	}

	CloseDataStore()
	datastoreOpen = false
	if err := OpenDataStore(config); err != nil {
		t.Fatal(err)
	}
	datastoreOpen = true

	restartedToken, err := GetDSLAccessToken()
	if err != nil {
		t.Fatal(err)
	}
	if restartedToken != token {
		t.Fatal("token was not persisted across restart")
	}
}

func TestDSLAccessTokenNoticeAfterPersistence(t *testing.T) {
	config := newDSLAccessTokenTestConfig(t)
	if err := OpenDataStore(config); err != nil {
		t.Fatal(err)
	}
	defer CloseDataStore()

	token := "-_8Ab3BhcXVlLXNlY3JldC10b2tlbg"

	var notices int
	err := SetNoticeWriter(NewNoticeReceiver(func(notice []byte) {
		if bytes.Contains(notice, []byte(token)) {
			t.Fatal("token leaked into notice")
		}
		var value struct {
			NoticeType string         `json:"noticeType"`
			Data       map[string]any `json:"data"`
		}
		if err := json.Unmarshal(notice, &value); err != nil {
			t.Fatal(err)
		}
		if value.NoticeType == "DSLAccessTokenAvailable" {
			if len(value.Data) != 0 {
				t.Fatal("DSLAccessTokenAvailable notice contains data")
			}
			persistedToken, err := GetDSLAccessToken()
			if err != nil {
				t.Fatal(err)
			}
			if persistedToken != token {
				t.Fatal("notice emitted before token persistence")
			}
			notices++
		}
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer ResetNoticeWriter()

	controller := &Controller{config: config}
	if err := handleDSLAccessTokenRegistrationResponse(token); err != nil {
		t.Fatal(err)
	}
	if notices != 1 {
		t.Fatal("new token was not announced exactly once")
	}

	if err := handleDSLAccessTokenRegistrationResponse(token); err != nil {
		t.Fatal(err)
	}
	if notices != 1 {
		t.Fatal("unchanged token was announced again")
	}

	notices = 0
	controller.announcePersistedDSLAccessToken()
	if notices != 1 {
		t.Fatal("persisted startup token was not announced")
	}
}

func TestDSLAccessTokenRegistrationCorruptRecordSelfHeal(t *testing.T) {
	config := newDSLAccessTokenTestConfig(t)
	if err := OpenDataStore(config); err != nil {
		t.Fatal(err)
	}
	defer CloseDataStore()

	corruptRecords := [][]byte{
		[]byte(`{"DSLAccessToken": 42, "trailing garbage`),
		[]byte(``),
		[]byte(`"just a string"`),
	}

	// Assert no corrupt record content leaks into warning notices.
	err := SetNoticeWriter(NewNoticeReceiver(func(notice []byte) {
		if bytes.Contains(notice, []byte("trailing garbage")) {
			t.Fatal("corrupt record content leaked into notice")
		}
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer ResetNoticeWriter()

	setCorruptRecord := func(corrupt []byte) {
		if err := setBucketValue(
			datastoreKeyValueBucket,
			datastoreDSLAccessTokenRegistrationKey,
			corrupt); err != nil {
			t.Fatal(err)
		}
	}

	for _, corrupt := range corruptRecords {

		setCorruptRecord(corrupt)

		// The load succeeds, degrading to a zero-value record, so the
		// doDSLFetch scheduling path proceeds.
		record, err := loadDSLAccessTokenRegistrationRecord()
		if err != nil {
			t.Fatal(err)
		}

		// Registration is considered due.
		if !isDSLAccessTokenRegistrationDue(record, time.Now(), 24*time.Hour) {
			t.Fatal("registration not due after corrupt record self-heal")
		}

		// The corrupt record was deleted.
		value, err := copyBucketValue(
			datastoreKeyValueBucket, datastoreDSLAccessTokenRegistrationKey)
		if err != nil {
			t.Fatal(err)
		}
		if value != nil {
			t.Fatal("corrupt record was not deleted")
		}
	}

	// A valid, zero-value record is not treated as corrupt.
	setCorruptRecord([]byte(`{}`))
	record, err := loadDSLAccessTokenRegistrationRecord()
	if err != nil {
		t.Fatal(err)
	}
	if !isDSLAccessTokenRegistrationDue(record, time.Now(), 24*time.Hour) {
		t.Fatal("registration not due for zero-value record")
	}
	value, err := copyBucketValue(
		datastoreKeyValueBucket, datastoreDSLAccessTokenRegistrationKey)
	if err != nil {
		t.Fatal(err)
	}
	if value == nil {
		t.Fatal("valid zero-value record was deleted")
	}

	// GetDSLAccessToken degrades to "no token", not an error (mobile binding
	// path).
	setCorruptRecord(corruptRecords[0])
	token, err := GetDSLAccessToken()
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		t.Fatal("GetDSLAccessToken did not tolerate corrupt record")
	}

	// A registration over a corrupt record succeeds, healing the
	// storeDSLAccessTokenRegistration path.
	setCorruptRecord(corruptRecords[0])
	if err := handleDSLAccessTokenRegistrationResponse("dG9rZW4"); err != nil {
		t.Fatal(err)
	}
	token, err = GetDSLAccessToken()
	if err != nil {
		t.Fatal(err)
	}
	if token != "dG9rZW4" {
		t.Fatal("registration did not overwrite corrupt record")
	}
}

func newDSLAccessTokenTestConfig(t *testing.T) *Config {
	t.Helper()
	config, err := LoadConfig([]byte(`{
		"SponsorId": "0000000000000000",
		"PropagationChannelId": "0000000000000000"
	}`))
	if err != nil {
		t.Fatal(err)
	}
	config.DataRootDirectory = t.TempDir()
	config.EnableDSLAccessTokenRegistration = true
	if err := config.Commit(false); err != nil {
		t.Fatal(err)
	}
	return config
}
