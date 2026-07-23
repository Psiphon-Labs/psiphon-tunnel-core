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

func TestDSLTokenRegistrationScheduling(t *testing.T) {
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	refreshTTL := 24 * time.Hour

	emptyRecord := new(dslTokenRegistrationRecord)
	if !isDSLTokenRegistrationDue(emptyRecord, now, refreshTTL) {
		t.Fatal("first registration is not due")
	}

	record := &dslTokenRegistrationRecord{
		DSLToken:                               "dG9rZW4",
		LastSuccessfulDSLTokenRegistrationTime: now,
	}
	refreshDeadline := now.Add(
		jitterDSLTokenRegistrationRefreshTTL(refreshTTL, record.DSLToken))

	if isDSLTokenRegistrationDue(record, now, refreshTTL) {
		t.Fatal("registration is due immediately after success")
	}
	if isDSLTokenRegistrationDue(
		record, refreshDeadline.Add(-time.Nanosecond), refreshTTL) {

		t.Fatal("registration is due before jittered refresh TTL")
	}
	if !isDSLTokenRegistrationDue(record, refreshDeadline, refreshTTL) {
		t.Fatal("registration is not due at jittered refresh TTL")
	}
}

func TestDSLTokenRegistrationRefreshTTLJitter(t *testing.T) {
	refreshTTL := 24 * time.Hour
	first := jitterDSLTokenRegistrationRefreshTTL(refreshTTL, "dG9rZW4")
	second := jitterDSLTokenRegistrationRefreshTTL(refreshTTL, "dG9rZW4")
	other := jitterDSLTokenRegistrationRefreshTTL(refreshTTL, "b3RoZXItdG9rZW4")

	if first != second {
		t.Fatalf("jitter is not deterministic: %s != %s", first, second)
	}
	if first == other {
		t.Fatal("jitter does not vary by token")
	}
	minimum := time.Duration(float64(refreshTTL) * (1 - dslTokenRegistrationRefreshTTLJitter))
	maximum := time.Duration(float64(refreshTTL) * (1 + dslTokenRegistrationRefreshTTLJitter))
	if first < minimum || first > maximum || other < minimum || other > maximum {
		t.Fatal("jitter is outside the configured range")
	}
}

func TestDSLTokenRegistrationPersistence(t *testing.T) {
	config := newDSLTokenTestConfig(t)
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
	changed, err := storeDSLTokenRegistration(token, successTime)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("first token was not reported as changed")
	}

	got, err := GetDSLToken()
	if err != nil {
		t.Fatal(err)
	}
	if got != token {
		t.Fatal("unexpected stored token")
	}

	failedRefreshTime := successTime.Add(time.Hour)
	if _, err := storeDSLTokenRegistration("", failedRefreshTime); err == nil {
		t.Fatal("empty token registration succeeded")
	}
	record, err := loadDSLTokenRegistrationRecord()
	if err != nil {
		t.Fatal(err)
	}
	if record.DSLToken != token ||
		!record.LastSuccessfulDSLTokenRegistrationTime.Equal(successTime) {

		t.Fatal("failed refresh did not preserve the successful record")
	}

	CloseDataStore()
	datastoreOpen = false
	if err := OpenDataStore(config); err != nil {
		t.Fatal(err)
	}
	datastoreOpen = true

	restartedToken, err := GetDSLToken()
	if err != nil {
		t.Fatal(err)
	}
	if restartedToken != token {
		t.Fatal("token was not persisted across restart")
	}
}

func TestDSLTokenNoticeAfterPersistence(t *testing.T) {
	config := newDSLTokenTestConfig(t)
	config.EnableDSLTokenRegistration = true
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
		if value.NoticeType == "DSLTokenAvailable" {
			if len(value.Data) != 0 {
				t.Fatal("DSLTokenAvailable notice contains data")
			}
			persistedToken, err := GetDSLToken()
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
	if err := controller.handleDSLTokenRegistrationResponse(token); err != nil {
		t.Fatal(err)
	}
	if notices != 1 {
		t.Fatal("new token was not announced exactly once")
	}

	if err := controller.handleDSLTokenRegistrationResponse(token); err != nil {
		t.Fatal(err)
	}
	if notices != 1 {
		t.Fatal("unchanged token was announced again")
	}

	notices = 0
	controller.announcePersistedDSLToken()
	if notices != 1 {
		t.Fatal("persisted startup token was not announced")
	}
}

func newDSLTokenTestConfig(t *testing.T) *Config {
	t.Helper()
	config, err := LoadConfig([]byte(`{
		"SponsorId": "0000000000000000",
		"PropagationChannelId": "0000000000000000"
	}`))
	if err != nil {
		t.Fatal(err)
	}
	config.DataRootDirectory = t.TempDir()
	if err := config.Commit(false); err != nil {
		t.Fatal(err)
	}
	return config
}
