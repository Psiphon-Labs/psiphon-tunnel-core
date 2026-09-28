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
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/dsl"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/parameters"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	"github.com/fxamacker/cbor/v2"
)

func TestDSLAccessTokenRegistrationScheduling(t *testing.T) {
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	refreshTTL := 24 * time.Hour

	emptyRecord := new(dslAccessTokenRegistrationRecord)
	if !isDSLAccessTokenRegistrationDue(emptyRecord, now, refreshTTL) {
		t.Fatal("first registration is not due")
	}

	record := &dslAccessTokenRegistrationRecord{
		DSLAccessToken: []byte("token"),
		LastSuccessfulDSLAccessTokenRegistrationTime: now,
	}
	refreshDeadline := now.Add(refreshTTL)

	if isDSLAccessTokenRegistrationDue(record, now, refreshTTL) {
		t.Fatal("registration is due immediately after success")
	}
	if isDSLAccessTokenRegistrationDue(
		record, refreshDeadline.Add(-time.Nanosecond), refreshTTL) {

		t.Fatal("registration is due before refresh TTL")
	}
	if !isDSLAccessTokenRegistrationDue(record, refreshDeadline, refreshTTL) {
		t.Fatal("registration is not due at refresh TTL")
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

	token := []byte("opaque-token")
	successTime := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	changed, err := storeDSLAccessTokenRegistration(token, successTime)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("first token was not reported as changed")
	}

	controller := &Controller{config: config}
	got := controller.GetDSLAccessToken()
	if got != base64.RawURLEncoding.EncodeToString(token) {
		t.Fatal("unexpected stored token")
	}

	failedRefreshTime := successTime.Add(time.Hour)
	if _, err := storeDSLAccessTokenRegistration(nil, failedRefreshTime); err == nil {
		t.Fatal("empty token registration succeeded")
	}
	record, err := loadDSLAccessTokenRegistrationRecord()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(record.DSLAccessToken, token) ||
		!record.LastSuccessfulDSLAccessTokenRegistrationTime.Equal(successTime) {

		t.Fatal("failed refresh did not preserve the successful record")
	}

	CloseDataStore()
	datastoreOpen = false
	if err := OpenDataStore(config); err != nil {
		t.Fatal(err)
	}
	datastoreOpen = true

	restartedToken := controller.GetDSLAccessToken()
	if restartedToken != base64.RawURLEncoding.EncodeToString(token) {
		t.Fatal("token was not persisted across restart")
	}
}

func TestDSLAccessTokenPolicyAndNotice(t *testing.T) {
	config := newDSLAccessTokenTestConfig(t)
	if err := OpenDataStore(config); err != nil {
		t.Fatal(err)
	}
	defer CloseDataStore()

	token := []byte{0xff, 0x00, 0x80, 's', 'e', 'c', 'r', 'e', 't'}

	controller := &Controller{config: config}
	var callbacks int
	config.OnAccessToken = func(got string) {
		if got != base64.RawURLEncoding.EncodeToString(token) {
			t.Fatal("callback did not deliver the expected token")
		}
		if controller.GetDSLAccessToken() != got {
			t.Fatal("callback invoked before token persistence")
		}
		callbacks++
		// A direct callback must run outside the notice logger lock.
		NoticeLightProxyAvailable()
	}

	var notices int
	err := SetNoticeWriter(NewNoticeReceiver(func(notice []byte) {
		// Neither the raw token nor the encoding a host application would
		// receive may appear in a notice.
		if bytes.Contains(notice, token) ||
			bytes.Contains(notice, []byte(base64.RawURLEncoding.EncodeToString(token))) {
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
			persistedToken := (&Controller{config: config}).GetDSLAccessToken()
			if persistedToken != base64.RawURLEncoding.EncodeToString(token) {
				t.Fatal("notice emitted before token persistence")
			}
			notices++
		}
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer ResetNoticeWriter()

	controller.announcePersistedDSLAccessToken()
	if notices != 0 || callbacks != 0 {
		t.Fatal("missing startup token was announced")
	}
	if err := handleDSLAccessTokenRegistrationResponse(config, nil); err == nil {
		t.Fatal("empty token registration succeeded")
	}
	if notices != 0 || callbacks != 0 {
		t.Fatal("failed registration was announced")
	}

	if err := handleDSLAccessTokenRegistrationResponse(config, token); err != nil {
		t.Fatal(err)
	}
	if notices != 1 || callbacks != 1 {
		t.Fatal("new token was not announced exactly once")
	}

	if err := handleDSLAccessTokenRegistrationResponse(config, token); err != nil {
		t.Fatal(err)
	}
	if notices != 1 || callbacks != 1 {
		t.Fatal("unchanged token was announced again")
	}

	token = []byte{0xfb, 0xff, 0x00, 0x80, 0x01}
	if err := handleDSLAccessTokenRegistrationResponse(config, token); err != nil {
		t.Fatal(err)
	}
	if notices != 2 || callbacks != 2 {
		t.Fatal("changed token was not announced exactly once")
	}

	notices, callbacks = 0, 0
	controller.announcePersistedDSLAccessToken()
	if notices != 1 || callbacks != 1 {
		t.Fatal("persisted startup token was not announced")
	}

	config.EnableDSLAccessTokenRegistration = false
	got := controller.GetDSLAccessToken()
	if got != "" {
		t.Fatal("config-disabled access token was returned")
	}
	notices, callbacks = 0, 0
	controller.announcePersistedDSLAccessToken()
	if notices != 0 || callbacks != 0 {
		t.Fatal("config-disabled access token was announced")
	}

	config.EnableDSLAccessTokenRegistration = true
	err = config.SetParameters("", false, map[string]interface{}{
		parameters.DSLAccessTokenDisableRegistration: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	got = controller.GetDSLAccessToken()
	if got != "" {
		t.Fatal("tactics-disabled access token was returned")
	}
	controller.announcePersistedDSLAccessToken()
	if notices != 0 || callbacks != 0 {
		t.Fatal("tactics-disabled access token was announced")
	}

	if err := config.SetParameters("", false, nil); err != nil {
		t.Fatal(err)
	}
	config.OnAccessToken = nil
	token = []byte("token-without-callback")
	if err := handleDSLAccessTokenRegistrationResponse(config, token); err != nil {
		t.Fatal(err)
	}
	controller.announcePersistedDSLAccessToken()
	if notices != 2 || callbacks != 0 {
		t.Fatal("availability notices require a callback")
	}
}

func TestDSLAccessTokenRegistrationDisabledDuringFetch(t *testing.T) {
	config := newDSLAccessTokenTestConfig(t)
	if err := OpenDataStore(config); err != nil {
		t.Fatal(err)
	}
	defer CloseDataStore()

	if err := config.SetParameters("", false, map[string]interface{}{
		parameters.EnableDSLFetcher: true,
	}); err != nil {
		t.Fatal(err)
	}
	// Skip OSL discovery so the round trip below handles only registration.
	if err := DSLSetLastActiveOSLsTime(time.Now()); err != nil {
		t.Fatal(err)
	}

	var receivedTokens []string
	config.OnAccessToken = func(token string) {
		receivedTokens = append(receivedTokens, token)
	}
	token := []byte{0xfb, 0xff, 0x00, 0x80, 0x01}
	var notices int
	if err := SetNoticeWriter(NewNoticeReceiver(func(notice []byte) {
		if bytes.Contains(notice, token) ||
			bytes.Contains(notice, []byte(base64.RawURLEncoding.EncodeToString(token))) {

			t.Fatal("token leaked into notice")
		}
		noticeType, data, err := GetNotice(notice)
		if err != nil {
			t.Fatal(err)
		}
		if noticeType == "DSLAccessTokenAvailable" {
			if len(data) != 0 {
				t.Fatal("DSLAccessTokenAvailable notice contains data")
			}
			notices++
		}
	})); err != nil {
		t.Fatal(err)
	}
	defer ResetNoticeWriter()

	registrationRequested := false
	roundTripper := func(_ context.Context, payload []byte) ([]byte, error) {
		var relayedRequest dsl.RelayedRequest
		if err := cbor.Unmarshal(payload, &relayedRequest); err != nil {
			return nil, err
		}
		var request dsl.DiscoverServerEntriesRequest
		if err := cbor.Unmarshal(relayedRequest.Request, &request); err != nil {
			return nil, err
		}
		registrationRequested = request.DSLAccessTokenRegistration

		// Apply new tactics after the request has been sent but before its
		// response is handled, without relying on concurrent goroutine timing.
		if err := config.SetParameters("", false, map[string]interface{}{
			parameters.EnableDSLFetcher:                  true,
			parameters.DSLAccessTokenDisableRegistration: true,
		}); err != nil {
			return nil, err
		}

		response, err := protocol.CBOREncoding.Marshal(&dsl.DiscoverServerEntriesResponse{
			DSLAccessToken: token,
		})
		if err != nil {
			return nil, err
		}
		return protocol.CBOREncoding.Marshal(&dsl.RelayedResponse{Response: response})
	}
	if err := doDSLFetch(t.Context(), config, config.GetNetworkID(), true, roundTripper); err != nil {
		t.Fatal(err)
	}
	if !registrationRequested {
		t.Fatal("access token registration was not requested")
	}
	if len(receivedTokens) != 0 {
		t.Fatal("access token was delivered after tactics disabled registration")
	}
	if notices != 1 {
		t.Fatal("successful registration was not logged")
	}
	controller := &Controller{config: config}
	if controller.GetDSLAccessToken() != "" {
		t.Fatal("tactics-disabled access token was returned")
	}

	// The successful registration is still persisted and may be delivered
	// at startup once registration is enabled again.
	record, err := loadDSLAccessTokenRegistrationRecord()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(record.DSLAccessToken, token) ||
		record.LastSuccessfulDSLAccessTokenRegistrationTime.IsZero() {

		t.Fatal("successful registration was not persisted")
	}
	if err := config.SetParameters("", false, map[string]interface{}{
		parameters.EnableDSLFetcher: true,
	}); err != nil {
		t.Fatal(err)
	}
	controller.announcePersistedDSLAccessToken()
	if len(receivedTokens) != 1 || receivedTokens[0] != base64.RawURLEncoding.EncodeToString(token) {
		t.Fatal("persisted token was not delivered after re-enabling registration")
	}
}

func TestDSLAccessTokenCallbackDiagnostics(t *testing.T) {
	emitDiagnostics := GetEmitDiagnosticNotices()
	emitNetworkParameters := GetEmitNetworkParameters()
	defer SetEmitDiagnosticNotices(emitDiagnostics, emitNetworkParameters)

	for _, testCase := range []struct {
		name            string
		emitDiagnostics bool
		useNoticeFiles  bool
	}{
		{name: "writer"},
		{name: "writer-diagnostics", emitDiagnostics: true},
		{name: "files", useNoticeFiles: true},
		{name: "files-diagnostics", emitDiagnostics: true, useNoticeFiles: true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			config := newDSLAccessTokenTestConfig(t)
			if err := OpenDataStore(config); err != nil {
				t.Fatal(err)
			}
			defer CloseDataStore()
			SetEmitDiagnosticNotices(testCase.emitDiagnostics, false)

			var receivedToken string
			config.OnAccessToken = func(token string) { receivedToken = token }
			configJSON, err := json.Marshal(config)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(configJSON, []byte("OnAccessToken")) {
				t.Fatal("callback included in serialized config")
			}

			var notices bytes.Buffer
			if err := SetNoticeWriter(&notices); err != nil {
				t.Fatal(err)
			}
			defer ResetNoticeWriter()

			var noticesFilename string
			if testCase.useNoticeFiles {
				noticesFilename = filepath.Join(t.TempDir(), "notices")
				if err := setNoticeFiles("", noticesFilename, 1<<20, 1); err != nil {
					t.Fatal(err)
				}
				defer func() {
					singletonNoticeLogger.mutex.Lock()
					defer singletonNoticeLogger.mutex.Unlock()
					singletonNoticeLogger.rotatingFile.Close()
					singletonNoticeLogger.rotatingFile = nil
				}()
			}

			token := []byte{0xfb, 0xff, 0x00, 0x80, 0x01}
			if err := handleDSLAccessTokenRegistrationResponse(config, token); err != nil {
				t.Fatal(err)
			}
			if receivedToken != base64.RawURLEncoding.EncodeToString(token) {
				t.Fatal("token was not delivered to the callback")
			}
			checkNotice := func(notice []byte) {
				t.Helper()
				noticeType, data, err := GetNotice(notice)
				if err != nil {
					t.Fatal(err)
				}
				if noticeType != "DSLAccessTokenAvailable" || len(data) != 0 {
					t.Fatal("expected a token-free availability notice")
				}
				if bytes.Contains(notice, token) || bytes.Contains(notice, []byte(receivedToken)) {
					t.Fatal("access token leaked into diagnostics")
				}
			}
			checkNotice(notices.Bytes())
			if testCase.useNoticeFiles {
				diagnostics, err := os.ReadFile(noticesFilename)
				if err != nil {
					t.Fatal(err)
				}
				checkNotice(diagnostics)
			}
		})
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
	token := (&Controller{config: config}).GetDSLAccessToken()
	if token != "" {
		t.Fatal("GetDSLAccessToken did not tolerate corrupt record")
	}

	// A registration over a corrupt record succeeds, healing the
	// storeDSLAccessTokenRegistration path.
	setCorruptRecord(corruptRecords[0])
	if err := handleDSLAccessTokenRegistrationResponse(config, []byte("token")); err != nil {
		t.Fatal(err)
	}
	token = (&Controller{config: config}).GetDSLAccessToken()
	if token != base64.RawURLEncoding.EncodeToString([]byte("token")) {
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
