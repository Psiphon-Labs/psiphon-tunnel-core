/*
 * Copyright (c) 2017, Psiphon Inc.
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

package psinet

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
)

func TestDatabase(t *testing.T) {

	testDataDirName, err := ioutil.TempDir("", "psinet-test")
	if err != nil {
		t.Fatalf("TempDir failed: %s\n", err)
	}
	defer os.RemoveAll(testDataDirName)

	server1, err := protocol.EncodeServerEntry(&protocol.ServerEntry{
		IpAddress: "1",
	})
	if err != nil {
		t.Fatalf("EncodeServerEntry failed: %s\n", err)
	}

	server2, err := protocol.EncodeServerEntry(&protocol.ServerEntry{
		IpAddress: "2",
	})
	if err != nil {
		t.Fatalf("EncodeServerEntry failed: %s\n", err)
	}

	databaseJSON := fmt.Sprintf(`
    {
        "sponsors" : {
            "SPONSOR-ID" : {
                "id" : "SPONSOR-ID",
                "home_pages" : {
                    "CLIENT-REGION" : [{
                        "region" : "CLIENT-REGION",
                        "url" : "HOME-PAGE-URL?client_region=XX&device_region=XX"
                     }],
                    "None" : [{
                        "region" : "None",
                        "url" : "DEFAULT-HOME-PAGE-URL?client_region=XX&device_region=XX"
                     }]
                },
                "mobile_home_pages": {
                    "CLIENT-REGION" : [{
                        "region" : "CLIENT-REGION",
                        "url" : "MOBILE-HOME-PAGE-URL?client_region=XX&client_asn=XX"
                     }],
                    "None" : [{
                        "region" : "None",
                        "url" : "DEFAULT-MOBILE-HOME-PAGE-URL?client_region=XX&client_asn=XX"
                     }]
                },
                "alert_action_urls" : {
                    "ALERT-REASON-1" : ["SPONSOR-ALERT-1-ACTION-URL?client_region=XX&device_region=XX"]
                },
                "https_request_regexes" : [{
                    "regex" : "REGEX-VALUE",
                    "replace" : "REPLACE-VALUE"
                }]
            }
        },

        "client_versions" : {
            "CLIENT-PLATFORM" : [
                {"version" : "1"},
                {"version" : "2"}
            ]
        },

        "default_sponsor_id" : "SPONSOR-ID",

        "default_alert_action_urls" : {
            "ALERT-REASON-1" : ["DEFAULT-ALERT-1-ACTION-URL?client_region=XX"],
            "ALERT-REASON-2" : ["DEFAULT-ALERT-2-ACTION-URL?client_region=XX"]
        },

        "valid_server_entry_tags" : {
            "SERVER-ENTRY-TAG" : true
        },

        "discovery_servers" : [
            {"discovery_date_range" : ["1900-01-01T00:00:00Z", "2000-01-01T00:00:00Z"], "encoded_server_entry" : "%s"},
            {"discovery_date_range" : ["2000-01-01T00:00:00Z", "2100-01-01T00:00:00Z"], "encoded_server_entry" : "%s"}
        ]
    }`, server1, server2)

	filename := filepath.Join(testDataDirName, "psinet.json")

	err = ioutil.WriteFile(filename, []byte(databaseJSON), 0600)
	if err != nil {
		t.Fatalf("WriteFile failed: %s", err)
	}

	db, err := NewDatabase(filename)
	if err != nil {
		t.Fatalf("NewDatabase failed: %s", err)
	}

	homePageTestCases := []struct {
		sponsorID    string
		clientRegion string
		clientASN    string
		deviceRegion string
		isMobile     bool
		expectedURL  string
	}{
		{"SPONSOR-ID", "CLIENT-REGION", "65535", "DEVICE-REGION", false, "HOME-PAGE-URL?client_region=CLIENT-REGION&device_region=DEVICE-REGION"},
		{"SPONSOR-ID", "UNCONFIGURED-CLIENT-REGION", "65535", "DEVICE-REGION", false, "DEFAULT-HOME-PAGE-URL?client_region=UNCONFIGURED-CLIENT-REGION&device_region=DEVICE-REGION"},
		{"SPONSOR-ID", "CLIENT-REGION", "65535", "DEVICE-REGION", true, "MOBILE-HOME-PAGE-URL?client_region=CLIENT-REGION&client_asn=65535"},
		{"SPONSOR-ID", "UNCONFIGURED-CLIENT-REGION", "65535", "DEVICE-REGION", true, "DEFAULT-MOBILE-HOME-PAGE-URL?client_region=UNCONFIGURED-CLIENT-REGION&client_asn=65535"},
		{"UNCONFIGURED-SPONSOR-ID", "CLIENT-REGION", "65535", "DEVICE-REGION", false, "HOME-PAGE-URL?client_region=CLIENT-REGION&device_region=DEVICE-REGION"},
		{"UNCONFIGURED-SPONSOR-ID", "UNCONFIGURED-CLIENT-REGION", "65535", "DEVICE-REGION", false, "DEFAULT-HOME-PAGE-URL?client_region=UNCONFIGURED-CLIENT-REGION&device_region=DEVICE-REGION"},
		{"UNCONFIGURED-SPONSOR-ID", "CLIENT-REGION", "65535", "DEVICE-REGION", true, "MOBILE-HOME-PAGE-URL?client_region=CLIENT-REGION&client_asn=65535"},
		{"UNCONFIGURED-SPONSOR-ID", "UNCONFIGURED-CLIENT-REGION", "65535", "DEVICE-REGION", true, "DEFAULT-MOBILE-HOME-PAGE-URL?client_region=UNCONFIGURED-CLIENT-REGION&client_asn=65535"},
	}

	for _, testCase := range homePageTestCases {
		t.Run(fmt.Sprintf("%+v", testCase), func(t *testing.T) {
			homepages := db.GetHomepages(testCase.sponsorID, testCase.clientRegion, testCase.clientASN, testCase.deviceRegion, testCase.isMobile)
			if len(homepages) != 1 || homepages[0] != testCase.expectedURL {
				t.Fatalf("unexpected home page: %+v", homepages)
			}
		})
	}

	alertActionURLTestCases := []struct {
		alertReason      string
		sponsorID        string
		expectedURLCount int
		expectedURL      string
	}{
		{"ALERT-REASON-1", "SPONSOR-ID", 1, "SPONSOR-ALERT-1-ACTION-URL?client_region=CLIENT-REGION&device_region=DEVICE-REGION"},
		{"ALERT-REASON-1", "UNCONFIGURED-SPONSOR-ID", 1, "DEFAULT-ALERT-1-ACTION-URL?client_region=CLIENT-REGION"},
		{"ALERT-REASON-2", "SPONSOR-ID", 1, "DEFAULT-ALERT-2-ACTION-URL?client_region=CLIENT-REGION"},
		{"ALERT-REASON-2", "UNCONFIGURED-SPONSOR-ID", 1, "DEFAULT-ALERT-2-ACTION-URL?client_region=CLIENT-REGION"},
		{"UNCONFIGURED-ALERT-REASON", "SPONSOR-ID", 0, ""},
	}

	for _, testCase := range alertActionURLTestCases {
		t.Run(fmt.Sprintf("%+v", testCase), func(t *testing.T) {
			URLs := db.GetAlertActionURLs(testCase.alertReason, testCase.sponsorID, "CLIENT-REGION", "", "DEVICE-REGION")
			if len(URLs) != testCase.expectedURLCount || (len(URLs) > 0 && URLs[0] != testCase.expectedURL) {
				t.Fatalf("unexpected URLs: %d %+v, %+v", testCase.expectedURLCount, testCase.expectedURL, URLs)
			}
		})
	}

	versionTestCases := []struct {
		currentClientVersion         string
		clientPlatform               string
		expectedUpgradeClientVersion string
	}{
		{"0", "CLIENT-PLATFORM", "2"},
		{"1", "CLIENT-PLATFORM", "2"},
		{"2", "CLIENT-PLATFORM", ""},
		{"3", "CLIENT-PLATFORM", ""},
		{"2", "UNCONFIGURED-CLIENT-PLATFORM", ""},
	}

	for _, testCase := range versionTestCases {
		t.Run(fmt.Sprintf("%+v", testCase), func(t *testing.T) {
			upgradeVersion := db.GetUpgradeClientVersion(testCase.currentClientVersion, testCase.clientPlatform)
			if upgradeVersion != testCase.expectedUpgradeClientVersion {
				t.Fatalf("unexpected upgrade version: %s", upgradeVersion)
			}
		})
	}

	httpsRegexTestCases := []struct {
		sponsorID            string
		expectedRegexValue   string
		expectedReplaceValue string
	}{
		{"SPONSOR-ID", "REGEX-VALUE", "REPLACE-VALUE"},
		{"UNCONFIGURED-SPONSOR-ID", "REGEX-VALUE", "REPLACE-VALUE"},
	}

	for _, testCase := range httpsRegexTestCases {
		t.Run(fmt.Sprintf("%+v", testCase), func(t *testing.T) {
			regexes, checksum := db.GetHttpsRequestRegexes(testCase.sponsorID)
			if !bytes.Equal(checksum, db.GetDomainBytesChecksum(testCase.sponsorID)) {
				t.Fatalf("unexpected checksum: %+v", checksum)
			}
			var regexValue, replaceValue string
			ok := false
			if len(regexes) == 1 && len(regexes[0]) == 2 {
				regexValue, ok = regexes[0]["regex"]
				if ok {
					replaceValue, ok = regexes[0]["replace"]
				}
			}
			if !ok || regexValue != testCase.expectedRegexValue || replaceValue != testCase.expectedReplaceValue {
				t.Fatalf("unexpected regexes: %+v", regexes)
			}
		})
	}

	if !db.IsValidServerEntryTag("SERVER-ENTRY-TAG") {
		t.Fatalf("unexpected invalid server entry tag")
	}

	if db.IsValidServerEntryTag("INVALID-SERVER-ENTRY-TAG") {
		t.Fatalf("unexpected valid server entry tag")
	}
}
