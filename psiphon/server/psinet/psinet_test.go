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
                        "url" : "HOME-PAGE-URL?client_region=XX&device_region=XX&feature-x=XX&feature-y=XX"
                     }],
                    "CLIENT-REGION-ANDROID-PLATFORM" : [{
                        "region" : "CLIENT-REGION-ANDROID-PLATFORM",
                        "url" : "HOME-PAGE-URL?client_region=XX&client_platform=XX&feature-x=static&unconfigured=XX"
                     }],
                    "CLIENT-REGION-RAW-QUERY" : [{
                        "region" : "CLIENT-REGION-RAW-QUERY",
                        "url" : "RAW-HOME-PAGE-URL?raw=%%2f%%2B&feature%%2Dx=XX&feature-x=XX&feature-y=%%58%%58#fragment"
                     }],
                    "CLIENT-REGION-EXACT-MATCH" : [{
                        "region" : "CLIENT-REGION-EXACT-MATCH",
                        "url" : "EXACT-MATCH-HOME-PAGE-URL?client_region=XX&feature-x=XXL&feature-x=XX&x=XX"
                     }],
                    "CLIENT-REGION-FRAGMENT-QUERY" : [{
                        "region" : "CLIENT-REGION-FRAGMENT-QUERY",
                        "url" : "FRAGMENT-QUERY-HOME-PAGE-URL#route?client_region=XX&feature-x=XX"
                     }],
                    "None" : [{
                        "region" : "None",
                        "url" : "DEFAULT-HOME-PAGE-URL?client_region=XX&device_region=XX&feature-x=XX"
                     }]
                },
                "mobile_home_pages": {
                    "CLIENT-REGION" : [{
                        "region" : "CLIENT-REGION",
                        "url" : "MOBILE-HOME-PAGE-URL?client_region=XX&client_asn=XX&feature-y=XX"
                     }],
                    "CLIENT-REGION-IOS-PLATFORM" : [{
                        "region" : "CLIENT-REGION-IOS-PLATFORM",
                        "url" : "MOBILE-HOME-PAGE-URL?client_asn=XX&client_platform=XX"
                     }],
                    "None" : [{
                        "region" : "None",
                        "url" : "DEFAULT-MOBILE-HOME-PAGE-URL?client_region=XX&client_asn=XX&feature-x=XX&feature-y=XX"
                     }]
                },
                "alert_action_urls" : {
                    "ALERT-REASON-1" : ["SPONSOR-ALERT-1-ACTION-URL?client_region=XX&device_region=XX&client_platform=XX&feature-x=XX"]
                }
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
            "ALERT-REASON-1" : ["DEFAULT-ALERT-1-ACTION-URL?client_region=XX&feature-x=XX"],
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
		sponsorID                string
		clientRegion             string
		clientASN                string
		deviceRegion             string
		normalizedClientPlatform string
		isMobile                 bool
		clientFeatureValues      map[string]string
		expectedURL              string
	}{
		{"SPONSOR-ID", "CLIENT-REGION", "65535", "DEVICE-REGION", "CLIENT-PLATFORM", false,
			map[string]string{"feature-x": "feature-x-a", "feature-y": "feature-y-b"},
			"HOME-PAGE-URL?client_region=CLIENT-REGION&device_region=DEVICE-REGION&feature-x=feature-x-a&feature-y=feature-y-b"},
		{"SPONSOR-ID", "CLIENT-REGION", "65535", "DEVICE-REGION", "CLIENT-PLATFORM", false,
			map[string]string{"feature-x": "feature-x-a", "feature-y": ""},
			"HOME-PAGE-URL?client_region=CLIENT-REGION&device_region=DEVICE-REGION&feature-x=feature-x-a&feature-y="},
		{"SPONSOR-ID", "UNCONFIGURED-CLIENT-REGION", "65535", "DEVICE-REGION", "CLIENT-PLATFORM", false,
			map[string]string{"feature-x": ""},
			"DEFAULT-HOME-PAGE-URL?client_region=UNCONFIGURED-CLIENT-REGION&device_region=DEVICE-REGION&feature-x="},
		{"SPONSOR-ID", "CLIENT-REGION", "65535", "DEVICE-REGION", "CLIENT-PLATFORM", true,
			map[string]string{"feature-y": "feature-y-c"},
			"MOBILE-HOME-PAGE-URL?client_region=CLIENT-REGION&client_asn=65535&feature-y=feature-y-c"},
		{"SPONSOR-ID", "UNCONFIGURED-CLIENT-REGION", "65535", "DEVICE-REGION", "CLIENT-PLATFORM", true,
			map[string]string{"feature-x": "feature-x-b", "feature-y": "feature-y-a"},
			"DEFAULT-MOBILE-HOME-PAGE-URL?client_region=UNCONFIGURED-CLIENT-REGION&client_asn=65535&feature-x=feature-x-b&feature-y=feature-y-a"},
		{"UNCONFIGURED-SPONSOR-ID", "CLIENT-REGION", "65535", "DEVICE-REGION", "CLIENT-PLATFORM", false, nil,
			"HOME-PAGE-URL?client_region=CLIENT-REGION&device_region=DEVICE-REGION&feature-x=XX&feature-y=XX"},
		{"UNCONFIGURED-SPONSOR-ID", "UNCONFIGURED-CLIENT-REGION", "65535", "DEVICE-REGION", "CLIENT-PLATFORM", false,
			map[string]string{"feature-x": ""},
			"DEFAULT-HOME-PAGE-URL?client_region=UNCONFIGURED-CLIENT-REGION&device_region=DEVICE-REGION&feature-x="},
		{"UNCONFIGURED-SPONSOR-ID", "CLIENT-REGION", "65535", "DEVICE-REGION", "CLIENT-PLATFORM", true,
			map[string]string{"feature-y": ""},
			"MOBILE-HOME-PAGE-URL?client_region=CLIENT-REGION&client_asn=65535&feature-y="},
		{"UNCONFIGURED-SPONSOR-ID", "UNCONFIGURED-CLIENT-REGION", "65535", "DEVICE-REGION", "CLIENT-PLATFORM", true,
			map[string]string{"feature-x": "", "feature-y": ""},
			"DEFAULT-MOBILE-HOME-PAGE-URL?client_region=UNCONFIGURED-CLIENT-REGION&client_asn=65535&feature-x=&feature-y="},
		{"SPONSOR-ID", "CLIENT-REGION-ANDROID-PLATFORM", "65535", "DEVICE-REGION", "Android", false,
			map[string]string{"feature-x": "feature-x-a"},
			"HOME-PAGE-URL?client_region=CLIENT-REGION-ANDROID-PLATFORM&client_platform=android&feature-x=static&unconfigured=XX"},
		{"SPONSOR-ID", "CLIENT-REGION-IOS-PLATFORM", "65535", "DEVICE-REGION", "iOS", true,
			map[string]string{"feature-x": "feature-x-a", "feature-y": "feature-y-a"},
			"MOBILE-HOME-PAGE-URL?client_asn=65535&client_platform=ios"},
		{"SPONSOR-ID", "CLIENT-REGION-RAW-QUERY", "65535", "DEVICE-REGION", "CLIENT-PLATFORM", false,
			map[string]string{"feature-x": "feature-x a&b", "feature-y": "feature-y/c"},
			"RAW-HOME-PAGE-URL?raw=%2f%2B&feature%2Dx=XX&feature-x=feature-x+a%26b&feature-y=%58%58#fragment"},
		{"SPONSOR-ID", "CLIENT-REGION-EXACT-MATCH", "65535", "DEVICE-REGION", "CLIENT-PLATFORM", false,
			map[string]string{"client_region": "shadowed", "x": "x-value", "feature-x": "feature-x-value"},
			"EXACT-MATCH-HOME-PAGE-URL?client_region=CLIENT-REGION-EXACT-MATCH&feature-x=XXL&feature-x=feature-x-value&x=x-value"},
		{"SPONSOR-ID", "CLIENT-REGION-FRAGMENT-QUERY", "65535", "DEVICE-REGION", "CLIENT-PLATFORM", false,
			map[string]string{"feature-x": "feature-x-value"},
			"FRAGMENT-QUERY-HOME-PAGE-URL#route?client_region=XX&feature-x=XX"},
	}

	for _, testCase := range homePageTestCases {
		t.Run(fmt.Sprintf("%+v", testCase), func(t *testing.T) {
			homepages := db.GetHomepages(
				testCase.sponsorID,
				testCase.clientRegion,
				testCase.clientASN,
				testCase.deviceRegion,
				testCase.normalizedClientPlatform,
				testCase.isMobile,
				testCase.clientFeatureValues)
			if len(homepages) != 1 || homepages[0] != testCase.expectedURL {
				t.Fatalf("unexpected home page: %+v", homepages)
			}
		})
	}

	alertActionURLTestCases := []struct {
		alertReason         string
		sponsorID           string
		clientFeatureValues map[string]string
		expectedURLCount    int
		expectedURL         string
	}{
		{"ALERT-REASON-1", "SPONSOR-ID",
			map[string]string{"feature-x": "feature-x-a"}, 1,
			"SPONSOR-ALERT-1-ACTION-URL?client_region=CLIENT-REGION&device_region=DEVICE-REGION&client_platform=client-platform&feature-x=feature-x-a"},
		{"ALERT-REASON-1", "UNCONFIGURED-SPONSOR-ID",
			map[string]string{"feature-x": ""}, 1,
			"DEFAULT-ALERT-1-ACTION-URL?client_region=CLIENT-REGION&feature-x="},
		{"ALERT-REASON-1", "UNCONFIGURED-SPONSOR-ID", nil, 1,
			"DEFAULT-ALERT-1-ACTION-URL?client_region=CLIENT-REGION&feature-x=XX"},
		{"ALERT-REASON-2", "SPONSOR-ID",
			map[string]string{"feature-x": "feature-x-a"}, 1,
			"DEFAULT-ALERT-2-ACTION-URL?client_region=CLIENT-REGION"},
		{"ALERT-REASON-2", "UNCONFIGURED-SPONSOR-ID", nil, 1,
			"DEFAULT-ALERT-2-ACTION-URL?client_region=CLIENT-REGION"},
		{"UNCONFIGURED-ALERT-REASON", "SPONSOR-ID", nil, 0, ""},
	}

	for _, testCase := range alertActionURLTestCases {
		t.Run(fmt.Sprintf("%+v", testCase), func(t *testing.T) {
			URLs := db.GetAlertActionURLs(
				testCase.alertReason,
				testCase.sponsorID,
				"CLIENT-REGION",
				"",
				"DEVICE-REGION",
				"CLIENT-PLATFORM",
				testCase.clientFeatureValues)
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

	if !db.IsValidServerEntryTag("SERVER-ENTRY-TAG") {
		t.Fatalf("unexpected invalid server entry tag")
	}

	if db.IsValidServerEntryTag("INVALID-SERVER-ENTRY-TAG") {
		t.Fatalf("unexpected valid server entry tag")
	}
}
