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
	"strconv"
	"testing"
	"time"
)

func TestDatabase(t *testing.T) {

	testDataDirName, err := ioutil.TempDir("", "psinet-test")
	if err != nil {
		t.Fatalf("TempDir failed: %s\n", err)
	}
	defer os.RemoveAll(testDataDirName)

	databaseJSON := `
    {
        "sponsors" : {
            "SPONSOR-ID" : {
                "id" : "SPONSOR-ID",
                "home_pages" : {
                    "CLIENT-REGION" : [{
                        "region" : "CLIENT-REGION",
                        "url" : "HOME-PAGE-URL?client_region=XX"
                     }],
                    "None" : [{
                        "region" : "None",
                        "url" : "DEFAULT-HOME-PAGE-URL?client_region=XX"
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
                    "ALERT-REASON-1" : ["SPONSOR-ALERT-1-ACTION-URL?client_region=XX"]
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
            {"discovery_date_range" : ["1900-01-01T00:00:00Z", "2000-01-01T00:00:00Z"], "encoded_server_entry" : "0"},
            {"discovery_date_range" : ["1900-01-01T00:00:00Z", "2000-01-01T00:00:00Z"], "encoded_server_entry" : "0"},
            {"discovery_date_range" : ["1900-01-01T00:00:00Z", "2000-01-01T00:00:00Z"], "encoded_server_entry" : "0"},
            {"discovery_date_range" : ["1900-01-01T00:00:00Z", "2000-01-01T00:00:00Z"], "encoded_server_entry" : "0"},
            {"discovery_date_range" : ["2000-01-01T00:00:00Z", "2100-01-01T00:00:00Z"], "encoded_server_entry" : "1"},
            {"discovery_date_range" : ["2000-01-01T00:00:00Z", "2100-01-01T00:00:00Z"], "encoded_server_entry" : "1"},
            {"discovery_date_range" : ["2000-01-01T00:00:00Z", "2100-01-01T00:00:00Z"], "encoded_server_entry" : "1"},
            {"discovery_date_range" : ["2000-01-01T00:00:00Z", "2100-01-01T00:00:00Z"], "encoded_server_entry" : "1"}
        ]
    }`

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
		isMobile     bool
		expectedURL  string
	}{
		{"SPONSOR-ID", "CLIENT-REGION", "65535", false, "HOME-PAGE-URL?client_region=CLIENT-REGION"},
		{"SPONSOR-ID", "UNCONFIGURED-CLIENT-REGION", "65535", false, "DEFAULT-HOME-PAGE-URL?client_region=UNCONFIGURED-CLIENT-REGION"},
		{"SPONSOR-ID", "CLIENT-REGION", "65535", true, "MOBILE-HOME-PAGE-URL?client_region=CLIENT-REGION&client_asn=65535"},
		{"SPONSOR-ID", "UNCONFIGURED-CLIENT-REGION", "65535", true, "DEFAULT-MOBILE-HOME-PAGE-URL?client_region=UNCONFIGURED-CLIENT-REGION&client_asn=65535"},
		{"UNCONFIGURED-SPONSOR-ID", "CLIENT-REGION", "65535", false, "HOME-PAGE-URL?client_region=CLIENT-REGION"},
		{"UNCONFIGURED-SPONSOR-ID", "UNCONFIGURED-CLIENT-REGION", "65535", false, "DEFAULT-HOME-PAGE-URL?client_region=UNCONFIGURED-CLIENT-REGION"},
		{"UNCONFIGURED-SPONSOR-ID", "CLIENT-REGION", "65535", true, "MOBILE-HOME-PAGE-URL?client_region=CLIENT-REGION&client_asn=65535"},
		{"UNCONFIGURED-SPONSOR-ID", "UNCONFIGURED-CLIENT-REGION", "65535", true, "DEFAULT-MOBILE-HOME-PAGE-URL?client_region=UNCONFIGURED-CLIENT-REGION&client_asn=65535"},
	}

	for _, testCase := range homePageTestCases {
		t.Run(fmt.Sprintf("%+v", testCase), func(t *testing.T) {
			homepages := db.GetHomepages(testCase.sponsorID, testCase.clientRegion, testCase.clientASN, testCase.isMobile)
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
		{"ALERT-REASON-1", "SPONSOR-ID", 1, "SPONSOR-ALERT-1-ACTION-URL?client_region=CLIENT-REGION"},
		{"ALERT-REASON-1", "UNCONFIGURED-SPONSOR-ID", 1, "DEFAULT-ALERT-1-ACTION-URL?client_region=CLIENT-REGION"},
		{"ALERT-REASON-2", "SPONSOR-ID", 1, "DEFAULT-ALERT-2-ACTION-URL?client_region=CLIENT-REGION"},
		{"ALERT-REASON-2", "UNCONFIGURED-SPONSOR-ID", 1, "DEFAULT-ALERT-2-ACTION-URL?client_region=CLIENT-REGION"},
		{"UNCONFIGURED-ALERT-REASON", "SPONSOR-ID", 0, ""},
	}

	for _, testCase := range alertActionURLTestCases {
		t.Run(fmt.Sprintf("%+v", testCase), func(t *testing.T) {
			URLs := db.GetAlertActionURLs(testCase.alertReason, testCase.sponsorID, "CLIENT-REGION", "")
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
			regexes := db.GetHttpsRequestRegexes(testCase.sponsorID)
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

	for i := 0; i < 1000; i++ {
		encodedServerEntries := db.DiscoverServers(i)
		if len(encodedServerEntries) != 1 || encodedServerEntries[0] != "1" {
			t.Fatalf("unexpected discovery server list: %+v", encodedServerEntries)
		}
	}

	if !db.IsValidServerEntryTag("SERVER-ENTRY-TAG") {
		t.Fatalf("unexpected invalid server entry tag")
	}

	if db.IsValidServerEntryTag("INVALID-SERVER-ENTRY-TAG") {
		t.Fatalf("unexpected valid server entry tag")
	}
}

func TestDiscoveryBuckets(t *testing.T) {

	checkBuckets := func(buckets [][]*DiscoveryServer, expectedServerEntries [][]int) {
		if len(buckets) != len(expectedServerEntries) {
			t.Errorf(
				"unexpected bucket count: got %d expected %d",
				len(buckets), len(expectedServerEntries))
			return
		}
		for i := 0; i < len(buckets); i++ {
			if len(buckets[i]) != len(expectedServerEntries[i]) {
				t.Errorf(
					"unexpected bucket %d size: got %d expected %d",
					i, len(buckets[i]), len(expectedServerEntries[i]))
				return
			}
			for j := 0; j < len(buckets[i]); j++ {
				expectedServerEntry := strconv.Itoa(expectedServerEntries[i][j])
				if buckets[i][j].EncodedServerEntry != expectedServerEntry {
					t.Errorf(
						"unexpected bucket %d item %d: got %s expected %s",
						i, j, buckets[i][j].EncodedServerEntry, expectedServerEntry)
					return
				}
			}
		}
	}

	// Partition test cases from:
	// http://stackoverflow.com/questions/2659900/python-slicing-a-list-into-n-nearly-equal-length-partitions

	servers := make([]*DiscoveryServer, 0)
	for i := 0; i < 105; i++ {
		servers = append(servers, &DiscoveryServer{EncodedServerEntry: strconv.Itoa(i)})
	}

	t.Run("5 servers, 5 buckets", func(t *testing.T) {
		checkBuckets(
			bucketizeServerList(servers[0:5], 5),
			[][]int{{0}, {1}, {2}, {3}, {4}})
	})

	t.Run("5 servers, 2 buckets", func(t *testing.T) {
		checkBuckets(
			bucketizeServerList(servers[0:5], 2),
			[][]int{{0, 1, 2}, {3, 4}})
	})

	t.Run("5 servers, 3 buckets", func(t *testing.T) {
		checkBuckets(
			bucketizeServerList(servers[0:5], 3),
			[][]int{{0, 1}, {2}, {3, 4}})
	})

	t.Run("105 servers, 10 buckets", func(t *testing.T) {
		checkBuckets(
			bucketizeServerList(servers, 10),
			[][]int{
				{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
				{11, 12, 13, 14, 15, 16, 17, 18, 19, 20},
				{21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31},
				{32, 33, 34, 35, 36, 37, 38, 39, 40, 41},
				{42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52},
				{53, 54, 55, 56, 57, 58, 59, 60, 61, 62},
				{63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73},
				{74, 75, 76, 77, 78, 79, 80, 81, 82, 83},
				{84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94},
				{95, 96, 97, 98, 99, 100, 101, 102, 103, 104},
			})
	})

	t.Run("repeatedly discover with fixed IP address", func(t *testing.T) {

		// For a IP address values, only one bucket should be used; with enough
		// iterations, all and only the items in a single bucket should be discovered.

		discoveredServers := make(map[string]bool)

		// discoveryValue is derived from the client's IP address and indexes the bucket;
		// a value of 0 always maps to the first bucket.
		discoveryValue := 0

		for i := 0; i < 1000; i++ {
			for _, server := range selectServers(servers, i*int(time.Hour/time.Second), discoveryValue) {
				discoveredServers[server.EncodedServerEntry] = true
			}
		}

		bucketCount := calculateBucketCount(len(servers))

		buckets := bucketizeServerList(servers, bucketCount)

		if len(buckets[0]) != len(discoveredServers) {
			t.Errorf(
				"unexpected discovered server count: got %d expected %d",
				len(discoveredServers), len(buckets[0]))
			return
		}

		for _, bucketServer := range buckets[0] {
			if _, ok := discoveredServers[bucketServer.EncodedServerEntry]; !ok {
				t.Errorf("unexpected missing discovery server: %s", bucketServer.EncodedServerEntry)
				return
			}
		}
	})

}
