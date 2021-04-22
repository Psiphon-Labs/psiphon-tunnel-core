/*
 * Copyright (c) 2016, Psiphon Inc.
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

// Package psinet implements psinet database services. The psinet database is a
// JSON-format file containing information about the Psiphon network, including
// sponsors, home pages, stats regexes, available upgrades, and other servers for
// discovery. This package also implements the Psiphon discovery algorithm.
package psinet

import (
	"encoding/json"
	"math"
	"math/rand"
	"strconv"
	"strings"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
)

const (
	MAX_DATABASE_AGE_FOR_SERVER_ENTRY_VALIDITY = 48 * time.Hour
)

// Database serves Psiphon API data requests. It's safe for
// concurrent usage. The Reload function supports hot reloading
// of Psiphon network data while the server is running.
type Database struct {
	common.ReloadableFile

	Sponsors               map[string]*Sponsor        `json:"sponsors"`
	Versions               map[string][]ClientVersion `json:"client_versions"`
	DefaultSponsorID       string                     `json:"default_sponsor_id"`
	DefaultAlertActionURLs map[string][]string        `json:"default_alert_action_urls"`
	ValidServerEntryTags   map[string]bool            `json:"valid_server_entry_tags"`
	DiscoveryServers       []*DiscoveryServer         `json:"discovery_servers"`

	fileModTime time.Time
}

type DiscoveryServer struct {
	DiscoveryDateRange []time.Time `json:"discovery_date_range"`
	EncodedServerEntry string      `json:"encoded_server_entry"`
}

type Sponsor struct {
	ID                  string                `json:"id"`
	HomePages           map[string][]HomePage `json:"home_pages"`
	MobileHomePages     map[string][]HomePage `json:"mobile_home_pages"`
	AlertActionURLs     map[string][]string   `json:"alert_action_urls"`
	HttpsRequestRegexes []HttpsRequestRegex   `json:"https_request_regexes"`
}

type ClientVersion struct {
	Version string `json:"version"`
}

type HomePage struct {
	Region string `json:"region"`
	URL    string `json:"url"`
}

type HttpsRequestRegex struct {
	Regex   string `json:"regex"`
	Replace string `json:"replace"`
}

// NewDatabase initializes a Database, calling Reload on the specified
// filename.
func NewDatabase(filename string) (*Database, error) {

	database := &Database{}

	database.ReloadableFile = common.NewReloadableFile(
		filename,
		true,
		func(fileContent []byte, fileModTime time.Time) error {
			var newDatabase *Database
			err := json.Unmarshal(fileContent, &newDatabase)
			if err != nil {
				return errors.Trace(err)
			}
			// Note: an unmarshal directly into &database would fail
			// to reset to zero value fields not present in the JSON.
			database.Sponsors = newDatabase.Sponsors
			database.Versions = newDatabase.Versions
			database.DefaultSponsorID = newDatabase.DefaultSponsorID
			database.DefaultAlertActionURLs = newDatabase.DefaultAlertActionURLs
			database.ValidServerEntryTags = newDatabase.ValidServerEntryTags
			database.DiscoveryServers = newDatabase.DiscoveryServers
			database.fileModTime = fileModTime

			return nil
		})

	_, err := database.Reload()
	if err != nil {
		return nil, errors.Trace(err)
	}

	return database, nil
}

// GetRandomizedHomepages returns a randomly ordered list of home pages
// for the specified sponsor, region, and platform.
func (db *Database) GetRandomizedHomepages(
	sponsorID, clientRegion, clientASN string, isMobilePlatform bool) []string {

	homepages := db.GetHomepages(sponsorID, clientRegion, clientASN, isMobilePlatform)
	if len(homepages) > 1 {
		shuffledHomepages := make([]string, len(homepages))
		perm := rand.Perm(len(homepages))
		for i, v := range perm {
			shuffledHomepages[v] = homepages[i]
		}
		return shuffledHomepages
	}
	return homepages
}

// GetHomepages returns a list of home pages for the specified sponsor,
// region, and platform.
func (db *Database) GetHomepages(
	sponsorID, clientRegion, clientASN string, isMobilePlatform bool) []string {

	db.ReloadableFile.RLock()
	defer db.ReloadableFile.RUnlock()

	sponsorHomePages := make([]string, 0)

	// Sponsor id does not exist: fail gracefully
	sponsor, ok := db.Sponsors[sponsorID]
	if !ok {
		sponsor, ok = db.Sponsors[db.DefaultSponsorID]
		if !ok {
			return sponsorHomePages
		}
	}

	if sponsor == nil {
		return sponsorHomePages
	}

	homePages := sponsor.HomePages

	if isMobilePlatform {
		if len(sponsor.MobileHomePages) > 0 {
			homePages = sponsor.MobileHomePages
		}
	}

	// Case: lookup succeeded and corresponding homepages found for region
	homePagesByRegion, ok := homePages[clientRegion]
	if ok {
		for _, homePage := range homePagesByRegion {
			sponsorHomePages = append(
				sponsorHomePages, homepageQueryParameterSubstitution(homePage.URL, clientRegion, clientASN))
		}
	}

	// Case: lookup failed or no corresponding homepages found for region --> use default
	if len(sponsorHomePages) == 0 {
		defaultHomePages, ok := homePages["None"]
		if ok {
			for _, homePage := range defaultHomePages {
				// client_region query parameter substitution
				sponsorHomePages = append(
					sponsorHomePages, homepageQueryParameterSubstitution(homePage.URL, clientRegion, clientASN))
			}
		}
	}

	return sponsorHomePages
}

func homepageQueryParameterSubstitution(
	url, clientRegion, clientASN string) string {

	return strings.Replace(
		strings.Replace(url, "client_region=XX", "client_region="+clientRegion, 1),
		"client_asn=XX", "client_asn="+clientASN, 1)
}

// GetAlertActionURLs returns a list of alert action URLs for the specified
// alert reason and sponsor.
func (db *Database) GetAlertActionURLs(
	alertReason, sponsorID, clientRegion, clientASN string) []string {

	db.ReloadableFile.RLock()
	defer db.ReloadableFile.RUnlock()

	// Prefer URLs from the Sponsor.AlertActionURLs. When there are no sponsor
	// URLs, then select from Database.DefaultAlertActionURLs.

	actionURLs := []string{}

	sponsor := db.Sponsors[sponsorID]
	if sponsor != nil {
		for _, URL := range sponsor.AlertActionURLs[alertReason] {
			actionURLs = append(
				actionURLs, homepageQueryParameterSubstitution(URL, clientRegion, clientASN))
		}
	}

	if len(actionURLs) == 0 {
		for _, URL := range db.DefaultAlertActionURLs[alertReason] {
			actionURLs = append(
				actionURLs, homepageQueryParameterSubstitution(URL, clientRegion, clientASN))
		}
	}

	return actionURLs
}

// GetUpgradeClientVersion returns a new client version when an upgrade is
// indicated for the specified client current version. The result is "" when
// no upgrade is available. Caller should normalize clientPlatform.
func (db *Database) GetUpgradeClientVersion(clientVersion, clientPlatform string) string {
	db.ReloadableFile.RLock()
	defer db.ReloadableFile.RUnlock()

	// Check lastest version number against client version number

	clientVersions, ok := db.Versions[clientPlatform]
	if !ok {
		return ""
	}

	if len(clientVersions) == 0 {
		return ""
	}

	// NOTE: Assumes versions list is in ascending version order
	lastVersion := clientVersions[len(clientVersions)-1].Version

	lastVersionInt, err := strconv.Atoi(lastVersion)
	if err != nil {
		return ""
	}
	clientVersionInt, err := strconv.Atoi(clientVersion)
	if err != nil {
		return ""
	}

	// Return latest version if upgrade needed
	if lastVersionInt > clientVersionInt {
		return lastVersion
	}

	return ""
}

// GetHttpsRequestRegexes returns bytes transferred stats regexes for the
// specified sponsor.
func (db *Database) GetHttpsRequestRegexes(sponsorID string) []map[string]string {
	db.ReloadableFile.RLock()
	defer db.ReloadableFile.RUnlock()

	regexes := make([]map[string]string, 0)

	sponsor, ok := db.Sponsors[sponsorID]
	if !ok {
		sponsor = db.Sponsors[db.DefaultSponsorID]
	}

	if sponsor == nil {
		return regexes
	}

	// If neither sponsorID or DefaultSponsorID were found, sponsor will be the
	// zero value of the map, an empty Sponsor struct.
	for _, sponsorRegex := range sponsor.HttpsRequestRegexes {
		regex := make(map[string]string)
		regex["replace"] = sponsorRegex.Replace
		regex["regex"] = sponsorRegex.Regex
		regexes = append(regexes, regex)
	}

	return regexes
}

// DiscoverServers selects new encoded server entries to be "discovered" by
// the client, using the discoveryValue -- a function of the client's IP
// address -- as the input into the discovery algorithm.
func (db *Database) DiscoverServers(discoveryValue int) []string {
	db.ReloadableFile.RLock()
	defer db.ReloadableFile.RUnlock()

	var servers []*DiscoveryServer

	discoveryDate := time.Now().UTC()
	candidateServers := make([]*DiscoveryServer, 0)

	for _, server := range db.DiscoveryServers {
		// All servers that are discoverable on this day are eligible for discovery
		if len(server.DiscoveryDateRange) == 2 &&
			discoveryDate.After(server.DiscoveryDateRange[0]) &&
			discoveryDate.Before(server.DiscoveryDateRange[1]) {

			candidateServers = append(candidateServers, server)
		}
	}

	timeInSeconds := int(discoveryDate.Unix())
	servers = selectServers(candidateServers, timeInSeconds, discoveryValue)

	encodedServerEntries := make([]string, 0)

	for _, server := range servers {
		encodedServerEntries = append(encodedServerEntries, server.EncodedServerEntry)
	}

	return encodedServerEntries
}

// Combine client IP address and time-of-day strategies to give out different
// discovery servers to different clients. The aim is to achieve defense against
// enumerability. We also want to achieve a degree of load balancing clients
// and these strategies are expected to have reasonably random distribution,
// even for a cluster of users coming from the same network.
//
// We only select one server: multiple results makes enumeration easier; the
// strategies have a built-in load balancing effect; and date range discoverability
// means a client will actually learn more servers later even if they happen to
// always pick the same result at this point.
//
// This is a blended strategy: as long as there are enough servers to pick from,
// both aspects determine which server is selected. IP address is given the
// priority: if there are only a couple of servers, for example, IP address alone
// determines the outcome.
func selectServers(
	servers []*DiscoveryServer, timeInSeconds, discoveryValue int) []*DiscoveryServer {

	TIME_GRANULARITY := 3600

	if len(servers) == 0 {
		return nil
	}

	// Time truncated to an hour
	timeStrategyValue := timeInSeconds / TIME_GRANULARITY

	// Divide servers into buckets. The bucket count is chosen such that the number
	// of buckets and the number of items in each bucket are close (using sqrt).
	// IP address selects the bucket, time selects the item in the bucket.

	// NOTE: this code assumes that the range of possible timeStrategyValues
	// and discoveryValues are sufficient to index to all bucket items.

	bucketCount := calculateBucketCount(len(servers))

	buckets := bucketizeServerList(servers, bucketCount)

	if len(buckets) == 0 {
		return nil
	}

	bucket := buckets[discoveryValue%len(buckets)]

	if len(bucket) == 0 {
		return nil
	}

	server := bucket[timeStrategyValue%len(bucket)]

	serverList := make([]*DiscoveryServer, 1)
	serverList[0] = server

	return serverList
}

// Number of buckets such that first strategy picks among about the same number
// of choices as the second strategy. Gives an edge to the "outer" strategy.
func calculateBucketCount(length int) int {
	return int(math.Ceil(math.Sqrt(float64(length))))
}

// bucketizeServerList creates nearly equal sized slices of the input list.
func bucketizeServerList(servers []*DiscoveryServer, bucketCount int) [][]*DiscoveryServer {

	// This code creates the same partitions as legacy servers:
	// https://bitbucket.org/psiphon/psiphon-circumvention-system/src/03bc1a7e51e7c85a816e370bb3a6c755fd9c6fee/Automation/psi_ops_discovery.py
	//
	// Both use the same algorithm from:
	// http://stackoverflow.com/questions/2659900/python-slicing-a-list-into-n-nearly-equal-length-partitions

	// TODO: this partition is constant for fixed Database content, so it could
	// be done once and cached in the Database ReloadableFile reloadAction.

	buckets := make([][]*DiscoveryServer, bucketCount)

	division := float64(len(servers)) / float64(bucketCount)

	for i := 0; i < bucketCount; i++ {
		start := int((division * float64(i)) + 0.5)
		end := int((division * (float64(i) + 1)) + 0.5)
		buckets[i] = servers[start:end]
	}

	return buckets
}

// IsValidServerEntryTag checks if the specified server entry tag is valid.
func (db *Database) IsValidServerEntryTag(serverEntryTag string) bool {
	db.ReloadableFile.RLock()
	defer db.ReloadableFile.RUnlock()

	// Default to "valid" if the valid list is unexpectedly empty or stale. This
	// helps prevent premature client-side server-entry pruning when there is an
	// issue with updating the database.

	if len(db.ValidServerEntryTags) == 0 ||
		db.fileModTime.Add(MAX_DATABASE_AGE_FOR_SERVER_ENTRY_VALIDITY).Before(time.Now()) {
		return true
	}

	// The tag must be in the map and have the value "true".
	return db.ValidServerEntryTags[serverEntryTag]
}
