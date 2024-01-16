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
// discovery.
package psinet

import (
	"crypto/md5"
	"encoding/json"
	"math/rand"
	"strconv"
	"strings"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
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

	IPAddress string `json:"-"`
}

// consistent.Member implementation.
// TODO: move to discovery package. Requires bridging to a new type.
func (s *DiscoveryServer) String() string {
	// Other options:
	// - Tag
	// - EncodedServerEntry
	// - ...
	return s.IPAddress
}

type Sponsor struct {
	ID                  string                `json:"id"`
	HomePages           map[string][]HomePage `json:"home_pages"`
	MobileHomePages     map[string][]HomePage `json:"mobile_home_pages"`
	AlertActionURLs     map[string][]string   `json:"alert_action_urls"`
	HttpsRequestRegexes []HttpsRequestRegex   `json:"https_request_regexes"`

	domainBytesChecksum []byte `json:"-"`
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

			for _, sponsor := range database.Sponsors {

				value, err := json.Marshal(sponsor.HttpsRequestRegexes)
				if err != nil {
					return errors.Trace(err)
				}

				// MD5 hash is used solely as a data checksum and not for any
				// security purpose.
				checksum := md5.Sum(value)
				sponsor.domainBytesChecksum = checksum[:]
			}

			// Decode each encoded server entry for its IP address, which is used in
			// the consistent.Member implementation in the discovery package.
			//
			// Also ensure that no servers share the same IP address, which is
			// a requirement of consistent hashing discovery; otherwise it will
			// panic in the underlying buraksezer/consistent package.
			serverIPToDiagnosticID := make(map[string]string)
			for i, server := range database.DiscoveryServers {

				serverEntry, err := protocol.DecodeServerEntry(server.EncodedServerEntry, "", "")
				if err != nil {
					return errors.Trace(err)
				}
				if serverEntry.IpAddress == "" {
					return errors.Tracef("unexpected empty IP address in server entry for %s ", serverEntry.GetDiagnosticID())
				}

				if diagnosticID, ok := serverIPToDiagnosticID[serverEntry.IpAddress]; ok {
					return errors.Tracef("unexpected %s and %s shared the same IP address", diagnosticID, serverEntry.GetDiagnosticID())
				} else {
					serverIPToDiagnosticID[serverEntry.IpAddress] = serverEntry.GetDiagnosticID()
				}

				database.DiscoveryServers[i].IPAddress = serverEntry.IpAddress
			}

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
	sponsorID, clientRegion, clientASN, deviceRegion string, isMobilePlatform bool) []string {

	homepages := db.GetHomepages(sponsorID, clientRegion, clientASN, deviceRegion, isMobilePlatform)
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
	sponsorID, clientRegion, clientASN, deviceRegion string, isMobilePlatform bool) []string {

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
				sponsorHomePages, homepageQueryParameterSubstitution(
					homePage.URL, clientRegion, clientASN, deviceRegion))
		}
	}

	// Case: lookup failed or no corresponding homepages found for region --> use default
	if len(sponsorHomePages) == 0 {
		defaultHomePages, ok := homePages["None"]
		if ok {
			for _, homePage := range defaultHomePages {
				// client_region query parameter substitution
				sponsorHomePages = append(
					sponsorHomePages, homepageQueryParameterSubstitution(
						homePage.URL, clientRegion, clientASN, deviceRegion))
			}
		}
	}

	return sponsorHomePages
}

func homepageQueryParameterSubstitution(
	url, clientRegion, clientASN, deviceRegion string) string {

	url = strings.Replace(url, "client_region=XX", "client_region="+clientRegion, 1)
	url = strings.Replace(url, "client_asn=XX", "client_asn="+clientASN, 1)
	url = strings.Replace(url, "device_region=XX", "device_region="+deviceRegion, 1)
	return url
}

// GetAlertActionURLs returns a list of alert action URLs for the specified
// alert reason and sponsor.
func (db *Database) GetAlertActionURLs(
	alertReason, sponsorID, clientRegion, clientASN, deviceRegion string) []string {

	db.ReloadableFile.RLock()
	defer db.ReloadableFile.RUnlock()

	// Prefer URLs from the Sponsor.AlertActionURLs. When there are no sponsor
	// URLs, then select from Database.DefaultAlertActionURLs.

	actionURLs := []string{}

	sponsor := db.Sponsors[sponsorID]
	if sponsor != nil {
		for _, URL := range sponsor.AlertActionURLs[alertReason] {
			actionURLs = append(
				actionURLs, homepageQueryParameterSubstitution(
					URL, clientRegion, clientASN, deviceRegion))
		}
	}

	if len(actionURLs) == 0 {
		for _, URL := range db.DefaultAlertActionURLs[alertReason] {
			actionURLs = append(
				actionURLs, homepageQueryParameterSubstitution(
					URL, clientRegion, clientASN, deviceRegion))
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

// GetHttpsRequestRegexes returns bytes transferred stats regexes and the
// associated checksum for the specified sponsor. The checksum may be nil.
func (db *Database) GetHttpsRequestRegexes(sponsorID string) ([]map[string]string, []byte) {
	db.ReloadableFile.RLock()
	defer db.ReloadableFile.RUnlock()

	regexes := make([]map[string]string, 0)

	sponsor, ok := db.Sponsors[sponsorID]
	if !ok {
		sponsor = db.Sponsors[db.DefaultSponsorID]
	}

	if sponsor == nil {
		return regexes, nil
	}

	// If neither sponsorID or DefaultSponsorID were found, sponsor will be the
	// zero value of the map, an empty Sponsor struct.
	for _, sponsorRegex := range sponsor.HttpsRequestRegexes {
		regex := make(map[string]string)
		regex["replace"] = sponsorRegex.Replace
		regex["regex"] = sponsorRegex.Regex
		regexes = append(regexes, regex)
	}

	return regexes, sponsor.domainBytesChecksum
}

// GetDomainBytesChecksum returns the bytes transferred stats regexes
// checksum for the specified sponsor. The checksum may be nil.
func (db *Database) GetDomainBytesChecksum(sponsorID string) []byte {
	db.ReloadableFile.RLock()
	defer db.ReloadableFile.RUnlock()

	sponsor, ok := db.Sponsors[sponsorID]
	if !ok {
		sponsor = db.Sponsors[db.DefaultSponsorID]
	}

	if sponsor == nil {
		return nil
	}

	return sponsor.domainBytesChecksum
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

func (db *Database) GetDiscoveryServers() []*DiscoveryServer {
	db.ReloadableFile.RLock()
	defer db.ReloadableFile.RUnlock()
	return db.DiscoveryServers
}
