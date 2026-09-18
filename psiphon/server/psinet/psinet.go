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
// sponsors, home pages, available upgrades, and other servers for
// discovery.
package psinet

import (
	"encoding/json"
	"math/rand"
	"net/url"
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

// Database serves Psiphon API data requests. The Reload function supports hot
// reloading of Psiphon network data while the server is running.
//
// All of the methods on Database are thread-safe, but callers must not mutate
// any returned data. The struct may be safely shared across goroutines.
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
	ID              string                `json:"id"`
	HomePages       map[string][]HomePage `json:"home_pages"`
	MobileHomePages map[string][]HomePage `json:"mobile_home_pages"`
	AlertActionURLs map[string][]string   `json:"alert_action_urls"`
}

type ClientVersion struct {
	Version string `json:"version"`
}

type HomePage struct {
	Region string `json:"region"`
	URL    string `json:"url"`
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

			// Decode each encoded server entry for its IP address, which is used in
			// the consistent.Member implementation in the discovery package.
			//
			// Also ensure that no servers share the same IP address, which is
			// a requirement of consistent hashing discovery; otherwise it will
			// panic in the underlying Psiphon-Labs/consistent package.
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
	sponsorID, clientRegion, clientASN, deviceRegion, normalizedClientPlatform string,
	isMobilePlatform bool,
	clientFeatureValues map[string]string) []string {

	homepages := db.GetHomepages(
		sponsorID, clientRegion, clientASN, deviceRegion, normalizedClientPlatform,
		isMobilePlatform, clientFeatureValues)
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
	sponsorID, clientRegion, clientASN, deviceRegion, normalizedClientPlatform string,
	isMobilePlatform bool,
	clientFeatureValues map[string]string) []string {

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
			homepageURL := homepageQueryParameterSubstitution(
				homePage.URL, clientRegion, clientASN, deviceRegion,
				normalizedClientPlatform, clientFeatureValues)
			sponsorHomePages = append(
				sponsorHomePages, homepageURL)
		}
	}

	// Case: lookup failed or no corresponding homepages found for region --> use default
	if len(sponsorHomePages) == 0 {
		defaultHomePages, ok := homePages["None"]
		if ok {
			for _, homePage := range defaultHomePages {
				homepageURL := homepageQueryParameterSubstitution(
					homePage.URL, clientRegion, clientASN, deviceRegion,
					normalizedClientPlatform, clientFeatureValues)
				sponsorHomePages = append(
					sponsorHomePages, homepageURL)
			}
		}
	}

	return sponsorHomePages
}

func homepageQueryParameterSubstitution(
	homepageURL, clientRegion, clientASN, deviceRegion, normalizedClientPlatform string,
	clientFeatureValues map[string]string) string {

	// Substitute <key>=XX templates in the URL query component, splitting
	// on "?", "&", and "#", ensuring exact key match and no substring
	// conflicts.
	//
	// Template keys and the XX value are assumed to be unencoded.
	//
	// Built-in parameters take precedence over any clientFeatureValues
	// parameter with the same name. Any <key>=XX placeholder that doesn't
	// match a built-in or clientFeatureValues query parameter is left
	// unsubstituted.
	//
	// url.QueryEscape guards against URL injection from untrusted inputs.

	urlWithoutFragment, fragment, hasFragment := strings.Cut(homepageURL, "#")
	base, query, ok := strings.Cut(urlWithoutFragment, "?")
	if !ok {
		return homepageURL
	}

	components := strings.Split(query, "&")
	for i, component := range components {
		key, ok := strings.CutSuffix(component, "=XX")
		if !ok {
			continue
		}
		var value string
		switch key {
		case "client_region":
			value = clientRegion
		case "client_asn":
			value = clientASN
		case "device_region":
			value = deviceRegion
		case "client_platform":
			value = strings.ToLower(normalizedClientPlatform)
		default:
			value, ok = clientFeatureValues[key]
			if !ok {
				continue
			}
		}
		components[i] = key + "=" + url.QueryEscape(value)
	}

	homepageURL = base + "?" + strings.Join(components, "&")
	if hasFragment {
		homepageURL += "#" + fragment
	}

	return homepageURL
}

// GetAlertActionURLs returns a list of alert action URLs for the specified
// alert reason and sponsor.
func (db *Database) GetAlertActionURLs(
	alertReason, sponsorID, clientRegion, clientASN, deviceRegion, normalizedClientPlatform string,
	clientFeatureValues map[string]string) []string {

	db.ReloadableFile.RLock()
	defer db.ReloadableFile.RUnlock()

	// Prefer URLs from the Sponsor.AlertActionURLs. When there are no sponsor
	// URLs, then select from Database.DefaultAlertActionURLs.

	actionURLs := []string{}

	sponsor := db.Sponsors[sponsorID]
	if sponsor != nil {
		for _, URL := range sponsor.AlertActionURLs[alertReason] {
			URL = homepageQueryParameterSubstitution(
				URL, clientRegion, clientASN, deviceRegion,
				normalizedClientPlatform, clientFeatureValues)
			actionURLs = append(
				actionURLs, URL)
		}
	}

	if len(actionURLs) == 0 {
		for _, URL := range db.DefaultAlertActionURLs[alertReason] {
			URL = homepageQueryParameterSubstitution(
				URL, clientRegion, clientASN, deviceRegion,
				normalizedClientPlatform, clientFeatureValues)
			actionURLs = append(
				actionURLs, URL)
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
