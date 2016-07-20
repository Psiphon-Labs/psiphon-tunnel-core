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

// Package psiphon/server/psinet implements psinet database services. The psinet
// database is a JSON-format file containing information about the Psiphon network,
// including sponsors, home pages, stats regexes, available upgrades, and other
// servers for discovery. This package also implements the Psiphon discovery algorithm.
package psinet

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math"
	"math/rand"
	"strconv"
	"strings"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
)

// Database serves Psiphon API data requests. It's safe for
// concurrent usage. The Reload function supports hot reloading
// of Psiphon network data while the server is running.
type Database struct {
	common.ReloadableFile

	AlternateMeekFrontingAddresses      map[string][]string        `json:"alternate_meek_fronting_addresses"`
	AlternateMeekFrontingAddressesRegex map[string]string          `json:"alternate_meek_fronting_addresses_regex"`
	Hosts                               map[string]Host            `json:"hosts"`
	MeekFrontingDisableSNI              map[string]bool            `json:"meek_fronting_disable_SNI"`
	Servers                             []Server                   `json:"servers"`
	Sponsors                            map[string]Sponsor         `json:"sponsors"`
	Versions                            map[string][]ClientVersion `json:"client_versions"`
}

type Host struct {
	AlternateMeekServerFrontingHosts []string `json:"alternate_meek_server_fronting_hosts"`
	DatacenterName                   string   `json:"datacenter_name"`
	Id                               string   `json:"id"`
	IpAddress                        string   `json:"ip_address"`
	MeekCookieEncryptionPublicKey    string   `json:"meek_cookie_encryption_public_key"`
	MeekServerFrontingDomain         string   `json:"meek_server_fronting_domain"`
	MeekServerFrontingHost           string   `json:"meek_server_fronting_host"`
	MeekServerObfuscatedKey          string   `json:"meek_server_obfuscated_key"`
	MeekServerPort                   int      `json:"meek_server_port"`
	Region                           string   `json:"region"`
}

type Server struct {
	AlternateSshObfuscatedPorts []string        `json:"alternate_ssh_obfuscated_ports"`
	Capabilities                map[string]bool `json:"capabilities"`
	DiscoveryDateRange          []string        `json:"discovery_date_range"`
	EgressIpAddress             string          `json:"egress_ip_address"`
	HostId                      string          `json:"host_id"`
	Id                          string          `json:"id"`
	InternalIpAddress           string          `json:"internal_ip_address"`
	IpAddress                   string          `json:"ip_address"`
	IsEmbedded                  bool            `json:"is_embedded"`
	IsPermanent                 bool            `json:"is_permanent"`
	PropogationChannelId        string          `json:"propagation_channel_id"`
	SshHostKey                  string          `json:"ssh_host_key"`
	SshObfuscatedKey            string          `json:"ssh_obfuscated_key"`
	SshObfuscatedPort           int             `json:"ssh_obfuscated_port"`
	SshPassword                 string          `json:"ssh_password"`
	SshPort                     string          `json:"ssh_port"`
	SshUsername                 string          `json:"ssh_username"`
	WebServerCertificate        string          `json:"web_server_certificate"`
	WebServerPort               string          `json:"web_server_port"`
	WebServerSecret             string          `json:"web_server_secret"`
}

type Sponsor struct {
	Banner              string
	HomePages           map[string][]HomePage `json:"home_pages"`
	HttpsRequestRegexes []HttpsRequestRegex   `json:"https_request_regexes"`
	Id                  string                `json:"id"`
	MobileHomePages     map[string][]HomePage `json:"mobile_home_pages"`
	Name                string                `json:"name"`
	PageViewRegexes     []PageViewRegex       `json:"page_view_regexes"`
	WebsiteBanner       string                `json:"website_banner"`
	WebsiteBannerLink   string                `json:"website_banner_link"`
}

type ClientVersion struct {
	Version string `json:"version"`
}

type HomePage struct {
	Region string `json:"region"`
	Url    string `json:"url"`
}

type HttpsRequestRegex struct {
	Regex   string `json:"regex"`
	Replace string `json:"replace"`
}

type MobileHomePage struct {
	Region string `json:"region"`
	Url    string `json:"url"`
}

type PageViewRegex struct {
	Regex   string `json:"regex"`
	Replace string `json:"replace"`
}

// NewDatabase initializes a Database, calling Reload on the specified
// filename.
func NewDatabase(filename string) (*Database, error) {

	database := &Database{}

	database.ReloadableFile = common.NewReloadableFile(
		filename,
		func(filename string) error {
			psinetJSON, err := ioutil.ReadFile(filename)
			if err != nil {
				// On error, state remains the same
				return common.ContextError(err)
			}
			err = json.Unmarshal(psinetJSON, &database)
			if err != nil {
				// On error, state remains the same
				// (Unmarshal first validates the provided
				//  JOSN and then populates the interface)
				return common.ContextError(err)
			}
			return nil
		})

	_, err := database.Reload()
	if err != nil {
		return nil, common.ContextError(err)
	}

	return database, nil
}

// GetHomepages returns a list of  home pages for the specified sponsor,
// region, and platform.
func (db *Database) GetHomepages(sponsorID, clientRegion string, isMobilePlatform bool) []string {
	db.ReloadableFile.RLock()
	defer db.ReloadableFile.RUnlock()

	sponsorHomePages := make([]string, 0)

	// Sponsor id does not exist: fail gracefully
	sponsor, ok := db.Sponsors[sponsorID]
	if !ok {
		return nil
	}

	homePages := sponsor.HomePages

	if isMobilePlatform {
		if sponsor.MobileHomePages != nil {
			homePages = sponsor.MobileHomePages
		}
	}

	// Case: lookup succeeded and corresponding homepages found for region
	homePagesByRegion, ok := homePages[clientRegion]
	if ok {
		for _, homePage := range homePagesByRegion {
			sponsorHomePages = append(sponsorHomePages, strings.Replace(homePage.Url, "client_region=XX", "client_region="+clientRegion, 1))
		}
	}

	// Case: lookup failed or no corresponding homepages found for region --> use default
	if sponsorHomePages == nil {
		defaultHomePages, ok := homePages["None"]
		if ok {
			for _, homePage := range defaultHomePages {
				// client_region query parameter substitution
				sponsorHomePages = append(sponsorHomePages, strings.Replace(homePage.Url, "client_region=XX", "client_region="+clientRegion, 1))
			}
		}
	}

	return sponsorHomePages
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
// specified sponsor. The result is nil when an unknown sponsorID is provided.
func (db *Database) GetHttpsRequestRegexes(sponsorID string) []map[string]string {
	db.ReloadableFile.RLock()
	defer db.ReloadableFile.RUnlock()

	regexes := make([]map[string]string, 0)

	for i := range db.Sponsors[sponsorID].HttpsRequestRegexes {
		regex := make(map[string]string)
		regex["replace"] = db.Sponsors[sponsorID].HttpsRequestRegexes[i].Replace
		regex["regex"] = db.Sponsors[sponsorID].HttpsRequestRegexes[i].Regex
		regexes = append(regexes, regex)
	}

	return regexes
}

// DiscoverServers selects new encoded server entries to be "discovered" by
// the client, using the discoveryValue as the input into the discovery algorithm.
// The server list (db.Servers) loaded from JSON is stored as an array instead of
// a map to ensure servers are discovered deterministically. Each iteration over a
// map in go is seeded with a random value which causes non-deterministic ordering.
func (db *Database) DiscoverServers(discoveryValue int) []string {
	db.ReloadableFile.RLock()
	defer db.ReloadableFile.RUnlock()

	var servers []Server

	discoveryDate := time.Now().UTC()
	candidateServers := make([]Server, 0)

	for _, server := range db.Servers {
		var start time.Time
		var end time.Time
		var err error

		// All servers that are discoverable on this day are eligable for discovery
		if len(server.DiscoveryDateRange) != 0 {
			start, err = time.Parse("2006-01-02T15:04:05", server.DiscoveryDateRange[0])
			if err != nil {
				continue
			}
			end, err = time.Parse("2006-01-02T15:04:05", server.DiscoveryDateRange[1])
			if err != nil {
				continue
			}
			if discoveryDate.After(start) && discoveryDate.Before(end) {
				candidateServers = append(candidateServers, server)
			}
		}
	}
	servers = selectServers(candidateServers, discoveryValue)

	encodedServerEntries := make([]string, 0)

	for _, server := range servers {
		encodedServerEntries = append(encodedServerEntries, db.getEncodedServerEntry(server))
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
func selectServers(servers []Server, discoveryValue int) []Server {
	TIME_GRANULARITY := 3600

	if len(servers) == 0 {
		return nil
	}

	// Current time truncated to an hour
	timeInSeconds := int(time.Now().Unix())
	timeStrategyValue := timeInSeconds / TIME_GRANULARITY

	// Divide servers into buckets. The bucket count is chosen such that the number
	// of buckets and the number of items in each bucket are close (using sqrt).
	// IP address selects the bucket, time selects the item in the bucket.

	// NOTE: this code assumes that the range of possible timeStrategyValues
	// and discoveryValues are sufficient to index to all bucket items.
	bucketCount := calculateBucketCount(len(servers))

	buckets := bucketizeServerList(servers, bucketCount)
	bucket := buckets[discoveryValue%len(buckets)]
	server := bucket[timeStrategyValue%len(bucket)]

	serverList := make([]Server, 1)
	serverList[0] = server

	return serverList
}

// Number of buckets such that first strategy picks among about the same number
// of choices as the second strategy. Gives an edge to the "outer" strategy.
func calculateBucketCount(length int) int {
	return int(math.Ceil(math.Sqrt(float64(length))))
}

// Create bucketCount buckets.
// Each bucket will be of size division or divison-1.
func bucketizeServerList(servers []Server, bucketCount int) [][]Server {
	division := float64(len(servers)) / float64(bucketCount)

	buckets := make([][]Server, bucketCount)

	var currentBucketIndex int = 0
	var serverIndex int = 0
	for _, server := range servers {
		bucketEndIndex := int(math.Floor(division * (float64(currentBucketIndex) + 1)))

		buckets[currentBucketIndex] = append(buckets[currentBucketIndex], server)

		serverIndex++
		if serverIndex > bucketEndIndex {
			currentBucketIndex++
		}
	}

	return buckets
}

// Return hex encoded server entry string for comsumption by client.
// Newer clients ignore the legacy fields and only utilize the extended (new) config.
func (db *Database) getEncodedServerEntry(server Server) string {

	// Double-check that we're not giving our blank server credentials
	if len(server.IpAddress) <= 1 || len(server.WebServerPort) <= 1 || len(server.WebServerSecret) <= 1 || len(server.WebServerCertificate) <= 1 {
		return ""
	}

	// Extended (new) entry fields are in a JSON string
	var extendedConfig struct {
		IpAddress                     string
		WebServerPort                 string
		WebServerSecret               string
		WebServerCertificate          string
		SshPort                       int
		SshUsername                   string
		SshPassword                   string
		SshHostKey                    string
		SshObfuscatedPort             int
		SshObfuscatedKey              string
		Region                        string
		MeekServerPort                int
		MeekObfuscatedKey             string
		MeekFrontingDomain            string
		MeekFrontingHost              string
		MeekCookieEncryptionPublicKey string
		meekFrontingAddresses         []string
		meekFrontingAddressesRegex    string
		meekFrontingDisableSNI        bool
		meekFrontingHosts             []string
		capabilities                  []string
	}

	// NOTE: also putting original values in extended config for easier parsing by new clients
	extendedConfig.IpAddress = server.IpAddress
	extendedConfig.WebServerPort = server.WebServerPort
	extendedConfig.WebServerSecret = server.WebServerSecret
	extendedConfig.WebServerCertificate = server.WebServerCertificate

	sshPort, err := strconv.Atoi(server.SshPort)
	if err != nil {
		extendedConfig.SshPort = 0
	} else {
		extendedConfig.SshPort = sshPort
	}

	extendedConfig.SshUsername = server.SshUsername
	extendedConfig.SshPassword = server.SshPassword

	sshHostKeyType, sshHostKey := parseSshKeyString(server.SshHostKey)

	if strings.Compare(sshHostKeyType, "ssh-rsa") == 0 {
		extendedConfig.SshHostKey = sshHostKey
	} else {
		extendedConfig.SshHostKey = ""
	}

	extendedConfig.SshObfuscatedPort = server.SshObfuscatedPort
	// Use the latest alternate port unless tunneling through meek
	if len(server.AlternateSshObfuscatedPorts) > 0 && !(server.Capabilities["FRONTED-MEEK"] || server.Capabilities["UNFRONTED-MEEK"]) {
		port, err := strconv.Atoi(server.AlternateSshObfuscatedPorts[len(server.AlternateSshObfuscatedPorts)-1])
		if err == nil {
			extendedConfig.SshObfuscatedPort = port
		}
	}

	extendedConfig.SshObfuscatedKey = server.SshObfuscatedKey

	host := db.Hosts[server.HostId]

	extendedConfig.Region = host.Region
	extendedConfig.MeekServerPort = host.MeekServerPort
	extendedConfig.MeekObfuscatedKey = host.MeekServerObfuscatedKey
	extendedConfig.MeekFrontingDomain = host.MeekServerFrontingDomain
	extendedConfig.MeekFrontingHost = host.MeekServerFrontingHost
	extendedConfig.MeekCookieEncryptionPublicKey = host.MeekCookieEncryptionPublicKey

	serverCapabilities := make(map[string]bool, 0)
	for capability, enabled := range server.Capabilities {
		serverCapabilities[capability] = enabled
	}

	if serverCapabilities["UNFRONTED-MEEK"] && host.MeekServerPort == 443 {
		serverCapabilities["UNFRONTED-MEEK"] = false
		serverCapabilities["UNFRONTED-MEEK-HTTPS"] = true
	}

	if host.MeekServerFrontingDomain != "" {
		alternateMeekFrontingAddresses := db.AlternateMeekFrontingAddresses[host.MeekServerFrontingDomain]
		if len(alternateMeekFrontingAddresses) > 0 {
			// Choose 3 addresses randomly
			perm := rand.Perm(len(alternateMeekFrontingAddresses))[:int(math.Min(float64(len(alternateMeekFrontingAddresses)), float64(3)))]

			for i := range perm {
				extendedConfig.meekFrontingAddresses = append(extendedConfig.meekFrontingAddresses, alternateMeekFrontingAddresses[perm[i]])
			}
		}

		extendedConfig.meekFrontingAddressesRegex = db.AlternateMeekFrontingAddressesRegex[host.MeekServerFrontingDomain]
		extendedConfig.meekFrontingDisableSNI = db.MeekFrontingDisableSNI[host.MeekServerFrontingDomain]
	}

	if host.AlternateMeekServerFrontingHosts != nil {
		// Choose 3 addresses randomly
		perm := rand.Perm(len(host.AlternateMeekServerFrontingHosts))[:int(math.Min(float64(len(host.AlternateMeekServerFrontingHosts)), float64(3)))]

		for i := range perm {
			extendedConfig.meekFrontingHosts = append(extendedConfig.meekFrontingHosts, host.AlternateMeekServerFrontingHosts[i])
		}

		if serverCapabilities["FRONTED-MEEK"] == true {
			serverCapabilities["FRONTED-MEEK-HTTP"] = true
		}
	}

	for capability, enabled := range serverCapabilities {
		if enabled == true {
			extendedConfig.capabilities = append(extendedConfig.capabilities, capability)
		}
	}

	jsonDump, err := json.Marshal(extendedConfig)
	if err != nil {
		return ""
	}

	// Legacy format + extended (new) config
	prefixString := fmt.Sprintf("%s %s %s %s ", server.IpAddress, server.WebServerPort, server.WebServerSecret, server.WebServerCertificate)

	return hex.EncodeToString(append([]byte(prefixString)[:], []byte(jsonDump)[:]...))
}

// Parse string of format "ssh-key-type ssh-key".
func parseSshKeyString(sshKeyString string) (keyType string, key string) {
	sshKeyArr := strings.Split(sshKeyString, " ")
	if len(sshKeyArr) != 2 {
		return "", ""
	}

	return sshKeyArr[0], sshKeyArr[1]
}
