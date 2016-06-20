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

package server

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"time"
)

var CLIENT_PLATFORM_ANDROID string = "Android"
var CLIENT_PLATFORM_WINDOWS string = "Windows"

// PsinetDatabase serves Psiphon API data requests. It's safe for
// concurrent usage.
type PsinetDatabase struct {
	Hosts    map[string]Host            `json:"_PsiphonNetwork__hosts"`
	Servers  map[string]Server          `json:"_PsiphonNetwork__servers"`
	Sponsors map[string]Sponsor         `json:"_PsiphonNetwork__sponsors"`
	Versions map[string][]ClientVersion `json:"_PsiphonNetwork__client_versions"`
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
	AlternateSshObfuscatedPorts bool            `json:"alternate_ssh_obfuscated_ports"`
	Capabilities                map[string]bool `json:"capabilities"`
	DiscoveryDateRange          TimeStamps      `json:"discovery_date_range"`
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
	Campaigns           map[string]Campaign   `json:"campaigns"`
	HomePages           map[string][]HomePage `json:"home_pages"`
	HttpsRequestRegexes []HttpsRequestRegex   `json:"https_request_regexes"`
	Id                  string                `json:"id"`
	MobileHomePages     map[string][]HomePage `json:"mobile_home_pages"`
	Name                string                `json:"name"`
	PageViewRegexes     []PageViewRegex       `json:"page_view_regexes"`
	WebsiteBanner       string                `json:"website_banner"`
	WebsiteBannerLink   string                `json:"website_banner_link"`
}

type Campaign struct {
	// TODO: implement
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

type TimeStamps struct {
	TimeStamp []TimeStamp `json:"py/tuple"`
}

type TimeStamp struct {
	PyObject string     `json:"py/object"`
	Reduce   [][]string `json:"__reduce__"`
}

// NewPsinetDatabase initializes a PsinetDatabase. It loads the specified
// file, which should be in the Psiphon automation jsonpickle format, and
// prepares to serve data requests.
// The input "" is valid and returns a functional PsinetDatabase with no
// data.
func NewPsinetDatabase(filename string) (*PsinetDatabase, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}

	psinetDatabase := new(PsinetDatabase)

	err = json.NewDecoder(file).Decode(psinetDatabase)

	return psinetDatabase, err
}

// GetHomepages returns a list of  home pages for the specified sponsor,
// region, and platform.
func (psinet *PsinetDatabase) GetHomepages(sponsorID, clientRegion, clientPlatform string) []string {

	sponsorHomePages := make([]string, 0)

	// Sponsor id does not exist, fail gracefully
	sponsor, ok := psinet.Sponsors[sponsorID]
	if !ok {
		return nil
	}

	homePages := sponsor.HomePages

	if getClientPlatform(clientPlatform) == CLIENT_PLATFORM_ANDROID {
		if sponsor.MobileHomePages != nil {
			homePages = sponsor.MobileHomePages
		}
	}

	// case: lookup succeeded and corresponding homepages found for region
	homePagesByRegion, ok := homePages[clientRegion]
	if ok {
		for _, homePage := range homePagesByRegion {
			sponsorHomePages = append(sponsorHomePages, strings.Replace(homePage.Url, "client_region=XX", "client_region="+clientRegion, 1))
		}
	}

	// case: lookup failed or no corresponding homepages found for region --> use default
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
// no upgrade is available.
func (psinet *PsinetDatabase) GetUpgradeClientVersion(clientVersion, clientPlatform string) string {
	// Check last version number against client version number
	// Assumes versions list is in ascending version order
	platform := getClientPlatform(clientPlatform)

	// If no versions exist for this platform
	clientVersions, ok := psinet.Versions[platform]
	if !ok {
		return ""
	}

	lastVersion := clientVersions[len(clientVersions)-1].Version

	lastVersionInt, err := strconv.Atoi(lastVersion)
	if err != nil {
		return ""
	}
	clientVersionInt, err := strconv.Atoi(clientVersion)
	if err != nil {
		return ""
	}

	// Return version if upgrade needed
	if lastVersionInt > clientVersionInt {
		return lastVersion
	}

	return ""
}

// GetHttpsRequestRegexes returns bytes transferred stats regexes for the
// specified sponsor.
func (psinet *PsinetDatabase) GetHttpsRequestRegexes(sponsorID string) []HttpsRequestRegex {
	return psinet.Sponsors[sponsorID].HttpsRequestRegexes
}

// DiscoverServers selects new encoded server entries to be "discovered" by
// the client, using the discoveryValue as the input into the discovery algorithm.
func (psinet *PsinetDatabase) DiscoverServers(discoveryValue int) []string {

	var servers []Server

	discoveryDate := time.Now().UTC()
	candidateServers := make(map[string]Server)

	for serverName, server := range psinet.Servers {
		var start *time.Time
		var end *time.Time
		var err error

		// All servers that are discoverable on this day are eligable for discovery
		if len(server.DiscoveryDateRange.TimeStamp) != 0 {
			if len(server.DiscoveryDateRange.TimeStamp[0].Reduce[1][0]) != 0 {
				start, err = parseJsonPickleDatetime(server.DiscoveryDateRange.TimeStamp[0].Reduce[1][0])
				if err != nil {
					continue
				}
			}
			if len(server.DiscoveryDateRange.TimeStamp[1].Reduce[1][0]) != 0 {
				end, err = parseJsonPickleDatetime(server.DiscoveryDateRange.TimeStamp[1].Reduce[1][0])
				if err != nil {
					continue
				}
			}
			if discoveryDate.After(*start) && discoveryDate.Before(*end) {
				candidateServers[serverName] = server
			}
		}
	}
	servers = selectServers(candidateServers, discoveryValue)

	encodedServerEntries := make([]string, 0)

	for _, server := range servers {
		encodedServerEntries = append(encodedServerEntries, psinet.getEncodedServerEntry(server))
	}

	return encodedServerEntries
}

// Parse legacy jsonpickle datetime object from python
// Object's base64 encoded hex string corresponds to UTC timestamp
func parseJsonPickleDatetime(base64DatetimeString string) (*time.Time, error) {
	var hexTimestamp string

	base64DecodedTimestamp, err := base64.StdEncoding.DecodeString(base64DatetimeString)
	if err != nil {
		return nil, err
	} else {
		hexTimestamp = hex.EncodeToString(base64DecodedTimestamp)
	}

	// If timestamp is malformed fail gracefully
	if len(hexTimestamp) != 20 {
		return nil, err
	}
	year, err := strconv.ParseInt(hexTimestamp[:4], 16, 64)
	if err != nil {
		return nil, err
	}
	month, err := strconv.ParseInt(hexTimestamp[4:6], 16, 64)
	if err != nil {
		return nil, err
	}
	day, err := strconv.ParseInt(hexTimestamp[6:8], 16, 64)
	if err != nil {
		return nil, err
	}
	hour, err := strconv.ParseInt(hexTimestamp[8:10], 16, 64)
	if err != nil {
		return nil, err
	}
	min, err := strconv.ParseInt(hexTimestamp[10:12], 16, 64)
	if err != nil {
		return nil, err
	}
	sec, err := strconv.ParseInt(hexTimestamp[12:14], 16, 64)
	if err != nil {
		return nil, err
	}
	nsec, err := strconv.ParseInt(hexTimestamp[14:20], 16, 64)
	if err != nil {
		return nil, err
	}

	time := time.Date(int(year), time.Month(month), int(day), int(hour), int(min), int(sec), int(nsec), time.UTC)

	return &time, nil
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
func selectServers(servers map[string]Server, discoveryValue int) []Server {
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

	// NOTE: this code assumes that range of possible time_values and
	// discoveryValue is sufficient to index to all bucket items.
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

// Create `bucketCount` buckets
// Each bucket will be of size `division` or `divison`-1
func bucketizeServerList(servers map[string]Server, bucketCount int) [][]Server {
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

func (psinet *PsinetDatabase) getEncodedServerEntry(server Server) string {

	if len(server.IpAddress) <= 1 || len(server.WebServerPort) <= 1 || len(server.WebServerSecret) <= 1 || len(server.WebServerCertificate) <= 1 {
		return ""
	}

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
		meekFrontingAddrssRegex       string
		meekFrontingDisableSNI        string
		meekFrontingHosts             string
		capabilities                  string
	}
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
	extendedConfig.SshObfuscatedKey = server.SshObfuscatedKey

	host := psinet.Hosts[server.HostId]

	extendedConfig.Region = host.Region
	extendedConfig.MeekServerPort = host.MeekServerPort
	extendedConfig.MeekObfuscatedKey = host.MeekServerObfuscatedKey
	extendedConfig.MeekFrontingDomain = host.MeekServerFrontingDomain
	extendedConfig.MeekFrontingHost = host.MeekServerFrontingHost
	extendedConfig.MeekCookieEncryptionPublicKey = host.MeekCookieEncryptionPublicKey

	if host.AlternateMeekServerFrontingHosts != nil {
		// TODO: implement
	}

	if host.MeekServerFrontingDomain != "" {
		// TODO: implement
	}

	capabilities := make([]string, 0)
	for capability, enabled := range server.Capabilities {
		if enabled == true {
			capabilities = append(capabilities, capability)
		}
	}

	jsonDump, err := json.Marshal(extendedConfig)
	if err != nil {
		return ""
	}

	prefixString := fmt.Sprintf("%s %s %s %s ", server.IpAddress, server.WebServerPort, server.WebServerSecret, server.WebServerCertificate)

	return hex.EncodeToString(append([]byte(prefixString)[:], []byte(jsonDump)[:]...))
}

func parseSshKeyString(sshKeyString string) (keyType string, key string) {
	sshKeyArr := strings.Split(sshKeyString, " ")
	if len(sshKeyArr) != 2 {
		return "", ""
	}

	return sshKeyArr[0], sshKeyArr[1]
}

func getClientPlatform(clientPlatformString string) string {
	platform := CLIENT_PLATFORM_WINDOWS

	if strings.Contains(strings.ToLower(clientPlatformString), strings.ToLower(CLIENT_PLATFORM_ANDROID)) {
		platform = CLIENT_PLATFORM_ANDROID
	}

	return platform
}
