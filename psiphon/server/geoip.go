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
	"crypto/hmac"
	"crypto/sha256"
	"net"
	"time"

	cache "github.com/Psiphon-Inc/go-cache"
	maxminddb "github.com/Psiphon-Inc/maxminddb-golang"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
)

const (
	GEOIP_SESSION_CACHE_TTL = 60 * time.Minute
	GEOIP_UNKNOWN_VALUE     = "None"
)

// GeoIPData is GeoIP data for a client session. Individual client
// IP addresses are neither logged nor explicitly referenced during a session.
// The GeoIP country, city, and ISP corresponding to a client IP address are
// resolved and then logged along with usage stats. The DiscoveryValue is
// a special value derived from the client IP that's used to compartmentalize
// discoverable servers (see calculateDiscoveryValue for details).
type GeoIPData struct {
	Country        string
	City           string
	ISP            string
	DiscoveryValue int
}

// NewGeoIPData returns a GeoIPData initialized with the expected
// GEOIP_UNKNOWN_VALUE values to be used when GeoIP lookup fails.
func NewGeoIPData() GeoIPData {
	return GeoIPData{
		Country: GEOIP_UNKNOWN_VALUE,
		City:    GEOIP_UNKNOWN_VALUE,
		ISP:     GEOIP_UNKNOWN_VALUE,
	}
}

// GeoIPService implements GeoIP lookup and session/GeoIP caching.
// Lookup is via a MaxMind database; the ReloadDatabase function
// supports hot reloading of MaxMind data while the server is
// running.
type GeoIPService struct {
	databases             []*geoIPDatabase
	sessionCache          *cache.Cache
	discoveryValueHMACKey string
}

type geoIPDatabase struct {
	common.ReloadableFile
	maxMindReader *maxminddb.Reader
}

// NewGeoIPService initializes a new GeoIPService.
func NewGeoIPService(
	databaseFilenames []string,
	discoveryValueHMACKey string) (*GeoIPService, error) {

	geoIP := &GeoIPService{
		databases:             make([]*geoIPDatabase, len(databaseFilenames)),
		sessionCache:          cache.New(GEOIP_SESSION_CACHE_TTL, 1*time.Minute),
		discoveryValueHMACKey: discoveryValueHMACKey,
	}

	for i, filename := range databaseFilenames {

		database := &geoIPDatabase{}
		database.ReloadableFile = common.NewReloadableFile(
			filename,
			func(filename string) error {
				maxMindReader, err := maxminddb.Open(filename)
				if err != nil {
					// On error, database state remains the same
					return common.ContextError(err)
				}
				if database.maxMindReader != nil {
					database.maxMindReader.Close()
				}
				database.maxMindReader = maxMindReader
				return nil
			})

		_, err := database.Reload()
		if err != nil {
			return nil, common.ContextError(err)
		}

		geoIP.databases[i] = database
	}

	return geoIP, nil
}

// Reloaders gets the list of reloadable databases in use
// by the GeoIPService. This list is used to hot reload
// these databases.
func (geoIP *GeoIPService) Reloaders() []common.Reloader {
	reloaders := make([]common.Reloader, len(geoIP.databases))
	for i, database := range geoIP.databases {
		reloaders[i] = database
	}
	return reloaders
}

// Lookup determines a GeoIPData for a given client IP address.
func (geoIP *GeoIPService) Lookup(ipAddress string) GeoIPData {
	result := NewGeoIPData()

	ip := net.ParseIP(ipAddress)

	if ip == nil || len(geoIP.databases) == 0 {
		return result
	}

	var geoIPFields struct {
		Country struct {
			ISOCode string `maxminddb:"iso_code"`
		} `maxminddb:"country"`
		City struct {
			Names map[string]string `maxminddb:"names"`
		} `maxminddb:"city"`
		ISP string `maxminddb:"isp"`
	}

	// Each database will populate geoIPFields with the values it contains. In the
	// currnt MaxMind deployment, the City database populates Country and City and
	// the separate ISP database populates ISP.
	for _, database := range geoIP.databases {
		database.ReloadableFile.RLock()
		err := database.maxMindReader.Lookup(ip, &geoIPFields)
		database.ReloadableFile.RUnlock()
		if err != nil {
			log.WithContextFields(LogFields{"error": err}).Warning("GeoIP lookup failed")
		}
	}

	if geoIPFields.Country.ISOCode != "" {
		result.Country = geoIPFields.Country.ISOCode
	}

	name, ok := geoIPFields.City.Names["en"]
	if ok && name != "" {
		result.City = name
	}

	if geoIPFields.ISP != "" {
		result.ISP = geoIPFields.ISP
	}

	result.DiscoveryValue = calculateDiscoveryValue(
		geoIP.discoveryValueHMACKey, ipAddress)

	return result
}

func (geoIP *GeoIPService) SetSessionCache(sessionID string, geoIPData GeoIPData) {
	geoIP.sessionCache.Set(sessionID, geoIPData, cache.DefaultExpiration)
}

func (geoIP *GeoIPService) GetSessionCache(
	sessionID string) GeoIPData {
	geoIPData, found := geoIP.sessionCache.Get(sessionID)
	if !found {
		return NewGeoIPData()
	}
	return geoIPData.(GeoIPData)
}

// calculateDiscoveryValue derives a value from the client IP address to be
// used as input in the server discovery algorithm. Since we do not explicitly
// store the client IP address, we must derive the value here and store it for
// later use by the discovery algorithm.
// See https://bitbucket.org/psiphon/psiphon-circumvention-system/src/tip/Automation/psi_ops_discovery.py
// for full details.
func calculateDiscoveryValue(discoveryValueHMACKey, ipAddress string) int {
	// From: psi_ops_discovery.calculate_ip_address_strategy_value:
	//     # Mix bits from all octets of the client IP address to determine the
	//     # bucket. An HMAC is used to prevent pre-calculation of buckets for IPs.
	//     return ord(hmac.new(HMAC_KEY, ip_address, hashlib.sha256).digest()[0])
	// TODO: use 3-octet algorithm?
	hash := hmac.New(sha256.New, []byte(discoveryValueHMACKey))
	hash.Write([]byte(ipAddress))
	return int(hash.Sum(nil)[0])
}
