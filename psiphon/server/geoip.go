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

	maxminddb "github.com/Psiphon-Inc/maxminddb-golang"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon"
)

const UNKNOWN_GEOIP_VALUE = "None"

// GeoIPData stores GeoIP data for a client session. Individual client
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
// UNKNOWN_GEOIP_VALUE values to be used when GeoIP lookup fails.
func NewGeoIPData() GeoIPData {
	return GeoIPData{
		Country: UNKNOWN_GEOIP_VALUE,
		City:    UNKNOWN_GEOIP_VALUE,
		ISP:     UNKNOWN_GEOIP_VALUE,
	}
}

// GeoIPLookup determines a GeoIPData for a given client IP address.
func GeoIPLookup(ipAddress string) GeoIPData {

	result := NewGeoIPData()

	ip := net.ParseIP(ipAddress)

	if ip == nil || geoIPReader == nil {
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

	err := geoIPReader.Lookup(ip, &geoIPFields)
	if err != nil {
		log.WithContextFields(LogFields{"error": err}).Warning("GeoIP lookup failed")
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

	result.DiscoveryValue = calculateDiscoveryValue(ipAddress)

	return result
}

// calculateDiscoveryValue derives a value from the client IP address to be
// used as input in the server discovery algorithm. Since we do not explicitly
// store the client IP address, we must derive the value here and store it for
// later use by the discovery algorithm.
// See https://bitbucket.org/psiphon/psiphon-circumvention-system/src/tip/Automation/psi_ops_discovery.py
// for full details.
func calculateDiscoveryValue(ipAddress string) int {
	// From: psi_ops_discovery.calculate_ip_address_strategy_value:
	//     # Mix bits from all octets of the client IP address to determine the
	//     # bucket. An HMAC is used to prevent pre-calculation of buckets for IPs.
	//     return ord(hmac.new(HMAC_KEY, ip_address, hashlib.sha256).digest()[0])
	// TODO: use 3-octet algorithm?
	hash := hmac.New(sha256.New, []byte(discoveryValueHMACKey))
	hash.Write([]byte(ipAddress))
	return int(hash.Sum(nil)[0])
}

var geoIPReader *maxminddb.Reader
var discoveryValueHMACKey string

// InitGeoIP opens a GeoIP2/GeoLite2 MaxMind database and prepares
// it for lookups.
func InitGeoIP(config *Config) error {

	discoveryValueHMACKey = config.DiscoveryValueHMACKey

	if config.GeoIPDatabaseFilename != "" {
		var err error
		geoIPReader, err = maxminddb.Open(config.GeoIPDatabaseFilename)
		if err != nil {
			return psiphon.ContextError(err)
		}
		log.WithContext().Info("GeoIP initialized")
	}

	return nil
}
