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
	"net"

	maxminddb "github.com/Psiphon-Inc/maxminddb-golang"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon"
)

const UNKNOWN_GEOIP_VALUE = "None"

type GeoIPData struct {
	Country string
	City    string
	ISP     string
}

func GeoIPLookup(ipAddress string) GeoIPData {

	result := GeoIPData{
		Country: UNKNOWN_GEOIP_VALUE,
		City:    UNKNOWN_GEOIP_VALUE,
		ISP:     UNKNOWN_GEOIP_VALUE,
	}

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

	result.Country = geoIPFields.Country.ISOCode
	name, ok := geoIPFields.City.Names["en"]
	if ok {
		result.City = name
	}
	result.ISP = geoIPFields.ISP

	return result
}

var geoIPReader *maxminddb.Reader

func InitGeoIP(config *Config) error {
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
