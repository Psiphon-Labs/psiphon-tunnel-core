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
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	maxminddb "github.com/oschwald/maxminddb-golang"
)

const (
	GEOIP_UNKNOWN_VALUE     = "None"
	GEOIP_DATABASE_TYPE_ISP = "GeoIP2-ISP"
)

// GeoIPData is GeoIP data for a client session. Individual client
// IP addresses are neither logged nor explicitly referenced during a session.
// The GeoIP country, city, and ISP corresponding to a client IP address are
// resolved and then logged along with usage stats.
type GeoIPData struct {
	Country string
	City    string
	ISP     string
	ASN     string
	ASO     string
}

// NewGeoIPData returns a GeoIPData initialized with the expected
// GEOIP_UNKNOWN_VALUE values to be used when GeoIP lookup fails.
func NewGeoIPData() GeoIPData {
	return GeoIPData{
		Country: GEOIP_UNKNOWN_VALUE,
		City:    GEOIP_UNKNOWN_VALUE,
		ISP:     GEOIP_UNKNOWN_VALUE,
		ASN:     GEOIP_UNKNOWN_VALUE,
		ASO:     GEOIP_UNKNOWN_VALUE,
	}
}

// SetClientLogFields adds the GeoIPData fields to LogFields, following
// Psiphon field name and format conventions. For example, GeoIPData.Country
// is logged as client_region.
func (g GeoIPData) SetClientLogFields(logFields LogFields) {
	g.SetClientLogFieldsWithPrefix("", logFields)
}

// SetClientLogFieldsWithPrefix adds the GeoIPData fields to LogFields,
// following Psiphon field name and format conventions and with the specified
// prefix. For example, GeoIPData.Country is logged as
// duplicate_authorization_client_region for the prefix "duplicate_authorization_".
func (g GeoIPData) SetClientLogFieldsWithPrefix(prefix string, logFields LogFields) {
	g.SetLogFieldsWithPrefix(prefix, "client", logFields)
}

// SetLogFieldsWithPrefix adds the GeoIPData fields to LogFields, following
// Psiphon field name and format conventions and with the specified prefix
// and name. For example, GeoIPData.Country is logged as proxy_region for the
// prefix "" and name "proxy".
func (g GeoIPData) SetLogFieldsWithPrefix(prefix string, name string, logFields LogFields) {

	// In psi_web, the space replacement was done to accommodate space
	// delimited logging, which is no longer required; we retain the
	// transformation so that stats aggregation isn't impacted.
	logFields[fmt.Sprintf("%s%s_region", prefix, name)] = strings.Replace(g.Country, " ", "_", -1)
	logFields[fmt.Sprintf("%s%s_city", prefix, name)] = strings.Replace(g.City, " ", "_", -1)
	logFields[fmt.Sprintf("%s%s_isp", prefix, name)] = strings.Replace(g.ISP, " ", "_", -1)
	logFields[fmt.Sprintf("%s%s_asn", prefix, name)] = strings.Replace(g.ASN, " ", "_", -1)
	logFields[fmt.Sprintf("%s%s_aso", prefix, name)] = strings.Replace(g.ASO, " ", "_", -1)
}

// GeoIPService implements GeoIP lookup and session/GeoIP caching.
// Lookup is via a MaxMind database; the ReloadDatabase function
// supports hot reloading of MaxMind data while the server is
// running.
type GeoIPService struct {
	databases []*geoIPDatabase
}

type geoIPDatabase struct {
	common.ReloadableFile
	filename       string
	tempFilename   string
	tempFileSuffix int64
	isISPType      bool
	maxMindReader  *maxminddb.Reader
}

// NewGeoIPService initializes a new GeoIPService.
func NewGeoIPService(databaseFilenames []string) (*GeoIPService, error) {

	geoIP := &GeoIPService{
		databases: make([]*geoIPDatabase, len(databaseFilenames)),
	}

	for i, filename := range databaseFilenames {

		database := &geoIPDatabase{
			filename: filename,
		}

		database.ReloadableFile = common.NewReloadableFile(
			filename,
			false,
			func(_ []byte, _ time.Time) error {

				// In order to safely mmap the database file, a temporary copy
				// is made and that copy is mmapped. The original file may be
				// repaved without affecting the mmap; upon hot reload, a new
				// temporary copy is made and once it is successful, the old
				// mmap is closed and previous temporary file deleted.
				//
				// On any reload error, database state remains the same.

				src, err := os.Open(database.filename)
				if err != nil {
					return errors.Trace(err)
				}

				tempFileSuffix := database.tempFileSuffix + 1

				tempFilename := fmt.Sprintf(
					"%s.%d",
					filepath.Join(os.TempDir(), filepath.Base(database.filename)),
					tempFileSuffix)

				dst, err := os.Create(tempFilename)
				if err != nil {
					src.Close()
					return errors.Trace(err)
				}

				_, err = io.Copy(dst, src)
				src.Close()
				dst.Close()
				if err != nil {
					_ = os.Remove(tempFilename)
					return errors.Trace(err)
				}

				maxMindReader, err := maxminddb.Open(tempFilename)
				if err != nil {
					_ = os.Remove(tempFilename)
					return errors.Trace(err)
				}

				if database.maxMindReader != nil {
					database.maxMindReader.Close()
					_ = os.Remove(database.tempFilename)
				}

				isISPType := (maxMindReader.Metadata.DatabaseType == GEOIP_DATABASE_TYPE_ISP)

				database.maxMindReader = maxMindReader
				database.isISPType = isISPType
				database.tempFilename = tempFilename
				database.tempFileSuffix = tempFileSuffix

				return nil
			})

		_, err := database.Reload()
		if err != nil {
			return nil, errors.Trace(err)
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

// Lookup determines a GeoIPData for a given string client IP address.
func (geoIP *GeoIPService) Lookup(strIP string) GeoIPData {
	return geoIP.LookupIP(net.ParseIP(strIP))
}

// LookupIP determines a GeoIPData for a given client IP address.
func (geoIP *GeoIPService) LookupIP(IP net.IP) GeoIPData {
	return geoIP.lookupIP(IP, false)
}

// LookupISPForIP determines a GeoIPData for a given client IP address. Only
// ISP, ASN, and ASO fields will be populated. This lookup is faster than a
// full lookup. Benchmarks show this lookup is <= ~1 microsecond against the
// production geo IP database.
func (geoIP *GeoIPService) LookupISPForIP(IP net.IP) GeoIPData {
	return geoIP.lookupIP(IP, true)
}

func (geoIP *GeoIPService) lookupIP(IP net.IP, ISPOnly bool) GeoIPData {

	result := NewGeoIPData()

	if IP == nil {
		return result
	}

	// Populate GeoIP fields.

	var geoIPFields struct {
		Country struct {
			ISOCode string `maxminddb:"iso_code"`
		} `maxminddb:"country"`
		City struct {
			Names map[string]string `maxminddb:"names"`
		} `maxminddb:"city"`
		ISP string `maxminddb:"isp"`
		ASN int    `maxminddb:"autonomous_system_number"`
		ASO string `maxminddb:"autonomous_system_organization"`
	}

	geoIPFields.ASN = -1

	// Each database will populate geoIPFields with the values it contains. In the
	// current MaxMind deployment, the City database populates Country and City and
	// the separate ISP database populates ISP.
	for _, database := range geoIP.databases {
		database.ReloadableFile.RLock()
		var err error
		// Don't lookup the City database when only ISP fields are required;
		// skipping the City lookup is 5-10x faster.
		if !ISPOnly || database.isISPType {
			err = database.maxMindReader.Lookup(IP, &geoIPFields)
		}
		database.ReloadableFile.RUnlock()
		if err != nil {
			log.WithTraceFields(LogFields{"error": err}).Warning("GeoIP lookup failed")
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

	if geoIPFields.ASN != -1 {
		result.ASN = strconv.Itoa(geoIPFields.ASN)
	}

	if geoIPFields.ASO != "" {
		result.ASO = geoIPFields.ASO
	}

	return result
}
