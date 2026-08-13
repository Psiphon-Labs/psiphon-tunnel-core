/*
 * Copyright (c) 2026, Psiphon Inc.
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

// Package deviceregion makes a best-effort approximation of the region the
// host device is located in, for use as the Psiphon DeviceRegion metric. It is
// the desktop counterpart to the getDeviceRegion functions in
// MobileLibrary/iOS and MobileLibrary/Android and follows the same contract:
// the result is an approximation, not authoritative geolocation, and is empty
// when no signal yields a value.
//
// Only APIs that require no permissions and prompt no user are used. No
// platform location service is consulted: not Windows.Devices.Geolocation and
// not CoreLocation. The region and locale APIs used here are a separate
// operating system subsystem from those.
//
// Three signals are collected and resolved in this order:
//
//	geo       the OS home-location setting; Windows only
//	timezone  the system time zone, mapped to a country
//	locale    the region subtag of the user's locale
//
// Locale is last because it is the least reliable: locales such as en-US are
// used in many places that are not the United States. MobileLibrary/iOS orders
// these the same way.
//
// This package works on iOS and Android, but the mobile libraries are
// preferred there, as they also consult the mobile network and SIM.
//
//go:generate go run zones_gen.go
package deviceregion

import "strings"

// Source identifies which signal produced a region.
type Source string

const (
	SourceNone     Source = ""
	SourceGeo      Source = "geo" // Windows only
	SourceTimezone Source = "timezone"
	SourceLocale   Source = "locale"
)

var resolutionOrder = []Source{SourceGeo, SourceTimezone, SourceLocale}

// Detail is a region and its provenance. Candidates holds every signal that
// produced a region, including those outranked by Region's, which allows a
// caller to measure detection coverage and signal agreement.
type Detail struct {
	Region     string
	Source     Source
	Candidates map[Source]string
}

// rawSignals are unvalidated platform readings. Implementations of
// platformSignals do no parsing, so that all logic stays portable and
// testable on every platform.
type rawSignals struct {
	Geo        string // an ISO 3166-1 alpha-2 code, such as "CA"
	TimezoneID string // an IANA name, such as "Asia/Tokyo", or a Windows key name, such as "Tokyo Standard Time"
	LocaleName string // a POSIX or BCP 47 name, such as "ja_JP.UTF-8" or "en-CA"
}

// Get returns the ISO 3166-1 alpha-2 code of the region the device is probably
// located in, or an empty string if none can be determined.
func Get() string {
	return GetDetail().Region
}

// GetDetail returns the region along with its provenance. See Detail.
func GetDetail() Detail {
	return resolve(platformSignals())
}

// resolve validates each signal and returns the highest-priority one that
// yielded a region. It is pure and total.
func resolve(raw rawSignals) Detail {

	candidates := make(map[Source]string)

	if region, ok := parseRegionCode(raw.Geo); ok {
		candidates[SourceGeo] = region
	}
	if region, ok := regionFromTimezoneID(raw.TimezoneID); ok {
		candidates[SourceTimezone] = region
	}
	if region, ok := regionFromLocaleName(raw.LocaleName); ok {
		candidates[SourceLocale] = region
	}

	for _, source := range resolutionOrder {
		if region, ok := candidates[source]; ok {
			return Detail{Region: region, Source: source, Candidates: candidates}
		}
	}

	return Detail{Source: SourceNone, Candidates: candidates}
}

// parseRegionCode uppercases a region code, canonicalizing any regionAliases
// entry. A code must be exactly two ASCII letters, which rejects the UN M.49
// numeric regions a locale may carry, such as the 419 in "es-419".
//
// As for the mobile libraries, the result is not guaranteed to be an assigned
// ISO 3166-1 code; validating that would mean carrying a country list, and the
// OS is the authority for what it reports.
func parseRegionCode(s string) (string, bool) {

	s = strings.TrimSpace(s)
	if len(s) != 2 {
		return "", false
	}

	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') {
			return "", false
		}
	}

	code := strings.ToUpper(s)
	if canonical, ok := regionAliases[code]; ok {
		code = canonical
	}

	return code, true
}

// regionAliases canonicalizes non-assigned region codes. UK is exceptionally
// reserved by ISO 3166 for the United Kingdom, whose assigned code is GB, and
// CLDR carries the same alias.
//
// Codes for dissolved states, such as SU and CS, are deliberately absent: no
// current OS reports them, and choosing a successor state for each is not a
// judgement for this package.
var regionAliases = map[string]string{
	"UK": "GB",
}

// regionFromTimezoneID maps an IANA zone name or a Windows time zone key name
// to a region. Zones with no country, such as the Etc/* UTC-offset zones,
// yield none.
func regionFromTimezoneID(id string) (string, bool) {

	// A TZ value may carry a leading colon.
	id = strings.TrimPrefix(strings.TrimSpace(id), ":")
	if id == "" {
		return "", false
	}

	if ianaZone, ok := windowsZoneIANA[id]; ok {
		id = ianaZone
	}

	region, ok := ianaZoneCountry[id]
	if !ok {
		return "", false
	}

	return parseRegionCode(region)
}

// regionFromLocaleName extracts the region subtag of a POSIX or BCP 47 locale
// name, such as the CA in "en_CA.UTF-8".
//
// A bare language such as "pt" yields no region: inferring a country from a
// language is unreliable, as Portuguese is used in several countries. The
// "C" and "POSIX" locales also yield none.
func regionFromLocaleName(s string) (string, bool) {

	s = strings.TrimSpace(s)

	// Strip a POSIX modifier, as in "en_GB@euro", then a character set, as in
	// "en_CA.UTF-8".
	if i := strings.IndexByte(s, '@'); i >= 0 {
		s = s[:i]
	}
	if i := strings.IndexByte(s, '.'); i >= 0 {
		s = s[:i]
	}

	if s == "" {
		return "", false
	}

	switch strings.ToUpper(s) {
	case "C", "POSIX":
		return "", false
	}

	subtags := strings.FieldsFunc(s, func(r rune) bool {
		return r == '_' || r == '-'
	})

	// FieldsFunc drops empty fields, so a name of only separators yields no
	// subtags at all.
	if len(subtags) < 2 {
		return "", false
	}

	// The first subtag is the language. The region is the first subsequent
	// two-letter subtag; a four-letter subtag in between is a script, as in
	// "zh_Hans_CN". A one-character subtag begins a BCP 47 extension, whose
	// two-letter keys are not regions: the ca in "en-u-ca-gregory" is a
	// calendar, not Canada.
	for _, subtag := range subtags[1:] {
		if len(subtag) == 1 {
			break
		}
		if region, ok := parseRegionCode(subtag); ok {
			return region, true
		}
	}

	return "", false
}

// localeEnvVars are consulted in this order. The formatting categories precede
// LANG because they reflect the user's region while LANG reflects the UI
// language; desktop installers commonly set LANG to en_US.UTF-8 while setting
// the formatting categories to the actual region.
var localeEnvVars = []string{
	"LC_ALL",
	"LC_MONETARY",
	"LC_TIME",
	"LC_MEASUREMENT",
	"LC_PAPER",
	"LC_NUMERIC",
	"LANG",
}

// localeNameFromEnv returns the first locale name in the environment that
// carries a region. Values carrying none, such as "C", are skipped rather than
// ending the search.
func localeNameFromEnv(getenv func(string) string) string {

	for _, name := range localeEnvVars {
		value := strings.TrimSpace(getenv(name))
		if value == "" {
			continue
		}
		if _, ok := regionFromLocaleName(value); ok {
			return value
		}
	}

	return ""
}

// ianaZoneFromPath extracts an IANA zone name from a zoneinfo path, such as the
// target of the /etc/localtime symlink: "/usr/share/zoneinfo/Europe/Kyiv"
// yields "Europe/Kyiv".
//
// The result is rejected unless it is shaped like a zone name. This value comes
// from the filesystem and reaches diagnostic logs, so control characters must
// not pass through even though an unknown name would simply fail to resolve.
func ianaZoneFromPath(path string) string {

	const marker = "zoneinfo/"

	i := strings.LastIndex(path, marker)
	if i < 0 {
		return ""
	}

	zone := path[i+len(marker):]
	if zone == "" || strings.HasPrefix(zone, "/") || strings.Contains(zone, "..") {
		return ""
	}

	if !isZoneName(zone) {
		return ""
	}

	return zone
}

// isZoneName reports whether s uses only the characters IANA zone names are
// composed of.
func isZoneName(s string) bool {

	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z',
			c >= 'a' && c <= 'z',
			c >= '0' && c <= '9',
			c == '/', c == '_', c == '-', c == '+':
		default:
			return false
		}
	}

	return true
}
