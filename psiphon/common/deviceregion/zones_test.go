//go:build !ios && !android

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

package deviceregion

import (
	"strings"
	"testing"
)

// Lower bounds, not exact counts, so that a tzdb or CLDR release that adds
// zones does not fail the test. A release that removes most of a table would.
const (
	minIANAZones    = 480
	minWindowsZones = 120
)

func TestIANAZoneCountryIntegrity(t *testing.T) {

	if len(ianaZoneCountry) < minIANAZones {
		t.Errorf("ianaZoneCountry has %d entries, want at least %d",
			len(ianaZoneCountry), minIANAZones)
	}

	for zone, region := range ianaZoneCountry {

		if zone == "" {
			t.Error("ianaZoneCountry contains an empty zone name")
			continue
		}

		if strings.TrimSpace(zone) != zone {
			t.Errorf("zone %q has surrounding whitespace", zone)
		}

		canonical, ok := parseRegionCode(region)
		if !ok {
			t.Errorf("zone %q maps to %q, which is not a valid region code", zone, region)
			continue
		}

		// The generator must emit codes already uppercased, so that lookups
		// need no normalization.
		if canonical != region {
			t.Errorf("zone %q maps to %q, want the uppercased form %q", zone, region, canonical)
		}
	}
}

func TestWindowsZoneIANAIntegrity(t *testing.T) {

	if len(windowsZoneIANA) < minWindowsZones {
		t.Errorf("windowsZoneIANA has %d entries, want at least %d",
			len(windowsZoneIANA), minWindowsZones)
	}

	for windowsZone, ianaZone := range windowsZoneIANA {

		if windowsZone == "" {
			t.Error("windowsZoneIANA contains an empty Windows zone name")
			continue
		}

		// This is the invariant most likely to break as the two tables are
		// regenerated from independently versioned sources. Every Windows zone
		// must resolve through the IANA table, otherwise it is dead weight
		// that silently yields no region.
		if _, ok := ianaZoneCountry[ianaZone]; !ok {
			t.Errorf("Windows zone %q maps to IANA zone %q, which is absent from ianaZoneCountry",
				windowsZone, ianaZone)
		}
	}
}

// TestWindowsZonesResolve asserts that every Windows zone name yields a region
// end to end, which is the property callers depend on.
func TestWindowsZonesResolve(t *testing.T) {

	for windowsZone := range windowsZoneIANA {
		if _, ok := regionFromTimezoneID(windowsZone); !ok {
			t.Errorf("Windows zone %q does not resolve to a region", windowsZone)
		}
	}
}

// TestIANAZonesResolve asserts the same for every IANA zone.
func TestIANAZonesResolve(t *testing.T) {

	for zone := range ianaZoneCountry {
		if _, ok := regionFromTimezoneID(zone); !ok {
			t.Errorf("IANA zone %q does not resolve to a region", zone)
		}
	}
}

// TestTzdbIANAAlignment cross-checks the generated table against the twelve
// corrections applied to the iOS mapping in Psiphon-Labs/psiphon-tunnel-core
// pull request 826, "Align iOS timezone regions with IANA".
//
// The mobile library keeps a legacy table and layers these overrides on top.
// This package generates its table from tzdb zone.tab instead, which should
// produce the same answers. A disagreement means either the generator or the
// pinned tzdb release needs review.
func TestTzdbIANAAlignment(t *testing.T) {

	overrides := map[string]string{
		"America/Ciudad_Juarez": "MX",
		"America/Coyhaique":     "CL",
		"America/Nuuk":          "GL",
		"America/Punta_Arenas":  "CL",
		"Asia/Atyrau":           "KZ",
		"Asia/Famagusta":        "CY",
		"Asia/Qostanay":         "KZ",
		"Asia/Yangon":           "MM",
		"Europe/Kyiv":           "UA",
		"Europe/Saratov":        "RU",
		"Europe/Simferopol":     "UA",
		"Pacific/Kanton":        "KI",
	}

	for zone, want := range overrides {
		got, ok := regionFromTimezoneID(zone)
		if !ok {
			t.Errorf("zone %q does not resolve; pull request 826 maps it to %q", zone, want)
			continue
		}
		if got != want {
			t.Errorf("zone %q: got %q, want %q per pull request 826", zone, got, want)
		}
	}
}

// TestLegacyZoneAliases asserts that the pre-2017 zone names still resolve.
// Systems that have not taken a recent tzdb update report these, and the
// mobile library's legacy table retains them for the same reason. Dropping
// them would silently lose the region for these countries.
func TestLegacyZoneAliases(t *testing.T) {

	aliases := map[string]string{
		"Europe/Kiev":          "UA",
		"Asia/Rangoon":         "MM",
		"America/Godthab":      "GL",
		"Pacific/Enderbury":    "KI",
		"Asia/Calcutta":        "IN",
		"Asia/Saigon":          "VN",
		"America/Buenos_Aires": "AR",

		// Both tzdb and CLDR place Johnston Atoll in US. This deliberately
		// differs from the pre-generator iOS table, which had the more precise
		// UM; no source supplies UM.
		"Pacific/Johnston": "US",
	}

	for zone, want := range aliases {
		got, ok := regionFromTimezoneID(zone)
		if !ok {
			t.Errorf("legacy zone %q does not resolve, want %q", zone, want)
			continue
		}
		if got != want {
			t.Errorf("legacy zone %q: got %q, want %q", zone, got, want)
		}
	}
}

// TestAmbiguousAliasesExcluded asserts that the generator dropped the backward
// aliases whose link target lies in another country.
//
// tzdb links zones sharing DST rules, not zones in the same country, so an
// alias does not always belong to its target's country: Africa/Timbuktu links
// to Africa/Abidjan, which would place Mali in Côte d'Ivoire. The generator
// keeps an alias only when tzdb and CLDR agree on it, so each of these must be
// absent rather than present with the target's country.
func TestAmbiguousAliasesExcluded(t *testing.T) {

	// The value is the country the link target would have wrongly supplied.
	wrongIfPresent := map[string]string{
		"Africa/Asmera":         "KE", // Asmara is in ER
		"Africa/Timbuktu":       "CI", // Timbuktu is in ML
		"America/Coral_Harbour": "PA", // Coral Harbour is in CA
		"America/Virgin":        "PR", // the US Virgin Islands are VI
		"Antarctica/South_Pole": "NZ", // the South Pole is AQ
		"Atlantic/Jan_Mayen":    "DE", // Jan Mayen is SJ
		"Iceland":               "CI", // Iceland is IS
		"Pacific/Ponape":        "SB", // Pohnpei is FM
		"Pacific/Truk":          "PG", // Chuuk is FM
		"Pacific/Yap":           "PG", // Yap is FM
	}

	for zone, wrong := range wrongIfPresent {
		if region, ok := ianaZoneCountry[zone]; ok {
			t.Errorf("zone %q is present as %q; it is ambiguous and must be excluded"+
				" (its link target would supply %q)", zone, region, wrong)
		}
		if _, ok := regionFromTimezoneID(zone); ok {
			t.Errorf("zone %q resolves to a region; it must yield none", zone)
		}
	}
}

// TestFlatLegacyNamesExcluded asserts that the flat compatibility aliases yield
// no region.
//
// An IANA zone name is Area/Location and every canonical zone has that form.
// The flat names name no location: CET and EET span a continent, so no single
// country is correct for them, and the rest are obsolete country names that no
// current system reports.
func TestFlatLegacyNamesExcluded(t *testing.T) {

	for _, zone := range []string{
		// Continent-wide abbreviations, for which there is no correct answer.
		"CET", "EET", "MET", "WET", "EST",
		// Obsolete country names.
		"Japan", "Poland", "Turkey", "Iran", "Israel", "Cuba", "GB", "PRC",
		"Iceland", "Portugal", "Singapore", "W-SU",
	} {
		if region, ok := regionFromTimezoneID(zone); ok {
			t.Errorf("flat legacy name %q resolves to %q; it must yield none",
				zone, region)
		}
	}

	for zone := range ianaZoneCountry {
		if !strings.Contains(zone, "/") {
			t.Errorf("table contains flat zone name %q", zone)
		}
	}
}

// TestCountryCoverage asserts the table covers a broad set of countries, and
// spot-checks regions of particular interest to Psiphon.
func TestCountryCoverage(t *testing.T) {

	countries := make(map[string]bool)
	for _, region := range ianaZoneCountry {
		countries[region] = true
	}

	const minCountries = 240
	if len(countries) < minCountries {
		t.Errorf("ianaZoneCountry covers %d countries, want at least %d",
			len(countries), minCountries)
	}

	for _, region := range []string{
		"IR", "CN", "RU", "TR", "TM", "UZ", "VN", "BY", "MM", "UA", "SA", "EG",
	} {
		if !countries[region] {
			t.Errorf("no time zone maps to %q", region)
		}
	}
}

// TestNoCountrylessZones asserts that the UTC-offset pseudo-zones are absent
// from both tables. They have no country, so including them would only add
// entries that can never yield a region.
func TestNoCountrylessZones(t *testing.T) {

	for _, zone := range []string{"Etc/UTC", "Etc/GMT", "Etc/GMT+12", "UTC"} {
		if region, ok := ianaZoneCountry[zone]; ok {
			t.Errorf("ianaZoneCountry contains country-less zone %q mapped to %q", zone, region)
		}
	}

	for _, windowsZone := range []string{"UTC", "UTC+12", "UTC-11", "Dateline Standard Time"} {
		if ianaZone, ok := windowsZoneIANA[windowsZone]; ok {
			t.Errorf("windowsZoneIANA contains country-less zone %q mapped to %q",
				windowsZone, ianaZone)
		}
	}
}
