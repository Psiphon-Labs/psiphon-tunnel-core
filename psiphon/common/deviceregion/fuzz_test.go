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

// Every parser here consumes a string supplied by the operating system, so each
// is fuzzed for the package contract: never panic, and either fail or produce a
// valid region code.

func FuzzParseRegionCode(f *testing.F) {

	for _, seed := range []string{
		"", "I", "JP", "jp", " GB ", "USA", "419", "ZZ", "UK", "\x00\x00", "İT", "🇨🇦",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {

		region, ok := parseRegionCode(input)

		if !ok {
			if region != "" {
				t.Fatalf("parseRegionCode(%q) failed but returned %q", input, region)
			}
			return
		}

		assertValidRegion(t, input, region)

		// Parsing an already-parsed code must be stable, since resolve applies
		// it to values that other helpers have already returned.
		again, ok := parseRegionCode(region)
		if !ok || again != region {
			t.Fatalf("parseRegionCode(%q) = %q, but reparsing gives (%q, %v)",
				input, region, again, ok)
		}
	})
}

func FuzzRegionFromLocaleName(f *testing.F) {

	for _, seed := range []string{
		"", "C", "POSIX", "en", "ja_JP", "en_CA.UTF-8", "en_GB@euro", "zh_Hans_CN",
		"es_419", "en_US_POSIX", "_", "__", "a_b_c_d", "en-", "-CA", "en_UK",
		"........", "@@@@", "\x00", "ru_RU.utf8@modifier",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {

		region, ok := regionFromLocaleName(input)

		if !ok {
			if region != "" {
				t.Fatalf("regionFromLocaleName(%q) failed but returned %q", input, region)
			}
			return
		}

		assertValidRegion(t, input, region)
	})
}

func FuzzRegionFromTimezoneID(f *testing.F) {

	for _, seed := range []string{
		"", ":", "Asia/Tokyo", ":Europe/Kyiv", "Europe/Kiev", "Tokyo Standard Time",
		"UTC", "Etc/GMT+12", "Mars/Olympus_Mons", "//", "../../etc/passwd", "\x00",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {

		region, ok := regionFromTimezoneID(input)

		if !ok {
			if region != "" {
				t.Fatalf("regionFromTimezoneID(%q) failed but returned %q", input, region)
			}
			return
		}

		assertValidRegion(t, input, region)
	})
}

func FuzzIANAZoneFromPath(f *testing.F) {

	for _, seed := range []string{
		"", "/etc/localtime", "/usr/share/zoneinfo/Asia/Tokyo",
		"/var/db/timezone/zoneinfo/America/Toronto", "zoneinfo/", "zoneinfo//",
		"/zoneinfo/../../etc/passwd", "zoneinfo/zoneinfo/UTC", "\x00zoneinfo/X",
		"zoneinfo/\x00", "zoneinfo/ ", "zoneinfo/A\nB",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {

		zone := ianaZoneFromPath(input)

		// The result is derived from a symlink target and reaches diagnostic
		// logs, so it must be shaped like a zone name: relative, no traversal,
		// and no character outside the IANA set.
		if zone == "" {
			return
		}
		if strings.Contains(zone, "..") {
			t.Fatalf("ianaZoneFromPath(%q) = %q, which contains traversal", input, zone)
		}
		if zone[0] == '/' {
			t.Fatalf("ianaZoneFromPath(%q) = %q, which is absolute", input, zone)
		}
		if !isZoneName(zone) {
			t.Fatalf("ianaZoneFromPath(%q) = %q, which is not shaped like a zone name",
				input, zone)
		}
	})
}

// FuzzResolve asserts the package contract over arbitrary combinations of
// platform readings: Region is empty or valid, Source agrees with Region, and
// Candidates never holds an invalid code.
func FuzzResolve(f *testing.F) {

	f.Add("JP", "Asia/Tokyo", "ja_JP.UTF-8")
	f.Add("", "Europe/Kyiv", "en_US.UTF-8")
	f.Add("419", "Etc/UTC", "C")
	f.Add("", "", "")
	f.Add("ZZ", "Tokyo Standard Time", "es_419")

	f.Fuzz(func(t *testing.T, geo, timezoneID, localeName string) {

		detail := resolve(rawSignals{
			Geo:        geo,
			TimezoneID: timezoneID,
			LocaleName: localeName,
		})

		if detail.Candidates == nil {
			t.Fatal("Candidates must never be nil")
		}

		for source, candidate := range detail.Candidates {
			assertValidRegion(t, string(source), candidate)
		}

		if detail.Region == "" {
			if detail.Source != SourceNone {
				t.Fatalf("empty Region with Source %q", detail.Source)
			}
			if len(detail.Candidates) != 0 {
				t.Fatalf("empty Region but %d candidates", len(detail.Candidates))
			}
			return
		}

		assertValidRegion(t, "resolved", detail.Region)

		if detail.Source == SourceNone {
			t.Fatalf("Region %q with SourceNone", detail.Region)
		}
		if detail.Candidates[detail.Source] != detail.Region {
			t.Fatalf("Region %q is not the candidate for Source %q",
				detail.Region, detail.Source)
		}

		// The winner must be the highest-priority candidate present.
		for _, source := range resolutionOrder {
			if _, ok := detail.Candidates[source]; ok {
				if source != detail.Source {
					t.Fatalf("Source is %q but %q is present and ranks higher",
						detail.Source, source)
				}
				break
			}
		}
	})
}

func assertValidRegion(t *testing.T, context, region string) {
	t.Helper()

	if len(region) != 2 {
		t.Fatalf("%s: region %q is not two characters", context, region)
	}
	for i := 0; i < len(region); i++ {
		if region[i] < 'A' || region[i] > 'Z' {
			t.Fatalf("%s: region %q is not two uppercase ASCII letters", context, region)
		}
	}
	if _, aliased := regionAliases[region]; aliased {
		t.Fatalf("%s: region %q is an alias that should have been canonicalized",
			context, region)
	}
}
