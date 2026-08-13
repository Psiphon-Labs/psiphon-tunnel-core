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
	"reflect"
	"testing"
)

func TestParseRegionCode(t *testing.T) {

	tests := []struct {
		input  string
		want   string
		wantOK bool
	}{
		{"JP", "JP", true},
		{"jp", "JP", true},
		{"Ca", "CA", true},
		{" GB ", "GB", true},

		// Unassigned and user-assigned codes pass the shape check; the
		// operating system is the authority for what it reports.
		{"ZZ", "ZZ", true},

		// UK is exceptionally reserved for the United Kingdom, whose assigned
		// code is GB.
		{"UK", "GB", true},
		{"uk", "GB", true},
		{" Uk ", "GB", true},

		// Codes for dissolved states are not aliased.
		{"SU", "SU", true},
		{"CS", "CS", true},

		// UN M.49 numeric region codes are rejected.
		{"419", "", false},
		{"001", "", false},

		{"", "", false},
		{"U", "", false},
		{"USA", "", false},
		{"U1", "", false},
		{"1R", "", false},
		{"U-", "", false},
	}

	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			got, gotOK := parseRegionCode(test.input)
			if got != test.want || gotOK != test.wantOK {
				t.Errorf("parseRegionCode(%q): got (%q, %v), want (%q, %v)",
					test.input, got, gotOK, test.want, test.wantOK)
			}
		})
	}
}

func TestRegionFromLocaleName(t *testing.T) {

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"posix with charset", "en_CA.UTF-8", "CA"},
		{"posix lowercase charset", "ru_RU.utf8", "RU"},
		{"posix no charset", "ja_JP", "JP"},
		{"posix with modifier", "en_GB@euro", "GB"},
		{"posix charset and modifier", "de_DE.UTF-8@euro", "DE"},
		{"bcp47", "en-US", "US"},
		{"bcp47 with script", "zh-Hans-CN", "CN"},
		{"posix with script", "sr_Latn_RS", "RS"},
		{"posix three part", "en_US_POSIX", "US"},
		{"lowercase region", "en_ca", "CA"},
		{"padded", "  ja_JP  ", "JP"},

		// A locale naming the United Kingdom as UK is canonicalized to GB.
		{"uk alias", "en_UK", "GB"},

		// A bare language must not be inferred to a country: Portuguese is used
		// in Portugal, Brazil, Angola and elsewhere.
		{"bare language pt", "pt", ""},
		{"bare language en", "en", ""},
		{"bare language tr", "tr", ""},

		{"c locale", "C", ""},
		{"c locale with charset", "C.UTF-8", ""},
		{"posix locale", "POSIX", ""},
		{"lowercase c", "c", ""},

		// A UN M.49 region is not a country code.
		{"m49 region", "es_419", ""},

		// Extension keys are not regions.
		{"unicode extension", "en-u-ca-gregory", ""},
		{"numbering extension", "en-u-nu-latn", ""},
		{"transform extension", "en-t-de", ""},
		{"private use", "en-x-US", ""},
		{"variant", "de-1901", ""},
		{"region before extension", "en-CA-u-ca-gregory", "CA"},

		{"empty", "", ""},
		{"charset only", ".UTF-8", ""},
		{"garbage", "!!!", ""},

		// Separators only: FieldsFunc drops empty fields, so these yield no
		// subtags. Found by FuzzRegionFromLocaleName, which panicked here.
		{"one separator", "_", ""},
		{"two separators", "__", ""},
		{"hyphen", "-", ""},
		{"mixed separators", "_-_", ""},
		{"leading separator", "_CA", ""},
		{"trailing separator", "en_", ""},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, gotOK := regionFromLocaleName(test.input)
			wantOK := test.want != ""
			if got != test.want || gotOK != wantOK {
				t.Errorf("regionFromLocaleName(%q): got (%q, %v), want (%q, %v)",
					test.input, got, gotOK, test.want, wantOK)
			}
		})
	}
}

func TestRegionFromTimezoneID(t *testing.T) {

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"iana", "Asia/Tokyo", "JP"},
		{"iana three part", "America/Argentina/Buenos_Aires", "AR"},
		{"iana current name", "Europe/Kyiv", "UA"},

		// Aliases are retained so that systems reporting pre-2017 zone names
		// still resolve.
		{"iana alias", "Europe/Kiev", "UA"},
		{"iana alias rangoon", "Asia/Rangoon", "MM"},
		{"iana alias godthab", "America/Godthab", "GL"},

		{"windows name", "Tokyo Standard Time", "JP"},
		{"windows name turkey", "Turkey Standard Time", "TR"},

		// TZ may carry a leading colon.
		{"tz with colon", ":Asia/Tokyo", "JP"},

		{"padded", "  Asia/Tokyo  ", "JP"},

		// UTC-offset zones have no country.
		{"etc utc", "Etc/UTC", ""},
		{"windows utc", "UTC", ""},
		{"windows dateline", "Dateline Standard Time", ""},

		{"empty", "", ""},
		{"colon only", ":", ""},
		{"unknown", "Mars/Olympus_Mons", ""},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, gotOK := regionFromTimezoneID(test.input)
			wantOK := test.want != ""
			if got != test.want || gotOK != wantOK {
				t.Errorf("regionFromTimezoneID(%q): got (%q, %v), want (%q, %v)",
					test.input, got, gotOK, test.want, wantOK)
			}
		})
	}
}

func TestResolvePrecedence(t *testing.T) {

	tests := []struct {
		name           string
		raw            rawSignals
		wantRegion     string
		wantSource     Source
		wantCandidates map[Source]string
	}{
		{
			name:       "all signals, geo wins",
			raw:        rawSignals{Geo: "CA", TimezoneID: "Asia/Tokyo", LocaleName: "en_GB"},
			wantRegion: "CA",
			wantSource: SourceGeo,
			wantCandidates: map[Source]string{
				SourceGeo: "CA", SourceTimezone: "JP", SourceLocale: "GB",
			},
		},
		{
			name:       "no geo, timezone wins",
			raw:        rawSignals{TimezoneID: "Asia/Tokyo", LocaleName: "en_GB"},
			wantRegion: "JP",
			wantSource: SourceTimezone,
			wantCandidates: map[Source]string{
				SourceTimezone: "JP", SourceLocale: "GB",
			},
		},
		{
			name:           "locale only",
			raw:            rawSignals{LocaleName: "en_GB"},
			wantRegion:     "GB",
			wantSource:     SourceLocale,
			wantCandidates: map[Source]string{SourceLocale: "GB"},
		},
		{
			name:           "geo only",
			raw:            rawSignals{Geo: "TR"},
			wantRegion:     "TR",
			wantSource:     SourceGeo,
			wantCandidates: map[Source]string{SourceGeo: "TR"},
		},
		{
			// An invalid higher-priority signal must not mask a valid lower
			// one.
			name:           "invalid geo falls through to timezone",
			raw:            rawSignals{Geo: "419", TimezoneID: "Europe/Istanbul"},
			wantRegion:     "TR",
			wantSource:     SourceTimezone,
			wantCandidates: map[Source]string{SourceTimezone: "TR"},
		},
		{
			name:           "invalid geo and timezone fall through to locale",
			raw:            rawSignals{Geo: "X", TimezoneID: "Etc/UTC", LocaleName: "ja_JP"},
			wantRegion:     "JP",
			wantSource:     SourceLocale,
			wantCandidates: map[Source]string{SourceLocale: "JP"},
		},
		{
			name:           "nothing resolves",
			raw:            rawSignals{},
			wantRegion:     "",
			wantSource:     SourceNone,
			wantCandidates: map[Source]string{},
		},
		{
			name:           "all signals invalid",
			raw:            rawSignals{Geo: "ZZZ", TimezoneID: "Nowhere/Nothing", LocaleName: "C"},
			wantRegion:     "",
			wantSource:     SourceNone,
			wantCandidates: map[Source]string{},
		},
		{
			// Signals may disagree; the winner is by priority, not consensus.
			name:       "signals disagree",
			raw:        rawSignals{Geo: "US", TimezoneID: "Asia/Tokyo", LocaleName: "en_US"},
			wantRegion: "US",
			wantSource: SourceGeo,
			wantCandidates: map[Source]string{
				SourceGeo: "US", SourceTimezone: "JP", SourceLocale: "US",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := resolve(test.raw)
			if got.Region != test.wantRegion {
				t.Errorf("Region: got %q, want %q", got.Region, test.wantRegion)
			}
			if got.Source != test.wantSource {
				t.Errorf("Source: got %q, want %q", got.Source, test.wantSource)
			}
			if !reflect.DeepEqual(got.Candidates, test.wantCandidates) {
				t.Errorf("Candidates: got %v, want %v", got.Candidates, test.wantCandidates)
			}
		})
	}
}

// TestResolveAlwaysValid asserts the package contract: the returned region is
// either empty or a valid region code, and Source is consistent with Region.
func TestResolveAlwaysValid(t *testing.T) {

	inputs := []rawSignals{
		{},
		{Geo: "JP"},
		{Geo: "!!"},
		{TimezoneID: "Europe/Kyiv"},
		{TimezoneID: "Tokyo Standard Time"},
		{LocaleName: "en_CA.UTF-8"},
		{LocaleName: "C"},
		{Geo: "419", TimezoneID: "Etc/UTC", LocaleName: "POSIX"},
		{Geo: "  ", TimezoneID: "  ", LocaleName: "  "},
	}

	for _, raw := range inputs {
		got := resolve(raw)

		if got.Region != "" {
			if _, ok := parseRegionCode(got.Region); !ok {
				t.Errorf("resolve(%+v): Region %q is not a valid region code", raw, got.Region)
			}
			if got.Source == SourceNone {
				t.Errorf("resolve(%+v): Region %q with SourceNone", raw, got.Region)
			}
		} else if got.Source != SourceNone {
			t.Errorf("resolve(%+v): empty Region with Source %q", raw, got.Source)
		}

		if got.Candidates == nil {
			t.Errorf("resolve(%+v): Candidates must not be nil", raw)
		}
	}
}

func TestLocaleNameFromEnv(t *testing.T) {

	tests := []struct {
		name string
		env  map[string]string
		want string
	}{
		{
			name: "LC_ALL wins",
			env:  map[string]string{"LC_ALL": "ja_JP.UTF-8", "LC_TIME": "de_DE.UTF-8", "LANG": "en_US.UTF-8"},
			want: "ja_JP.UTF-8",
		},
		{
			// The common desktop case: LANG carries the interface language
			// while a formatting category carries the actual region.
			name: "formatting category preferred over LANG",
			env:  map[string]string{"LANG": "en_US.UTF-8", "LC_TIME": "de_DE.UTF-8"},
			want: "de_DE.UTF-8",
		},
		{
			name: "LC_MONETARY before LC_TIME",
			env:  map[string]string{"LC_MONETARY": "fr_FR.UTF-8", "LC_TIME": "de_DE.UTF-8"},
			want: "fr_FR.UTF-8",
		},
		{
			name: "LANG used when nothing else set",
			env:  map[string]string{"LANG": "tr_TR.UTF-8"},
			want: "tr_TR.UTF-8",
		},
		{
			// A value carrying no region is skipped rather than ending the
			// search.
			name: "regionless value skipped",
			env:  map[string]string{"LC_ALL": "C.UTF-8", "LANG": "ja_JP.UTF-8"},
			want: "ja_JP.UTF-8",
		},
		{
			name: "bare language skipped",
			env:  map[string]string{"LC_ALL": "pt", "LANG": "en_GB"},
			want: "en_GB",
		},
		{
			name: "nothing set",
			env:  map[string]string{},
			want: "",
		},
		{
			name: "all regionless",
			env:  map[string]string{"LC_ALL": "C", "LANG": "POSIX"},
			want: "",
		},
		{
			name: "empty values ignored",
			env:  map[string]string{"LC_ALL": "", "LC_TIME": "   ", "LANG": "ru_RU.UTF-8"},
			want: "ru_RU.UTF-8",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			getenv := func(name string) string { return test.env[name] }
			if got := localeNameFromEnv(getenv); got != test.want {
				t.Errorf("localeNameFromEnv: got %q, want %q", got, test.want)
			}
		})
	}
}

func TestIANAZoneFromPath(t *testing.T) {

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"macos", "/var/db/timezone/zoneinfo/America/Toronto", "America/Toronto"},
		{"linux", "/usr/share/zoneinfo/Europe/Kyiv", "Europe/Kyiv"},
		{"relative", "../usr/share/zoneinfo/Asia/Tokyo", "Asia/Tokyo"},
		{"three part zone", "/usr/share/zoneinfo/America/Argentina/Salta", "America/Argentina/Salta"},
		{"single component zone", "/usr/share/zoneinfo/UTC", "UTC"},

		{"no marker", "/etc/localtime", ""},
		{"empty", "", ""},
		{"marker only", "/usr/share/zoneinfo/", ""},
		{"traversal rejected", "/usr/share/zoneinfo/../../etc/passwd", ""},

		// Not shaped like a zone name. The NUL case was found by
		// FuzzIANAZoneFromPath; such a value would otherwise reach the
		// diagnostic logs.
		{"nul rejected", "/usr/share/zoneinfo/\x00", ""},
		{"space rejected", "/usr/share/zoneinfo/ ", ""},
		{"newline rejected", "/usr/share/zoneinfo/A\nB", ""},
		{"non-ascii rejected", "/usr/share/zoneinfo/Améric/Toronto", ""},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := ianaZoneFromPath(test.input); got != test.want {
				t.Errorf("ianaZoneFromPath(%q): got %q, want %q", test.input, got, test.want)
			}
		})
	}
}

// TestGetContract asserts that the exported API is total on the current
// platform: it must not panic and must return either empty or a valid region.
// The platform readings themselves are exercised by the per-platform tests.
func TestGetContract(t *testing.T) {

	region := Get()
	if region != "" {
		if _, ok := parseRegionCode(region); !ok {
			t.Errorf("Get: %q is not a valid region code", region)
		}
	}

	detail := GetDetail()
	if detail.Region != region {
		t.Errorf("GetDetail.Region %q does not match Get %q", detail.Region, region)
	}
	if detail.Candidates == nil {
		t.Error("GetDetail.Candidates must not be nil")
	}
	for source, candidate := range detail.Candidates {
		if _, ok := parseRegionCode(candidate); !ok {
			t.Errorf("candidate %q from source %q is not a valid region code", candidate, source)
		}
	}
}
