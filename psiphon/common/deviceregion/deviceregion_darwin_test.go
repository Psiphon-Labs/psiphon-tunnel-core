//go:build darwin && !ios && cgo

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

import "testing"

// TestCoreFoundationReadings exercises the cgo accessors against the running
// system. It asserts shape rather than value, since the correct answer depends
// on how the machine is configured.
func TestCoreFoundationReadings(t *testing.T) {

	timeZone := cfTimeZoneName()
	locale := cfLocaleIdentifier()
	country := cfCountryCode()

	t.Logf("CFTimeZoneGetName=%q CFLocaleGetIdentifier=%q kCFLocaleCountryCode=%q",
		timeZone, locale, country)

	// A macOS or iOS system always has a time zone and a locale. An empty
	// reading here means the Core Foundation calls are broken rather than the
	// machine being unconfigured.
	if timeZone == "" {
		t.Error("CFTimeZoneGetName returned nothing")
	}
	if locale == "" {
		t.Error("CFLocaleGetIdentifier returned nothing")
	}

	if _, ok := regionFromTimezoneID(timeZone); !ok {
		t.Errorf("time zone %q does not resolve to a region", timeZone)
	}

	if country != "" {
		if _, ok := parseRegionCode(country); !ok {
			t.Errorf("country code %q is not a valid region code", country)
		}
	}

	// Repeated calls must agree; CFTimeZoneCopySystem in particular caches.
	for i := 0; i < 5; i++ {
		if cfTimeZoneName() != timeZone || cfLocaleIdentifier() != locale || cfCountryCode() != country {
			t.Fatal("Core Foundation readings are not stable across calls")
		}
	}
}

func TestDarwinSignalsFallbacks(t *testing.T) {

	tests := []struct {
		name           string
		cfTimeZone     string
		cfLocale       string
		cfCountry      string
		system         simulatedSystem
		wantTimezoneID string
		wantLocaleName string
	}{
		{
			name:           "core foundation supplies everything",
			cfTimeZone:     "Asia/Tokyo",
			cfLocale:       "ja_JP",
			cfCountry:      "JP",
			wantTimezoneID: "Asia/Tokyo",
			wantLocaleName: "ja_JP",
		},
		{
			// The identifier carries no region, so the region setting is used
			// on its own as a BCP 47 tag with an undetermined language.
			name:           "locale identifier without a region",
			cfTimeZone:     "Europe/Istanbul",
			cfLocale:       "tr",
			cfCountry:      "TR",
			wantTimezoneID: "Europe/Istanbul",
			wantLocaleName: "und-TR",
		},
		{
			// An identifier carrying a region override is used as-is; the
			// region reading, which reports the region of the language, must
			// not replace it. regionFromLocaleName resolves the override.
			name:           "locale identifier with a region override",
			cfTimeZone:     "America/Toronto",
			cfLocale:       "en_US@rg=cazzzz",
			cfCountry:      "US",
			wantTimezoneID: "America/Toronto",
			wantLocaleName: "en_US@rg=cazzzz",
		},
		{
			name:           "empty locale identifier",
			cfTimeZone:     "Europe/Kyiv",
			cfLocale:       "",
			cfCountry:      "UA",
			wantTimezoneID: "Europe/Kyiv",
			wantLocaleName: "und-UA",
		},
		{
			// Neither Core Foundation locale reading is usable, so the POSIX
			// environment is consulted.
			name:           "locale falls through to posix",
			cfTimeZone:     "Asia/Tokyo",
			cfLocale:       "pt",
			cfCountry:      "",
			system:         simulatedSystem{env: map[string]string{"LANG": "vi_VN.UTF-8"}},
			wantTimezoneID: "Asia/Tokyo",
			wantLocaleName: "vi_VN.UTF-8",
		},
		{
			// An unresolvable time zone must not mask the POSIX sources.
			name:           "time zone falls through to posix",
			cfTimeZone:     "",
			cfLocale:       "en_CA",
			cfCountry:      "CA",
			system:         simulatedSystem{localtime: "/usr/share/zoneinfo/Africa/Cairo"},
			wantTimezoneID: "Africa/Cairo",
			wantLocaleName: "en_CA",
		},
		{
			name:           "countryless time zone falls through to posix",
			cfTimeZone:     "Etc/UTC",
			cfLocale:       "en_GB",
			cfCountry:      "GB",
			system:         simulatedSystem{timezoneFile: "Asia/Kabul\n"},
			wantTimezoneID: "Asia/Kabul",
			wantLocaleName: "en_GB",
		},
		{
			name:           "nothing available anywhere",
			cfTimeZone:     "",
			cfLocale:       "",
			cfCountry:      "",
			system:         simulatedSystem{},
			wantTimezoneID: "",
			wantLocaleName: "",
		},
		{
			// A country code that fails validation must not be wrapped into a
			// tag.
			name:           "invalid country code is not used",
			cfTimeZone:     "Asia/Tokyo",
			cfLocale:       "pt",
			cfCountry:      "419",
			system:         simulatedSystem{},
			wantTimezoneID: "Asia/Tokyo",
			wantLocaleName: "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			test.system.apply(t)

			got := darwinSignals(test.cfTimeZone, test.cfLocale, test.cfCountry)

			if got.Geo != "" {
				t.Errorf("geo: got %q, want empty on Darwin", got.Geo)
			}
			if got.TimezoneID != test.wantTimezoneID {
				t.Errorf("timezone: got %q, want %q", got.TimezoneID, test.wantTimezoneID)
			}
			if got.LocaleName != test.wantLocaleName {
				t.Errorf("locale: got %q, want %q", got.LocaleName, test.wantLocaleName)
			}
		})
	}
}

// TestDarwinUndTagResolves asserts that the tag darwinSignals synthesizes from
// the region setting is one regionFromLocaleName accepts. The "und" subtag is
// the BCP 47 undetermined language.
func TestDarwinUndTagResolves(t *testing.T) {

	for _, code := range []string{"JP", "CA", "TR", "UA", "GB"} {
		tag := "und-" + code
		region, ok := regionFromLocaleName(tag)
		if !ok {
			t.Errorf("%q does not resolve", tag)
			continue
		}
		if region != code {
			t.Errorf("%q resolved to %q, want %q", tag, region, code)
		}
	}
}
