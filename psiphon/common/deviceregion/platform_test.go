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
	"os"
	"runtime"
	"sort"
	"testing"
)

// These tests run on whichever platform is building. They assert shape rather
// than any particular region, so that they pass unattended anywhere, including
// on a machine with no locale or time zone configured.

func TestPlatformSignalsShape(t *testing.T) {

	raw := platformSignals()

	t.Logf("%s/%s raw signals: geo=%q timezone=%q locale=%q",
		runtime.GOOS, runtime.GOARCH, raw.Geo, raw.TimezoneID, raw.LocaleName)

	// A reading is either unusable, and ignored, or it parses. Nothing may
	// panic and nothing may produce an invalid region.
	if region, ok := parseRegionCode(raw.Geo); ok {
		if len(region) != 2 {
			t.Errorf("geo %q parsed to %q", raw.Geo, region)
		}
	}
	if region, ok := regionFromTimezoneID(raw.TimezoneID); ok {
		if len(region) != 2 {
			t.Errorf("timezone %q parsed to %q", raw.TimezoneID, region)
		}
	}
	if region, ok := regionFromLocaleName(raw.LocaleName); ok {
		if len(region) != 2 {
			t.Errorf("locale %q parsed to %q", raw.LocaleName, region)
		}
	}

	// Only Windows has a home-location setting.
	if runtime.GOOS != "windows" && raw.Geo != "" {
		t.Errorf("geo signal %q on %s, which has no home-location setting",
			raw.Geo, runtime.GOOS)
	}
}

func TestPlatformSignalsStable(t *testing.T) {

	first := platformSignals()

	for i := 0; i < 10; i++ {
		if platformSignals() != first {
			t.Fatalf("platformSignals is not stable across calls: %+v then %+v",
				first, platformSignals())
		}
	}
}

func TestGetIsConsistent(t *testing.T) {

	first := Get()

	for i := 0; i < 10; i++ {
		if got := Get(); got != first {
			t.Fatalf("Get returned %q then %q", first, got)
		}
	}

	detail := GetDetail()

	if detail.Region != first {
		t.Errorf("GetDetail.Region %q does not match Get %q", detail.Region, first)
	}

	if detail.Region == "" {
		if detail.Source != SourceNone {
			t.Errorf("empty region with source %q", detail.Source)
		}
	} else {
		if detail.Source == SourceNone {
			t.Errorf("region %q with SourceNone", detail.Region)
		}
		if detail.Candidates[detail.Source] != detail.Region {
			t.Errorf("Region %q is not the candidate for Source %q (%q)",
				detail.Region, detail.Source, detail.Candidates[detail.Source])
		}
	}

	for source, candidate := range detail.Candidates {
		if _, ok := parseRegionCode(candidate); !ok {
			t.Errorf("candidate %q from %q is not a valid region code", candidate, source)
		}
	}
}

// TestGetNoPanicUnderEmptyEnvironment exercises the path taken by a process
// started with no environment, as a service or a desktop application launched
// from a file manager may be.
func TestGetNoPanicUnderEmptyEnvironment(t *testing.T) {

	for _, name := range append([]string{"TZ"}, localeEnvVars...) {
		t.Setenv(name, "")
	}

	region := Get()

	t.Logf("region with an empty environment: %q", region)

	if region != "" {
		if _, ok := parseRegionCode(region); !ok {
			t.Errorf("%q is not a valid region code", region)
		}
	}
}

// TestDeviceRegionProbe reports what this machine resolves, for verification on
// a real system. It asserts nothing, since the correct answer depends on how
// the machine is configured; a human compares the output against the machine's
// actual location and settings.
//
//	CONDUIT_TEST_DEVICE_REGION=1 go test -v -run TestDeviceRegionProbe \
//	    ./psiphon/common/deviceregion/
func TestDeviceRegionProbe(t *testing.T) {

	if os.Getenv("CONDUIT_TEST_DEVICE_REGION") == "" {
		t.Skip("set CONDUIT_TEST_DEVICE_REGION=1 to run")
	}

	raw := platformSignals()
	detail := GetDetail()

	t.Logf("platform:  %s/%s", runtime.GOOS, runtime.GOARCH)
	t.Logf("raw geo:       %q", raw.Geo)
	t.Logf("raw timezone:  %q", raw.TimezoneID)
	t.Logf("raw locale:    %q", raw.LocaleName)

	sources := make([]string, 0, len(detail.Candidates))
	for source := range detail.Candidates {
		sources = append(sources, string(source))
	}
	sort.Strings(sources)

	for _, source := range sources {
		t.Logf("candidate %-9s %q", source, detail.Candidates[Source(source)])
	}

	t.Logf("RESOLVED:  %q from %q", detail.Region, detail.Source)

	if detail.Region == "" {
		t.Logf("NOTE: no region resolved; DeviceRegion would be reported empty")
	}

	if len(detail.Candidates) > 1 {
		distinct := make(map[string]bool)
		for _, region := range detail.Candidates {
			distinct[region] = true
		}
		if len(distinct) > 1 {
			t.Logf("NOTE: signals disagree; on Windows this is expected, as the " +
				"time zone signal is country-coarse")
		}
	}
}
