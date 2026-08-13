//go:build ignore

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

// This program generates zones.go. Run it with:
//
//	go generate ./psiphon/common/deviceregion/
//
// It fetches the IANA time zone database and CLDR windowsZones mapping over
// the network and records the versions it used in the generated file.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	tzdbVersionURL  = "https://data.iana.org/time-zones/data/version"
	tzdbZoneTabURL  = "https://data.iana.org/time-zones/data/zone.tab"
	tzdbBackwardURL = "https://data.iana.org/time-zones/data/backward"

	cldrWindowsZonesURL = "https://raw.githubusercontent.com/unicode-org/cldr/main/common/supplemental/windowsZones.xml"
	cldrTimezoneURL     = "https://raw.githubusercontent.com/unicode-org/cldr/main/common/bcp47/timezone.xml"

	outputFilename = "zones.go"
)

func main() {
	log.SetFlags(0)
	log.SetPrefix("zones_gen: ")

	tzdbVersion := strings.TrimSpace(fetch(tzdbVersionURL))

	windowsZonesXML := fetch(cldrWindowsZonesURL)
	windowsZonesDigest := digest(windowsZonesXML)

	timezoneXML := fetch(cldrTimezoneURL)
	timezoneDigest := digest(timezoneXML)

	zoneCountry := parseZoneTab(fetch(tzdbZoneTabURL))
	log.Printf("zone.tab: %d canonical zones", len(zoneCountry))

	cldrTerritories := parseCLDRTerritories(timezoneXML)
	log.Printf("CLDR bcp47: %d zone names with a territory", len(cldrTerritories))

	aliases := parseBackward(fetch(tzdbBackwardURL), zoneCountry, cldrTerritories)

	ianaZoneCountry := make(map[string]string, len(zoneCountry)+len(aliases))
	for zone, region := range zoneCountry {
		ianaZoneCountry[zone] = region
	}
	for zone, region := range aliases {
		ianaZoneCountry[zone] = region
	}

	windowsZoneIANA := parseWindowsZones(windowsZonesXML)
	log.Printf("windowsZones: %d Windows zone names", len(windowsZoneIANA))

	// Drop Windows zones whose representative IANA zone has no country, as the
	// Etc/* UTC-offset pseudo-zones do. They can never yield a region, so
	// omitting them keeps TestWindowsZoneIANAIntegrity's invariant strict.
	var dropped []string
	for windowsZone, ianaZone := range windowsZoneIANA {
		if _, ok := ianaZoneCountry[ianaZone]; !ok {
			dropped = append(dropped, windowsZone)
			delete(windowsZoneIANA, windowsZone)
		}
	}
	sort.Strings(dropped)
	log.Printf("dropped %d country-less Windows zones: %s", len(dropped), strings.Join(dropped, ", "))

	var b strings.Builder
	writeHeader(&b, tzdbVersion, windowsZonesDigest, timezoneDigest)
	writeMap(&b, "ianaZoneCountry", ianaZoneCountry, ianaZoneCountryDoc)
	b.WriteString("\n")
	writeMap(&b, "windowsZoneIANA", windowsZoneIANA, windowsZoneIANADoc)

	if err := os.WriteFile(outputFilename, []byte(b.String()), 0644); err != nil {
		log.Fatalf("write %s: %v", outputFilename, err)
	}

	log.Printf("wrote %s: %d IANA entries, %d Windows entries",
		outputFilename, len(ianaZoneCountry), len(windowsZoneIANA))
	log.Printf("remember to run gofmt on %s", outputFilename)
}

func fetch(url string) string {
	client := &http.Client{Timeout: 60 * time.Second}
	response, err := client.Get(url)
	if err != nil {
		log.Fatalf("fetch %s: %v", url, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		log.Fatalf("fetch %s: %s", url, response.Status)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		log.Fatalf("read %s: %v", url, err)
	}
	return string(body)
}

// parseZoneTab parses zone.tab, whose tab-separated fields are the ISO 3166-1
// alpha-2 code, coordinates, zone name, and an optional comment. Each canonical
// zone appears once.
func parseZoneTab(data string) map[string]string {

	zoneCountry := make(map[string]string)

	for _, line := range strings.Split(data, "\n") {
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Split(strings.TrimRight(line, "\r"), "\t")
		if len(fields) < 3 {
			continue
		}
		region := strings.ToUpper(strings.TrimSpace(fields[0]))
		zone := strings.TrimSpace(fields[2])
		if len(region) != 2 || zone == "" {
			continue
		}
		if existing, ok := zoneCountry[zone]; ok && existing != region {
			log.Fatalf("zone %q is assigned to both %q and %q", zone, existing, region)
		}
		zoneCountry[zone] = region
	}

	if len(zoneCountry) == 0 {
		log.Fatal("zone.tab yielded no zones")
	}

	return zoneCountry
}

// parseBackward parses backward, whose Link lines have the form
// "Link TARGET LINK-NAME". These aliases are pre-rename zone names, such as
// Europe/Kiev for Europe/Kyiv, which systems on older tzdb still report.
//
// An alias is only accepted when the country of its link target agrees with the
// territory CLDR assigns the alias itself. tzdb links zones that share DST
// rules, not zones in the same country, so the target's country is not always
// the alias's: tzdb retired Africa/Timbuktu by linking it to Africa/Abidjan,
// which would place Mali in Côte d'Ivoire. Requiring two independent sources to
// agree drops every such alias without this generator having to assert any
// geography of its own. A dropped alias simply yields no region, and the caller
// falls through to its next signal.
func parseBackward(
	data string, zoneCountry, cldrTerritories map[string]string) map[string]string {

	aliases := make(map[string]string)
	var rejected []string

	for _, line := range strings.Split(data, "\n") {
		if !strings.HasPrefix(line, "Link") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		target, name := fields[1], fields[2]

		// Skip a name that zone.tab already assigns directly.
		if _, ok := zoneCountry[name]; ok {
			continue
		}

		// Skip the flat legacy names. An IANA zone name is Area/Location, and
		// every canonical zone has that form; the flat names are compatibility
		// aliases that name no location. Some are whole-continent abbreviations
		// for which no single country is correct, such as CET and EET, and tzdb
		// and CLDR agree only because both pick the same arbitrary
		// representative. The rest, such as Japan and Poland, are obsolete names
		// that no current system reports.
		if !strings.Contains(name, "/") {
			continue
		}

		// Skip an alias whose target has no country, such as the Etc/* zones.
		region, ok := zoneCountry[target]
		if !ok {
			continue
		}

		if cldrTerritories[name] != region {
			rejected = append(rejected,
				fmt.Sprintf("%s(link=%s,cldr=%s)", name, region, cldrTerritories[name]))
			continue
		}

		aliases[name] = region
	}

	sort.Strings(rejected)
	log.Printf("backward: %d aliases accepted, %d rejected on disagreement: %s",
		len(aliases), len(rejected), strings.Join(rejected, " "))

	return aliases
}

var cldrTypeRE = regexp.MustCompile(`<type name="([^"]+)"[^>]*?alias="([^"]*)"`)

// parseCLDRTerritories maps a time zone name to the ISO 3166-1 alpha-2 territory
// CLDR places it in, which is the first two letters of its BCP 47 key: the key
// for Africa/Timbuktu is mlbko, giving ML.
//
// This is used only to cross-check the backward aliases. It is deliberately not
// used for the canonical zones, where zone.tab is authoritative: the key prefix
// is a territory by convention rather than by rule, and it misfires for a few
// zones whose key abbreviates the city instead, such as Asia/Jerusalem keying to
// jeusl and so appearing to be JE.
func parseCLDRTerritories(data string) map[string]string {

	territories := make(map[string]string)

	for _, match := range cldrTypeRE.FindAllStringSubmatch(data, -1) {
		key, aliases := match[1], strings.Fields(match[2])

		// The UTC-offset and unknown keys name no territory.
		if strings.HasPrefix(key, "utc") || strings.HasPrefix(key, "unk") {
			continue
		}
		if len(key) < 2 {
			continue
		}
		territory := strings.ToUpper(key[:2])
		if territory[0] < 'A' || territory[0] > 'Z' || territory[1] < 'A' || territory[1] > 'Z' {
			continue
		}

		for _, alias := range aliases {
			territories[alias] = territory
		}
	}

	if len(territories) == 0 {
		log.Fatal("CLDR timezone.xml yielded no territories")
	}

	return territories
}

var mapZoneRE = regexp.MustCompile(`<mapZone\s+other="([^"]+)"\s+territory="([^"]+)"\s+type="([^"]+)"`)

// parseWindowsZones parses the CLDR windowsZones mapping, keeping the
// territory="001" rows, which name the default representative IANA zone for
// each Windows zone. The type attribute may list several; the first is
// representative.
func parseWindowsZones(data string) map[string]string {

	windowsZoneIANA := make(map[string]string)

	for _, match := range mapZoneRE.FindAllStringSubmatch(data, -1) {
		windowsZone, territory, ianaZones := match[1], match[2], match[3]
		if territory != "001" {
			continue
		}
		zones := strings.Fields(ianaZones)
		if len(zones) == 0 {
			continue
		}
		windowsZoneIANA[windowsZone] = zones[0]
	}

	if len(windowsZoneIANA) == 0 {
		log.Fatal("windowsZones.xml yielded no zones")
	}

	return windowsZoneIANA
}

func writeMap(b *strings.Builder, name string, mapping map[string]string, doc string) {

	keys := make([]string, 0, len(mapping))
	for key := range mapping {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	b.WriteString(doc)
	fmt.Fprintf(b, "var %s = map[string]string{\n", name)
	for _, key := range keys {
		fmt.Fprintf(b, "\t%q: %q,\n", key, mapping[key])
	}
	b.WriteString("}\n")
}

// digest identifies a fetched source by content. CLDR windowsZones.xml carries
// no usable version number of its own, and the output must be a pure function
// of the inputs so that regenerating without an upstream change produces no
// diff. That is what makes "go generate && git diff --exit-code" a valid drift
// check for a scheduled job.
func digest(data string) string {
	sum := sha256.Sum256([]byte(data))
	return hex.EncodeToString(sum[:])[:12]
}

func writeHeader(b *strings.Builder, tzdbVersion, windowsZonesDigest, timezoneDigest string) {
	b.WriteString(gplHeader)
	fmt.Fprintf(b, `// Code generated by zones_gen.go. DO NOT EDIT.
//
// Sources:
//
//	IANA tzdb %s
//	  %s
//	  %s
//
//	CLDR, main branch
//	  %s
//	    sha256 %s
//	  %s
//	    sha256 %s
//
// Regenerate with:
//
//	go generate ./psiphon/common/deviceregion/
//
// Regenerating without an upstream change produces no diff, so a scheduled job
// can detect new releases with:
//
//	go generate ./psiphon/common/deviceregion/ && git diff --exit-code

package deviceregion

`,
		tzdbVersion,
		tzdbZoneTabURL,
		tzdbBackwardURL,
		cldrWindowsZonesURL,
		windowsZonesDigest,
		cldrTimezoneURL,
		timezoneDigest)
}

const gplHeader = `/*
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

`

const ianaZoneCountryDoc = `// ianaZoneCountry maps an IANA time zone name to the ISO 3166-1 alpha-2 code of
// the country containing it. Aliases from backward are included alongside the
// canonical zones, because a system on older tzdb reports the pre-rename name,
// such as Europe/Kiev rather than Europe/Kyiv. Zones with no country, such as
// the Etc/* UTC-offset zones, are omitted.
`

const windowsZoneIANADoc = `// windowsZoneIANA maps a Windows time zone key name, as reported by
// GetDynamicTimeZoneInformation, to a representative IANA zone.
//
// Windows zone names span countries, so this uses the CLDR territory="001"
// default: a machine in Austria resolves through "W. Europe Standard Time" to
// Europe/Berlin and so to DE. This signal is therefore coarse and is ranked
// below the Windows home-location setting; disagreement between the two is not
// necessarily an error.
`
