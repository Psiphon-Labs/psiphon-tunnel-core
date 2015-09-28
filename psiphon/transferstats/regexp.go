/*
 * Copyright (c) 2015, Psiphon Inc.
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

package transferstats

import (
	"fmt"
	"regexp"
)

type regexpReplace struct {
	regexp  *regexp.Regexp
	replace string
}

// Regexps holds the regular expressions and replacement strings used for
// transforming URLs and hostnames into a stats-appropriate forms.
type Regexps []regexpReplace

// MakeRegexps takes the raw string-map form of the regex-replace pairs
// returned by the server handshake and turns them into a usable object.
func MakeRegexps(pageViewRegexes, httpsRequestRegexes []map[string]string) (regexps *Regexps, notices []string) {
	regexpsSlice := make(Regexps, 0)
	notices = make([]string, 0)

	// We aren't doing page view stats anymore, so we won't process those regexps.
	for _, rr := range httpsRequestRegexes {
		regexString := rr["regex"]
		if regexString == "" {
			notices = append(notices, "MakeRegexps: empty regex")
			continue
		}

		replace := rr["replace"]
		if replace == "" {
			notices = append(notices, "MakeRegexps: empty replace")
			continue
		}

		regex, err := regexp.Compile(regexString)
		if err != nil {
			notices = append(notices, fmt.Sprintf("MakeRegexps: failed to compile regex: %s: %s", regexString, err))
			continue
		}

		regexpsSlice = append(regexpsSlice, regexpReplace{regex, replace})
	}

	regexps = &regexpsSlice

	return
}

// regexHostname processes hostname through the given regexps and returns the
// string that should be used for stats.
func regexHostname(hostname string, regexps *Regexps) (statsHostname string) {
	statsHostname = "(OTHER)"
	if regexps != nil {
		for _, rr := range *regexps {
			if rr.regexp.MatchString(hostname) {
				statsHostname = rr.regexp.ReplaceAllString(hostname, rr.replace)
				break
			}
		}
	}
	return
}
