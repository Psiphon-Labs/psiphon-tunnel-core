/*
 * Copyright (c) 2014, Psiphon Inc.
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

package psiphon

import "regexp"

type regexpReplace struct {
	regexp  *regexp.Regexp
	replace string
}

type Regexps []regexpReplace

func MakeRegexps(pageViewRegexes, httpsRequestRegexes []map[string]string) *Regexps {
	regexps := make(Regexps, 0)

	// We aren't doing page view stats anymore, so we won't process those regexps.
	for _, rr := range httpsRequestRegexes {
		regexString := rr["regex"]
		if regexString == "" {
			Notice(NOTICE_ALERT, "MakeRegexps: empty regex")
			continue
		}

		replace := rr["replace"]
		if replace == "" {
			Notice(NOTICE_ALERT, "MakeRegexps: empty replace")
			continue
		}

		regex, err := regexp.Compile(regexString)
		if err != nil {
			Notice(NOTICE_ALERT, "MakeRegexps: failed to compile regex: %s: %s", regexString, err)
			continue
		}

		regexps = append(regexps, regexpReplace{regex, replace})
	}

	return &regexps
}

func regexHostname(hostname string, regexps *Regexps) (statsHostname string) {
	statsHostname = "(OTHER)"
	for _, rr := range *regexps {
		if rr.regexp.MatchString(hostname) {
			statsHostname = rr.regexp.ReplaceAllString(hostname, rr.replace)
			break
		}
	}
	return
}
