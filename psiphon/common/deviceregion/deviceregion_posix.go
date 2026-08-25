//go:build !windows

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
	"strings"
)

// The POSIX readings shared by every non-Windows platform, including Darwin,
// where they are the cgo-disabled fallback.

// The system paths read below. These are variables rather than constants so
// that tests can point them at a simulated filesystem, which is the only way to
// exercise the fallback chain on a platform that does not have these files.
var (
	// localeConfPaths are read when the environment carries no usable locale,
	// which is common for a process not started from a shell. /etc/locale.conf
	// is the systemd location and /etc/default/locale the Debian one.
	localeConfPaths = []string{
		"/etc/locale.conf",
		"/etc/default/locale",
	}

	localtimePath    = "/etc/localtime"
	timezoneFilePath = "/etc/timezone"
)

// posixLocaleName returns a locale name from the environment, falling back to
// the locale configuration files.
func posixLocaleName() string {

	if name := localeNameFromEnv(os.Getenv); name != "" {
		return name
	}

	for _, path := range localeConfPaths {
		if name := localeNameFromFile(path); name != "" {
			return name
		}
	}

	return ""
}

// localeNameFromFile applies the localeNameFromEnv precedence to the
// assignments in a locale configuration file.
func localeNameFromFile(path string) string {

	values := parseAssignments(path)
	if len(values) == 0 {
		return ""
	}

	return localeNameFromEnv(func(name string) string { return values[name] })
}

// parseAssignments reads a file of NAME=value lines, as used by
// /etc/locale.conf. Values may be quoted. Comments and malformed lines are
// skipped.
func parseAssignments(path string) map[string]string {

	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	values := make(map[string]string)

	for _, line := range strings.Split(string(data), "\n") {

		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		name, value, found := strings.Cut(line, "=")
		if !found {
			continue
		}

		name = strings.TrimSpace(name)
		value = strings.TrimSpace(value)
		value = strings.Trim(value, `"'`)

		if name != "" && value != "" {
			values[name] = value
		}
	}

	return values
}

// posixTimezoneID returns an IANA zone name from TZ, the /etc/localtime
// symlink, or /etc/timezone.
//
// Each candidate is checked against the zone table, so that a value which does
// not name a zone, such as the POSIX TZ form "EST5EDT,M3.2.0,M11.1.0", falls
// through to the next source rather than suppressing it.
func posixTimezoneID() string {

	candidates := []string{
		os.Getenv("TZ"),
		zoneFromSymlink(localtimePath),
		firstLineOfFile(timezoneFilePath),
	}

	for _, candidate := range candidates {
		if _, ok := regionFromTimezoneID(candidate); ok {
			return candidate
		}
	}

	return ""
}

// zoneFromSymlink resolves a zoneinfo symlink, as /etc/localtime usually is, to
// an IANA zone name.
func zoneFromSymlink(path string) string {

	target, err := os.Readlink(path)
	if err != nil {
		return ""
	}

	return ianaZoneFromPath(target)
}

// firstLineOfFile returns the first non-empty, non-comment line of a file, as
// /etc/timezone holds the zone name that way.
func firstLineOfFile(path string) string {

	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}

	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			return line
		}
	}

	return ""
}
