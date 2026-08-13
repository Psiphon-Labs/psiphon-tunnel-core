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
	"path/filepath"
	"testing"
)

// These tests point the POSIX readings at a simulated /etc so that the full
// fallback chain is exercised on any platform. Without this, the chain is only
// reachable on a Linux machine, and the file branches would go untested.

// simulatedSystem is a fake /etc. A zero value has no files at all, which is the
// case for a minimal container image.
type simulatedSystem struct {
	localeConf   string // contents of /etc/locale.conf
	defaultLocal string // contents of /etc/default/locale
	localtime    string // symlink target for /etc/localtime
	timezoneFile string // contents of /etc/timezone
	env          map[string]string
}

// apply builds the simulated system and redirects the package at it for the
// duration of the test.
func (s simulatedSystem) apply(t *testing.T) {
	t.Helper()

	dir := t.TempDir()

	write := func(name, content string) string {
		path := filepath.Join(dir, name)
		if content == "" {
			return path // deliberately absent
		}
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}

	localeConf := write("locale.conf", s.localeConf)
	defaultLocale := write("default-locale", s.defaultLocal)
	timezoneFile := write("timezone", s.timezoneFile)

	localtime := filepath.Join(dir, "localtime")
	if s.localtime != "" {
		if err := os.Symlink(s.localtime, localtime); err != nil {
			t.Fatal(err)
		}
	}

	originalPaths := localeConfPaths
	originalLocaltime := localtimePath
	originalTimezoneFile := timezoneFilePath

	localeConfPaths = []string{localeConf, defaultLocale}
	localtimePath = localtime
	timezoneFilePath = timezoneFile

	t.Cleanup(func() {
		localeConfPaths = originalPaths
		localtimePath = originalLocaltime
		timezoneFilePath = originalTimezoneFile
	})

	// Clear every variable the package reads, then apply the case's own.
	for _, name := range append([]string{"TZ"}, localeEnvVars...) {
		t.Setenv(name, "")
	}
	for name, value := range s.env {
		t.Setenv(name, value)
	}
}

func TestSimulatedPosixLocaleName(t *testing.T) {

	tests := []struct {
		name   string
		system simulatedSystem
		want   string
	}{
		{
			name:   "environment wins over files",
			system: simulatedSystem{env: map[string]string{"LANG": "ja_JP.UTF-8"}, localeConf: "LANG=en_US.UTF-8\n"},
			want:   "ja_JP.UTF-8",
		},
		{
			name:   "systemd locale.conf when environment is empty",
			system: simulatedSystem{localeConf: "LANG=tr_TR.UTF-8\n"},
			want:   "tr_TR.UTF-8",
		},
		{
			name:   "debian default locale when locale.conf is absent",
			system: simulatedSystem{defaultLocal: "LANG=\"vi_VN.UTF-8\"\n"},
			want:   "vi_VN.UTF-8",
		},
		{
			name: "locale.conf takes precedence over default locale",
			system: simulatedSystem{
				localeConf:   "LANG=ru_RU.UTF-8\n",
				defaultLocal: "LANG=en_US.UTF-8\n",
			},
			want: "ru_RU.UTF-8",
		},
		{
			// A container image commonly sets only a regionless locale.
			name:   "regionless locale.conf falls through to default locale",
			system: simulatedSystem{localeConf: "LANG=C.UTF-8\n", defaultLocal: "LANG=uk_UA.UTF-8\n"},
			want:   "uk_UA.UTF-8",
		},
		{
			name: "formatting category inside a file wins over LANG",
			system: simulatedSystem{
				localeConf: "LANG=en_US.UTF-8\nLC_TIME=de_DE.UTF-8\n",
			},
			want: "de_DE.UTF-8",
		},
		{
			name:   "nothing configured",
			system: simulatedSystem{},
			want:   "",
		},
		{
			name:   "everything regionless",
			system: simulatedSystem{env: map[string]string{"LANG": "C"}, localeConf: "LANG=POSIX\n"},
			want:   "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			test.system.apply(t)
			if got := posixLocaleName(); got != test.want {
				t.Errorf("got %q, want %q", got, test.want)
			}
		})
	}
}

func TestSimulatedPosixTimezoneID(t *testing.T) {

	tests := []struct {
		name   string
		system simulatedSystem
		want   string
	}{
		{
			name:   "TZ wins",
			system: simulatedSystem{env: map[string]string{"TZ": "Asia/Tokyo"}, localtime: "/usr/share/zoneinfo/Europe/Kyiv"},
			want:   "Asia/Tokyo",
		},
		{
			name:   "localtime symlink",
			system: simulatedSystem{localtime: "/usr/share/zoneinfo/Europe/Kyiv"},
			want:   "Europe/Kyiv",
		},
		{
			name:   "debian timezone file when there is no symlink",
			system: simulatedSystem{timezoneFile: "Asia/Yangon\n"},
			want:   "Asia/Yangon",
		},
		{
			name: "symlink takes precedence over the timezone file",
			system: simulatedSystem{
				localtime:    "/usr/share/zoneinfo/Africa/Cairo",
				timezoneFile: "Europe/London\n",
			},
			want: "Africa/Cairo",
		},
		{
			// The POSIX TZ form is legal and names no zone; it must not mask the
			// remaining sources.
			name: "posix TZ form falls through to the symlink",
			system: simulatedSystem{
				env:       map[string]string{"TZ": "EST5EDT,M3.2.0,M11.1.0"},
				localtime: "/usr/share/zoneinfo/America/Toronto",
			},
			want: "America/Toronto",
		},
		{
			name: "UTC TZ falls through, having no country",
			system: simulatedSystem{
				env:          map[string]string{"TZ": "UTC"},
				timezoneFile: "Asia/Tbilisi\n",
			},
			want: "Asia/Tbilisi",
		},
		{
			// A copied rather than symlinked /etc/localtime is common, and the
			// timezone file is then the only usable source.
			name: "unresolvable symlink falls through to the timezone file",
			system: simulatedSystem{
				localtime:    "/dev/null",
				timezoneFile: "Asia/Kabul\n",
			},
			want: "Asia/Kabul",
		},
		{
			name:   "nothing configured",
			system: simulatedSystem{},
			want:   "",
		},
		{
			name: "all sources unusable",
			system: simulatedSystem{
				env:          map[string]string{"TZ": "Nowhere/Nothing"},
				localtime:    "/dev/null",
				timezoneFile: "Etc/UTC\n",
			},
			want: "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			test.system.apply(t)
			if got := posixTimezoneID(); got != test.want {
				t.Errorf("got %q, want %q", got, test.want)
			}
		})
	}
}

// TestSimulatedDistributions resolves a region end to end for configurations
// taken from real distributions, so that the whole chain is covered rather than
// each reading in isolation.
//
// On Darwin with cgo, Core Foundation supplies the readings and these files are
// only the fallback, so the assertion is limited to the resolution being valid.
func TestSimulatedDistributions(t *testing.T) {

	tests := []struct {
		name   string
		system simulatedSystem
		want   string
		source Source
	}{
		{
			name: "fedora workstation in Japan",
			system: simulatedSystem{
				localeConf: "LANG=ja_JP.UTF-8\n",
				localtime:  "/usr/share/zoneinfo/Asia/Tokyo",
			},
			want:   "JP",
			source: SourceTimezone,
		},
		{
			name: "debian desktop in Turkey",
			system: simulatedSystem{
				defaultLocal: "LANG=\"tr_TR.UTF-8\"\n",
				timezoneFile: "Europe/Istanbul\n",
			},
			want:   "TR",
			source: SourceTimezone,
		},
		{
			// The interface language is English while the formatting region is
			// the user's own, which is the common GNOME configuration.
			name: "english interface with a local region",
			system: simulatedSystem{
				env:       map[string]string{"LANG": "en_US.UTF-8", "LC_TIME": "uk_UA.UTF-8"},
				localtime: "/usr/share/zoneinfo/Europe/Kyiv",
			},
			want:   "UA",
			source: SourceTimezone,
		},
		{
			// A minimal container: no zone files, only a regionless locale.
			name:   "minimal container",
			system: simulatedSystem{env: map[string]string{"LANG": "C.UTF-8"}},
			want:   "",
			source: SourceNone,
		},
		{
			// Locale only, with no usable time zone, must still resolve.
			name: "locale only",
			system: simulatedSystem{
				env:       map[string]string{"LANG": "vi_VN.UTF-8"},
				localtime: "/dev/null",
			},
			want:   "VN",
			source: SourceLocale,
		},
		{
			// A stale zone name from a system without a recent tzdb update.
			name: "legacy zone name",
			system: simulatedSystem{
				localtime: "/usr/share/zoneinfo/Europe/Kiev",
			},
			want:   "UA",
			source: SourceTimezone,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			test.system.apply(t)

			detail := resolve(rawSignals{
				TimezoneID: posixTimezoneID(),
				LocaleName: posixLocaleName(),
			})

			if detail.Region != test.want {
				t.Errorf("region: got %q, want %q (candidates %v)",
					detail.Region, test.want, detail.Candidates)
			}
			if detail.Source != test.source {
				t.Errorf("source: got %q, want %q", detail.Source, test.source)
			}
		})
	}
}
