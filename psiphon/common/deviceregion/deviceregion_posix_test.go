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

func TestParseAssignments(t *testing.T) {

	tests := []struct {
		name    string
		content string
		want    map[string]string
	}{
		{
			name:    "systemd locale.conf",
			content: "LANG=en_US.UTF-8\nLC_TIME=de_DE.UTF-8\n",
			want:    map[string]string{"LANG": "en_US.UTF-8", "LC_TIME": "de_DE.UTF-8"},
		},
		{
			name:    "debian default/locale with quotes",
			content: "LANG=\"ja_JP.UTF-8\"\nLANGUAGE=\"ja_JP:ja\"\n",
			want:    map[string]string{"LANG": "ja_JP.UTF-8", "LANGUAGE": "ja_JP:ja"},
		},
		{
			name:    "single quotes",
			content: "LANG='tr_TR.UTF-8'\n",
			want:    map[string]string{"LANG": "tr_TR.UTF-8"},
		},
		{
			name:    "comments and blank lines skipped",
			content: "# a comment\n\n  \nLANG=ru_RU.UTF-8\n# LANG=should_not_win\n",
			want:    map[string]string{"LANG": "ru_RU.UTF-8"},
		},
		{
			name:    "surrounding whitespace trimmed",
			content: "  LANG  =  en_GB.UTF-8  \n",
			want:    map[string]string{"LANG": "en_GB.UTF-8"},
		},
		{
			name:    "malformed lines skipped",
			content: "not an assignment\nLANG=en_CA.UTF-8\n=novalue\nEMPTY=\n",
			want:    map[string]string{"LANG": "en_CA.UTF-8"},
		},
		{
			name:    "crlf line endings",
			content: "LANG=vi_VN.UTF-8\r\nLC_TIME=vi_VN.UTF-8\r\n",
			want:    map[string]string{"LANG": "vi_VN.UTF-8", "LC_TIME": "vi_VN.UTF-8"},
		},
		{
			name:    "empty file",
			content: "",
			want:    map[string]string{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			path := filepath.Join(t.TempDir(), "locale.conf")
			if err := os.WriteFile(path, []byte(test.content), 0600); err != nil {
				t.Fatal(err)
			}

			got := parseAssignments(path)

			if len(got) != len(test.want) {
				t.Fatalf("got %v, want %v", got, test.want)
			}
			for name, want := range test.want {
				if got[name] != want {
					t.Errorf("%s: got %q, want %q", name, got[name], want)
				}
			}
		})
	}
}

func TestParseAssignmentsMissingFile(t *testing.T) {

	if values := parseAssignments(filepath.Join(t.TempDir(), "absent")); values != nil {
		t.Errorf("got %v, want nil for a missing file", values)
	}
}

func TestLocaleNameFromFile(t *testing.T) {

	tests := []struct {
		name    string
		content string
		want    string
	}{
		{
			// The precedence from localeNameFromEnv must apply to file
			// assignments too.
			name:    "formatting category beats LANG",
			content: "LANG=en_US.UTF-8\nLC_TIME=de_DE.UTF-8\n",
			want:    "de_DE.UTF-8",
		},
		{
			name:    "LC_ALL beats everything",
			content: "LC_ALL=ja_JP.UTF-8\nLC_TIME=de_DE.UTF-8\nLANG=en_US.UTF-8\n",
			want:    "ja_JP.UTF-8",
		},
		{
			name:    "LANG when alone",
			content: "LANG=tr_TR.UTF-8\n",
			want:    "tr_TR.UTF-8",
		},
		{
			name:    "regionless values skipped",
			content: "LC_ALL=C.UTF-8\nLANG=ru_RU.UTF-8\n",
			want:    "ru_RU.UTF-8",
		},
		{
			name:    "nothing usable",
			content: "LANG=C\nLC_ALL=POSIX\n",
			want:    "",
		},
		{
			// LANGUAGE is a GNU extension holding a preference list, not a
			// locale, and is not in localeEnvVars.
			name:    "LANGUAGE ignored",
			content: "LANGUAGE=ja_JP:ja\n",
			want:    "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			path := filepath.Join(t.TempDir(), "locale.conf")
			if err := os.WriteFile(path, []byte(test.content), 0600); err != nil {
				t.Fatal(err)
			}

			if got := localeNameFromFile(path); got != test.want {
				t.Errorf("got %q, want %q", got, test.want)
			}
		})
	}
}

func TestZoneFromSymlink(t *testing.T) {

	tests := []struct {
		name   string
		target string
		want   string
	}{
		{"linux zoneinfo", "/usr/share/zoneinfo/Asia/Tokyo", "Asia/Tokyo"},
		{"macos zoneinfo", "/var/db/timezone/zoneinfo/America/Toronto", "America/Toronto"},
		{"relative target", "../usr/share/zoneinfo/Europe/Kyiv", "Europe/Kyiv"},
		{"multi component zone", "/usr/share/zoneinfo/America/Argentina/Salta", "America/Argentina/Salta"},
		{"posix subtree", "/usr/share/zoneinfo/posix/Europe/Kyiv", "Europe/Kyiv"},
		{"not a zoneinfo path", "/dev/null", ""},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			path := filepath.Join(t.TempDir(), "localtime")
			if err := os.Symlink(test.target, path); err != nil {
				t.Fatal(err)
			}

			if got := zoneFromSymlink(path); got != test.want {
				t.Errorf("got %q, want %q", got, test.want)
			}
		})
	}
}

func TestZoneFromSymlinkNotASymlink(t *testing.T) {

	dir := t.TempDir()

	missing := filepath.Join(dir, "absent")
	if got := zoneFromSymlink(missing); got != "" {
		t.Errorf("missing path: got %q, want empty", got)
	}

	// On some systems /etc/localtime is a copy rather than a symlink, which
	// must not be reported as a zone name.
	regular := filepath.Join(dir, "regular")
	if err := os.WriteFile(regular, []byte("TZif2"), 0600); err != nil {
		t.Fatal(err)
	}
	if got := zoneFromSymlink(regular); got != "" {
		t.Errorf("regular file: got %q, want empty", got)
	}
}

func TestFirstLineOfFile(t *testing.T) {

	tests := []struct {
		name    string
		content string
		want    string
	}{
		{"debian timezone", "Europe/Istanbul\n", "Europe/Istanbul"},
		{"no trailing newline", "Asia/Tokyo", "Asia/Tokyo"},
		{"leading blank lines", "\n\n  \nAsia/Kabul\n", "Asia/Kabul"},
		{"comment skipped", "# generated\nAfrica/Cairo\n", "Africa/Cairo"},
		{"whitespace trimmed", "   Europe/Kyiv   \n", "Europe/Kyiv"},
		{"crlf", "Asia/Yangon\r\n", "Asia/Yangon"},
		{"empty", "", ""},
		{"only comments", "# nothing here\n", ""},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			path := filepath.Join(t.TempDir(), "timezone")
			if err := os.WriteFile(path, []byte(test.content), 0600); err != nil {
				t.Fatal(err)
			}

			if got := firstLineOfFile(path); got != test.want {
				t.Errorf("got %q, want %q", got, test.want)
			}
		})
	}
}

func TestFirstLineOfFileMissing(t *testing.T) {

	if got := firstLineOfFile(filepath.Join(t.TempDir(), "absent")); got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

// TestPosixTimezoneIDPrefersTZ covers the TZ branch of posixTimezoneID, which
// is the only part reachable without writing to absolute system paths.
func TestPosixTimezoneIDPrefersTZ(t *testing.T) {

	tests := []struct {
		name string
		tz   string
		want string
	}{
		{"iana name", "Asia/Tokyo", "Asia/Tokyo"},
		{"leading colon", ":Europe/Kyiv", ":Europe/Kyiv"},
		{"legacy alias", "Europe/Kiev", "Europe/Kiev"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			t.Setenv("TZ", test.tz)

			if got := posixTimezoneID(); got != test.want {
				t.Errorf("got %q, want %q", got, test.want)
			}

			// Whatever is returned must resolve, which is the property
			// platformSignals depends on.
			if _, ok := regionFromTimezoneID(test.want); !ok {
				t.Errorf("%q does not resolve to a region", test.want)
			}
		})
	}
}

// TestPosixTimezoneIDIgnoresUnusableTZ asserts that a TZ value which does not
// name a zone falls through to the next source rather than suppressing it. The
// POSIX form is legal in TZ and would otherwise mask /etc/localtime.
func TestPosixTimezoneIDIgnoresUnusableTZ(t *testing.T) {

	for _, tz := range []string{
		"EST5EDT,M3.2.0,M11.1.0",
		"UTC",
		"Etc/UTC",
		"Nowhere/Nothing",
	} {
		t.Run(tz, func(t *testing.T) {

			t.Setenv("TZ", tz)

			got := posixTimezoneID()
			if got == tz {
				t.Errorf("unusable TZ %q was returned instead of falling through", tz)
			}

			// Any fallback value must itself resolve.
			if got != "" {
				if _, ok := regionFromTimezoneID(got); !ok {
					t.Errorf("fallback %q does not resolve to a region", got)
				}
			}
		})
	}
}

// TestPosixLocaleNamePrefersEnv covers the environment branch of
// posixLocaleName.
func TestPosixLocaleNamePrefersEnv(t *testing.T) {

	t.Setenv("LC_ALL", "")
	t.Setenv("LC_MONETARY", "")
	t.Setenv("LC_TIME", "")
	t.Setenv("LC_MEASUREMENT", "")
	t.Setenv("LC_PAPER", "")
	t.Setenv("LC_NUMERIC", "")
	t.Setenv("LANG", "ja_JP.UTF-8")

	if got := posixLocaleName(); got != "ja_JP.UTF-8" {
		t.Errorf("got %q, want %q", got, "ja_JP.UTF-8")
	}

	t.Setenv("LC_TIME", "de_DE.UTF-8")

	if got := posixLocaleName(); got != "de_DE.UTF-8" {
		t.Errorf("formatting category should win: got %q", got)
	}
}
