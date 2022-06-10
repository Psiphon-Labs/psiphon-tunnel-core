/*
 * Copyright (c) 2020, Psiphon Inc.
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

package common

import (
	"os"
	"strings"
	"testing"
)

func TestRedactIPAddresses(t *testing.T) {

	testCases := []struct {
		description    string
		input          string
		expectedOutput string
		escape         bool
	}{
		{
			"IPv4 address",
			"prefix 192.168.0.1 suffix",
			"prefix [redacted] suffix",
			false,
		},
		{
			"IPv6 address",
			"prefix 2001:0db8:0000:0000:0000:ff00:0042:8329 suffix",
			"prefix [redacted] suffix",
			false,
		},
		{
			"Remove leading zeros IPv6 address",
			"prefix 2001:db8:0:0:0:ff00:42:8329 suffix",
			"prefix [redacted] suffix",
			false,
		},
		{
			"Omit consecutive zeros sections IPv6 address",
			"prefix 2001:db8::ff00:42:8329 suffix",
			"prefix [redacted] suffix",
			false,
		},
		{
			"IPv4 mapped/translated/embedded address",
			"prefix 0::ffff:192.168.0.1, 0::ffff:0:192.168.0.1, 64:ff9b::192.168.0.1 suffix",
			"prefix [redacted], [redacted], [redacted] suffix",
			false,
		},
		{
			"IPv4 address and port",
			"read tcp 127.0.0.1:1025->127.0.0.1:8000: use of closed network connection",
			"read tcp [redacted]->[redacted]: use of closed network connection",
			false,
		},
		{
			"IPv6 address and port",
			"read tcp [2001:db8::ff00:42:8329]:1025->[2001:db8::ff00:42:8329]:8000: use of closed network connection",
			"read tcp [redacted]->[redacted]: use of closed network connection",
			false,
		},
		{
			"Loopback IPv6 address and invalid port number",
			"dial tcp [::1]:88888: network is unreachable",
			"dial tcp [redacted]: network is unreachable",
			false,
		},
		{
			"Numbers and periods",
			"prefix 192. 168. 0. 1 suffix",
			"prefix 192. 168. 0. 1 suffix",
			false,
		},
		{
			"Hex string and colon",
			"prefix 0123456789abcdef: suffix",
			"prefix 0123456789abcdef: suffix",
			false,
		},
		{
			"Colons",
			"prefix :: suffix",
			"prefix :: suffix",
			false,
		},
		{
			"Notice",
			`{"data":{"SSHClientVersion":"SSH-2.0-C","candidateNumber":0,"diagnosticID":"se0XVQ/4","dialPortNumber":"4000","establishedTunnelsCount":0,"isReplay":false,"networkLatencyMultiplier":2.8284780852763953,"networkType":"WIFI","protocol":"OSSH","region":"US","upstream_ossh_padding":7077},"noticeType":"ConnectedServer","timestamp":"2020-12-16T14:07:02.030Z"}`,
			`{"data":{"SSHClientVersion":"SSH-2.0-C","candidateNumber":0,"diagnosticID":"se0XVQ/4","dialPortNumber":"4000","establishedTunnelsCount":0,"isReplay":false,"networkLatencyMultiplier":2.8284780852763953,"networkType":"WIFI","protocol":"OSSH","region":"US","upstream_ossh_padding":7077},"noticeType":"ConnectedServer","timestamp":"2020-12-16T14:07:02.030Z"}`,
			false,
		},
		{
			"escape IPv4 address and port",
			"prefix 192.168.0.1:443 suffix",
			"prefix 192\\.168\\.0\\.1\\:443 suffix",
			true,
		},
		{
			"escape IPv6 address and port",
			"prefix [2001:db8::ff00:42:8329]:443 suffix",
			"prefix [2001\\:db8\\:\\:ff00\\:42\\:8329]\\:443 suffix",
			true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.description, func(t *testing.T) {
			input := testCase.input
			if testCase.escape {
				input = EscapeRedactIPAddressString(input)
			}
			output := RedactIPAddressesString(input)
			if output != testCase.expectedOutput {
				t.Errorf("unexpected output: %s", output)
			}
		})
	}
}

func TestRedactFilePaths(t *testing.T) {

	testCases := []struct {
		description    string
		input          string
		expectedOutput string
		filePaths      []string
	}{
		{
			"Absolute path",
			"prefix /a suffix",
			"prefix [redacted] suffix",
			nil,
		},
		{
			"Absolute path with directories",
			"prefix /a/b/c/d suffix",
			"prefix [redacted] suffix",
			nil,
		},
		{
			"Relative path 1",
			"prefix ./a/b/c/d suffix",
			"prefix [redacted] suffix",
			nil,
		},
		{
			"Relative path 2",
			"prefix a/b/c/d suffix",
			"prefix [redacted] suffix",
			nil,
		},
		{
			"Relative path 3",
			"prefix ../a/b/c/d/../ suffix",
			"prefix [redacted] suffix",
			nil,
		},
		{
			"File path with home directory tilde",
			"prefix ~/a/b/c/d suffix",
			"prefix [redacted] suffix",
			nil,
		},
		{
			"Multiple file paths",
			"prefix /a/b c/d suffix",
			"prefix [redacted] [redacted] suffix",
			nil,
		},
		{
			"File path with percent encoded spaces",
			"prefix /a/b%20c/d suffix",
			"prefix [redacted] suffix",
			nil,
		},
		{
			"Strip file paths unhandled case",
			"prefix /a/file name with spaces /e/f/g/ suffix",
			"prefix [redacted] name with spaces [redacted] suffix",
			nil,
		},
		{
			"Strip file paths catch unhandled case with provided path",
			"prefix /a/file name with spaces /e/f/g/ suffix",
			"prefix [redacted] [redacted] suffix",
			[]string{"/a/file name with spaces"},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.description, func(t *testing.T) {
			// For convenience replace separators in input string and
			// file paths with the OS-specific path separator here instead
			// constructing the test input strings with os.PathSeparator.
			input := strings.ReplaceAll(testCase.input, "/", string(os.PathSeparator))
			var filePaths []string
			for _, filePath := range testCase.filePaths {
				filePaths = append(filePaths, strings.ReplaceAll(filePath, "/", string(os.PathSeparator)))
			}
			output := RedactFilePaths(input, filePaths...)
			if output != testCase.expectedOutput {
				t.Errorf("unexpected output: %s", output)
			}
		})
	}
}
