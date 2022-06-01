/*
 * Copyright (c) 2022, Psiphon Inc.
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
	std_errors "errors"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
)

// RedactURLError transforms an error, when it is a url.Error, removing
// the URL value. This is to avoid logging private user data in cases
// where the URL may be a user input value.
// This function is used with errors returned by net/http and net/url,
// which are (currently) of type url.Error. In particular, the round trip
// function used by our HttpProxy, http.Client.Do, returns errors of type
// url.Error, with the URL being the url sent from the user's tunneled
// applications:
// https://github.com/golang/go/blob/release-branch.go1.4/src/net/http/client.go#L394
func RedactURLError(err error) error {
	if urlErr, ok := err.(*url.Error); ok {
		err = &url.Error{
			Op:  urlErr.Op,
			URL: "",
			Err: urlErr.Err,
		}
	}
	return err
}

var redactIPAddressAndPortRegex = regexp.MustCompile(
	// IP address
	`(` +
		// IPv4
		//
		// An IPv4 address can also be represented as an unsigned integer, or with
		// octal or with hex octet values, but we do not check for any of these
		// uncommon representations as some may match non-IP values and we don't
		// expect the "net" package, etc., to emit them.)

		`\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|` +

		// IPv6
		//
		// Optional brackets for IPv6 with port
		`\[?` +
		`(` +
		// Uncompressed IPv6; ensure there are 8 segments to avoid matching, e.g., a
		// timestamp
		`(([a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4})|` +
		// Compressed IPv6
		`([a-fA-F0-9:]*::[a-fA-F0-9:]+)|([a-fA-F0-9:]+::[a-fA-F0-9:]*)` +
		`)` +
		// Optional mapped/translated/embeded IPv4 suffix
		`(.\d{1,3}\.\d{1,3}\.\d{1,3})?` +
		`\]?` +
		`)` +

		// Optional port number
		`(:\d+)?`)

// RedactIPAddresses returns a copy of the input with all IP addresses (and
// optional ports) replaced by "[redacted]". This is intended to be used to
// redact addresses from "net" package I/O error messages and otherwise avoid
// inadvertently recording direct server IPs via error message logs; and, in
// metrics, to reduce the error space due to superfluous source port data.
//
// RedactIPAddresses uses a simple regex match which liberally matches IP
// address-like patterns and will match invalid addresses; for example, it
// will match port numbers greater than 65535. We err on the side of redaction
// and are not as concerned, in this context, with false positive matches. If
// a user configures an upstream proxy address with an invalid IP or port
// value, we prefer to redact it.
//
// See the redactIPAddressAndPortRegex comment for some uncommon IP address
// representations that are not matched.
func RedactIPAddresses(b []byte) []byte {
	return redactIPAddressAndPortRegex.ReplaceAll(b, []byte("[redacted]"))
}

// RedactIPAddressesString is RedactIPAddresses for strings.
func RedactIPAddressesString(s string) string {
	return redactIPAddressAndPortRegex.ReplaceAllString(s, "[redacted]")
}

// EscapeRedactIPAddressString escapes the IP or IP:port addresses in the
// input in such a way that they won't be redacted when part of the input to
// RedactIPAddresses.
//
// The escape encoding is not guaranteed to be reversable or suitable for
// machine processing; the goal is to simply ensure the original value is
// human readable.
func EscapeRedactIPAddressString(address string) string {
	address = strings.ReplaceAll(address, ".", "\\.")
	address = strings.ReplaceAll(address, ":", "\\:")
	return address
}

var redactFilePathRegex = regexp.MustCompile(
	// File path
	`(` +
		// Leading characters
		`[^ ]*` +
		// At least one path separator
		`/` +
		// Path component; take until next space
		`[^ ]*` +
		`)+`)

// RedactFilePaths returns a copy of the input with all file paths
// replaced by "[redacted]". First any occurrences of the provided file paths
// are replaced and then an attempt is made to replace any other file paths by
// searching with a heuristic. The latter is a best effort attempt it is not
// guaranteed that it will catch every file path.
func RedactFilePaths(s string, filePaths ...string) string {
	for _, filePath := range filePaths {
		s = strings.ReplaceAll(s, filePath, "[redacted]")
	}
	return redactFilePathRegex.ReplaceAllLiteralString(filepath.ToSlash(s), "[redacted]")
}

// RedactFilePathsError is RedactFilePaths for errors.
func RedactFilePathsError(err error, filePaths ...string) error {
	return std_errors.New(RedactFilePaths(err.Error(), filePaths...))
}

// RedactNetError removes network address information from a "net" package
// error message. Addresses may be domains or IP addresses.
//
// Limitations: some non-address error context can be lost; this function
// makes assumptions about how the Go "net" package error messages are
// formatted and will fail to redact network addresses if this assumptions
// become untrue.
func RedactNetError(err error) error {

	// Example "net" package error messages:
	//
	// - lookup <domain>: no such host
	// - lookup <domain>: No address associated with hostname
	// - dial tcp <address>: connectex: No connection could be made because the target machine actively refused it
	// - write tcp <address>-><address>: write: connection refused

	if err == nil {
		return err
	}

	errstr := err.Error()
	index := strings.Index(errstr, ": ")
	if index == -1 {
		return err
	}

	return std_errors.New("[redacted]" + errstr[index:])
}
