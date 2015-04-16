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

package psiphon

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
)

// ServerEntry represents a Psiphon server. It contains information
// about how to estalish a tunnel connection to the server through
// several protocols. ServerEntry are JSON records downloaded from
// various sources.
type ServerEntry struct {
	IpAddress                     string   `json:"ipAddress"`
	WebServerPort                 string   `json:"webServerPort"` // not an int
	WebServerSecret               string   `json:"webServerSecret"`
	WebServerCertificate          string   `json:"webServerCertificate"`
	SshPort                       int      `json:"sshPort"`
	SshUsername                   string   `json:"sshUsername"`
	SshPassword                   string   `json:"sshPassword"`
	SshHostKey                    string   `json:"sshHostKey"`
	SshObfuscatedPort             int      `json:"sshObfuscatedPort"`
	SshObfuscatedKey              string   `json:"sshObfuscatedKey"`
	Capabilities                  []string `json:"capabilities"`
	Region                        string   `json:"region"`
	MeekServerPort                int      `json:"meekServerPort"`
	MeekCookieEncryptionPublicKey string   `json:"meekCookieEncryptionPublicKey"`
	MeekObfuscatedKey             string   `json:"meekObfuscatedKey"`
	MeekFrontingHost              string   `json:"meekFrontingHost"`
	MeekFrontingDomain            string   `json:"meekFrontingDomain"`
	MeekFrontingAddresses         []string `json:"meekFrontingAddresses"`
}

// DecodeServerEntry extracts server entries from the encoding
// used by remote server lists and Psiphon server handshake requests.
func DecodeServerEntry(encodedServerEntry string) (serverEntry *ServerEntry, err error) {
	hexDecodedServerEntry, err := hex.DecodeString(encodedServerEntry)
	if err != nil {
		return nil, ContextError(err)
	}
	// Skip past legacy format (4 space delimited fields) and just parse the JSON config
	fields := bytes.SplitN(hexDecodedServerEntry, []byte(" "), 5)
	if len(fields) != 5 {
		return nil, ContextError(errors.New("invalid encoded server entry"))
	}
	serverEntry = new(ServerEntry)
	err = json.Unmarshal(fields[4], &serverEntry)
	if err != nil {
		return nil, ContextError(err)
	}

	return serverEntry, nil
}

// ValidateServerEntry checks for malformed server entries.
// Currently, it checks for a valid ipAddress. This is important since
// handshake requests submit back to the server a list of known server
// IP addresses and the handshake API expects well-formed inputs.
// TODO: validate more fields
func ValidateServerEntry(serverEntry *ServerEntry) error {
	ipAddr := net.ParseIP(serverEntry.IpAddress)
	if ipAddr == nil {
		errMsg := fmt.Sprintf("server entry has invalid IpAddress: '%s'", serverEntry.IpAddress)
		// Some callers skip invalid server entries without propagating
		// the error mesage, so issue a notice.
		NoticeAlert(errMsg)
		return ContextError(errors.New(errMsg))
	}
	return nil
}

// DecodeAndValidateServerEntryList extracts server entries from the list encoding
// used by remote server lists and Psiphon server handshake requests.
// Each server entry is validated and invalid entries are skipped.
func DecodeAndValidateServerEntryList(encodedServerEntryList string) (serverEntries []*ServerEntry, err error) {
	serverEntries = make([]*ServerEntry, 0)
	for _, encodedServerEntry := range strings.Split(encodedServerEntryList, "\n") {
		if len(encodedServerEntry) == 0 {
			continue
		}

		// TODO: skip this entry and continue if can't decode?
		serverEntry, err := DecodeServerEntry(encodedServerEntry)
		if err != nil {
			return nil, ContextError(err)
		}

		if ValidateServerEntry(serverEntry) != nil {
			// Skip this entry and continue with the next one
			continue
		}

		serverEntries = append(serverEntries, serverEntry)
	}
	return serverEntries, nil
}
