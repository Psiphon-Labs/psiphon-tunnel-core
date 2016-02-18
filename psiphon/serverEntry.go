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

const (
	TUNNEL_PROTOCOL_SSH                  = "SSH"
	TUNNEL_PROTOCOL_OBFUSCATED_SSH       = "OSSH"
	TUNNEL_PROTOCOL_UNFRONTED_MEEK       = "UNFRONTED-MEEK-OSSH"
	TUNNEL_PROTOCOL_UNFRONTED_MEEK_HTTPS = "UNFRONTED-MEEK-HTTPS-OSSH"
	TUNNEL_PROTOCOL_FRONTED_MEEK         = "FRONTED-MEEK-OSSH"
	TUNNEL_PROTOCOL_FRONTED_MEEK_HTTP    = "FRONTED-MEEK-HTTP-OSSH"
)

var SupportedTunnelProtocols = []string{
	TUNNEL_PROTOCOL_FRONTED_MEEK,
	TUNNEL_PROTOCOL_FRONTED_MEEK_HTTP,
	TUNNEL_PROTOCOL_UNFRONTED_MEEK,
	TUNNEL_PROTOCOL_UNFRONTED_MEEK_HTTPS,
	TUNNEL_PROTOCOL_OBFUSCATED_SSH,
	TUNNEL_PROTOCOL_SSH,
}

// ServerEntry represents a Psiphon server. It contains information
// about how to establish a tunnel connection to the server through
// several protocols. Server entries are JSON records downloaded from
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
	MeekFrontingHosts             []string `json:"meekFrontingHosts"`
	MeekFrontingDomain            string   `json:"meekFrontingDomain"`
	MeekFrontingAddresses         []string `json:"meekFrontingAddresses"`
	MeekFrontingAddressesRegex    string   `json:"meekFrontingAddressesRegex"`
	MeekFrontingDisableSNI        bool     `json:"meekFrontingDisableSNI"`

	// These local fields are not expected to be present in downloaded server
	// entries. They are added by the client to record and report stats about
	// how and when server entries are obtained.
	LocalSource    string `json:"localSource"`
	LocalTimestamp string `json:"localTimestamp"`
}

type ServerEntrySource string

const (
	SERVER_ENTRY_SOURCE_EMBEDDED  ServerEntrySource = "EMBEDDED"
	SERVER_ENTRY_SOURCE_REMOTE    ServerEntrySource = "REMOTE"
	SERVER_ENTRY_SOURCE_DISCOVERY ServerEntrySource = "DISCOVERY"
	SERVER_ENTRY_SOURCE_TARGET    ServerEntrySource = "TARGET"
)

// SupportsProtocol returns true if and only if the ServerEntry has
// the necessary capability to support the specified tunnel protocol.
func (serverEntry *ServerEntry) SupportsProtocol(protocol string) bool {
	requiredCapability := strings.TrimSuffix(protocol, "-OSSH")
	return Contains(serverEntry.Capabilities, requiredCapability)
}

// GetSupportedProtocols returns a list of tunnel protocols supported
// by the ServerEntry's capabilities.
func (serverEntry *ServerEntry) GetSupportedProtocols() []string {
	supportedProtocols := make([]string, 0)
	for _, protocol := range SupportedTunnelProtocols {
		if serverEntry.SupportsProtocol(protocol) {
			supportedProtocols = append(supportedProtocols, protocol)
		}
	}
	return supportedProtocols
}

// DisableImpairedProtocols modifies the ServerEntry to disable
// the specified protocols.
// Note: this assumes that protocol capabilities are 1-to-1.
func (serverEntry *ServerEntry) DisableImpairedProtocols(impairedProtocols []string) {
	capabilities := make([]string, 0)
	for _, capability := range serverEntry.Capabilities {
		omit := false
		for _, protocol := range impairedProtocols {
			requiredCapability := strings.TrimSuffix(protocol, "-OSSH")
			if capability == requiredCapability {
				omit = true
				break
			}
		}
		if !omit {
			capabilities = append(capabilities, capability)
		}
	}
	serverEntry.Capabilities = capabilities
}

func (serverEntry *ServerEntry) GetDirectWebRequestPorts() []string {
	ports := make([]string, 0)
	if Contains(serverEntry.Capabilities, "handshake") {
		// Server-side configuration quirk: there's a port forward from
		// port 443 to the web server, which we can try, except on servers
		// running FRONTED_MEEK, which listens on port 443.
		if !serverEntry.SupportsProtocol(TUNNEL_PROTOCOL_FRONTED_MEEK) {
			ports = append(ports, "443")
		}
		ports = append(ports, serverEntry.WebServerPort)
	}
	return ports
}

// DecodeServerEntry extracts server entries from the encoding
// used by remote server lists and Psiphon server handshake requests.
//
// The resulting ServerEntry.LocalSource is populated with serverEntrySource,
// which should be one of SERVER_ENTRY_SOURCE_EMBEDDED, SERVER_ENTRY_SOURCE_REMOTE,
// SERVER_ENTRY_SOURCE_DISCOVERY, SERVER_ENTRY_SOURCE_TARGET.
// ServerEntry.LocalTimestamp is populated with the provided timestamp, which
// should be a RFC 3339 formatted string. These local fields are stored with the
// server entry and reported to the server as stats (a coarse granularity timestamp
// is reported).
func DecodeServerEntry(
	encodedServerEntry, timestamp string,
	serverEntrySource ServerEntrySource) (serverEntry *ServerEntry, err error) {

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

	// NOTE: if the source JSON happens to have values in these fields, they get clobbered.
	serverEntry.LocalSource = string(serverEntrySource)
	serverEntry.LocalTimestamp = timestamp

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
// See DecodeServerEntry for note on serverEntrySource/timestamp.
func DecodeAndValidateServerEntryList(
	encodedServerEntryList, timestamp string,
	serverEntrySource ServerEntrySource) (serverEntries []*ServerEntry, err error) {

	serverEntries = make([]*ServerEntry, 0)
	for _, encodedServerEntry := range strings.Split(encodedServerEntryList, "\n") {
		if len(encodedServerEntry) == 0 {
			continue
		}

		// TODO: skip this entry and continue if can't decode?
		serverEntry, err := DecodeServerEntry(encodedServerEntry, timestamp, serverEntrySource)
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
