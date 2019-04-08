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

package protocol

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
)

// ServerEntry represents a Psiphon server. It contains information
// about how to establish a tunnel connection to the server through
// several protocols. Server entries are JSON records downloaded from
// various sources.
type ServerEntry struct {
	Tag                           string   `json:"tag"`
	IpAddress                     string   `json:"ipAddress"`
	WebServerPort                 string   `json:"webServerPort"` // not an int
	WebServerSecret               string   `json:"webServerSecret"`
	WebServerCertificate          string   `json:"webServerCertificate"`
	SshPort                       int      `json:"sshPort"`
	SshUsername                   string   `json:"sshUsername"`
	SshPassword                   string   `json:"sshPassword"`
	SshHostKey                    string   `json:"sshHostKey"`
	SshObfuscatedPort             int      `json:"sshObfuscatedPort"`
	SshObfuscatedQUICPort         int      `json:"sshObfuscatedQUICPort"`
	SshObfuscatedTapdancePort     int      `json:"sshObfuscatedTapdancePort"`
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
	TacticsRequestPublicKey       string   `json:"tacticsRequestPublicKey"`
	TacticsRequestObfuscatedKey   string   `json:"tacticsRequestObfuscatedKey"`
	MarionetteFormat              string   `json:"marionetteFormat"`
	ConfigurationVersion          int      `json:"configurationVersion"`

	// These local fields are not expected to be present in downloaded server
	// entries. They are added by the client to record and report stats about
	// how and when server entries are obtained.
	LocalSource    string `json:"localSource"`
	LocalTimestamp string `json:"localTimestamp"`
}

// ServerEntryFields is an alternate representation of ServerEntry which
// enables future compatibility when unmarshaling and persisting new server
// entries which may contain new, unrecognized fields not in the ServerEntry
// type for a particular client version.
//
// When new JSON server entries with new fields are unmarshaled to ServerEntry
// types, unrecognized fields are discarded. When unmarshaled to
// ServerEntryFields, unrecognized fields are retained and may be persisted
// and available when the client is upgraded and unmarshals to an updated
// ServerEntry type.
type ServerEntryFields map[string]interface{}

func (fields ServerEntryFields) GetTag() string {
	tag, ok := fields["tag"]
	if !ok {
		return ""
	}
	tagStr, ok := tag.(string)
	if !ok {
		return ""
	}
	return tagStr
}

func (fields ServerEntryFields) SetTag(tag string) {
	fields["tag"] = tag
}

func (fields ServerEntryFields) GetIPAddress() string {
	ipAddress, ok := fields["ipAddress"]
	if !ok {
		return ""
	}
	ipAddressStr, ok := ipAddress.(string)
	if !ok {
		return ""
	}
	return ipAddressStr
}

func (fields ServerEntryFields) GetWebServerSecret() string {
	webServerSecret, ok := fields["webServerSecret"]
	if !ok {
		return ""
	}
	webServerSecretStr, ok := webServerSecret.(string)
	if !ok {
		return ""
	}
	return webServerSecretStr
}

func (fields ServerEntryFields) GetConfigurationVersion() int {
	configurationVersion, ok := fields["configurationVersion"]
	if !ok {
		return 0
	}
	configurationVersionInt, ok := configurationVersion.(int)
	if !ok {
		return 0
	}
	return configurationVersionInt
}

func (fields ServerEntryFields) SetLocalSource(source string) {
	fields["localSource"] = source
}

func (fields ServerEntryFields) SetLocalTimestamp(timestamp string) {
	fields["localTimestamp"] = timestamp
}

// GetCapability returns the server capability corresponding
// to the tunnel protocol.
func GetCapability(protocol string) string {
	return strings.TrimSuffix(protocol, "-OSSH")
}

// GetTacticsCapability returns the server tactics capability
// corresponding to the tunnel protocol.
func GetTacticsCapability(protocol string) string {
	return GetCapability(protocol) + "-TACTICS"
}

// SupportsProtocol returns true if and only if the ServerEntry has
// the necessary capability to support the specified tunnel protocol.
func (serverEntry *ServerEntry) SupportsProtocol(protocol string) bool {
	requiredCapability := GetCapability(protocol)
	return common.Contains(serverEntry.Capabilities, requiredCapability)
}

// GetSupportedProtocols returns a list of tunnel protocols supported
// by the ServerEntry's capabilities.
func (serverEntry *ServerEntry) GetSupportedProtocols(
	useUpstreamProxy bool,
	limitTunnelProtocols []string,
	excludeIntensive bool) []string {

	supportedProtocols := make([]string, 0)

	for _, protocol := range SupportedTunnelProtocols {

		// TODO: Marionette UDP formats are incompatible with
		// useUpstreamProxy, but not currently supported
		if useUpstreamProxy && TunnelProtocolUsesQUIC(protocol) {
			continue
		}

		if len(limitTunnelProtocols) > 0 {
			if !common.Contains(limitTunnelProtocols, protocol) {
				continue
			}
		} else {
			if common.Contains(DefaultDisabledTunnelProtocols, protocol) {
				continue
			}
		}

		if excludeIntensive && TunnelProtocolIsResourceIntensive(protocol) {
			continue
		}

		if serverEntry.SupportsProtocol(protocol) {
			supportedProtocols = append(supportedProtocols, protocol)
		}

	}
	return supportedProtocols
}

// GetSupportedTacticsProtocols returns a list of tunnel protocols,
// supported by the ServerEntry's capabilities, that may be used
// for tactics requests.
func (serverEntry *ServerEntry) GetSupportedTacticsProtocols() []string {

	supportedProtocols := make([]string, 0)

	for _, protocol := range SupportedTunnelProtocols {

		if !TunnelProtocolUsesMeek(protocol) {
			continue
		}

		requiredCapability := GetTacticsCapability(protocol)
		if !common.Contains(serverEntry.Capabilities, requiredCapability) {
			continue
		}

		supportedProtocols = append(supportedProtocols, protocol)
	}

	return supportedProtocols
}

// SupportsSSHAPIRequests returns true when the server supports
// SSH API requests.
func (serverEntry *ServerEntry) SupportsSSHAPIRequests() bool {
	return common.Contains(serverEntry.Capabilities, CAPABILITY_SSH_API_REQUESTS)
}

func (serverEntry *ServerEntry) GetUntunneledWebRequestPorts() []string {
	ports := make([]string, 0)
	if common.Contains(serverEntry.Capabilities, CAPABILITY_UNTUNNELED_WEB_API_REQUESTS) {
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

// GenerateServerEntryTag creates a server entry tag value that is
// cryptographically derived from the IP address and web server secret in a
// way that is difficult to reverse the IP address value from the tag or
// compute the tag without having the web server secret, a 256-bit random
// value which is unique per server, in addition to the IP address. A database
// consisting only of server entry tags should be resistent to an attack that
// attempts to reverse all the server IPs, even given a small IP space (IPv4),
// or some subset of the web server secrets.
func GenerateServerEntryTag(ipAddress, webServerSecret string) string {
	h := hmac.New(sha256.New, []byte(webServerSecret))
	h.Write([]byte(ipAddress))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// EncodeServerEntry returns a string containing the encoding of
// a ServerEntry following Psiphon conventions.
func EncodeServerEntry(serverEntry *ServerEntry) (string, error) {
	serverEntryContents, err := json.Marshal(serverEntry)
	if err != nil {
		return "", common.ContextError(err)
	}

	return hex.EncodeToString([]byte(fmt.Sprintf(
		"%s %s %s %s %s",
		serverEntry.IpAddress,
		serverEntry.WebServerPort,
		serverEntry.WebServerSecret,
		serverEntry.WebServerCertificate,
		serverEntryContents))), nil
}

// DecodeServerEntry extracts a server entry from the encoding
// used by remote server lists and Psiphon server handshake requests.
//
// The resulting ServerEntry.LocalSource is populated with serverEntrySource,
// which should be one of SERVER_ENTRY_SOURCE_EMBEDDED, SERVER_ENTRY_SOURCE_REMOTE,
// SERVER_ENTRY_SOURCE_DISCOVERY, SERVER_ENTRY_SOURCE_TARGET,
// SERVER_ENTRY_SOURCE_OBFUSCATED.
// ServerEntry.LocalTimestamp is populated with the provided timestamp, which
// should be a RFC 3339 formatted string. These local fields are stored with the
// server entry and reported to the server as stats (a coarse granularity timestamp
// is reported).
func DecodeServerEntry(
	encodedServerEntry, timestamp, serverEntrySource string) (*ServerEntry, error) {

	serverEntry := new(ServerEntry)
	err := decodeServerEntry(encodedServerEntry, timestamp, serverEntrySource, serverEntry)
	if err != nil {
		return nil, common.ContextError(err)
	}

	// NOTE: if the source JSON happens to have values in these fields, they get clobbered.
	serverEntry.LocalSource = serverEntrySource
	serverEntry.LocalTimestamp = timestamp

	return serverEntry, nil
}

// DecodeServerEntryFields extracts an encoded server entry into a
// ServerEntryFields type, much like DecodeServerEntry. Unrecognized fields
// not in ServerEntry are retained in the ServerEntryFields.
func DecodeServerEntryFields(
	encodedServerEntry, timestamp, serverEntrySource string) (ServerEntryFields, error) {

	serverEntryFields := make(ServerEntryFields)
	err := decodeServerEntry(encodedServerEntry, timestamp, serverEntrySource, &serverEntryFields)
	if err != nil {
		return nil, common.ContextError(err)
	}

	// NOTE: if the source JSON happens to have values in these fields, they get clobbered.
	serverEntryFields.SetLocalSource(serverEntrySource)
	serverEntryFields.SetLocalTimestamp(timestamp)

	return serverEntryFields, nil
}

func decodeServerEntry(
	encodedServerEntry, timestamp, serverEntrySource string,
	target interface{}) error {

	hexDecodedServerEntry, err := hex.DecodeString(encodedServerEntry)
	if err != nil {
		return common.ContextError(err)
	}

	// Skip past legacy format (4 space delimited fields) and just parse the JSON config
	fields := bytes.SplitN(hexDecodedServerEntry, []byte(" "), 5)
	if len(fields) != 5 {
		return common.ContextError(errors.New("invalid encoded server entry"))
	}

	err = json.Unmarshal(fields[4], target)
	if err != nil {
		return common.ContextError(err)
	}

	return nil
}

// ValidateServerEntryFields checks for malformed server entries.
// Currently, it checks for a valid ipAddress. This is important since
// the IP address is the key used to store/lookup the server entry.
// TODO: validate more fields?
func ValidateServerEntryFields(serverEntryFields ServerEntryFields) error {
	ipAddress := serverEntryFields.GetIPAddress()
	if net.ParseIP(ipAddress) == nil {
		return common.ContextError(
			fmt.Errorf("server entry has invalid ipAddress: %s", ipAddress))
	}
	return nil
}

// DecodeServerEntryList extracts server entries from the list encoding
// used by remote server lists and Psiphon server handshake requests.
// Each server entry is validated and invalid entries are skipped.
// See DecodeServerEntry for note on serverEntrySource/timestamp.
func DecodeServerEntryList(
	encodedServerEntryList, timestamp,
	serverEntrySource string) ([]ServerEntryFields, error) {

	serverEntries := make([]ServerEntryFields, 0)
	for _, encodedServerEntry := range strings.Split(encodedServerEntryList, "\n") {
		if len(encodedServerEntry) == 0 {
			continue
		}

		// TODO: skip this entry and continue if can't decode?
		serverEntryFields, err := DecodeServerEntryFields(encodedServerEntry, timestamp, serverEntrySource)
		if err != nil {
			return nil, common.ContextError(err)
		}

		if ValidateServerEntryFields(serverEntryFields) != nil {
			// Skip this entry and continue with the next one
			// TODO: invoke a logging callback
			continue
		}

		serverEntries = append(serverEntries, serverEntryFields)
	}
	return serverEntries, nil
}

// StreamingServerEntryDecoder performs the DecodeServerEntryList
// operation, loading only one server entry into memory at a time.
type StreamingServerEntryDecoder struct {
	scanner           *bufio.Scanner
	timestamp         string
	serverEntrySource string
}

// NewStreamingServerEntryDecoder creates a new StreamingServerEntryDecoder.
func NewStreamingServerEntryDecoder(
	encodedServerEntryListReader io.Reader,
	timestamp, serverEntrySource string) *StreamingServerEntryDecoder {

	return &StreamingServerEntryDecoder{
		scanner:           bufio.NewScanner(encodedServerEntryListReader),
		timestamp:         timestamp,
		serverEntrySource: serverEntrySource,
	}
}

// Next reads and decodes, and validates the next server entry from the
// input stream, returning a nil server entry when the stream is complete.
//
// Limitations:
// - Each encoded server entry line cannot exceed bufio.MaxScanTokenSize,
//   the default buffer size which this decoder uses. This is 64K.
// - DecodeServerEntry is called on each encoded server entry line, which
//   will allocate memory to hex decode and JSON deserialze the server
//   entry. As this is not presently reusing a fixed buffer, each call
//   will allocate additional memory; garbage collection is necessary to
//   reclaim that memory for reuse for the next server entry.
//
func (decoder *StreamingServerEntryDecoder) Next() (ServerEntryFields, error) {

	for {
		if !decoder.scanner.Scan() {
			return nil, common.ContextError(decoder.scanner.Err())
		}

		// TODO: use scanner.Bytes which doesn't allocate, instead of scanner.Text

		// TODO: skip this entry and continue if can't decode?
		serverEntryFields, err := DecodeServerEntryFields(
			decoder.scanner.Text(), decoder.timestamp, decoder.serverEntrySource)
		if err != nil {
			return nil, common.ContextError(err)
		}

		if ValidateServerEntryFields(serverEntryFields) != nil {
			// Skip this entry and continue with the next one
			// TODO: invoke a logging callback
			continue
		}

		return serverEntryFields, nil
	}
}
