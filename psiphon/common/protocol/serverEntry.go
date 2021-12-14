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
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
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
	LimitQUICVersions             []string `json:"limitQUICVersions"`
	SshObfuscatedTapDancePort     int      `json:"sshObfuscatedTapdancePort"`
	SshObfuscatedConjurePort      int      `json:"sshObfuscatedConjurePort"`
	SshObfuscatedKey              string   `json:"sshObfuscatedKey"`
	Capabilities                  []string `json:"capabilities"`
	Region                        string   `json:"region"`
	FrontingProviderID            string   `json:"frontingProviderID"`
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
	ConfigurationVersion          int      `json:"configurationVersion"`
	Signature                     string   `json:"signature"`

	// These local fields are not expected to be present in downloaded server
	// entries. They are added by the client to record and report stats about
	// how and when server entries are obtained.
	// All local fields should be included the list of fields in RemoveUnsignedFields.
	LocalSource       string `json:"localSource,omitempty"`
	LocalTimestamp    string `json:"localTimestamp,omitempty"`
	IsLocalDerivedTag bool   `json:"isLocalDerivedTag,omitempty"`
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

// GetServerEntry converts a ServerEntryFields into a ServerEntry.
func (fields ServerEntryFields) GetServerEntry() (*ServerEntry, error) {

	marshaledServerEntry, err := json.Marshal(fields)
	if err != nil {
		return nil, errors.Trace(err)
	}

	var serverEntry *ServerEntry
	err = json.Unmarshal(marshaledServerEntry, &serverEntry)
	if err != nil {
		return nil, errors.Trace(err)
	}

	return serverEntry, nil
}

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

// SetTag sets a local, derived server entry tag. A tag is an identifier used
// in server entry pruning and potentially other use cases. An explict tag,
// set by the Psiphon Network, may be present in a server entry that is
// imported; otherwise, the client will set a derived tag. The tag should be
// generated using GenerateServerEntryTag. When SetTag finds a explicit tag,
// the new, derived tag is ignored. The isLocalTag local field is set to
// distinguish explict and derived tags and is used in signature verification
// to determine if the tag field is part of the signature.
func (fields ServerEntryFields) SetTag(tag string) {

	// Don't replace explicit tag
	if tag, ok := fields["tag"]; ok {
		tagStr, ok := tag.(string)
		if ok && tagStr != "" {
			isLocalDerivedTag, ok := fields["isLocalDerivedTag"]
			if !ok {
				return
			}
			isLocalDerivedTagBool, ok := isLocalDerivedTag.(bool)
			if ok && !isLocalDerivedTagBool {
				return
			}
		}
	}

	fields["tag"] = tag

	// Mark this tag as local
	fields["isLocalDerivedTag"] = true
}

func (fields ServerEntryFields) GetDiagnosticID() string {
	tag, ok := fields["tag"]
	if !ok {
		return ""
	}
	tagStr, ok := tag.(string)
	if !ok {
		return ""
	}
	return TagToDiagnosticID(tagStr)
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

func (fields ServerEntryFields) GetWebServerPort() string {
	webServerPort, ok := fields["webServerPort"]
	if !ok {
		return ""
	}
	webServerPortStr, ok := webServerPort.(string)
	if !ok {
		return ""
	}
	return webServerPortStr
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

func (fields ServerEntryFields) GetWebServerCertificate() string {
	webServerCertificate, ok := fields["webServerCertificate"]
	if !ok {
		return ""
	}
	webServerCertificateStr, ok := webServerCertificate.(string)
	if !ok {
		return ""
	}
	return webServerCertificateStr
}

func (fields ServerEntryFields) GetConfigurationVersion() int {
	configurationVersion, ok := fields["configurationVersion"]
	if !ok {
		return 0
	}
	configurationVersionFloat, ok := configurationVersion.(float64)
	if !ok {
		return 0
	}
	return int(configurationVersionFloat)
}

func (fields ServerEntryFields) GetLocalSource() string {
	localSource, ok := fields["localSource"]
	if !ok {
		return ""
	}
	localSourceStr, ok := localSource.(string)
	if !ok {
		return ""
	}
	return localSourceStr
}

func (fields ServerEntryFields) SetLocalSource(source string) {
	fields["localSource"] = source
}

func (fields ServerEntryFields) GetLocalTimestamp() string {
	localTimestamp, ok := fields["localTimestamp"]
	if !ok {
		return ""
	}
	localTimestampStr, ok := localTimestamp.(string)
	if !ok {
		return ""
	}
	return localTimestampStr
}

func (fields ServerEntryFields) SetLocalTimestamp(timestamp string) {
	fields["localTimestamp"] = timestamp
}

func (fields ServerEntryFields) HasSignature() bool {
	signature, ok := fields["signature"]
	if !ok {
		return false
	}
	signatureStr, ok := signature.(string)
	if !ok {
		return false
	}
	return signatureStr != ""
}

const signaturePublicKeyDigestSize = 8

// AddSignature signs a server entry and attaches a new field containing the
// signature. Any existing "signature" field will be replaced.
//
// The signature incudes a public key ID that is derived from a digest of the
// public key value. This ID is intended for future use when multiple signing
// keys may be deployed.
func (fields ServerEntryFields) AddSignature(publicKey, privateKey string) error {

	// Make a copy so that removing unsigned fields will have no side effects
	copyFields := make(ServerEntryFields)
	for k, v := range fields {
		copyFields[k] = v
	}

	copyFields.RemoveUnsignedFields()

	delete(copyFields, "signature")

	// Best practise would be to sign the JSON encoded server entry bytes and
	// append the signature to those bytes. However, due to backwards
	// compatibility requirements, we must retain the outer server entry encoding
	// as-is and insert the signature.
	//
	// Limitation: since the verifyier must remarshal its server entry before
	// verifying, the JSON produced there must be a byte-for-byte match to the
	// JSON signed here. The precise output of the JSON encoder that is used,
	// "encoding/json", with default formatting, as of Go 1.11.5, is therefore
	// part of the signature protocol.
	//
	// TODO: use a standard, canonical encoding, such as JCS:
	// https://tools.ietf.org/id/draft-rundgren-json-canonicalization-scheme-05.html

	marshaledFields, err := json.Marshal(copyFields)
	if err != nil {
		return errors.Trace(err)
	}

	decodedPublicKey, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		return errors.Trace(err)
	}

	publicKeyDigest := sha256.Sum256(decodedPublicKey)
	publicKeyID := publicKeyDigest[:signaturePublicKeyDigestSize]

	decodedPrivateKey, err := base64.StdEncoding.DecodeString(privateKey)
	if err != nil {
		return errors.Trace(err)
	}

	signature := ed25519.Sign(decodedPrivateKey, marshaledFields)

	fields["signature"] = base64.StdEncoding.EncodeToString(
		append(publicKeyID, signature...))

	return nil
}

// VerifySignature verifies the signature set by AddSignature.
//
// VerifySignature must be called before using any server entry that is
// imported from an untrusted source, such as client-to-client exchange.
func (fields ServerEntryFields) VerifySignature(publicKey string) error {

	if publicKey == "" {
		return errors.TraceNew("missing public key")
	}

	// Make a copy so that removing unsigned fields will have no side effects
	copyFields := make(ServerEntryFields)
	for k, v := range fields {
		copyFields[k] = v
	}

	signatureField, ok := copyFields["signature"]
	if !ok {
		return errors.TraceNew("missing signature field")
	}

	signatureFieldStr, ok := signatureField.(string)
	if !ok {
		return errors.TraceNew("invalid signature field")
	}

	decodedSignatureField, err := base64.StdEncoding.DecodeString(signatureFieldStr)
	if err != nil {
		return errors.Trace(err)
	}

	if len(decodedSignatureField) < signaturePublicKeyDigestSize {
		return errors.TraceNew("invalid signature field length")
	}

	publicKeyID := decodedSignatureField[:signaturePublicKeyDigestSize]
	signature := decodedSignatureField[signaturePublicKeyDigestSize:]

	if len(signature) != ed25519.SignatureSize {
		return errors.TraceNew("invalid signature length")
	}

	decodedPublicKey, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		return errors.Trace(err)
	}

	publicKeyDigest := sha256.Sum256(decodedPublicKey)
	expectedPublicKeyID := publicKeyDigest[:signaturePublicKeyDigestSize]

	if !bytes.Equal(expectedPublicKeyID, publicKeyID) {
		return errors.TraceNew("unexpected public key ID")
	}

	copyFields.RemoveUnsignedFields()

	delete(copyFields, "signature")

	marshaledFields, err := json.Marshal(copyFields)
	if err != nil {
		return errors.Trace(err)
	}

	if !ed25519.Verify(decodedPublicKey, marshaledFields, signature) {
		return errors.TraceNew("invalid signature")
	}

	return nil
}

// RemoveUnsignedFields prepares a server entry for signing or signature
// verification by removing unsigned fields. The JSON marshalling of the
// remaining fields is the data that is signed.
func (fields ServerEntryFields) RemoveUnsignedFields() {
	delete(fields, "localSource")
	delete(fields, "localTimestamp")

	// Only non-local, explicit tags are part of the signature
	isLocalDerivedTag := fields["isLocalDerivedTag"]
	isLocalDerivedTagBool, ok := isLocalDerivedTag.(bool)
	if ok && isLocalDerivedTagBool {
		delete(fields, "tag")
	}
	delete(fields, "isLocalDerivedTag")
}

// NewServerEntrySignatureKeyPair creates an ed25519 key pair for use in
// server entry signing and verification.
func NewServerEntrySignatureKeyPair() (string, string, error) {

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", errors.Trace(err)
	}

	return base64.StdEncoding.EncodeToString(publicKey),
		base64.StdEncoding.EncodeToString(privateKey),
		nil
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

// hasCapability indicates if the server entry has the specified capability.
//
// Any internal "PASSTHROUGH-v2 or "PASSTHROUGH" componant in the server
// entry's capabilities is ignored. These PASSTHROUGH components are used to
// mask protocols which are running the passthrough mechanisms from older
// clients which do not implement the passthrough messages. Older clients
// will treat these capabilities as unknown protocols and skip them.
//
// Any "QUICv1" capability is treated as "QUIC". "QUICv1" is used to mask the
// QUIC-OSSH capability from older clients to ensure that older clients do
// not send gQUIC packets to second generation QUICv1-only QUIC-OSSH servers.
// New clients must check SupportsOnlyQUICv1 before selecting a QUIC version;
// for "QUICv1", this ensures that new clients also do not select gQUIC to
// QUICv1-only servers.
func (serverEntry *ServerEntry) hasCapability(requiredCapability string) bool {
	for _, capability := range serverEntry.Capabilities {

		capability = strings.ReplaceAll(capability, "-PASSTHROUGH-v2", "")
		capability = strings.ReplaceAll(capability, "-PASSTHROUGH", "")

		quicCapability := GetCapability(TUNNEL_PROTOCOL_QUIC_OBFUSCATED_SSH)
		if capability == quicCapability+"v1" {
			capability = quicCapability
		}

		if capability == requiredCapability {
			return true
		}
	}
	return false
}

// SupportsProtocol returns true if and only if the ServerEntry has
// the necessary capability to support the specified tunnel protocol.
func (serverEntry *ServerEntry) SupportsProtocol(protocol string) bool {
	requiredCapability := GetCapability(protocol)
	return serverEntry.hasCapability(requiredCapability)
}

// ProtocolUsesLegacyPassthrough indicates whether the ServerEntry supports
// the specified protocol using legacy passthrough messages.
//
// There is no correspondong check for v2 passthrough, as clients send v2
// passthrough messages unconditionally, by default, for passthrough
// protocols.
func (serverEntry *ServerEntry) ProtocolUsesLegacyPassthrough(protocol string) bool {
	legacyCapability := GetCapability(protocol) + "-PASSTHROUGH"
	for _, capability := range serverEntry.Capabilities {
		if capability == legacyCapability {
			return true
		}
	}
	return false
}

// SupportsOnlyQUICv1 indicates that the QUIC-OSSH server supports only QUICv1
// and gQUIC versions should not be selected, as they will fail to connect
// while sending atypical traffic to the server.
func (serverEntry *ServerEntry) SupportsOnlyQUICv1() bool {
	quicCapability := GetCapability(TUNNEL_PROTOCOL_QUIC_OBFUSCATED_SSH)
	return serverEntry.hasCapability(quicCapability+"v1") && !serverEntry.hasCapability(quicCapability)
}

// ConditionallyEnabledComponents defines an interface which can be queried to
// determine which conditionally compiled protocol components are present.
type ConditionallyEnabledComponents interface {
	QUICEnabled() bool
	RefractionNetworkingEnabled() bool
}

// TunnelProtocolPortLists is a map from tunnel protocol names (or "All") to a
// list of port number ranges.
type TunnelProtocolPortLists map[string]*common.PortList

// GetSupportedProtocols returns a list of tunnel protocols supported by the
// ServerEntry's capabilities and allowed by various constraints.
func (serverEntry *ServerEntry) GetSupportedProtocols(
	conditionallyEnabled ConditionallyEnabledComponents,
	useUpstreamProxy bool,
	limitTunnelProtocols TunnelProtocols,
	limitTunnelDialPortNumbers TunnelProtocolPortLists,
	limitQUICVersions QUICVersions,
	excludeIntensive bool) TunnelProtocols {

	supportedProtocols := make(TunnelProtocols, 0)

	for _, tunnelProtocol := range SupportedTunnelProtocols {

		if useUpstreamProxy && !TunnelProtocolSupportsUpstreamProxy(tunnelProtocol) {
			continue
		}

		if len(limitTunnelProtocols) > 0 {
			if !common.Contains(limitTunnelProtocols, tunnelProtocol) {
				continue
			}
		} else {
			if common.Contains(DefaultDisabledTunnelProtocols, tunnelProtocol) {
				continue
			}
		}

		if excludeIntensive && TunnelProtocolIsResourceIntensive(tunnelProtocol) {
			continue
		}

		if (TunnelProtocolUsesQUIC(tunnelProtocol) && !conditionallyEnabled.QUICEnabled()) ||
			(TunnelProtocolUsesRefractionNetworking(tunnelProtocol) &&
				!conditionallyEnabled.RefractionNetworkingEnabled()) {
			continue
		}

		if !serverEntry.SupportsProtocol(tunnelProtocol) {
			continue
		}

		// If the server is limiting QUIC versions, at least one must be
		// supported. And if tactics is also limiting QUIC versions, there
		// must be a common version in both limit lists for this server entry
		// to support QUIC-OSSH.
		//
		// Limitation: to avoid additional complexity, we do not consider
		// DisableFrontingProviderQUICVersion here, as fronting providers are
		// expected to support QUICv1 and gQUIC is expected to become
		// obsolete in general.

		if TunnelProtocolUsesQUIC(tunnelProtocol) && len(serverEntry.LimitQUICVersions) > 0 {
			if !common.ContainsAny(serverEntry.LimitQUICVersions, SupportedQUICVersions) {
				continue
			}
			if len(limitQUICVersions) > 0 &&
				!common.ContainsAny(serverEntry.LimitQUICVersions, limitQUICVersions) {
				continue
			}
		}

		dialPortNumber, err := serverEntry.GetDialPortNumber(tunnelProtocol)
		if err != nil {
			continue
		}

		if len(limitTunnelDialPortNumbers) > 0 {
			if portList, ok := limitTunnelDialPortNumbers[tunnelProtocol]; ok {
				if !portList.Lookup(dialPortNumber) {
					continue
				}
			} else if portList, ok := limitTunnelDialPortNumbers[TUNNEL_PROTOCOLS_ALL]; ok {
				if !portList.Lookup(dialPortNumber) {
					continue
				}
			}
		}

		supportedProtocols = append(supportedProtocols, tunnelProtocol)

	}
	return supportedProtocols
}

func (serverEntry *ServerEntry) GetDialPortNumber(tunnelProtocol string) (int, error) {

	if !serverEntry.SupportsProtocol(tunnelProtocol) {
		return 0, errors.TraceNew("protocol not supported")
	}

	switch tunnelProtocol {

	case TUNNEL_PROTOCOL_SSH:
		return serverEntry.SshPort, nil

	case TUNNEL_PROTOCOL_OBFUSCATED_SSH:
		return serverEntry.SshObfuscatedPort, nil

	case TUNNEL_PROTOCOL_TAPDANCE_OBFUSCATED_SSH:
		return serverEntry.SshObfuscatedTapDancePort, nil

	case TUNNEL_PROTOCOL_CONJURE_OBFUSCATED_SSH:
		return serverEntry.SshObfuscatedConjurePort, nil

	case TUNNEL_PROTOCOL_QUIC_OBFUSCATED_SSH:
		return serverEntry.SshObfuscatedQUICPort, nil

	case TUNNEL_PROTOCOL_FRONTED_MEEK,
		TUNNEL_PROTOCOL_FRONTED_MEEK_QUIC_OBFUSCATED_SSH:
		return 443, nil

	case TUNNEL_PROTOCOL_FRONTED_MEEK_HTTP:
		return 80, nil

	case TUNNEL_PROTOCOL_UNFRONTED_MEEK_HTTPS,
		TUNNEL_PROTOCOL_UNFRONTED_MEEK_SESSION_TICKET,
		TUNNEL_PROTOCOL_UNFRONTED_MEEK:
		return serverEntry.MeekServerPort, nil
	}

	return 0, errors.TraceNew("unknown protocol")
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
		if !serverEntry.hasCapability(requiredCapability) {
			continue
		}

		supportedProtocols = append(supportedProtocols, protocol)
	}

	return supportedProtocols
}

// SupportsSSHAPIRequests returns true when the server supports
// SSH API requests.
func (serverEntry *ServerEntry) SupportsSSHAPIRequests() bool {
	return serverEntry.hasCapability(CAPABILITY_SSH_API_REQUESTS)
}

func (serverEntry *ServerEntry) GetUntunneledWebRequestPorts() []string {
	ports := make([]string, 0)
	if serverEntry.hasCapability(CAPABILITY_UNTUNNELED_WEB_API_REQUESTS) {
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

func (serverEntry *ServerEntry) HasSignature() bool {
	return serverEntry.Signature != ""
}

func (serverEntry *ServerEntry) GetDiagnosticID() string {
	return TagToDiagnosticID(serverEntry.Tag)
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

// TagToDiagnosticID returns a prefix of the server entry tag that should be
// sufficient to uniquely identify servers in diagnostics, while also being
// more human readable than emitting the full tag. The tag is used as the base
// of the diagnostic ID as it doesn't leak the server IP address in diagnostic
// output.
func TagToDiagnosticID(tag string) string {
	if len(tag) < 8 {
		return "<unknown>"
	}
	return tag[:8]
}

// EncodeServerEntry returns a string containing the encoding of
// a ServerEntry following Psiphon conventions.
func EncodeServerEntry(serverEntry *ServerEntry) (string, error) {
	return encodeServerEntry(
		serverEntry.IpAddress,
		serverEntry.WebServerPort,
		serverEntry.WebServerSecret,
		serverEntry.WebServerCertificate,
		serverEntry)
}

// EncodeServerEntryFields returns a string containing the encoding of
// ServerEntryFields following Psiphon conventions.
func EncodeServerEntryFields(serverEntryFields ServerEntryFields) (string, error) {
	return encodeServerEntry(
		serverEntryFields.GetIPAddress(),
		serverEntryFields.GetWebServerPort(),
		serverEntryFields.GetWebServerSecret(),
		serverEntryFields.GetWebServerCertificate(),
		serverEntryFields)
}

func encodeServerEntry(
	prefixIPAddress string,
	prefixWebServerPort string,
	prefixWebServerSecret string,
	prefixWebServerCertificate string,
	serverEntry interface{}) (string, error) {

	serverEntryJSON, err := json.Marshal(serverEntry)
	if err != nil {
		return "", errors.Trace(err)
	}

	// Legacy clients use a space-delimited fields prefix, and all clients expect
	// to at least parse the prefix in order to skip over it.
	//
	// When the server entry has no web API server certificate, the entire prefix
	// can be compacted down to single character placeholders. Clients that can
	// use the ssh API always prefer it over the web API and won't use the prefix
	// values.
	if len(prefixWebServerCertificate) == 0 {
		prefixIPAddress = "0"
		prefixWebServerPort = "0"
		prefixWebServerSecret = "0"
		prefixWebServerCertificate = "0"
	}

	return hex.EncodeToString([]byte(fmt.Sprintf(
		"%s %s %s %s %s",
		prefixIPAddress,
		prefixWebServerPort,
		prefixWebServerSecret,
		prefixWebServerCertificate,
		serverEntryJSON))), nil
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
		return nil, errors.Trace(err)
	}

	// NOTE: if the source JSON happens to have values in these fields, they get clobbered.
	serverEntry.LocalSource = serverEntrySource
	serverEntry.LocalTimestamp = timestamp

	return serverEntry, nil
}

// DecodeServerEntryFields extracts an encoded server entry into a
// ServerEntryFields type, much like DecodeServerEntry. Unrecognized fields
// not in ServerEntry are retained in the ServerEntryFields.
//
// LocalSource/LocalTimestamp map entries are set only when the corresponding
// inputs are non-blank.
func DecodeServerEntryFields(
	encodedServerEntry, timestamp, serverEntrySource string) (ServerEntryFields, error) {

	serverEntryFields := make(ServerEntryFields)
	err := decodeServerEntry(encodedServerEntry, timestamp, serverEntrySource, &serverEntryFields)
	if err != nil {
		return nil, errors.Trace(err)
	}

	// NOTE: if the source JSON happens to have values in these fields, they get clobbered.
	if serverEntrySource != "" {
		serverEntryFields.SetLocalSource(serverEntrySource)
	}
	if timestamp != "" {
		serverEntryFields.SetLocalTimestamp(timestamp)
	}

	return serverEntryFields, nil
}

func decodeServerEntry(
	encodedServerEntry, timestamp, serverEntrySource string,
	target interface{}) error {

	hexDecodedServerEntry, err := hex.DecodeString(encodedServerEntry)
	if err != nil {
		return errors.Trace(err)
	}

	// Skip past legacy format (4 space delimited fields) and just parse the JSON config
	fields := bytes.SplitN(hexDecodedServerEntry, []byte(" "), 5)
	if len(fields) != 5 {
		return errors.TraceNew("invalid encoded server entry")
	}

	err = json.Unmarshal(fields[4], target)
	if err != nil {
		return errors.Trace(err)
	}

	return nil
}

// ValidateServerEntryFields checks for malformed server entries.
func ValidateServerEntryFields(serverEntryFields ServerEntryFields) error {

	// Checks for a valid ipAddress. This is important since the IP
	// address is the key used to store/lookup the server entry.

	ipAddress := serverEntryFields.GetIPAddress()
	if net.ParseIP(ipAddress) == nil {
		return errors.Tracef("server entry has invalid ipAddress: %s", ipAddress)
	}

	// TODO: validate more fields?

	// Ensure locally initialized fields have been set.

	source := serverEntryFields.GetLocalSource()
	if !common.Contains(
		SupportedServerEntrySources, source) {
		return errors.Tracef("server entry has invalid source: %s", source)
	}

	timestamp := serverEntryFields.GetLocalTimestamp()
	_, err := time.Parse(time.RFC3339, timestamp)
	if err != nil {
		return errors.Tracef("server entry has invalid timestamp: %s", err)
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
			return nil, errors.Trace(err)
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
			return nil, errors.Trace(decoder.scanner.Err())
		}

		// TODO: use scanner.Bytes which doesn't allocate, instead of scanner.Text

		// TODO: skip this entry and continue if can't decode?
		serverEntryFields, err := DecodeServerEntryFields(
			decoder.scanner.Text(), decoder.timestamp, decoder.serverEntrySource)
		if err != nil {
			return nil, errors.Trace(err)
		}

		if ValidateServerEntryFields(serverEntryFields) != nil {
			// Skip this entry and continue with the next one
			// TODO: invoke a logging callback
			continue
		}

		return serverEntryFields, nil
	}
}
