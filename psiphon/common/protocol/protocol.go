/*
 * Copyright (c) 2016, Psiphon Inc.
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
	"crypto/sha256"
	"encoding/json"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/osl"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
)

const (
	TUNNEL_PROTOCOL_SSH                              = "SSH"
	TUNNEL_PROTOCOL_OBFUSCATED_SSH                   = "OSSH"
	TUNNEL_PROTOCOL_UNFRONTED_MEEK                   = "UNFRONTED-MEEK-OSSH"
	TUNNEL_PROTOCOL_UNFRONTED_MEEK_HTTPS             = "UNFRONTED-MEEK-HTTPS-OSSH"
	TUNNEL_PROTOCOL_UNFRONTED_MEEK_SESSION_TICKET    = "UNFRONTED-MEEK-SESSION-TICKET-OSSH"
	TUNNEL_PROTOCOL_FRONTED_MEEK                     = "FRONTED-MEEK-OSSH"
	TUNNEL_PROTOCOL_FRONTED_MEEK_HTTP                = "FRONTED-MEEK-HTTP-OSSH"
	TUNNEL_PROTOCOL_QUIC_OBFUSCATED_SSH              = "QUIC-OSSH"
	TUNNEL_PROTOCOL_FRONTED_MEEK_QUIC_OBFUSCATED_SSH = "FRONTED-MEEK-QUIC-OSSH"
	TUNNEL_PROTOCOL_MARIONETTE_OBFUSCATED_SSH        = "MARIONETTE-OSSH"
	TUNNEL_PROTOCOL_TAPDANCE_OBFUSCATED_SSH          = "TAPDANCE-OSSH"
	TUNNEL_PROTOCOL_CONJOUR_OBFUSCATED_SSH           = "CONJOUR-OSSH"

	SERVER_ENTRY_SOURCE_EMBEDDED   = "EMBEDDED"
	SERVER_ENTRY_SOURCE_REMOTE     = "REMOTE"
	SERVER_ENTRY_SOURCE_DISCOVERY  = "DISCOVERY"
	SERVER_ENTRY_SOURCE_TARGET     = "TARGET"
	SERVER_ENTRY_SOURCE_OBFUSCATED = "OBFUSCATED"
	SERVER_ENTRY_SOURCE_EXCHANGED  = "EXCHANGED"

	CAPABILITY_SSH_API_REQUESTS            = "ssh-api-requests"
	CAPABILITY_UNTUNNELED_WEB_API_REQUESTS = "handshake"

	CLIENT_CAPABILITY_SERVER_REQUESTS = "server-requests"

	PSIPHON_API_HANDSHAKE_REQUEST_NAME = "psiphon-handshake"
	PSIPHON_API_CONNECTED_REQUEST_NAME = "psiphon-connected"
	PSIPHON_API_STATUS_REQUEST_NAME    = "psiphon-status"
	PSIPHON_API_OSL_REQUEST_NAME       = "psiphon-osl"
	PSIPHON_API_ALERT_REQUEST_NAME     = "psiphon-alert"

	PSIPHON_API_ALERT_DISALLOWED_TRAFFIC = "disallowed-traffic"
	PSIPHON_API_ALERT_UNSAFE_TRAFFIC     = "unsafe-traffic"

	// PSIPHON_API_CLIENT_VERIFICATION_REQUEST_NAME may still be used by older Android clients
	PSIPHON_API_CLIENT_VERIFICATION_REQUEST_NAME = "psiphon-client-verification"

	PSIPHON_API_CLIENT_SESSION_ID_LENGTH = 16

	PSIPHON_SSH_API_PROTOCOL = "ssh"
	PSIPHON_WEB_API_PROTOCOL = "web"

	PACKET_TUNNEL_CHANNEL_TYPE = "tun@psiphon.ca"
	RANDOM_STREAM_CHANNEL_TYPE = "random@psiphon.ca"

	PSIPHON_API_HANDSHAKE_AUTHORIZATIONS = "authorizations"
)

type TunnelProtocols []string

func (t TunnelProtocols) Validate() error {
	for _, p := range t {
		if !common.Contains(SupportedTunnelProtocols, p) {
			return errors.Tracef("invalid tunnel protocol: %s", p)
		}
	}
	return nil
}

func (t TunnelProtocols) PruneInvalid() TunnelProtocols {
	u := make(TunnelProtocols, 0)
	for _, p := range t {
		if common.Contains(SupportedTunnelProtocols, p) {
			u = append(u, p)
		}
	}
	return u
}

var SupportedTunnelProtocols = TunnelProtocols{
	TUNNEL_PROTOCOL_SSH,
	TUNNEL_PROTOCOL_OBFUSCATED_SSH,
	TUNNEL_PROTOCOL_UNFRONTED_MEEK,
	TUNNEL_PROTOCOL_UNFRONTED_MEEK_HTTPS,
	TUNNEL_PROTOCOL_UNFRONTED_MEEK_SESSION_TICKET,
	TUNNEL_PROTOCOL_FRONTED_MEEK,
	TUNNEL_PROTOCOL_FRONTED_MEEK_HTTP,
	TUNNEL_PROTOCOL_QUIC_OBFUSCATED_SSH,
	TUNNEL_PROTOCOL_FRONTED_MEEK_QUIC_OBFUSCATED_SSH,
	TUNNEL_PROTOCOL_MARIONETTE_OBFUSCATED_SSH,
	TUNNEL_PROTOCOL_TAPDANCE_OBFUSCATED_SSH,
	TUNNEL_PROTOCOL_CONJOUR_OBFUSCATED_SSH,
}

var DefaultDisabledTunnelProtocols = TunnelProtocols{
	TUNNEL_PROTOCOL_FRONTED_MEEK_QUIC_OBFUSCATED_SSH,
	TUNNEL_PROTOCOL_MARIONETTE_OBFUSCATED_SSH,
	TUNNEL_PROTOCOL_TAPDANCE_OBFUSCATED_SSH,
	TUNNEL_PROTOCOL_CONJOUR_OBFUSCATED_SSH,
}

var SupportedServerEntrySources = TunnelProtocols{
	SERVER_ENTRY_SOURCE_EMBEDDED,
	SERVER_ENTRY_SOURCE_REMOTE,
	SERVER_ENTRY_SOURCE_DISCOVERY,
	SERVER_ENTRY_SOURCE_TARGET,
	SERVER_ENTRY_SOURCE_OBFUSCATED,
	SERVER_ENTRY_SOURCE_EXCHANGED,
}

func TunnelProtocolUsesTCP(protocol string) bool {
	// Limitation: Marionette network protocol depends on its format configuration.
	return protocol != TUNNEL_PROTOCOL_QUIC_OBFUSCATED_SSH &&
		protocol != TUNNEL_PROTOCOL_FRONTED_MEEK_QUIC_OBFUSCATED_SSH &&
		protocol != TUNNEL_PROTOCOL_MARIONETTE_OBFUSCATED_SSH
}

func TunnelProtocolUsesSSH(protocol string) bool {
	return true
}

func TunnelProtocolUsesObfuscatedSSH(protocol string) bool {
	return protocol != TUNNEL_PROTOCOL_SSH
}

func TunnelProtocolUsesMeek(protocol string) bool {
	return TunnelProtocolUsesMeekHTTP(protocol) ||
		TunnelProtocolUsesMeekHTTPS(protocol) ||
		TunnelProtocolUsesFrontedMeekQUIC(protocol)
}

func TunnelProtocolUsesFrontedMeek(protocol string) bool {
	return protocol == TUNNEL_PROTOCOL_FRONTED_MEEK ||
		protocol == TUNNEL_PROTOCOL_FRONTED_MEEK_HTTP ||
		protocol == TUNNEL_PROTOCOL_FRONTED_MEEK_QUIC_OBFUSCATED_SSH
}

func TunnelProtocolUsesMeekHTTP(protocol string) bool {
	return protocol == TUNNEL_PROTOCOL_UNFRONTED_MEEK ||
		protocol == TUNNEL_PROTOCOL_FRONTED_MEEK_HTTP
}

func TunnelProtocolUsesMeekHTTPS(protocol string) bool {
	return protocol == TUNNEL_PROTOCOL_FRONTED_MEEK ||
		protocol == TUNNEL_PROTOCOL_UNFRONTED_MEEK_HTTPS ||
		protocol == TUNNEL_PROTOCOL_UNFRONTED_MEEK_SESSION_TICKET
}

func TunnelProtocolUsesObfuscatedSessionTickets(protocol string) bool {
	return protocol == TUNNEL_PROTOCOL_UNFRONTED_MEEK_SESSION_TICKET
}

func TunnelProtocolUsesQUIC(protocol string) bool {
	return protocol == TUNNEL_PROTOCOL_QUIC_OBFUSCATED_SSH ||
		protocol == TUNNEL_PROTOCOL_FRONTED_MEEK_QUIC_OBFUSCATED_SSH
}

func TunnelProtocolUsesFrontedMeekQUIC(protocol string) bool {
	return protocol == TUNNEL_PROTOCOL_FRONTED_MEEK_QUIC_OBFUSCATED_SSH
}

func TunnelProtocolUsesMarionette(protocol string) bool {
	return protocol == TUNNEL_PROTOCOL_MARIONETTE_OBFUSCATED_SSH
}

func TunnelProtocolUsesTapdance(protocol string) bool {
	return protocol == TUNNEL_PROTOCOL_TAPDANCE_OBFUSCATED_SSH ||
		protocol == TUNNEL_PROTOCOL_CONJOUR_OBFUSCATED_SSH
}

func TunnelProtocolUsesDarkDecoys(protocol string) bool {
	return protocol == TUNNEL_PROTOCOL_CONJOUR_OBFUSCATED_SSH
}

func TunnelProtocolIsResourceIntensive(protocol string) bool {
	return TunnelProtocolUsesMeek(protocol) ||
		TunnelProtocolUsesQUIC(protocol) ||
		TunnelProtocolUsesMarionette(protocol) ||
		TunnelProtocolUsesTapdance(protocol)
}

func TunnelProtocolIsCompatibleWithFragmentor(protocol string) bool {
	return protocol == TUNNEL_PROTOCOL_SSH ||
		protocol == TUNNEL_PROTOCOL_OBFUSCATED_SSH ||
		protocol == TUNNEL_PROTOCOL_UNFRONTED_MEEK ||
		protocol == TUNNEL_PROTOCOL_UNFRONTED_MEEK_HTTPS ||
		protocol == TUNNEL_PROTOCOL_UNFRONTED_MEEK_SESSION_TICKET ||
		protocol == TUNNEL_PROTOCOL_FRONTED_MEEK ||
		protocol == TUNNEL_PROTOCOL_FRONTED_MEEK_HTTP
}

func TunnelProtocolRequiresTLS12SessionTickets(protocol string) bool {
	return protocol == TUNNEL_PROTOCOL_UNFRONTED_MEEK_SESSION_TICKET
}

func TunnelProtocolSupportsPassthrough(protocol string) bool {
	return protocol == TUNNEL_PROTOCOL_UNFRONTED_MEEK_HTTPS ||
		protocol == TUNNEL_PROTOCOL_UNFRONTED_MEEK_SESSION_TICKET
}

func TunnelProtocolSupportsUpstreamProxy(protocol string) bool {

	// TODO: Marionette UDP formats are incompatible with
	// UpstreamProxy, but not currently supported.

	return !TunnelProtocolUsesQUIC(protocol)
}

func UseClientTunnelProtocol(
	clientProtocol string,
	serverProtocols TunnelProtocols) bool {

	// When the server is running multiple fronted protocols, and the client
	// reports a fronted protocol, use the client's reported tunnel protocol
	// since some CDNs forward several protocols to the same server port; in this
	// case the server port is not sufficient to distinguish these protocols.

	if !TunnelProtocolUsesFrontedMeek(clientProtocol) {
		return false
	}

	frontedProtocolCount := 0
	for _, protocol := range serverProtocols {
		if TunnelProtocolUsesFrontedMeek(protocol) {
			frontedProtocolCount += 1
			if frontedProtocolCount > 1 {
				return true
			}
		}
	}

	return false
}

const (
	TLS_VERSION_12 = "TLSv1.2"
	TLS_VERSION_13 = "TLSv1.3"

	TLS_PROFILE_IOS_111    = "iOS-11.1"
	TLS_PROFILE_IOS_121    = "iOS-12.1"
	TLS_PROFILE_CHROME_58  = "Chrome-58"
	TLS_PROFILE_CHROME_62  = "Chrome-62"
	TLS_PROFILE_CHROME_70  = "Chrome-70"
	TLS_PROFILE_CHROME_72  = "Chrome-72"
	TLS_PROFILE_CHROME_83  = "Chrome-83"
	TLS_PROFILE_FIREFOX_55 = "Firefox-55"
	TLS_PROFILE_FIREFOX_56 = "Firefox-56"
	TLS_PROFILE_FIREFOX_65 = "Firefox-65"
	TLS_PROFILE_RANDOMIZED = "Randomized-v2"
)

var SupportedTLSProfiles = TLSProfiles{
	TLS_PROFILE_IOS_111,
	TLS_PROFILE_IOS_121,
	TLS_PROFILE_CHROME_58,
	TLS_PROFILE_CHROME_62,
	TLS_PROFILE_CHROME_70,
	TLS_PROFILE_CHROME_72,
	TLS_PROFILE_CHROME_83,
	TLS_PROFILE_FIREFOX_55,
	TLS_PROFILE_FIREFOX_56,
	TLS_PROFILE_FIREFOX_65,
	TLS_PROFILE_RANDOMIZED,
}

var legacyTLSProfiles = TLSProfiles{
	"iOS-Safari-11.3.1",
	"Android-6.0",
	"Android-5.1",
	"Chrome-57",
	"Randomized",
	"TLS-1.3-Randomized",
}

func TLSProfileIsRandomized(tlsProfile string) bool {
	return tlsProfile == TLS_PROFILE_RANDOMIZED
}

func TLS12ProfileOmitsSessionTickets(tlsProfile string) bool {
	if tlsProfile == TLS_PROFILE_IOS_111 ||
		tlsProfile == TLS_PROFILE_IOS_121 {
		return true
	}
	return false
}

type TLSProfiles []string

func (profiles TLSProfiles) Validate(customTLSProfiles []string) error {

	for _, p := range profiles {
		if !common.Contains(SupportedTLSProfiles, p) &&
			!common.Contains(customTLSProfiles, p) &&
			!common.Contains(legacyTLSProfiles, p) {
			return errors.Tracef("invalid TLS profile: %s", p)
		}
	}
	return nil
}

func (profiles TLSProfiles) PruneInvalid(customTLSProfiles []string) TLSProfiles {
	q := make(TLSProfiles, 0)
	for _, p := range profiles {
		if common.Contains(SupportedTLSProfiles, p) ||
			common.Contains(customTLSProfiles, p) {
			q = append(q, p)
		}
	}
	return q
}

type LabeledTLSProfiles map[string]TLSProfiles

func (labeledProfiles LabeledTLSProfiles) Validate(customTLSProfiles []string) error {
	for _, profiles := range labeledProfiles {
		err := profiles.Validate(customTLSProfiles)
		if err != nil {
			return errors.Trace(err)
		}
	}
	return nil
}

func (labeledProfiles LabeledTLSProfiles) PruneInvalid(customTLSProfiles []string) LabeledTLSProfiles {
	l := make(LabeledTLSProfiles)
	for label, profiles := range labeledProfiles {
		l[label] = profiles.PruneInvalid(customTLSProfiles)
	}
	return l
}

const (
	QUIC_VERSION_GQUIC39      = "gQUICv39"
	QUIC_VERSION_GQUIC43      = "gQUICv43"
	QUIC_VERSION_GQUIC44      = "gQUICv44"
	QUIC_VERSION_OBFUSCATED   = "OBFUSCATED"
	QUIC_VERSION_IETF_DRAFT24 = "IETF-draft-24"
)

var SupportedQUICVersions = QUICVersions{
	QUIC_VERSION_GQUIC39,
	QUIC_VERSION_GQUIC43,
	QUIC_VERSION_GQUIC44,
	QUIC_VERSION_OBFUSCATED,
	QUIC_VERSION_IETF_DRAFT24,
}

func QUICVersionIsObfuscated(version string) bool {
	return version == QUIC_VERSION_OBFUSCATED
}

type QUICVersions []string

func (versions QUICVersions) Validate() error {
	for _, v := range versions {
		if !common.Contains(SupportedQUICVersions, v) {
			return errors.Tracef("invalid QUIC version: %s", v)
		}
	}
	return nil
}

func (versions QUICVersions) PruneInvalid() QUICVersions {
	u := make(QUICVersions, 0)
	for _, v := range versions {
		if common.Contains(SupportedQUICVersions, v) {
			u = append(u, v)
		}
	}
	return u
}

type LabeledQUICVersions map[string]QUICVersions

func (labeledVersions LabeledQUICVersions) Validate() error {
	for _, versions := range labeledVersions {
		err := versions.Validate()
		if err != nil {
			return errors.Trace(err)
		}
	}
	return nil
}

func (labeledVersions LabeledQUICVersions) PruneInvalid() LabeledQUICVersions {
	l := make(LabeledQUICVersions)
	for label, versions := range labeledVersions {
		l[label] = versions.PruneInvalid()
	}
	return l
}

type HandshakeResponse struct {
	SSHSessionID             string              `json:"ssh_session_id"`
	Homepages                []string            `json:"homepages"`
	UpgradeClientVersion     string              `json:"upgrade_client_version"`
	PageViewRegexes          []map[string]string `json:"page_view_regexes"`
	HttpsRequestRegexes      []map[string]string `json:"https_request_regexes"`
	EncodedServerList        []string            `json:"encoded_server_list"`
	ClientRegion             string              `json:"client_region"`
	ServerTimestamp          string              `json:"server_timestamp"`
	ActiveAuthorizationIDs   []string            `json:"active_authorization_ids"`
	TacticsPayload           json.RawMessage     `json:"tactics_payload"`
	UpstreamBytesPerSecond   int64               `json:"upstream_bytes_per_second"`
	DownstreamBytesPerSecond int64               `json:"downstream_bytes_per_second"`
	Padding                  string              `json:"padding"`
}

type ConnectedResponse struct {
	ConnectedTimestamp string `json:"connected_timestamp"`
	Padding            string `json:"padding"`
}

type StatusResponse struct {
	InvalidServerEntryTags []string `json:"invalid_server_entry_tags"`
	Padding                string   `json:"padding"`
}

type OSLRequest struct {
	ClearLocalSLOKs bool             `json:"clear_local_sloks"`
	SeedPayload     *osl.SeedPayload `json:"seed_payload"`
}

type SSHPasswordPayload struct {
	SessionId          string   `json:"SessionId"`
	SshPassword        string   `json:"SshPassword"`
	ClientCapabilities []string `json:"ClientCapabilities"`
}

type MeekCookieData struct {
	MeekProtocolVersion  int    `json:"v"`
	ClientTunnelProtocol string `json:"t"`
	EndPoint             string `json:"e"`
}

type RandomStreamRequest struct {
	UpstreamBytes   int `json:"u"`
	DownstreamBytes int `json:"d"`
}

type AlertRequest struct {
	Reason  string `json:"reason"`
	Subject string `json:"subject"`
}

func DeriveSSHServerKEXPRNGSeed(obfuscatedKey string) (*prng.Seed, error) {
	// By convention, the obfuscatedKey will often be a hex-encoded 32 byte value,
	// but this isn't strictly required or validated, so we use SHA256 to map the
	// obfuscatedKey to the necessary 32-byte seed value.
	seed := prng.Seed(sha256.Sum256([]byte(obfuscatedKey)))
	return prng.NewSaltedSeed(&seed, "ssh-server-kex")
}

func DeriveSSHServerVersionPRNGSeed(obfuscatedKey string) (*prng.Seed, error) {
	seed := prng.Seed(sha256.Sum256([]byte(obfuscatedKey)))
	return prng.NewSaltedSeed(&seed, "ssh-server-version")
}

func DeriveBPFServerProgramPRNGSeed(obfuscatedKey string) (*prng.Seed, error) {
	seed := prng.Seed(sha256.Sum256([]byte(obfuscatedKey)))
	return prng.NewSaltedSeed(&seed, "bpf-server-program")
}
