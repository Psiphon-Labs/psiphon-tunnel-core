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
	"fmt"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/osl"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
)

const (
	TUNNEL_PROTOCOL_SSH                           = "SSH"
	TUNNEL_PROTOCOL_OBFUSCATED_SSH                = "OSSH"
	TUNNEL_PROTOCOL_UNFRONTED_MEEK                = "UNFRONTED-MEEK-OSSH"
	TUNNEL_PROTOCOL_UNFRONTED_MEEK_HTTPS          = "UNFRONTED-MEEK-HTTPS-OSSH"
	TUNNEL_PROTOCOL_UNFRONTED_MEEK_SESSION_TICKET = "UNFRONTED-MEEK-SESSION-TICKET-OSSH"
	TUNNEL_PROTOCOL_FRONTED_MEEK                  = "FRONTED-MEEK-OSSH"
	TUNNEL_PROTOCOL_FRONTED_MEEK_HTTP             = "FRONTED-MEEK-HTTP-OSSH"
	TUNNEL_PROTOCOL_QUIC_OBFUSCATED_SSH           = "QUIC-OSSH"
	TUNNEL_PROTOCOL_MARIONETTE_OBFUSCATED_SSH     = "MARIONETTE-OSSH"
	TUNNEL_PROTOCOL_TAPDANCE_OBFUSCATED_SSH       = "TAPDANCE-OSSH"

	SERVER_ENTRY_SOURCE_EMBEDDED   = "EMBEDDED"
	SERVER_ENTRY_SOURCE_REMOTE     = "REMOTE"
	SERVER_ENTRY_SOURCE_DISCOVERY  = "DISCOVERY"
	SERVER_ENTRY_SOURCE_TARGET     = "TARGET"
	SERVER_ENTRY_SOURCE_OBFUSCATED = "OBFUSCATED"

	CAPABILITY_SSH_API_REQUESTS            = "ssh-api-requests"
	CAPABILITY_UNTUNNELED_WEB_API_REQUESTS = "handshake"

	CLIENT_CAPABILITY_SERVER_REQUESTS = "server-requests"

	PSIPHON_API_HANDSHAKE_REQUEST_NAME = "psiphon-handshake"
	PSIPHON_API_CONNECTED_REQUEST_NAME = "psiphon-connected"
	PSIPHON_API_STATUS_REQUEST_NAME    = "psiphon-status"
	PSIPHON_API_OSL_REQUEST_NAME       = "psiphon-osl"

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
			return common.ContextError(fmt.Errorf("invalid tunnel protocol: %s", p))
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
	TUNNEL_PROTOCOL_MARIONETTE_OBFUSCATED_SSH,
	TUNNEL_PROTOCOL_TAPDANCE_OBFUSCATED_SSH,
}

var DefaultDisabledTunnelProtocols = TunnelProtocols{
	TUNNEL_PROTOCOL_MARIONETTE_OBFUSCATED_SSH,
	TUNNEL_PROTOCOL_TAPDANCE_OBFUSCATED_SSH,
}

var SupportedServerEntrySources = TunnelProtocols{
	SERVER_ENTRY_SOURCE_EMBEDDED,
	SERVER_ENTRY_SOURCE_REMOTE,
	SERVER_ENTRY_SOURCE_DISCOVERY,
	SERVER_ENTRY_SOURCE_TARGET,
	SERVER_ENTRY_SOURCE_OBFUSCATED,
}

func TunnelProtocolUsesSSH(protocol string) bool {
	return true
}

func TunnelProtocolUsesObfuscatedSSH(protocol string) bool {
	return protocol != TUNNEL_PROTOCOL_SSH
}

func TunnelProtocolUsesMeek(protocol string) bool {
	return TunnelProtocolUsesMeekHTTP(protocol) ||
		TunnelProtocolUsesMeekHTTPS(protocol)
}

func TunnelProtocolUsesFrontedMeek(protocol string) bool {
	return protocol == TUNNEL_PROTOCOL_FRONTED_MEEK ||
		protocol == TUNNEL_PROTOCOL_FRONTED_MEEK_HTTP
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
	return protocol == TUNNEL_PROTOCOL_QUIC_OBFUSCATED_SSH
}

func TunnelProtocolUsesMarionette(protocol string) bool {
	return protocol == TUNNEL_PROTOCOL_MARIONETTE_OBFUSCATED_SSH
}

func TunnelProtocolUsesTapdance(protocol string) bool {
	return protocol == TUNNEL_PROTOCOL_TAPDANCE_OBFUSCATED_SSH
}

func TunnelProtocolIsResourceIntensive(protocol string) bool {
	return TunnelProtocolUsesMeek(protocol) ||
		TunnelProtocolUsesQUIC(protocol) ||
		TunnelProtocolUsesMarionette(protocol) ||
		TunnelProtocolUsesTapdance(protocol)
}

func UseClientTunnelProtocol(
	clientProtocol string,
	serverProtocols TunnelProtocols) bool {

	// When the server is running _both_ fronted HTTP and
	// fronted HTTPS, use the client's reported tunnel
	// protocol since some CDNs forward both to the same
	// server port; in this case the server port is not
	// sufficient to distinguish these protocols.
	if (clientProtocol == TUNNEL_PROTOCOL_FRONTED_MEEK ||
		clientProtocol == TUNNEL_PROTOCOL_FRONTED_MEEK_HTTP) &&
		common.Contains(serverProtocols, TUNNEL_PROTOCOL_FRONTED_MEEK) &&
		common.Contains(serverProtocols, TUNNEL_PROTOCOL_FRONTED_MEEK_HTTP) {

		return true
	}

	return false
}

const (
	TLS_PROFILE_IOS_1131         = "iOS-Safari-11.3.1"
	TLS_PROFILE_ANDROID_60       = "Android-6.0"
	TLS_PROFILE_ANDROID_51       = "Android-5.1"
	TLS_PROFILE_CHROME_58        = "Chrome-58"
	TLS_PROFILE_CHROME_57        = "Chrome-57"
	TLS_PROFILE_FIREFOX_56       = "Firefox-56"
	TLS_PROFILE_RANDOMIZED       = "Randomized"
	TLS_PROFILE_TLS13_RANDOMIZED = "TLS-1.3-Randomized"
)

var SupportedTLSProfiles = TLSProfiles{
	TLS_PROFILE_IOS_1131,
	TLS_PROFILE_ANDROID_60,
	TLS_PROFILE_ANDROID_51,
	TLS_PROFILE_CHROME_58,
	TLS_PROFILE_CHROME_57,
	TLS_PROFILE_FIREFOX_56,
	TLS_PROFILE_RANDOMIZED,
	TLS_PROFILE_TLS13_RANDOMIZED,
}

func TLSProfileIsRandomized(tlsProfile string) bool {
	return tlsProfile == TLS_PROFILE_RANDOMIZED ||
		tlsProfile == TLS_PROFILE_TLS13_RANDOMIZED
}

func TLSProfileIsTLS13(tlsProfile string) bool {
	return tlsProfile == TLS_PROFILE_TLS13_RANDOMIZED
}

type TLSProfiles []string

func (profiles TLSProfiles) Validate() error {
	for _, p := range profiles {
		if !common.Contains(SupportedTLSProfiles, p) {
			return common.ContextError(fmt.Errorf("invalid TLS profile: %s", p))
		}
	}
	return nil
}

func (profiles TLSProfiles) PruneInvalid() TLSProfiles {
	q := make(TLSProfiles, 0)
	for _, p := range profiles {
		if common.Contains(SupportedTLSProfiles, p) {
			q = append(q, p)
		}
	}
	return q
}

const (
	QUIC_VERSION_GQUIC39    = "gQUICv39"
	QUIC_VERSION_GQUIC43    = "gQUICv43"
	QUIC_VERSION_GQUIC44    = "gQUICv44"
	QUIC_VERSION_OBFUSCATED = "OBFUSCATED"
)

var SupportedQUICVersions = QUICVersions{
	QUIC_VERSION_GQUIC39,
	QUIC_VERSION_GQUIC43,
	QUIC_VERSION_GQUIC44,
	QUIC_VERSION_OBFUSCATED,
}

func QUICVersionIsObfuscated(version string) bool {
	return version == QUIC_VERSION_OBFUSCATED
}

type QUICVersions []string

func (versions QUICVersions) Validate() error {
	for _, v := range versions {
		if !common.Contains(SupportedQUICVersions, v) {
			return common.ContextError(fmt.Errorf("invalid QUIC version: %s", v))
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

type HandshakeResponse struct {
	SSHSessionID           string              `json:"ssh_session_id"`
	Homepages              []string            `json:"homepages"`
	UpgradeClientVersion   string              `json:"upgrade_client_version"`
	PageViewRegexes        []map[string]string `json:"page_view_regexes"`
	HttpsRequestRegexes    []map[string]string `json:"https_request_regexes"`
	EncodedServerList      []string            `json:"encoded_server_list"`
	ClientRegion           string              `json:"client_region"`
	ServerTimestamp        string              `json:"server_timestamp"`
	ActiveAuthorizationIDs []string            `json:"active_authorization_ids"`
	TacticsPayload         json.RawMessage     `json:"tactics_payload"`
	Padding                string              `json:"padding"`
}

type ConnectedResponse struct {
	ConnectedTimestamp string `json:"connected_timestamp"`
	Padding            string `json:"padding"`
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
