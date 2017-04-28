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
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/osl"
)

const (
	TUNNEL_PROTOCOL_SSH                           = "SSH"
	TUNNEL_PROTOCOL_OBFUSCATED_SSH                = "OSSH"
	TUNNEL_PROTOCOL_UNFRONTED_MEEK                = "UNFRONTED-MEEK-OSSH"
	TUNNEL_PROTOCOL_UNFRONTED_MEEK_HTTPS          = "UNFRONTED-MEEK-HTTPS-OSSH"
	TUNNEL_PROTOCOL_UNFRONTED_MEEK_SESSION_TICKET = "UNFRONTED-MEEK-SESSION-TICKET-OSSH"
	TUNNEL_PROTOCOL_FRONTED_MEEK                  = "FRONTED-MEEK-OSSH"
	TUNNEL_PROTOCOL_FRONTED_MEEK_HTTP             = "FRONTED-MEEK-HTTP-OSSH"

	SERVER_ENTRY_SOURCE_EMBEDDED   = "EMBEDDED"
	SERVER_ENTRY_SOURCE_REMOTE     = "REMOTE"
	SERVER_ENTRY_SOURCE_DISCOVERY  = "DISCOVERY"
	SERVER_ENTRY_SOURCE_TARGET     = "TARGET"
	SERVER_ENTRY_SOURCE_OBFUSCATED = "OBFUSCATED"

	CAPABILITY_SSH_API_REQUESTS            = "ssh-api-requests"
	CAPABILITY_UNTUNNELED_WEB_API_REQUESTS = "handshake"

	CLIENT_CAPABILITY_SERVER_REQUESTS = "server-requests"

	PSIPHON_API_HANDSHAKE_REQUEST_NAME           = "psiphon-handshake"
	PSIPHON_API_CONNECTED_REQUEST_NAME           = "psiphon-connected"
	PSIPHON_API_STATUS_REQUEST_NAME              = "psiphon-status"
	PSIPHON_API_CLIENT_VERIFICATION_REQUEST_NAME = "psiphon-client-verification"
	PSIPHON_API_OSL_REQUEST_NAME                 = "psiphon-osl"

	PSIPHON_API_CLIENT_SESSION_ID_LENGTH = 16

	PSIPHON_SSH_API_PROTOCOL = "ssh"
	PSIPHON_WEB_API_PROTOCOL = "web"
)

var SupportedTunnelProtocols = []string{
	TUNNEL_PROTOCOL_FRONTED_MEEK,
	TUNNEL_PROTOCOL_FRONTED_MEEK_HTTP,
	TUNNEL_PROTOCOL_UNFRONTED_MEEK,
	TUNNEL_PROTOCOL_UNFRONTED_MEEK_HTTPS,
	TUNNEL_PROTOCOL_UNFRONTED_MEEK_SESSION_TICKET,
	TUNNEL_PROTOCOL_OBFUSCATED_SSH,
	TUNNEL_PROTOCOL_SSH,
}

var SupportedServerEntrySources = []string{
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

func UseClientTunnelProtocol(
	clientProtocol string,
	serverProtocols []string) bool {

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

type HandshakeResponse struct {
	SSHSessionID         string              `json:"ssh_session_id"`
	Homepages            []string            `json:"homepages"`
	UpgradeClientVersion string              `json:"upgrade_client_version"`
	PageViewRegexes      []map[string]string `json:"page_view_regexes"`
	HttpsRequestRegexes  []map[string]string `json:"https_request_regexes"`
	EncodedServerList    []string            `json:"encoded_server_list"`
	ClientRegion         string              `json:"client_region"`
	ServerTimestamp      string              `json:"server_timestamp"`
}

type ConnectedResponse struct {
	ConnectedTimestamp string `json:"connected_timestamp"`
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
	ServerAddress        string `json:"p"`
	SessionID            string `json:"s"`
	MeekProtocolVersion  int    `json:"v"`
	ClientTunnelProtocol string `json:"t"`
}
