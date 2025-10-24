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
	"strings"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/osl"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"github.com/fxamacker/cbor/v2"
)

const (
	TUNNEL_PROTOCOL_SSH                              = "SSH"
	TUNNEL_PROTOCOL_OBFUSCATED_SSH                   = "OSSH"
	TUNNEL_PROTOCOL_TLS_OBFUSCATED_SSH               = "TLS-OSSH"
	TUNNEL_PROTOCOL_SHADOWSOCKS_OSSH                 = "SHADOWSOCKS-OSSH"
	TUNNEL_PROTOCOL_UNFRONTED_MEEK                   = "UNFRONTED-MEEK-OSSH"
	TUNNEL_PROTOCOL_UNFRONTED_MEEK_HTTPS             = "UNFRONTED-MEEK-HTTPS-OSSH"
	TUNNEL_PROTOCOL_UNFRONTED_MEEK_SESSION_TICKET    = "UNFRONTED-MEEK-SESSION-TICKET-OSSH"
	TUNNEL_PROTOCOL_FRONTED_MEEK                     = "FRONTED-MEEK-OSSH"
	TUNNEL_PROTOCOL_FRONTED_MEEK_HTTP                = "FRONTED-MEEK-HTTP-OSSH"
	TUNNEL_PROTOCOL_QUIC_OBFUSCATED_SSH              = "QUIC-OSSH"
	TUNNEL_PROTOCOL_FRONTED_MEEK_QUIC_OBFUSCATED_SSH = "FRONTED-MEEK-QUIC-OSSH"
	TUNNEL_PROTOCOL_TAPDANCE_OBFUSCATED_SSH          = "TAPDANCE-OSSH"
	TUNNEL_PROTOCOL_CONJURE_OBFUSCATED_SSH           = "CONJURE-OSSH"

	FRONTING_TRANSPORT_HTTPS = "FRONTED-HTTPS"
	FRONTING_TRANSPORT_HTTP  = "FRONTED-HTTP"
	FRONTING_TRANSPORT_QUIC  = "FRONTED-QUIC"

	TUNNEL_PROTOCOLS_ALL = "All"

	INPROXY_PROTOCOL_WEBRTC = "INPROXY-WEBRTC"

	SERVER_ENTRY_SOURCE_EMBEDDED   = "EMBEDDED"
	SERVER_ENTRY_SOURCE_REMOTE     = "REMOTE"
	SERVER_ENTRY_SOURCE_DISCOVERY  = "DISCOVERY"
	SERVER_ENTRY_SOURCE_TARGET     = "TARGET"
	SERVER_ENTRY_SOURCE_OBFUSCATED = "OBFUSCATED"
	SERVER_ENTRY_SOURCE_EXCHANGED  = "EXCHANGED"
	SERVER_ENTRY_SOURCE_DSL        = "DSL-*"

	CAPABILITY_SSH_API_REQUESTS            = "ssh-api-requests"
	CAPABILITY_UNTUNNELED_WEB_API_REQUESTS = "handshake"

	CLIENT_CAPABILITY_SERVER_REQUESTS = "server-requests"

	PSIPHON_API_HANDSHAKE_REQUEST_NAME     = "psiphon-handshake"
	PSIPHON_API_CONNECTED_REQUEST_NAME     = "psiphon-connected"
	PSIPHON_API_STATUS_REQUEST_NAME        = "psiphon-status"
	PSIPHON_API_OSL_REQUEST_NAME           = "psiphon-osl"
	PSIPHON_API_ALERT_REQUEST_NAME         = "psiphon-alert"
	PSIPHON_API_INPROXY_RELAY_REQUEST_NAME = "psiphon-inproxy-relay"
	PSIPHON_API_DSL_REQUEST_NAME           = "psiphon-dsl"

	PSIPHON_API_ALERT_DISALLOWED_TRAFFIC = "disallowed-traffic"
	PSIPHON_API_ALERT_UNSAFE_TRAFFIC     = "unsafe-traffic"

	// PSIPHON_API_CLIENT_VERIFICATION_REQUEST_NAME may still be used by older Android clients
	PSIPHON_API_CLIENT_VERIFICATION_REQUEST_NAME = "psiphon-client-verification"

	PSIPHON_API_CLIENT_SESSION_ID_LENGTH = 16

	PSIPHON_API_TUNNEL_ID_LENGTH = 16

	PSIPHON_API_PROTOCOL_SSH  = "ssh"
	PSIPHON_API_PROTOCOL_WEB  = "web"
	PSIPHON_API_ENCODING_CBOR = "cbor"
	PSIPHON_API_ENCODING_JSON = "json"

	PSIPHON_API_RESPONSE_VERSION_FIELD_NAME = "psiphon_api_response_version"
	PSIPHON_API_RESPONSE_V1                 = "1"

	PACKET_TUNNEL_CHANNEL_TYPE            = "tun@psiphon.ca"
	RANDOM_STREAM_CHANNEL_TYPE            = "random@psiphon.ca"
	TCP_PORT_FORWARD_NO_SPLIT_TUNNEL_TYPE = "direct-tcpip-no-split-tunnel@psiphon.ca"

	// Reject reason codes are returned in SSH open channel responses.
	//
	// Values 0xFE000000 to 0xFFFFFFFF are reserved for "PRIVATE USE" (see
	// https://tools.ietf.org/rfc/rfc4254.html#section-5.1).
	CHANNEL_REJECT_REASON_SPLIT_TUNNEL = 0xFE000000

	PSIPHON_API_HANDSHAKE_AUTHORIZATIONS = "authorizations"
	PSIPHON_API_HANDSHAKE_CLIENT_VERSION = "client_version"
)

var SupportedServerEntrySources = []string{
	SERVER_ENTRY_SOURCE_EMBEDDED,
	SERVER_ENTRY_SOURCE_REMOTE,
	SERVER_ENTRY_SOURCE_DISCOVERY,
	SERVER_ENTRY_SOURCE_TARGET,
	SERVER_ENTRY_SOURCE_OBFUSCATED,
	SERVER_ENTRY_SOURCE_EXCHANGED,
	SERVER_ENTRY_SOURCE_DSL,
}

func AllowServerEntrySourceWithUpstreamProxy(source string) bool {
	return source == SERVER_ENTRY_SOURCE_EMBEDDED ||
		source == SERVER_ENTRY_SOURCE_REMOTE
}

func PsiphonAPIProtocolIsValid(protocol string) bool {
	return protocol == PSIPHON_API_PROTOCOL_SSH ||
		protocol == PSIPHON_API_PROTOCOL_WEB
}

func PsiphonAPIEncodingIsValid(protocol string) bool {
	return protocol == PSIPHON_API_ENCODING_CBOR ||
		protocol == PSIPHON_API_ENCODING_JSON
}

type TunnelProtocols []string

func (t TunnelProtocols) Validate() error {
	for _, p := range t {
		if !common.Contains(SupportedTunnelProtocols, p) ||
			common.Contains(DisabledTunnelProtocols, p) {
			return errors.Tracef("invalid tunnel protocol: %s", p)
		}
	}
	return nil
}

func (t TunnelProtocols) PruneInvalid() TunnelProtocols {
	u := make(TunnelProtocols, 0)
	for _, p := range t {
		if common.Contains(SupportedTunnelProtocols, p) &&
			!common.Contains(DisabledTunnelProtocols, p) {
			u = append(u, p)
		}
	}
	return u
}

func (t TunnelProtocols) PruneNonInproxyTunnelProtocols() TunnelProtocols {
	u := make(TunnelProtocols, 0)
	for _, p := range t {
		if TunnelProtocolUsesInproxy(p) {
			u = append(u, p)
		}
	}
	return u
}

func (t TunnelProtocols) PruneInproxyTunnelProtocols() TunnelProtocols {
	u := make(TunnelProtocols, 0)
	for _, p := range t {
		if !TunnelProtocolUsesInproxy(p) {
			u = append(u, p)
		}
	}
	return u
}

func (t TunnelProtocols) IsOnlyInproxyTunnelProtocols() bool {
	for _, p := range t {
		if !TunnelProtocolUsesInproxy(p) {
			return false
		}
	}
	return true
}

func (t TunnelProtocols) HasInproxyTunnelProtocols() bool {
	for _, p := range t {
		if TunnelProtocolUsesInproxy(p) {
			return true
		}
	}
	return false
}

type LabeledTunnelProtocols map[string]TunnelProtocols

func (labeledProtocols LabeledTunnelProtocols) Validate() error {
	for _, protocols := range labeledProtocols {
		err := protocols.Validate()
		if err != nil {
			return errors.Trace(err)
		}
	}
	return nil
}

func (labeledProtocols LabeledTunnelProtocols) PruneInvalid() LabeledTunnelProtocols {
	l := make(LabeledTunnelProtocols)
	for label, protocols := range labeledProtocols {
		l[label] = protocols.PruneInvalid()
	}
	return l
}

var SupportedTunnelProtocols = TunnelProtocols{
	TUNNEL_PROTOCOL_SSH,
	TUNNEL_PROTOCOL_OBFUSCATED_SSH,
	TUNNEL_PROTOCOL_TLS_OBFUSCATED_SSH,
	TUNNEL_PROTOCOL_UNFRONTED_MEEK,
	TUNNEL_PROTOCOL_UNFRONTED_MEEK_HTTPS,
	TUNNEL_PROTOCOL_UNFRONTED_MEEK_SESSION_TICKET,
	TUNNEL_PROTOCOL_FRONTED_MEEK,
	TUNNEL_PROTOCOL_FRONTED_MEEK_HTTP,
	TUNNEL_PROTOCOL_QUIC_OBFUSCATED_SSH,
	TUNNEL_PROTOCOL_FRONTED_MEEK_QUIC_OBFUSCATED_SSH,
	TUNNEL_PROTOCOL_TAPDANCE_OBFUSCATED_SSH,
	TUNNEL_PROTOCOL_CONJURE_OBFUSCATED_SSH,
	TUNNEL_PROTOCOL_SHADOWSOCKS_OSSH,
}

var DefaultDisabledTunnelProtocols = TunnelProtocols{
	TUNNEL_PROTOCOL_FRONTED_MEEK_QUIC_OBFUSCATED_SSH,
	TUNNEL_PROTOCOL_TAPDANCE_OBFUSCATED_SSH,
	TUNNEL_PROTOCOL_CONJURE_OBFUSCATED_SSH,
}

// DisabledTunnelProtocols are protocols which are still integrated, but which
// cannot be enabled in tactics and cannot be selected by clients.
var DisabledTunnelProtocols = TunnelProtocols{

	// TUNNEL_PROTOCOL_TAPDANCE_OBFUSCATED_SSH should not be reenabled without
	// retesting the integration. github.com/refraction-networking/gotapdance
	// and github.com/refraction-networking/conjure have undergone major
	// changes since TapDance was last active and tested.
	//
	// Furthermore, existing deployed clients will use the same ClientConf for
	// both TapDance and Conjure, which creates a risk that enabling TapDance
	// via tactics may cause existing clients to use Conjure ClientConf
	// decoys for TapDance, which may violate load assumptions.
	TUNNEL_PROTOCOL_TAPDANCE_OBFUSCATED_SSH,
}

var InproxyTunnelProtocols = TunnelProtocols{
	// Populated by init.
}

func init() {

	// Instead of duplicating most TUNNEL_PROTOCOL* constants,
	// programmatically add in-proxy variants of all (compatible) tunnel
	// protocols. All in-proxy variants are default disabled.

	for _, p := range SupportedTunnelProtocols {
		if TunnelProtocolIsCompatibleWithInproxy(p) {
			InproxyTunnelProtocols = append(
				InproxyTunnelProtocols, TunnelProtocolPlusInproxyWebRTC(p))
		}
	}
	SupportedTunnelProtocols = append(SupportedTunnelProtocols, InproxyTunnelProtocols...)
	DefaultDisabledTunnelProtocols = append(DefaultDisabledTunnelProtocols, InproxyTunnelProtocols...)
}

func TunnelProtocolPlusInproxyWebRTC(protocol string) string {
	return fmt.Sprintf("%s-%s", INPROXY_PROTOCOL_WEBRTC, protocol)
}

func TunnelProtocolMinusInproxy(protocol string) string {
	// Remove the in-proxy 1st hop portion of the protocol name, which
	// currently is always "INPROXY-WEBRTC".
	protocol, _ = strings.CutPrefix(protocol, fmt.Sprintf("%s-", INPROXY_PROTOCOL_WEBRTC))
	return protocol
}

func TunnelProtocolUsesInproxy(protocol string) bool {
	// Check for the in-proxy 1st hop portion of the protocol name, which
	// currently can only be "INPROXY-WEBRTC".
	return strings.HasPrefix(protocol, INPROXY_PROTOCOL_WEBRTC)
}

func TunnelProtocolIsCompatibleWithInproxy(protocol string) bool {
	// The TapDance and Conjure destination addresses are not included
	// in the server entry, so TAPDANCE-OSSH and CONJURE-OSSH dial
	// destinations cannot be validated for inproxy use.
	return !TunnelProtocolUsesRefractionNetworking(protocol)
}

func TunnelProtocolUsesTCP(protocol string) bool {
	protocol = TunnelProtocolMinusInproxy(protocol)
	return protocol != TUNNEL_PROTOCOL_QUIC_OBFUSCATED_SSH &&
		protocol != TUNNEL_PROTOCOL_FRONTED_MEEK_QUIC_OBFUSCATED_SSH
}

func TunnelProtocolUsesSSH(protocol string) bool {
	return true
}

func TunnelProtocolIsObfuscatedSSH(protocol string) bool {
	protocol = TunnelProtocolMinusInproxy(protocol)
	return protocol == TUNNEL_PROTOCOL_OBFUSCATED_SSH
}

func TunnelProtocolUsesObfuscatedSSH(protocol string) bool {
	protocol = TunnelProtocolMinusInproxy(protocol)
	return protocol != TUNNEL_PROTOCOL_SSH
}

// NOTE: breaks the naming convention of dropping the OSSH suffix because
// UsesTLS is ambiguous by itself as there are other protocols which use
// a TLS layer, e.g. UNFRONTED-MEEK-HTTPS-OSSH.
func TunnelProtocolUsesTLSOSSH(protocol string) bool {
	protocol = TunnelProtocolMinusInproxy(protocol)
	return protocol == TUNNEL_PROTOCOL_TLS_OBFUSCATED_SSH
}

func TunnelProtocolUsesMeek(protocol string) bool {
	protocol = TunnelProtocolMinusInproxy(protocol)
	return TunnelProtocolUsesMeekHTTP(protocol) ||
		TunnelProtocolUsesMeekHTTPS(protocol) ||
		TunnelProtocolUsesFrontedMeekQUIC(protocol)
}

func TunnelProtocolUsesFrontedMeek(protocol string) bool {
	protocol = TunnelProtocolMinusInproxy(protocol)
	return protocol == TUNNEL_PROTOCOL_FRONTED_MEEK ||
		protocol == TUNNEL_PROTOCOL_FRONTED_MEEK_HTTP ||
		protocol == TUNNEL_PROTOCOL_FRONTED_MEEK_QUIC_OBFUSCATED_SSH
}

func TunnelProtocolUsesMeekHTTP(protocol string) bool {
	protocol = TunnelProtocolMinusInproxy(protocol)
	return protocol == TUNNEL_PROTOCOL_UNFRONTED_MEEK ||
		protocol == TUNNEL_PROTOCOL_FRONTED_MEEK_HTTP
}

func TunnelProtocolUsesMeekHTTPNormalizer(protocol string) bool {
	protocol = TunnelProtocolMinusInproxy(protocol)
	return protocol == TUNNEL_PROTOCOL_UNFRONTED_MEEK
}

func TunnelProtocolUsesMeekHTTPS(protocol string) bool {
	protocol = TunnelProtocolMinusInproxy(protocol)
	return protocol == TUNNEL_PROTOCOL_FRONTED_MEEK ||
		protocol == TUNNEL_PROTOCOL_UNFRONTED_MEEK_HTTPS ||
		protocol == TUNNEL_PROTOCOL_UNFRONTED_MEEK_SESSION_TICKET
}

func TunnelProtocolUsesObfuscatedSessionTickets(protocol string) bool {
	protocol = TunnelProtocolMinusInproxy(protocol)
	return protocol == TUNNEL_PROTOCOL_UNFRONTED_MEEK_SESSION_TICKET
}

func TunnelProtocolUsesQUIC(protocol string) bool {
	protocol = TunnelProtocolMinusInproxy(protocol)
	return protocol == TUNNEL_PROTOCOL_QUIC_OBFUSCATED_SSH ||
		protocol == TUNNEL_PROTOCOL_FRONTED_MEEK_QUIC_OBFUSCATED_SSH
}

func TunnelProtocolUsesFrontedMeekQUIC(protocol string) bool {
	protocol = TunnelProtocolMinusInproxy(protocol)
	return protocol == TUNNEL_PROTOCOL_FRONTED_MEEK_QUIC_OBFUSCATED_SSH
}

func TunnelProtocolUsesFrontedMeekNonHTTPS(protocol string) bool {
	protocol = TunnelProtocolMinusInproxy(protocol)
	return protocol == TUNNEL_PROTOCOL_FRONTED_MEEK_HTTP ||
		protocol == TUNNEL_PROTOCOL_FRONTED_MEEK_QUIC_OBFUSCATED_SSH
}

func TunnelProtocolUsesRefractionNetworking(protocol string) bool {
	return protocol == TUNNEL_PROTOCOL_TAPDANCE_OBFUSCATED_SSH ||
		protocol == TUNNEL_PROTOCOL_CONJURE_OBFUSCATED_SSH
}

func TunnelProtocolUsesTapDance(protocol string) bool {
	return protocol == TUNNEL_PROTOCOL_TAPDANCE_OBFUSCATED_SSH
}

func TunnelProtocolUsesConjure(protocol string) bool {
	return protocol == TUNNEL_PROTOCOL_CONJURE_OBFUSCATED_SSH
}

func TunnelProtocolUsesShadowsocks(protocol string) bool {
	protocol = TunnelProtocolMinusInproxy(protocol)
	return protocol == TUNNEL_PROTOCOL_SHADOWSOCKS_OSSH
}

func TunnelProtocolIsResourceIntensive(protocol string) bool {
	return TunnelProtocolUsesMeek(protocol) ||
		TunnelProtocolUsesQUIC(protocol) ||
		TunnelProtocolUsesRefractionNetworking(protocol) ||
		TunnelProtocolUsesInproxy(protocol)
}

func TunnelProtocolIsCompatibleWithFragmentor(protocol string) bool {
	protocol = TunnelProtocolMinusInproxy(protocol)
	return protocol == TUNNEL_PROTOCOL_SSH ||
		protocol == TUNNEL_PROTOCOL_OBFUSCATED_SSH ||
		protocol == TUNNEL_PROTOCOL_TLS_OBFUSCATED_SSH ||
		protocol == TUNNEL_PROTOCOL_UNFRONTED_MEEK ||
		protocol == TUNNEL_PROTOCOL_UNFRONTED_MEEK_HTTPS ||
		protocol == TUNNEL_PROTOCOL_UNFRONTED_MEEK_SESSION_TICKET ||
		protocol == TUNNEL_PROTOCOL_FRONTED_MEEK ||
		protocol == TUNNEL_PROTOCOL_FRONTED_MEEK_HTTP ||
		protocol == TUNNEL_PROTOCOL_CONJURE_OBFUSCATED_SSH ||
		protocol == TUNNEL_PROTOCOL_SHADOWSOCKS_OSSH
}

func TunnelProtocolIsDirect(protocol string) bool {
	return protocol == TUNNEL_PROTOCOL_SSH ||
		protocol == TUNNEL_PROTOCOL_OBFUSCATED_SSH ||
		protocol == TUNNEL_PROTOCOL_TLS_OBFUSCATED_SSH ||
		protocol == TUNNEL_PROTOCOL_UNFRONTED_MEEK ||
		protocol == TUNNEL_PROTOCOL_UNFRONTED_MEEK_HTTPS ||
		protocol == TUNNEL_PROTOCOL_UNFRONTED_MEEK_SESSION_TICKET ||
		protocol == TUNNEL_PROTOCOL_QUIC_OBFUSCATED_SSH ||
		protocol == TUNNEL_PROTOCOL_SHADOWSOCKS_OSSH
}

func TunnelProtocolRequiresTLS12SessionTickets(protocol string) bool {
	protocol = TunnelProtocolMinusInproxy(protocol)
	return protocol == TUNNEL_PROTOCOL_UNFRONTED_MEEK_SESSION_TICKET
}

func TunnelProtocolRequiresTLS13Support(protocol string) bool {
	protocol = TunnelProtocolMinusInproxy(protocol)
	return protocol == TUNNEL_PROTOCOL_TLS_OBFUSCATED_SSH
}

func TunnelProtocolSupportsPassthrough(protocol string) bool {
	protocol = TunnelProtocolMinusInproxy(protocol)
	return protocol == TUNNEL_PROTOCOL_UNFRONTED_MEEK_HTTPS ||
		protocol == TUNNEL_PROTOCOL_UNFRONTED_MEEK_SESSION_TICKET ||
		protocol == TUNNEL_PROTOCOL_UNFRONTED_MEEK ||
		protocol == TUNNEL_PROTOCOL_TLS_OBFUSCATED_SSH
}

func TunnelProtocolSupportsUpstreamProxy(protocol string) bool {
	return !TunnelProtocolUsesInproxy(protocol) &&
		!TunnelProtocolUsesQUIC(protocol)
}

func TunnelProtocolSupportsTactics(protocol string) bool {
	return TunnelProtocolUsesMeek(protocol)
}

func TunnelProtocolMayUseServerPacketManipulation(protocol string) bool {
	protocol = TunnelProtocolMinusInproxy(protocol)
	return protocol == TUNNEL_PROTOCOL_SSH ||
		protocol == TUNNEL_PROTOCOL_OBFUSCATED_SSH ||
		protocol == TUNNEL_PROTOCOL_TLS_OBFUSCATED_SSH ||
		protocol == TUNNEL_PROTOCOL_UNFRONTED_MEEK ||
		protocol == TUNNEL_PROTOCOL_UNFRONTED_MEEK_HTTPS ||
		protocol == TUNNEL_PROTOCOL_UNFRONTED_MEEK_SESSION_TICKET ||
		protocol == TUNNEL_PROTOCOL_SHADOWSOCKS_OSSH
}

func TunnelProtocolMayUseClientBPF(protocol string) bool {
	if TunnelProtocolUsesInproxy(protocol) {
		return false
	}
	return protocol != TUNNEL_PROTOCOL_QUIC_OBFUSCATED_SSH &&
		protocol != TUNNEL_PROTOCOL_FRONTED_MEEK_QUIC_OBFUSCATED_SSH
}

func IsValidClientTunnelProtocol(
	clientProtocol string,
	listenerProtocol string,
	serverProtocols TunnelProtocols) bool {

	if !common.Contains(serverProtocols, clientProtocol) {
		return false
	}

	// If the client reports the same tunnel protocol as the listener, the value
	// is valid.

	if clientProtocol == listenerProtocol {
		return true
	}

	// When the server is running multiple fronted protocols, and the client
	// reports a fronted protocol, the client's reported tunnel protocol is
	// presumed to be valid since some CDNs forward several protocols to the same
	// server port; in this case the listener port is not sufficient to
	// distinguish these protocols.

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

// FrontingTransports are transport protocols used for non-tunnel, fronted
// connections such as in-proxy broker requests.
type FrontingTransports []string

func (transports FrontingTransports) Validate() error {
	for _, t := range transports {
		switch t {
		case FRONTING_TRANSPORT_HTTPS,
			FRONTING_TRANSPORT_HTTP,
			FRONTING_TRANSPORT_QUIC:
		default:
			return errors.Tracef("invalid fronting transport: %s", t)
		}
	}
	return nil
}

// EquivilentTunnelProtocol returns the tunnel protocol equivilent of a
// fronting transport. This value may be used to select tactics, defined for
// the tunnel protocol, for the fronting transport.
func EquivilentTunnelProtocol(t string) (string, error) {
	switch t {
	case FRONTING_TRANSPORT_HTTPS:
		return TUNNEL_PROTOCOL_FRONTED_MEEK, nil
	case FRONTING_TRANSPORT_HTTP:
		return TUNNEL_PROTOCOL_FRONTED_MEEK_HTTP, nil
	case FRONTING_TRANSPORT_QUIC:
		return TUNNEL_PROTOCOL_FRONTED_MEEK_QUIC_OBFUSCATED_SSH, nil
	}
	return "", errors.Tracef("invalid fronting transport: %s", t)
}

const (
	TLS_VERSION_12             = "TLSv1.2"
	TLS_VERSION_13             = "TLSv1.3"
	TLS_PROFILE_IOS_111        = "iOS-11.1"
	TLS_PROFILE_IOS_121        = "iOS-12.1"
	TLS_PROFILE_IOS_13         = "iOS-13"
	TLS_PROFILE_IOS_14         = "iOS-14"
	TLS_PROFILE_SAFARI_16      = "Safari-16"
	TLS_PROFILE_CHROME_58      = "Chrome-58"
	TLS_PROFILE_CHROME_62      = "Chrome-62"
	TLS_PROFILE_CHROME_70      = "Chrome-70"
	TLS_PROFILE_CHROME_72      = "Chrome-72"
	TLS_PROFILE_CHROME_83      = "Chrome-83"
	TLS_PROFILE_CHROME_96      = "Chrome-96"
	TLS_PROFILE_CHROME_102     = "Chrome-102"
	TLS_PROFILE_CHROME_106     = "Chrome-106"
	TLS_PROFILE_CHROME_112_PSK = "Chrome-112_PSK"
	TLS_PROFILE_CHROME_120     = "Chrome-120"
	TLS_PROFILE_CHROME_120_PQ  = "Chrome-120_PQ"
	TLS_PROFILE_FIREFOX_55     = "Firefox-55"
	TLS_PROFILE_FIREFOX_56     = "Firefox-56"
	TLS_PROFILE_FIREFOX_65     = "Firefox-65"
	TLS_PROFILE_FIREFOX_99     = "Firefox-99"
	TLS_PROFILE_FIREFOX_105    = "Firefox-105"
	TLS_PROFILE_RANDOMIZED     = "Randomized-v2"
)

var SupportedTLSProfiles = TLSProfiles{
	TLS_PROFILE_IOS_111,
	TLS_PROFILE_IOS_121,
	TLS_PROFILE_IOS_13,
	TLS_PROFILE_IOS_14,
	TLS_PROFILE_SAFARI_16,
	TLS_PROFILE_CHROME_58,
	TLS_PROFILE_CHROME_62,
	TLS_PROFILE_CHROME_70,
	TLS_PROFILE_CHROME_72,
	TLS_PROFILE_CHROME_83,
	TLS_PROFILE_CHROME_96,
	TLS_PROFILE_CHROME_102,
	TLS_PROFILE_CHROME_106,
	TLS_PROFILE_CHROME_112_PSK,
	TLS_PROFILE_CHROME_120,
	TLS_PROFILE_CHROME_120_PQ,
	TLS_PROFILE_FIREFOX_55,
	TLS_PROFILE_FIREFOX_56,
	TLS_PROFILE_FIREFOX_65,
	TLS_PROFILE_FIREFOX_99,
	TLS_PROFILE_FIREFOX_105,
	TLS_PROFILE_RANDOMIZED,
}

var legacyTLSProfiles = TLSProfiles{
	"iOS-Safari-11.3.1",
	"Android-6.0",
	"Android-5.1",
	"Chrome-57",
	"Randomized",
	"TLS-1.3-Randomized",
	"Firefox-102",
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
	QUIC_VERSION_GQUIC39       = "gQUICv39"
	QUIC_VERSION_GQUIC43       = "gQUICv43"
	QUIC_VERSION_GQUIC44       = "gQUICv44"
	QUIC_VERSION_OBFUSCATED    = "OBFUSCATED"
	QUIC_VERSION_V1            = "QUICv1"
	QUIC_VERSION_RANDOMIZED_V1 = "RANDOMIZED-QUICv1"
	QUIC_VERSION_OBFUSCATED_V1 = "OBFUSCATED-QUICv1"
	QUIC_VERSION_DECOY_V1      = "DECOY-QUICv1"
)

// The value of SupportedQUICVersions is conditionally compiled based on
// whether gQUIC is enabled. SupportedQUICv1Versions are the supported QUIC
// versions that are based on QUICv1.

var SupportedGQUICVersions = QUICVersions{
	QUIC_VERSION_GQUIC39,
	QUIC_VERSION_GQUIC43,
	QUIC_VERSION_GQUIC44,
	QUIC_VERSION_OBFUSCATED,
}

var SupportedQUICv1Versions = QUICVersions{
	QUIC_VERSION_V1,
	QUIC_VERSION_RANDOMIZED_V1,
	QUIC_VERSION_OBFUSCATED_V1,
	QUIC_VERSION_DECOY_V1,
}

var legacyQUICVersions = QUICVersions{
	"IETF-draft-24",
}

func QUICVersionHasRandomizedClientHello(version string) bool {
	return version == QUIC_VERSION_RANDOMIZED_V1
}

func QUICVersionIsObfuscated(version string) bool {
	return version == QUIC_VERSION_OBFUSCATED ||
		version == QUIC_VERSION_OBFUSCATED_V1 ||
		version == QUIC_VERSION_DECOY_V1
}

func QUICVersionUsesPathMTUDiscovery(version string) bool {
	return version != QUIC_VERSION_GQUIC39 &&
		version != QUIC_VERSION_GQUIC43 &&
		version != QUIC_VERSION_GQUIC44 &&
		version != QUIC_VERSION_OBFUSCATED
}

type QUICVersions []string

func (versions QUICVersions) Validate() error {
	for _, v := range versions {
		if !common.Contains(SupportedQUICVersions, v) &&
			!common.Contains(legacyQUICVersions, v) {
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

const (
	CONJURE_TRANSPORT_MIN_OSSH    = "Min-OSSH"
	CONJURE_TRANSPORT_PREFIX_OSSH = "Prefix-OSSH"
	CONJURE_TRANSPORT_DTLS_OSSH   = "DTLS-OSSH"
)

var SupportedConjureTransports = ConjureTransports{
	CONJURE_TRANSPORT_MIN_OSSH,
	CONJURE_TRANSPORT_PREFIX_OSSH,
	CONJURE_TRANSPORT_DTLS_OSSH,
}

func ConjureTransportUsesSTUN(transport string) bool {
	return transport == CONJURE_TRANSPORT_DTLS_OSSH
}

func ConjureTransportUsesDTLS(transport string) bool {
	return transport == CONJURE_TRANSPORT_DTLS_OSSH
}

type ConjureTransports []string

func (transports ConjureTransports) Validate() error {
	for _, t := range transports {
		if !common.Contains(SupportedConjureTransports, t) {
			return errors.Tracef("invalid Conjure transport: %s", t)
		}
	}
	return nil
}

func (transports ConjureTransports) PruneInvalid() ConjureTransports {
	u := make(ConjureTransports, 0)
	for _, t := range transports {
		if common.Contains(SupportedConjureTransports, t) {
			u = append(u, t)
		}
	}
	return u
}

type HandshakeResponse struct {
	Homepages                 []string            `json:"homepages,omitempty" cbor:"1,keyasint,omitempty"`
	UpgradeClientVersion      string              `json:"upgrade_client_version,omitempty" cbor:"2,keyasint,omitempty"`
	PageViewRegexes           []map[string]string `json:"page_view_regexes,omitempty" cbor:"3,keyasint,omitempty"`
	HttpsRequestRegexes       []map[string]string `json:"https_request_regexes,omitempty" cbor:"4,keyasint,omitempty"`
	EncodedServerList         []string            `json:"encoded_server_list,omitempty" cbor:"5,keyasint,omitempty"`
	ClientRegion              string              `json:"client_region,omitempty" cbor:"6,keyasint,omitempty"`
	ClientAddress             string              `json:"client_address,omitempty" cbor:"7,keyasint,omitempty"`
	ServerTimestamp           string              `json:"server_timestamp,omitempty" cbor:"8,keyasint,omitempty"`
	ActiveAuthorizationIDs    []string            `json:"active_authorization_ids,omitempty" cbor:"9,keyasint,omitempty"`
	TacticsPayload            json.RawMessage     `json:"tactics_payload,omitempty" cbor:"10,keyasint,omitempty"`
	TacticsPayloadCompression int32               `json:"tactics_payload_compression,omitempty" cbor:"11,keyasint,omitempty"`
	UpstreamBytesPerSecond    int64               `json:"upstream_bytes_per_second,omitempty" cbor:"12,keyasint,omitempty"`
	DownstreamBytesPerSecond  int64               `json:"downstream_bytes_per_second,omitempty" cbor:"13,keyasint,omitempty"`
	SteeringIP                string              `json:"steering_ip,omitempty" cbor:"14,keyasint,omitempty"`
	Padding                   string              `json:"padding,omitempty" cbor:"15,keyasint,omitempty"`
}

type ConnectedResponse struct {
	ConnectedTimestamp string `json:"connected_timestamp,omitempty"`
	Padding            string `json:"padding,omitempty"`
}

type StatusResponse struct {
	InvalidServerEntryTags []string `json:"invalid_server_entry_tags,omitempty"`
	Padding                string   `json:"padding,omitempty"`
}

type OSLRequest struct {
	ClearLocalSLOKs bool             `json:"clear_local_sloks,omitempty"`
	SeedPayload     *osl.SeedPayload `json:"seed_payload,omitempty"`
}

type SSHPasswordPayload struct {
	SessionId          string   `json:"SessionId,omitempty"`
	SshPassword        string   `json:"SshPassword,omitempty"`
	ClientCapabilities []string `json:"ClientCapabilities,omitempty"`
	SponsorID          string   `json:"SponsorId,omitempty"`
}

type MeekCookieData struct {
	MeekProtocolVersion  int    `json:"v,omitempty"`
	ClientTunnelProtocol string `json:"t,omitempty"`
	EndPoint             string `json:"e,omitempty"`
}

type RandomStreamRequest struct {
	UpstreamBytes   int `json:"u,omitempty"`
	DownstreamBytes int `json:"d,omitempty"`
}

type AlertRequest struct {
	Reason     string   `json:"reason,omitempty"`
	Subject    string   `json:"subject,omitempty"`
	ActionURLs []string `json:"action,omitempty"`
}

// CBOREncoding defines the specific CBDR encoding used for all Psiphon CBOR
// message encoding. This is initialized to FIDO2 CTAP2 Canonical CBOR.
var CBOREncoding cbor.EncMode

func init() {
	encOptions := cbor.CTAP2EncOptions()

	// TimeRFC3339Nano matches the JSON encoding time format and is required
	// for accesscontrol.packedAuthorization types, which marshal a time.Time.
	encOptions.Time = cbor.TimeRFC3339Nano

	CBOREncoding, _ = encOptions.EncMode()
}

type InproxyRelayRequest struct {
	Packet []byte `cbor:"1,keyasint,omitempty"`
}

type InproxyRelayResponse struct {
	Packet []byte `cbor:"1,keyasint,omitempty"`
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

// GetCompressTactics checks for the parameter field indicating that
// compressed tactics are supported and requested.
func GetCompressTactics(params common.APIParameters) bool {

	// The generic, versioned psiphon_api_response_version field allows for
	// future enhancements and upgrades to other responses and response values.
	//
	// Version 1 adds compressed tactics payloads, and CBOR binary encoding of
	// responses containing compressed tactics payloads.

	if params[PSIPHON_API_RESPONSE_VERSION_FIELD_NAME] == nil {
		return false
	}
	value, ok := params[PSIPHON_API_RESPONSE_VERSION_FIELD_NAME].(string)
	if !ok {
		return false
	}
	return value == PSIPHON_API_RESPONSE_V1
}

// SetCompressTactics adds a field to params indicating that compressed
// tactics are support and requested.
func SetCompressTactics(params common.APIParameters) {
	params[PSIPHON_API_RESPONSE_VERSION_FIELD_NAME] = PSIPHON_API_RESPONSE_V1
}
