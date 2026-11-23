/*
 * Copyright (c) 2026, Psiphon Inc.
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

// Package light implements a lightweight, blocking resistant TLS and QUIC
// proxy.
package light

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"math"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/proxyheader"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/tlsdialer"
	"github.com/fxamacker/cbor/v2"
)

const (
	proxyIDSize               = 16
	personalCompartmentIDSize = 32
)

// ProxyAddress specifies a Light transport endpoint.
type ProxyAddress struct {
	IPAddress string `cbor:"1,keyasint"`
	Port      int    `cbor:"2,keyasint"`
	Protocol  string `cbor:"3,keyasint"`
}

// String returns the IP:port address.
func (address ProxyAddress) String() string {
	return net.JoinHostPort(address.IPAddress, strconv.Itoa(address.Port))
}

// isSupported indicates whether the address protocol is supported.
func (address ProxyAddress) isSupported() bool {
	return address.Protocol == LIGHT_PROTOCOL_TLS ||
		address.Protocol == LIGHT_PROTOCOL_QUIC
}

func (address ProxyAddress) validate(listen bool) error {
	if !address.isSupported() {
		return errors.TraceNew("unsupported proxy protocol")
	}

	IP := net.ParseIP(address.IPAddress)
	if IP == nil || IP.IsMulticast() || (!listen && IP.IsUnspecified()) {
		return errors.TraceNew("invalid proxy IP address")
	}

	if address.Port < 0 || address.Port > 65535 ||
		(!listen && address.Port == 0) {

		return errors.TraceNew("invalid proxy port")
	}

	return nil
}

// ValidateProxyAddresses checks public and local endpoints paired by index.
// Omitted listen addresses default to the dial addresses for validation.
func ValidateProxyAddresses(
	dialAddresses, listenAddresses []ProxyAddress) error {

	if len(dialAddresses) == 0 {
		return errors.TraceNew("missing dial addresses")
	}
	if len(listenAddresses) == 0 {
		listenAddresses = dialAddresses
	}
	if len(listenAddresses) != len(dialAddresses) {
		return errors.TraceNew("mismatched dial and listen address counts")
	}

	err := ValidateProxyListenAddresses(listenAddresses)
	if err != nil {
		return errors.Trace(err)
	}
	for i, dialAddress := range dialAddresses {
		err = dialAddress.validate(false)
		if err != nil {
			return errors.Trace(err)
		}

		listenAddress := listenAddresses[i]
		if listenAddress.Protocol != dialAddress.Protocol {
			return errors.TraceNew("mismatched dial and listen protocols")
		}
		dialIsIPv4 := net.ParseIP(dialAddress.IPAddress).To4() != nil
		listenIsIPv4 := net.ParseIP(listenAddress.IPAddress).To4() != nil
		if dialIsIPv4 != listenIsIPv4 {
			return errors.TraceNew("mismatched dial and listen IP address families")
		}
	}
	return nil
}

// ValidateProxyConfigAddresses validates proxy endpoints and returns the
// effective listen addresses. requireDialAddresses is false for tunnel proxies,
// whose public addresses may not be known until port mapping completes.
func ValidateProxyConfigAddresses(
	dialAddresses, listenAddresses []ProxyAddress,
	requireDialAddresses bool) ([]ProxyAddress, error) {

	var err error
	if len(dialAddresses) == 0 && !requireDialAddresses {
		err = ValidateProxyListenAddresses(listenAddresses)
	} else {
		err = ValidateProxyAddresses(dialAddresses, listenAddresses)
	}
	if err != nil {
		return nil, errors.Trace(err)
	}
	if len(listenAddresses) == 0 {
		listenAddresses = dialAddresses
	}
	return listenAddresses, nil
}

// ValidateProxyListenAddresses validates local endpoints without requiring
// public addresses, which may not be known until port mapping completes.
func ValidateProxyListenAddresses(addresses []ProxyAddress) error {
	if len(addresses) == 0 {
		return errors.TraceNew("missing listen addresses")
	}
	seen := make(map[ProxyAddress]bool)
	for _, address := range addresses {
		err := address.validate(true)
		if err != nil {
			return errors.Trace(err)
		}
		// Port zero requests distinct, dynamically assigned listeners.
		if address.Port != 0 {
			address.IPAddress = net.ParseIP(address.IPAddress).String()
			if seen[address] {
				return errors.TraceNew("duplicate listen address")
			}
			seen[address] = true
		}
	}
	return nil
}

// ProxyEntry is the proxy connection information distributed to clients.
// In tunnel mode, ProxyID must match GetTunnelProxyID for the signing key.
// VerifyServerName is retained for legacy fallback clients; new clients
// verify only VerifyPin.
//
// Protocol and DialAddressIPv4/6 support legacy fallback clients.
// Non-legacy clients use DialAddresses when present.
type ProxyEntry struct {
	Protocol                                  string         `cbor:"1,keyasint,omitempty"`
	DialAddressIPv4                           string         `cbor:"2,keyasint,omitempty"`
	RecommendedSNI                            string         `cbor:"3,keyasint,omitempty"`
	ObfuscationKey                            []byte         `cbor:"4,keyasint,omitempty"`
	VerifyPin                                 []byte         `cbor:"5,keyasint,omitempty"`
	VerifyServerName                          string         `cbor:"6,keyasint,omitempty"`
	DialAddressIPv6                           string         `cbor:"7,keyasint,omitempty"`
	RecommendedSNIRegex                       string         `cbor:"8,keyasint,omitempty"`
	RecommendedFragmentClientHelloProbability float64        `cbor:"9,keyasint,omitempty"`
	RecommendedTLSPaddingProbability          float64        `cbor:"10,keyasint,omitempty"`
	RecommendedMinTLSPadding                  int            `cbor:"11,keyasint,omitempty"`
	RecommendedMaxTLSPadding                  int            `cbor:"12,keyasint,omitempty"`
	RecommendedSNIProbability                 float64        `cbor:"13,keyasint,omitempty"`
	RecommendedTLSProfile                     string         `cbor:"14,keyasint,omitempty"`
	RecommendedTLSProfileProbability          float64        `cbor:"15,keyasint,omitempty"`
	TTLSeconds                                int64          `cbor:"16,keyasint,omitempty"`
	DialAddresses                             []ProxyAddress `cbor:"17,keyasint,omitempty"`
	ProxyID                                   string         `cbor:"18,keyasint,omitempty"`
	PersonalCompartmentID                     []byte         `cbor:"19,keyasint,omitempty"`
}

// SignedProxyEntry is a signed ProxyEntry.
type SignedProxyEntry struct {

	// Currently signatures are not added or verified since the initial
	// distribution scheme for proxy entries is via ephemeral push payloads,
	// which are already signed. Adding the SignedProxyEntry layer now allows
	// for the addition of signatures in the future without changing the
	// expected unmarshal type, SignedProxyEntry.

	Signature  []byte     `cbor:"1,keyasint,omitempty"`
	ProxyEntry ProxyEntry `cbor:"2,keyasint,omitempty"`
}

// DecodeAndValidateProxyEntry decodes and validates a SignedProxyEntry.
//
// Entries are not signed; see SignedProxyEntry. A personal pairing entry is
// supplied by the user and is trusted as-is.
func DecodeAndValidateProxyEntry(encodedSignedProxyEntry []byte) (*ProxyEntry, error) {

	var signedProxyEntry SignedProxyEntry
	err := cbor.Unmarshal(encodedSignedProxyEntry, &signedProxyEntry)
	if err != nil {
		return nil, errors.Trace(err)
	}

	// There is currently no signature. See SignedProxyEntry comment.
	proxyEntry := &signedProxyEntry.ProxyEntry

	legacyEntry := proxyEntry.DialAddresses == nil
	if legacyEntry {
		err = validateIPAddressFamily(proxyEntry.DialAddressIPv4, false)
		if err != nil {
			return nil, errors.Trace(err)
		}

		address, err := parseProxyAddress(
			proxyEntry.DialAddressIPv4, proxyEntry.Protocol)
		if err != nil {
			return nil, errors.Trace(err)
		}
		proxyEntry.DialAddresses = append(proxyEntry.DialAddresses, address)

		if proxyEntry.DialAddressIPv6 != "" {
			err = validateIPAddressFamily(proxyEntry.DialAddressIPv6, true)
			if err != nil {
				return nil, errors.Trace(err)
			}
			address, err := parseProxyAddress(
				proxyEntry.DialAddressIPv6, proxyEntry.Protocol)
			if err != nil {
				return nil, errors.Trace(err)
			}
			proxyEntry.DialAddresses = append(proxyEntry.DialAddresses, address)
		}
	}

	// Skip dial addresses with unsupported protocols, so that entries may
	// add addresses for future protocols without being rejected by existing
	// clients.
	var dialAddresses []ProxyAddress
	for _, address := range proxyEntry.DialAddresses {
		if !address.isSupported() {
			continue
		}
		if err := address.validate(false); err != nil {
			return nil, errors.Trace(err)
		}
		dialAddresses = append(dialAddresses, address)
	}
	if len(dialAddresses) == 0 {
		return nil, errors.TraceNew("missing dial addresses")
	}
	proxyEntry.DialAddresses = dialAddresses

	if len(proxyEntry.ObfuscationKey) == 0 {
		return nil, errors.TraceNew("missing obfuscation key")
	}

	if proxyEntry.ProxyID == "" {
		if !legacyEntry {
			return nil, errors.TraceNew("missing proxy ID")
		}
		proxyEntry.ProxyID = makeLegacyProxyID(
			proxyEntry.DialAddressIPv4,
			hex.EncodeToString(proxyEntry.ObfuscationKey))
	} else {
		// The proxy ID is reported in API parameters that require unpadded
		// base64.
		_, err := base64.RawStdEncoding.DecodeString(proxyEntry.ProxyID)
		if err != nil {
			return nil, errors.TraceNew("invalid proxy ID")
		}
	}

	if len(proxyEntry.VerifyPin) == 0 {
		return nil, errors.TraceNew("missing verify pin")
	}

	if len(proxyEntry.PersonalCompartmentID) != 0 &&
		len(proxyEntry.PersonalCompartmentID) != personalCompartmentIDSize {

		return nil, errors.TraceNew("invalid personal compartment ID")
	}

	err = validateRecommendedTLSSettings(
		proxyEntry.RecommendedFragmentClientHelloProbability,
		proxyEntry.RecommendedTLSPaddingProbability,
		proxyEntry.RecommendedMinTLSPadding,
		proxyEntry.RecommendedMaxTLSPadding,
		proxyEntry.RecommendedSNIProbability,
		proxyEntry.RecommendedTLSProfileProbability)
	if err != nil {
		return nil, errors.Trace(err)
	}

	if proxyEntry.TTLSeconds < 0 ||
		proxyEntry.TTLSeconds > int64(math.MaxInt64/time.Second) {
		return nil, errors.TraceNew("invalid TTL")
	}

	// Do not validate RecommendedTLSProfile here. Future proxy entries may
	// recommend profiles not present in this client's SupportedTLSProfiles;
	// callers must fall back when the recommendation is unknown.

	return proxyEntry, nil
}

func getLightProtocols(addresses []ProxyAddress) []string {
	var protocols []string
	for _, address := range addresses {
		if !common.Contains(protocols, address.Protocol) {
			protocols = append(protocols, address.Protocol)
		}
	}
	return protocols
}

func parseProxyAddress(address, protocol string) (ProxyAddress, error) {
	host, portString, err := net.SplitHostPort(address)
	if err != nil {
		return ProxyAddress{}, errors.Trace(err)
	}
	port, err := strconv.Atoi(portString)
	if err != nil {
		return ProxyAddress{}, errors.Trace(err)
	}

	return ProxyAddress{
		IPAddress: host,
		Port:      port,
		Protocol:  protocol,
	}, nil
}

func validateIPAddressFamily(addr string, isIPv6 bool) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return errors.Trace(err)
	}
	IP := net.ParseIP(host)
	if IP == nil {
		return errors.TraceNew("invalid IP address")
	}
	if (IP.To4() == nil) != isIPv6 {
		return errors.TraceNew("unexpected IP address family")
	}
	return nil
}

// makeLegacyProxyID derives the legacy fallback proxy ID from the IPv4
// dial address and hex obfuscation key.
func makeLegacyProxyID(dialAddress, obfuscationKey string) string {
	h := hmac.New(sha256.New, []byte(obfuscationKey))
	h.Write([]byte(dialAddress))
	return base64.RawStdEncoding.EncodeToString(h.Sum(nil)[:proxyIDSize])
}

func validateRecommendedTLSSettings(
	fragmentClientHelloProbability float64,
	tlsPaddingProbability float64,
	minTLSPadding int,
	maxTLSPadding int,
	sniProbability float64,
	tlsProfileProbability float64) error {

	if !(fragmentClientHelloProbability >= 0.0 &&
		fragmentClientHelloProbability <= 1.0) {
		return errors.TraceNew("invalid recommended FragmentClientHello probability")
	}

	if !(tlsPaddingProbability >= 0.0 &&
		tlsPaddingProbability <= 1.0) {
		return errors.TraceNew("invalid recommended TLS padding probability")
	}

	if !(sniProbability >= 0.0 && sniProbability <= 1.0) {
		return errors.TraceNew("invalid recommended SNI probability")
	}

	if !(tlsProfileProbability >= 0.0 && tlsProfileProbability <= 1.0) {
		return errors.TraceNew("invalid recommended TLS profile probability")
	}

	if minTLSPadding < 0 ||
		maxTLSPadding < minTLSPadding ||
		maxTLSPadding > tlsdialer.MaxTLSPadding {
		return errors.TraceNew("invalid recommended TLS padding range")
	}

	return nil
}

type proxyProtocolHeaderConfig struct {
	macKey                     []byte
	customTLV                  []byte
	targetDestinationAddresses common.StringLookup
}

func prepareProxyProtocolHeaderConfigs(
	proxyProtocolHeaderMACKeys map[string]string,
	proxyProtocolHeaderCustomTLVs map[string]string,
	proxyProtocolHeaderTargetDestinationAddresses map[string][]string,
) (map[string]proxyProtocolHeaderConfig, error) {

	proxyProtocolHeaderConfigs := make(map[string]proxyProtocolHeaderConfig)
	for sponsorID, base64Value := range proxyProtocolHeaderMACKeys {
		value, err := base64.StdEncoding.DecodeString(base64Value)
		if err != nil {
			return nil, errors.Trace(err)
		}
		err = proxyheader.ValidateMACKey(value)
		if err != nil {
			return nil, errors.Tracef(
				"invalid ProxyProtocolHeaderMACKeys value: %v", err)
		}
		proxyProtocolHeaderConfigs[sponsorID] = proxyProtocolHeaderConfig{macKey: value}
	}

	for sponsorID, base64Value := range proxyProtocolHeaderCustomTLVs {
		proxyProtocolHeaderConfig, ok := proxyProtocolHeaderConfigs[sponsorID]
		if !ok {
			return nil, errors.TraceNew(
				"missing ProxyProtocolHeaderMACKeys entry")
		}

		customTLV, err := base64.StdEncoding.DecodeString(base64Value)
		if err != nil {
			return nil, errors.Tracef(
				"invalid ProxyProtocolHeaderCustomTLVs value: %v", err)
		}

		err = proxyheader.ValidateCustomTLV(customTLV)
		if err != nil {
			return nil, errors.Tracef(
				"invalid ProxyProtocolHeaderCustomTLVs value: %v", err)
		}

		proxyProtocolHeaderConfig.customTLV = customTLV
		proxyProtocolHeaderConfigs[sponsorID] = proxyProtocolHeaderConfig
	}

	for sponsorID, targets := range proxyProtocolHeaderTargetDestinationAddresses {
		proxyProtocolHeaderConfig, ok := proxyProtocolHeaderConfigs[sponsorID]
		if !ok {
			return nil, errors.TraceNew("missing ProxyProtocolHeaderMACKey entry")
		}
		normalizedTargets := make([]string, 0, len(targets))
		for _, target := range targets {
			if target == "" || (net.ParseIP(target) == nil && strings.ContainsAny(target, ":[]")) {
				return nil, errors.TraceNew("PROXY protocol target must be a host without a port")
			}
			normalizedTargets = append(normalizedTargets, common.NormalizeHostAddress(target))
		}
		proxyProtocolHeaderConfig.targetDestinationAddresses =
			common.NewStringLookup(normalizedTargets)
		proxyProtocolHeaderConfigs[sponsorID] = proxyProtocolHeaderConfig
	}

	return proxyProtocolHeaderConfigs, nil
}

func normalizeDestinationAddress(address string) (string, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return "", errors.Trace(err)
	}
	return net.JoinHostPort(common.NormalizeHostAddress(host), port), nil
}

func encodeClientPlatform(clientPlatform string) uint8 {
	clientPlatform = strings.ToLower(clientPlatform)
	switch {
	case strings.Contains(clientPlatform, "ios") ||
		strings.Contains(clientPlatform, "ipados"):
		return 1
	case strings.Contains(clientPlatform, "android"):
		return 2
	case strings.Contains(clientPlatform, "windows"):
		return 3
	case strings.Contains(clientPlatform, "linux"):
		return 4
	case strings.Contains(clientPlatform, "macos") ||
		strings.Contains(clientPlatform, "darwin") ||
		strings.Contains(clientPlatform, "osx"):
		return 5
	default:
		return 0
	}
}

func decodeClientPlatform(encodedClientPlatform uint8) string {
	switch encodedClientPlatform {
	case 1:
		return "iOS"
	case 2:
		return "Android"
	case 3:
		return "Windows"
	case 4:
		return "Linux"
	case 5:
		return "macOS"
	default:
		return ""
	}
}

func encodeNetworkType(networkType string) uint8 {
	switch networkType {
	case "WIFI":
		return 1
	case "MOBILE":
		return 2
	case "WIRED":
		return 3
	case "VPN":
		return 4
	case "UNKNOWN":
		return 5
	default:
		return 0
	}
}

func decodeNetworkType(encodedNetworkType uint8) string {
	switch encodedNetworkType {
	case 1:
		return "WIFI"
	case 2:
		return "MOBILE"
	case 3:
		return "WIRED"
	case 4:
		return "VPN"
	case 5:
		return "UNKNOWN"
	default:
		return ""
	}
}

var tlsProfileToCode = map[string]uint8{

	// When protocol.SupportedTLSProfiles changes this table must be updated.

	protocol.TLS_PROFILE_IOS_111:        1,
	protocol.TLS_PROFILE_IOS_121:        2,
	protocol.TLS_PROFILE_IOS_13:         3,
	protocol.TLS_PROFILE_IOS_14:         4,
	protocol.TLS_PROFILE_SAFARI_16:      5,
	protocol.TLS_PROFILE_CHROME_58:      6,
	protocol.TLS_PROFILE_CHROME_62:      7,
	protocol.TLS_PROFILE_CHROME_70:      8,
	protocol.TLS_PROFILE_CHROME_72:      9,
	protocol.TLS_PROFILE_CHROME_83:      10,
	protocol.TLS_PROFILE_CHROME_96:      11,
	protocol.TLS_PROFILE_CHROME_102:     12,
	protocol.TLS_PROFILE_CHROME_106:     13,
	protocol.TLS_PROFILE_CHROME_112_PSK: 14,
	protocol.TLS_PROFILE_CHROME_120:     15,
	protocol.TLS_PROFILE_CHROME_120_PQ:  16,
	protocol.TLS_PROFILE_FIREFOX_55:     17,
	protocol.TLS_PROFILE_FIREFOX_56:     18,
	protocol.TLS_PROFILE_FIREFOX_65:     19,
	protocol.TLS_PROFILE_FIREFOX_99:     20,
	protocol.TLS_PROFILE_FIREFOX_105:    21,
	protocol.TLS_PROFILE_RANDOMIZED:     22,
	protocol.TLS_PROFILE_CHROME_131:     23,
	protocol.TLS_PROFILE_CHROME_133:     24,
}

var codeToTLSProfile = map[uint8]string{
	1:  protocol.TLS_PROFILE_IOS_111,
	2:  protocol.TLS_PROFILE_IOS_121,
	3:  protocol.TLS_PROFILE_IOS_13,
	4:  protocol.TLS_PROFILE_IOS_14,
	5:  protocol.TLS_PROFILE_SAFARI_16,
	6:  protocol.TLS_PROFILE_CHROME_58,
	7:  protocol.TLS_PROFILE_CHROME_62,
	8:  protocol.TLS_PROFILE_CHROME_70,
	9:  protocol.TLS_PROFILE_CHROME_72,
	10: protocol.TLS_PROFILE_CHROME_83,
	11: protocol.TLS_PROFILE_CHROME_96,
	12: protocol.TLS_PROFILE_CHROME_102,
	13: protocol.TLS_PROFILE_CHROME_106,
	14: protocol.TLS_PROFILE_CHROME_112_PSK,
	15: protocol.TLS_PROFILE_CHROME_120,
	16: protocol.TLS_PROFILE_CHROME_120_PQ,
	17: protocol.TLS_PROFILE_FIREFOX_55,
	18: protocol.TLS_PROFILE_FIREFOX_56,
	19: protocol.TLS_PROFILE_FIREFOX_65,
	20: protocol.TLS_PROFILE_FIREFOX_99,
	21: protocol.TLS_PROFILE_FIREFOX_105,
	22: protocol.TLS_PROFILE_RANDOMIZED,
	23: protocol.TLS_PROFILE_CHROME_131,
	24: protocol.TLS_PROFILE_CHROME_133,
}

func encodeTLSProfile(tlsProfile string) uint8 {
	return tlsProfileToCode[tlsProfile]
}

func decodeTLSProfile(encodedTLSProfile uint8) string {
	return codeToTLSProfile[encodedTLSProfile]
}

var quicVersionToCode = map[string]uint8{
	protocol.QUIC_VERSION_V1:            1,
	protocol.QUIC_VERSION_RANDOMIZED_V1: 2,
	protocol.QUIC_VERSION_OBFUSCATED_V1: 3,
	protocol.QUIC_VERSION_DECOY_V1:      4,
}

var codeToQUICVersion = map[uint8]string{
	1: protocol.QUIC_VERSION_V1,
	2: protocol.QUIC_VERSION_RANDOMIZED_V1,
	3: protocol.QUIC_VERSION_OBFUSCATED_V1,
	4: protocol.QUIC_VERSION_DECOY_V1,
}

func encodeQUICVersion(QUICVersion string) uint8 {
	return quicVersionToCode[QUICVersion]
}

func decodeQUICVersion(encodedQUICVersion uint8) string {
	return codeToQUICVersion[encodedQUICVersion]
}
