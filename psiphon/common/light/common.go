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

// Package light implements a lightweight, blocking resistent TLS proxy.
package light

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"math"
	"net"
	"strings"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/proxyheader"
	"github.com/fxamacker/cbor/v2"
)

const (
	proxyIDSize              = 16
	maxRecommendedTLSPadding = 65535
)

// ProxyEntry is the proxy connection information distributed to clients.
type ProxyEntry struct {
	Protocol                                  string  `cbor:"1,keyasint,omitempty"`
	DialAddressIPv4                           string  `cbor:"2,keyasint,omitempty"`
	RecommendedSNI                            string  `cbor:"3,keyasint,omitempty"`
	ObfuscationKey                            []byte  `cbor:"4,keyasint,omitempty"`
	VerifyPin                                 []byte  `cbor:"5,keyasint,omitempty"`
	VerifyServerName                          string  `cbor:"6,keyasint,omitempty"`
	DialAddressIPv6                           string  `cbor:"7,keyasint,omitempty"`
	RecommendedSNIRegex                       string  `cbor:"8,keyasint,omitempty"`
	RecommendedFragmentClientHelloProbability float64 `cbor:"9,keyasint,omitempty"`
	RecommendedTLSPaddingProbability          float64 `cbor:"10,keyasint,omitempty"`
	RecommendedMinTLSPadding                  int     `cbor:"11,keyasint,omitempty"`
	RecommendedMaxTLSPadding                  int     `cbor:"12,keyasint,omitempty"`
	RecommendedSNIProbability                 float64 `cbor:"13,keyasint,omitempty"`
	RecommendedTLSProfile                     string  `cbor:"14,keyasint,omitempty"`
	RecommendedTLSProfileProbability          float64 `cbor:"15,keyasint,omitempty"`
	TTLSeconds                                int64   `cbor:"16,keyasint,omitempty"`
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
func DecodeAndValidateProxyEntry(encodedSignedProxyEntry []byte) (*ProxyEntry, error) {

	var signedProxyEntry SignedProxyEntry
	err := cbor.Unmarshal(encodedSignedProxyEntry, &signedProxyEntry)
	if err != nil {
		return nil, errors.Trace(err)
	}

	// There is currently no signature. See SignedProxyEntry comment.
	proxyEntry := &signedProxyEntry.ProxyEntry

	if proxyEntry.Protocol != LIGHT_PROTOCOL_TLS {
		return nil, errors.TraceNew("unsupported proxy protocol")
	}

	err = validateIPAddressFamily(proxyEntry.DialAddressIPv4, false)
	if err != nil {
		return nil, errors.Trace(err)
	}

	if proxyEntry.DialAddressIPv6 != "" {
		err = validateIPAddressFamily(proxyEntry.DialAddressIPv6, true)
		if err != nil {
			return nil, errors.Trace(err)
		}
	}

	if len(proxyEntry.ObfuscationKey) == 0 {
		return nil, errors.TraceNew("missing obfuscation key")
	}

	if len(proxyEntry.VerifyPin) == 0 {
		return nil, errors.TraceNew("missing TLS verify pin")
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

// makeProxyID derives a unique proxy ID from a proxy's dial address and
// obfuscation key. This derivation saves light header space.
func makeProxyID(dialAddress, obfuscationKey string) string {
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
		maxTLSPadding > maxRecommendedTLSPadding {
		return errors.TraceNew("invalid recommended TLS padding range")
	}

	return nil
}

type proxyProtocolHeaderConfig struct {
	macKey                     []byte
	targetDestinationAddresses common.StringLookup
}

func prepareProxyProtocolHeaderConfigs(
	proxyProtocolHeaderMACKeys map[string]string,
	proxyProtocolHeaderTargetDestinationAddresses map[string][]string,
) (map[string]proxyProtocolHeaderConfig, error) {

	proxyProtocolHeaderConfigs := make(map[string]proxyProtocolHeaderConfig)
	for sponsorID, base64Value := range proxyProtocolHeaderMACKeys {
		value, err := base64.StdEncoding.DecodeString(base64Value)
		if err != nil {
			return nil, errors.Trace(err)
		}
		if len(value) != proxyheader.ProxyProtocolHeaderKeyIDSize+proxyheader.ProxyProtocolHeaderMACKeySize {
			return nil, errors.TraceNew("unexpected ProxyProtocolHeaderMACKeys value size")
		}
		proxyProtocolHeaderConfigs[sponsorID] = proxyProtocolHeaderConfig{macKey: value}
	}

	for sponsorID, targets := range proxyProtocolHeaderTargetDestinationAddresses {
		proxyProtocolHeaderConfig, ok := proxyProtocolHeaderConfigs[sponsorID]
		if !ok {
			return nil, errors.TraceNew("missing ProxyProtocolHeaderMACKey entry")
		}
		normalizedTargets := make([]string, 0, len(targets))
		for _, target := range targets {
			normalizedTarget, err := normalizeDestinationAddress(target)
			if err != nil {
				return nil, errors.Trace(err)
			}
			normalizedTargets = append(normalizedTargets, normalizedTarget)
		}
		proxyProtocolHeaderConfig.targetDestinationAddresses =
			common.NewStringLookup(normalizedTargets)
		proxyProtocolHeaderConfigs[sponsorID] = proxyProtocolHeaderConfig
	}

	return proxyProtocolHeaderConfigs, nil
}

func normalizeDestinationAddress(address string) (string, error) {

	// TODO: make common helper and also use for
	// psiphon/server.normalizeProxyProtocolTargetDestinationAddress.

	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return "", errors.Trace(err)
	}

	// Normalize IP address representation.
	ip := net.ParseIP(host)
	if ip != nil {
		return net.JoinHostPort(ip.String(), port), nil
	}

	// Normalize domain case and remove any trailing .
	host = strings.TrimSuffix(host, ".")
	host = strings.ToLower(host)
	return net.JoinHostPort(host, port), nil
}

func encodeClientPlatform(clientPlatform string) uint8 {
	clientPlatform = strings.ToLower(clientPlatform)
	switch {
	case strings.Contains(clientPlatform, "ios"):
		return 1
	case strings.Contains(clientPlatform, "android"):
		return 2
	case strings.Contains(clientPlatform, "windows"):
		return 3
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
