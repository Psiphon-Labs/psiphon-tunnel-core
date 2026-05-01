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
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
)

// ProxyEntry is the proxy connection information distributed to clients.
type ProxyEntry struct {
	Protocol         string `cbor:"1,keyasint,omitempty"`
	DialAddress      string `cbor:"2,keyasint,omitempty"`
	RecommendedSNI   string `cbor:"3,keyasint,omitempty"`
	ObfuscationKey   []byte `cbor:"4,keyasint,omitempty"`
	VerifyPin        []byte `cbor:"5,keyasint,omitempty"`
	VerifyServerName string `cbor:"6,keyasint,omitempty"`
}

// SignedProxyEntry is a signed ProxyEntry.
type SignedProxyEntry struct {

	// Currently signatures are not added or verified since the initial
	// distribution scheme for proxy entries is via ephemeral push payloads,
	// which are already signed, with no persistent storage. Adding the
	// SignedProxyEntry layer now allows for the addition of signatures in
	// the future without changing the expected unmarshal type,
	// SignedProxyEntry.

	Signature  []byte     `cbor:"1,keyasint,omitempty"`
	ProxyEntry ProxyEntry `cbor:"2,keyasint,omitempty"`
}

// ConnectionStats are the proxy connection stats reported to
// ProxyEventReceiver at the end of connection. If the connection failed to
// fully establish, the ConnectionFailure reports the reason. Values that the
// clients sends in the light header will be zero values when the light
// header was not read successfully, and the proxy's phase-completed
// timestamps will be zero values when the phase was not completed.
type ConnectionStats struct {
	ProxyID                    string
	ProxyProviderID            string
	ProxyGeoIPData             common.GeoIPData
	ProxyConnectionNum         int64
	ClientGeoIPData            common.GeoIPData
	SponsorID                  string
	ClientPlatform             string
	ClientBuildRev             string
	DeviceRegion               string
	SessionID                  string
	ProxyEntryTracker          int64
	NetworkType                string
	ClientConnectionNum        int64
	DestinationAddress         string
	TLSProfile                 string
	SNI                        string
	ClientTCPDuration          time.Duration
	ClientTLSDuration          time.Duration
	ProxyCompletedTCP          time.Time
	ProxyCompletedTLS          time.Time
	ProxyCompletedLightHeader  time.Time
	ProxyCompletedUpstreamDial time.Time
	BytesRead                  int64
	BytesWritten               int64
	ConnectionFailure          error
}

// makeProxyID derives a unique proxy ID from a proxy's dial address and
// obfuscation key. This derivation saves light header space.
func makeProxyID(dialAddress, obfuscationKey string) string {
	h := hmac.New(sha256.New, []byte(obfuscationKey))
	h.Write([]byte(dialAddress))
	return base64.RawStdEncoding.EncodeToString(h.Sum(nil))
}

type bytesCounter struct {
	bytesRead    atomic.Int64
	bytesWritten atomic.Int64
}

func (b *bytesCounter) UpdateProgress(bytesRead, bytesWritten, _ int64) {
	b.bytesRead.Add(bytesRead)
	b.bytesWritten.Add(bytesWritten)
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
	// TODO: add a corresponding  note next to protocol.SupportedTLSProfiles.

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
}

func encodeTLSProfile(tlsProfile string) uint8 {
	return tlsProfileToCode[tlsProfile]
}

func decodeTLSProfile(encodedTLSProfile uint8) string {
	return codeToTLSProfile[encodedTLSProfile]
}
