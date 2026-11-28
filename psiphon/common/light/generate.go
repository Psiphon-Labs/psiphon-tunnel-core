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

package light

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/inproxy"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/regen"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/tlsdialer"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/values"
)

// Generate creates light proxy key material and produces a ProxyConfig for
// running a proxy and corresponding, encoded SignedProxyEntry for
// distribution to clients.
//
// listenAddresses specifies local endpoints paired by index with the public
// dialAddresses distributed in the proxy entry. When omitted, dialAddresses
// is used for listening.
//
// Fallback entries without a personal compartment ID include legacy TLS fields
// when a TLS IPv4 endpoint is available, using the first TLS endpoint per IP
// address family and the legacy-derived proxy ID. All entries include the full
// endpoint list.
//
// recommendedSNI, recommendedSNIRegex, and recommendedSNIProbability are
// optional SNI selection hints distributed in the proxy entry.
//
// recommendedTLSProfile, recommendedTLSProfileProbability,
// recommendedFragmentClientHelloProbability,
// recommendedTLSPaddingProbability, recommendedMinTLSPadding, and
// recommendedMaxTLSPadding are optional TLS traffic appearance and
// traffic-shaping recommendations distributed in the proxy entry.
//
// proxyEntryTTL is an optional value distributed in the proxy entry which
// indicates how long to store and use the proxy entry. The zero value means
// no TTL/no expiry. The TTL is encoded at second granularity.
//
// allowedDestinations lists permitted fallback destinations as host:port
// addresses. An empty list imposes no destination-list restriction. This
// list is not distributed in the proxy entry.
//
// proxyProtocolHeaderMACKeys/proxyProtocolHeaderCustomTLVs/
// proxyProtocolHeaderTargetDestinationAddresses enable adding PROXY protocol
// headers to fallback upstream connections. Targets are hosts without ports,
// matching psiphond tactics. All values are selected by sponsor ID.
//
// passthroughAddress is a psiphon-tls PassthroughAddress and is required for TLS.
//
// personalCompartmentID optionally sets the personal pairing secret in the
// config and entry, using the same unpadded base64 encoding as INPROXY.
// When set, the caller must configure ProxyLimits before calling NewProxy.
//
// A non-empty tunnelProxyID enables tunnel mode and must be the value returned
// by GetTunnelProxyID for the proxy report signing key. The caller must also
// configure TunnelProxyPrivateKey, TunnelDialAuthorizationPublicKey, and at
// least one of ProxyTLSDialer or ProxyQUICDialer before calling NewProxy.
func Generate(
	providerID string,
	listenAddresses []ProxyAddress,
	dialAddresses []ProxyAddress,
	recommendedSNI string,
	recommendedSNIRegex string,
	recommendedSNIProbability float64,
	recommendedTLSProfile string,
	recommendedTLSProfileProbability float64,
	recommendedFragmentClientHelloProbability float64,
	recommendedTLSPaddingProbability float64,
	recommendedMinTLSPadding int,
	recommendedMaxTLSPadding int,
	proxyEntryTTL time.Duration,
	allowedDestinations []string,
	proxyProtocolHeaderMACKeys map[string]string,
	proxyProtocolHeaderCustomTLVs map[string]string,
	proxyProtocolHeaderTargetDestinationAddresses map[string][]string,
	passthroughAddress string,
	personalCompartmentID string,
	tunnelProxyID string) (*ProxyConfig, []byte, error) {

	err := ValidateProxyAddresses(dialAddresses, listenAddresses)
	if err != nil {
		return nil, nil, errors.Trace(err)
	}

	if tunnelProxyID != "" {
		if _, err := inproxy.IDFromString(tunnelProxyID); err != nil {
			return nil, nil, errors.Trace(err)
		}
	}

	var personalCompartmentIDBytes []byte
	if personalCompartmentID != "" {
		id, err := inproxy.IDFromString(personalCompartmentID)
		if err != nil {
			return nil, nil, errors.TraceNew("invalid personal compartment ID")
		}
		personalCompartmentIDBytes = id[:]
	}

	var dialAddressIPv4, dialAddressIPv6 string
	if tunnelProxyID == "" && personalCompartmentID == "" {
		for _, address := range dialAddresses {
			if address.Protocol != LIGHT_PROTOCOL_TLS {
				continue
			}
			if net.ParseIP(address.IPAddress).To4() != nil {
				if dialAddressIPv4 == "" {
					dialAddressIPv4 = address.String()
				}
			} else if dialAddressIPv6 == "" {
				dialAddressIPv6 = address.String()
			}
		}
	}

	if recommendedSNIRegex != "" {
		_, err := regen.GenerateString(recommendedSNIRegex)
		if err != nil {
			return nil, nil, errors.Trace(err)
		}
	}

	err = validateRecommendedTLSSettings(
		recommendedFragmentClientHelloProbability,
		recommendedTLSPaddingProbability,
		recommendedMinTLSPadding,
		recommendedMaxTLSPadding,
		recommendedSNIProbability,
		recommendedTLSProfileProbability)
	if err != nil {
		return nil, nil, errors.Trace(err)
	}

	if proxyEntryTTL < 0 ||
		(proxyEntryTTL > 0 && proxyEntryTTL < time.Second) {
		return nil, nil, errors.TraceNew("invalid proxy entry TTL")
	}

	if recommendedTLSProfile != "" {
		if !common.Contains(protocol.SupportedTLSProfiles, recommendedTLSProfile) {
			return nil, nil, errors.TraceNew("invalid recommended TLS profile")
		}

		// Light protocol requires TLS 1.3.
		supportsTLS13, err := tlsdialer.TLSProfileSupportsTLS13(
			recommendedTLSProfile, nil)
		if err != nil {
			return nil, nil, errors.Trace(err)
		}
		if !supportsTLS13 {
			return nil, nil, errors.TraceNew(
				"recommended TLS profile does not support TLS 1.3")
		}
	}

	if tunnelProxyID != "" &&
		(len(proxyProtocolHeaderMACKeys) != 0 ||
			len(proxyProtocolHeaderCustomTLVs) != 0 ||
			len(proxyProtocolHeaderTargetDestinationAddresses) != 0) {

		return nil, nil, errors.TraceNew("PROXY protocol headers are unsupported in tunnel mode")
	}

	_, err = prepareProxyProtocolHeaderConfigs(
		proxyProtocolHeaderMACKeys,
		proxyProtocolHeaderCustomTLVs,
		proxyProtocolHeaderTargetDestinationAddresses)
	if err != nil {
		return nil, nil, errors.Trace(err)
	}

	// Required: see comment in NewProxy.
	if common.Contains(getLightProtocols(dialAddresses), LIGHT_PROTOCOL_TLS) &&
		passthroughAddress == "" {

		return nil, nil, errors.TraceNew("missing passthrough address")
	}

	obfuscationKeyBytes, err := common.MakeSecureRandomBytes(obfuscationKeySize)
	if err != nil {
		return nil, nil, errors.Trace(err)
	}
	obfuscationKey := hex.EncodeToString(obfuscationKeyBytes)

	verifyPin, verifyServerName, cert, privateKey, err := generateCert()
	if err != nil {
		return nil, nil, errors.Trace(err)
	}

	// To minimize size, the entry uses the more compact byte representation
	// of the obfuscation key.

	entry := ProxyEntry{
		RecommendedSNI:                            recommendedSNI,
		RecommendedSNIRegex:                       recommendedSNIRegex,
		RecommendedSNIProbability:                 recommendedSNIProbability,
		RecommendedTLSProfile:                     recommendedTLSProfile,
		RecommendedTLSProfileProbability:          recommendedTLSProfileProbability,
		RecommendedFragmentClientHelloProbability: recommendedFragmentClientHelloProbability,
		RecommendedTLSPaddingProbability:          recommendedTLSPaddingProbability,
		RecommendedMinTLSPadding:                  recommendedMinTLSPadding,
		RecommendedMaxTLSPadding:                  recommendedMaxTLSPadding,
		TTLSeconds:                                int64(proxyEntryTTL / time.Second),
		ObfuscationKey:                            obfuscationKeyBytes,
		VerifyPin:                                 verifyPin,
		VerifyServerName:                          verifyServerName,
		PersonalCompartmentID:                     personalCompartmentIDBytes,
	}

	var proxyID string
	switch {
	case tunnelProxyID != "":
		proxyID = tunnelProxyID
	case dialAddressIPv4 != "":
		entry.Protocol = LIGHT_PROTOCOL_TLS
		entry.DialAddressIPv4 = dialAddressIPv4
		entry.DialAddressIPv6 = dialAddressIPv6
		proxyID = makeLegacyProxyID(dialAddressIPv4, obfuscationKey)
	default:
		proxyIDBytes, err := common.MakeSecureRandomBytes(proxyIDSize)
		if err != nil {
			return nil, nil, errors.Trace(err)
		}
		proxyID = base64.RawStdEncoding.EncodeToString(proxyIDBytes)
	}
	entry.ProxyID = proxyID
	entry.DialAddresses = append([]ProxyAddress(nil), dialAddresses...)

	config := &ProxyConfig{
		ProviderID:                    providerID,
		DialAddresses:                 append([]ProxyAddress(nil), dialAddresses...),
		ListenAddresses:               append([]ProxyAddress(nil), listenAddresses...),
		ObfuscationKey:                obfuscationKey,
		TLSCertificate:                cert,
		TLSPrivateKey:                 privateKey,
		PassthroughAddress:            passthroughAddress,
		AllowedDestinations:           allowedDestinations,
		ProxyProtocolHeaderMACKeys:    proxyProtocolHeaderMACKeys,
		ProxyProtocolHeaderCustomTLVs: proxyProtocolHeaderCustomTLVs,
		ProxyProtocolHeaderTargetDestinationAddresses: proxyProtocolHeaderTargetDestinationAddresses,
		PersonalCompartmentID:                         personalCompartmentID,
		TunnelMode:                                    tunnelProxyID != "",
	}
	if !config.TunnelMode {
		config.ProxyID = proxyID
	}

	// There is currently no signature. See SignedProxyEntry comment.

	signedProxy := SignedProxyEntry{
		ProxyEntry: entry,
	}

	cborEntry, err := protocol.CBOREncoding.Marshal(&signedProxy)
	if err != nil {
		return nil, nil, errors.Trace(err)
	}

	return config, cborEntry, nil
}

func generateCert() ([]byte, string, []byte, []byte, error) {

	hostname := values.GetHostName()

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: hostname},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{hostname},
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", nil, nil, errors.Trace(err)
	}

	certDER, err := x509.CreateCertificate(
		rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, "", nil, nil, errors.Trace(err)
	}

	parsedCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, "", nil, nil, errors.Trace(err)
	}

	pubKeyPin := sha256.Sum256(parsedCert.RawSubjectPublicKeyInfo)

	var certBuf bytes.Buffer
	err = pem.Encode(&certBuf, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	if err != nil {
		return nil, "", nil, nil, errors.Trace(err)
	}

	privateKeyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, "", nil, nil, errors.Trace(err)
	}

	var privateKeyBuf bytes.Buffer
	err = pem.Encode(&privateKeyBuf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privateKeyDER})
	if err != nil {
		return nil, "", nil, nil, errors.Trace(err)
	}

	return pubKeyPin[:], hostname, certBuf.Bytes(), privateKeyBuf.Bytes(), nil
}
