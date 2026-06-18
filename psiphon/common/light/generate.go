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
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/regen"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/tlsdialer"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/values"
)

// Generate creates light proxy key material and produces a ProxyConfig for
// running a proxy and corresponding, encoded SignedProxyEntry for
// distribution to clients.
//
// listenAddresses specifies the network addresses the proxy is to listen on.
// dialAddressIPv4 and an optional dialAddressIPv6 are the values,
// distributed in the proxy entry, which the client will connect to.
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
// allowedDestinations is a list of network addresses, host and post, that the
// proxy will connect to. Only destinations on this list are allowed; when
// empty, any destination is allowed. This list is not distributed in the proxy
// entry.
//
// proxyProtocolHeaderMACKeys/proxyProtocolHeaderTargetDestinationAddresses
// enable adding PROXY protocol headers to upstream connections.
//
// passthroughAddress is a psiphon-tls PassthroughAddress and is required.
func Generate(
	providerID string,
	listenAddresses []string,
	dialAddressIPv4 string,
	dialAddressIPv6 string,
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
	proxyProtocolHeaderTargetDestinationAddresses map[string][]string,
	passthroughAddress string) (*ProxyConfig, []byte, error) {

	if len(listenAddresses) == 0 {
		return nil, nil, errors.TraceNew("missing listen addresses")
	}

	for _, listenAddress := range listenAddresses {
		if listenAddress == "" {
			return nil, nil, errors.TraceNew("missing listen address")
		}
	}

	if dialAddressIPv4 == "" {
		return nil, nil, errors.TraceNew("missing IPv4 dial address")
	}

	err := validateIPAddressFamily(dialAddressIPv4, false)
	if err != nil {
		return nil, nil, errors.Trace(err)
	}

	if dialAddressIPv6 != "" {
		err := validateIPAddressFamily(dialAddressIPv6, true)
		if err != nil {
			return nil, nil, errors.Trace(err)
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
			recommendedTLSProfile)
		if err != nil {
			return nil, nil, errors.Trace(err)
		}
		if !supportsTLS13 {
			return nil, nil, errors.TraceNew(
				"recommended TLS profile does not support TLS 1.3")
		}
	}

	_, err = prepareProxyProtocolHeaderConfigs(
		proxyProtocolHeaderMACKeys,
		proxyProtocolHeaderTargetDestinationAddresses)
	if err != nil {
		return nil, nil, errors.Trace(err)
	}

	// Required: see comment in NewProxy.
	if passthroughAddress == "" {
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

	config := &ProxyConfig{
		Protocol:                   LIGHT_PROTOCOL_TLS,
		ProviderID:                 providerID,
		ListenAddresses:            append([]string(nil), listenAddresses...),
		DialAddressIPv4:            dialAddressIPv4,
		DialAddressIPv6:            dialAddressIPv6,
		ObfuscationKey:             obfuscationKey,
		TLSCertificate:             cert,
		TLSPrivateKey:              privateKey,
		PassthroughAddress:         passthroughAddress,
		AllowedDestinations:        allowedDestinations,
		ProxyProtocolHeaderMACKeys: proxyProtocolHeaderMACKeys,
		ProxyProtocolHeaderTargetDestinationAddresses: proxyProtocolHeaderTargetDestinationAddresses,
	}

	// To minimize size, the entry uses the more compact byte representation
	// of the obfuscation key.

	entry := ProxyEntry{
		Protocol:                                  LIGHT_PROTOCOL_TLS,
		DialAddressIPv4:                           dialAddressIPv4,
		DialAddressIPv6:                           dialAddressIPv6,
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
