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
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/values"
)

// Generate creates light proxy key material and produces a ProxyConfig for
// running a proxy and corresponding, encoded SignedProxyEntry for
// distribution to clients.
//
// listenAddress specifies the network address the proxy is to listen on. A
// distinct dialAddress is optional, and defaults to listenAddress.
// dialAddress is the value, distributed in the proxy entry, which the client
// will connect to. recommendedSNI is an optional SNI selection hint
// distributed in the proxy entry.
//
// allowedDestinations is a list of network addresses, host and post, that the
// proxy will connect to. Only destinations on this list are allowed, and at
// least one destination must be specified. This list is not distributed in
// the proxy entry.
//
// passthroughAddress is a psiphon-tls PassthroughAddress and is required.
func Generate(
	listenAddress string,
	dialAddress string,
	recommendedSNI string,
	allowedDestinations []string,
	passthroughAddress string) (*ProxyConfig, []byte, error) {

	if listenAddress == "" {
		return nil, nil, errors.TraceNew("missing listen address")
	}

	if dialAddress == "" {
		dialAddress = listenAddress
	}

	if len(allowedDestinations) == 0 {
		return nil, nil, errors.TraceNew("missing allowed destinations")
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
		Protocol:            LIGHT_PROTOCOL_TLS,
		ListenAddress:       listenAddress,
		DialAddress:         dialAddress,
		ObfuscationKey:      obfuscationKey,
		TLSCertificate:      cert,
		TLSPrivateKey:       privateKey,
		PassthroughAddress:  passthroughAddress,
		AllowedDestinations: allowedDestinations,
	}

	// To minimize size, the entry uses the more compact byte representation
	// of the obfuscation key.

	entry := ProxyEntry{
		Protocol:         LIGHT_PROTOCOL_TLS,
		DialAddress:      dialAddress,
		RecommendedSNI:   recommendedSNI,
		ObfuscationKey:   obfuscationKeyBytes,
		VerifyPin:        verifyPin,
		VerifyServerName: verifyServerName,
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
