/*
 * Copyright (c) 2018, Psiphon Inc.
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

package common

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
)

// GenerateWebServerCertificate creates a self-signed web server certificate,
// using the specified host name (commonName).
// This is primarily intended for use by MeekServer to generate on-the-fly,
// self-signed TLS certificates for fronted HTTPS mode. In this case, the nature
// of the certificate is non-circumvention; it only has to be acceptable to the
// front CDN making connections to meek.
// The same certificates are used for unfronted HTTPS meek. In this case, the
// certificates may be a fingerprint used to detect Psiphon servers or traffic.
// TODO: more effort to mitigate fingerprinting these certificates.
//
// In addition, GenerateWebServerCertificate is used by GenerateConfig to create
// Psiphon web server certificates for test/example configurations. If these Psiphon
// web server certificates are used in production, the same caveats about
// fingerprints apply.
func GenerateWebServerCertificate(commonName string) (string, string, error) {

	// Based on https://golang.org/src/crypto/tls/generate_cert.go
	// TODO: use other key types: anti-fingerprint by varying params

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", errors.Trace(err)
	}

	// Validity period is 1 or 2 years, starting 1 to 6 months ago.
	validityPeriodYears := 1
	delta, err := rand.Int(rand.Reader, big.NewInt(2))
	if err != nil {
		return "", "", errors.Trace(err)
	}
	validityPeriodYears += int(delta.Int64())
	retroactiveMonths := 1
	delta, err = rand.Int(rand.Reader, big.NewInt(6))
	if err != nil {
		return "", "", errors.Trace(err)
	}
	retroactiveMonths += int(delta.Int64())
	notBefore := time.Now().Truncate(time.Hour).UTC().AddDate(0, -retroactiveMonths, 0)
	notAfter := notBefore.AddDate(validityPeriodYears, 0, 0)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return "", "", errors.Trace(err)
	}

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(rsaKey.Public())
	if err != nil {
		return "", "", errors.Trace(err)
	}
	// as per RFC3280 sec. 4.2.1.2
	subjectKeyID := sha1.Sum(publicKeyBytes)

	var subject pkix.Name
	if commonName != "" {
		subject = pkix.Name{CommonName: commonName}
	}

	template := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               subject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          subjectKeyID[:],
		MaxPathLen:            1,
		Version:               2,
	}

	derCert, err := x509.CreateCertificate(
		rand.Reader,
		&template,
		&template,
		rsaKey.Public(),
		rsaKey)
	if err != nil {
		return "", "", errors.Trace(err)
	}

	webServerCertificate := pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: derCert,
		},
	)

	webServerPrivateKey := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(rsaKey),
		},
	)

	return string(webServerCertificate), string(webServerPrivateKey), nil
}
