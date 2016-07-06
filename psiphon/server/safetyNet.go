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

package server

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

const (
	safetynetCN = "attest.android.com"
	// Cert of the root certificate authority (GeoTrust Global CA)
	// which signs the intermediate certificate from Google (GIAG2)
	geotrustCert = "-----BEGIN CERTIFICATE-----\nMIIDVDCCAjygAwIBAgIDAjRWMA0GCSqGSIb3DQEBBQUAMEIxCzAJBgNVBAYTAlVT\nMRYwFAYDVQQKEw1HZW9UcnVzdCBJbmMuMRswGQYDVQQDExJHZW9UcnVzdCBHbG9i\nYWwgQ0EwHhcNMDIwNTIxMDQwMDAwWhcNMjIwNTIxMDQwMDAwWjBCMQswCQYDVQQG\nEwJVUzEWMBQGA1UEChMNR2VvVHJ1c3QgSW5jLjEbMBkGA1UEAxMSR2VvVHJ1c3Qg\nR2xvYmFsIENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2swYYzD9\n9BcjGlZ+W988bDjkcbd4kdS8odhM+KhDtgPpTSEHCIjaWC9mOSm9BXiLnTjoBbdq\nfnGk5sRgprDvgOSJKA+eJdbtg/OtppHHmMlCGDUUna2YRpIuT8rxh0PBFpVXLVDv\niS2Aelet8u5fa9IAjbkU+BQVNdnARqN7csiRv8lVK83Qlz6cJmTM386DGXHKTubU\n1XupGc1V3sjs0l44U+VcT4wt/lAjNvxm5suOpDkZALeVAjmRCw7+OC7RHQWa9k0+\nbw8HHa8sHo9gOeL6NlMTOdReJivbPagUvTLrGAMoUgRx5aszPeE4uwc2hGKceeoW\nMPRfwCvocWvk+QIDAQABo1MwUTAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTA\nephojYn7qwVkDBF9qn1luMrMTjAfBgNVHSMEGDAWgBTAephojYn7qwVkDBF9qn1l\nuMrMTjANBgkqhkiG9w0BAQUFAAOCAQEANeMpauUvXVSOKVCUn5kaFOSPeCpilKIn\nZ57QzxpeR+nBsqTP3UEaBU6bS+5Kb1VSsyShNwrrZHYqLizz/Tt1kL/6cdjHPTfS\ntQWVYrmm3ok9Nns4d0iXrKYgjy6myQzCsplFAMfOEVEiIuCl6rYVSAlk6l5PdPcF\nPseKUgzbFbS9bZvlxrFUaKnjaZC2mqUPuLk/IH2uSrW4nOQdtqvmlKXBx4Ot2/Un\nhw4EbNX/3aBd7YdStysVAq45pmp06drE57xNNB6pXE0zX5IJL4hmXXeXxx12E6nV\n5fEWCRE11azbJHFwLJhWC9kXtNHjUStedejV0NxPNO3CBWaAocvmMw==\n-----END CERTIFICATE-----\n"
	// base64 encoded sha256 hash of the license used to sign the android
	// client (.apk) https://psiphon.ca/en/faq.html#authentic-android
	//
	// keytool -printcert -file CERT.RSA
	// SHA256: 76:DB:EF:15:F6:77:26:D4:51:A1:23:59:B8:57:9C:0D:7A:9F:63:5D:52:6A:A3:74:24:DF:13:16:32:F1:78:10
	//
	// echo dtvvFfZ3JtRRoSNZuFecDXqfY11SaqN0JN8TFjLxeBA= | base64 -d | hexdump  -e '32/1 "%02X " "\n"'
	// 76 DB EF 15 F6 77 26 D4 51 A1 23 59 B8 57 9C 0D 7A 9F 63 5D 52 6A A3 74 24 DF 13 16 32 F1 78 10
	psiphon3Base64CertHash = "dtvvFfZ3JtRRoSNZuFecDXqfY11SaqN0JN8TFjLxeBA="
)

var psiphonApkPackagenames = []string{"com.psiphon3", "com.psiphon3.subscription"}

type X5C []string

type jwt struct {
	status  int
	payload string
}

func newJwt(token requestJSONObject) *jwt {
	status, ok := token["status"].(float64)
	if !ok {
		return nil
	}
	payload, ok := token["payload"].(string)
	if !ok {
		return nil
	}
	return &jwt{
		status:  int(status),
		payload: payload,
	}
}

type jwtHeader struct {
	Algorithm string `json:"alg"`
	CertChain X5C    `json:"x5c"`
}

func newJwtHeader(jsonBytes []byte) (jwtHeader, error) {
	var header jwtHeader
	err := json.Unmarshal(jsonBytes, &header)
	return header, err
}

type jwtBody struct {
	Nonce                      string   `json:"nonce"`
	TimestampMs                int      `json:"timestampMs"`
	ApkPackageName             string   `json:"apkPackageName"`
	ApkDigestSha256            string   `json:"apkDigestSha256"`
	CtsProfileMatch            bool     `json:"ctsProfileMatch"`
	Extension                  string   `json:"extension"`
	ApkCertificateDigestSha256 []string `json:"apkCertificateDigestSha256"`
}

func newJwtBody(jsonBytes []byte) (jwtBody, error) {
	var body jwtBody
	err := json.Unmarshal(jsonBytes, &body)
	return body, err
}

// Add missing padding so data is not
// truncated in Decode
func decodeBase64(data string) ([]byte, error) {
	missingPadding := 4 - len(data)%4

	for i := 0; i < missingPadding; i++ {
		data += "="
	}

	d, err := base64.URLEncoding.DecodeString(data)

	return d, err
}

// Verify x509 certificate chain
func (x5c X5C) verifyCertChain() (*x509.Certificate, error) {
	if len(x5c) == 0 || len(x5c) > 10 {
		// OpenSSL's default maximum chain length is 10
		return nil, fmt.Errorf("Invalid certchain length of %d\n", len(x5c))
	}

	// Parse leaf certificate
	leafCertDer, err := base64.StdEncoding.DecodeString(x5c[0])
	if err != nil {
		return nil, err
	}
	leafCert, err := x509.ParseCertificate(leafCertDer)
	if err != nil {
		return nil, err
	}

	// Verify CN
	if leafCert.Subject.CommonName != safetynetCN {
		return nil, err
	}

	// Parse and add intermediate certificates
	intermediates := x509.NewCertPool()
	for i := 1; i < len(x5c); i++ {
		intermediateCertDer, err := base64.StdEncoding.DecodeString(x5c[i])
		if err != nil {
			return nil, err
		}

		intermediateCert, err := x509.ParseCertificate(intermediateCertDer)
		if err != nil {
			return nil, err
		}
		intermediates.AddCert(intermediateCert)
	}

	// Parse and verify root cert
	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM([]byte(geotrustCert))
	if !ok {
		return nil, fmt.Errorf("Failed to append GEOTRUST cert\n")
	}

	// Verify leaf certificate
	storeCtx := x509.VerifyOptions{
		Intermediates: intermediates,
		Roots:         roots,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	_, err = leafCert.Verify(storeCtx)
	if err != nil {
		return nil, err
	}

	return leafCert, nil
}

func (body *jwtBody) verifyJWTBody() bool {
	// Verify apk certificate digest
	if len(body.ApkCertificateDigestSha256) < 1 || body.ApkCertificateDigestSha256[0] != psiphon3Base64CertHash {
		return false
	}

	// Verify apk package name
	if !sliceContains(psiphonApkPackagenames, body.ApkPackageName) {
		return false
	}

	return true
}

func sliceContains(arr []string, str string) bool {
	for _, s := range arr {
		if s == str {
			return true
		}
	}

	return false
}

// Validate JWT produced by safteynet
func verifySafetyNetPayload(params requestJSONObject) bool {

	jwt := newJwt(params)
	if jwt == nil {
		// Malformed JWT
		return false
	}

	// SafetyNet check failed
	if (*jwt).status != 0 {
		return false
	}

	// Split into base64 encoded header, body, signature
	jwtParts := strings.Split((*jwt).payload, ".")
	if len(jwtParts) != 3 {
		// Malformed payload
		return false
	}

	// Decode header, body, signature
	headerJson, err := decodeBase64(jwtParts[0])
	if err != nil {
		return false
	}
	bodyJson, err := decodeBase64(jwtParts[1])
	if err != nil {
		return false
	}
	signature, err := decodeBase64(jwtParts[2])
	if err != nil {
		return false
	}

	// Extract header from json
	header, err := newJwtHeader(headerJson)
	if err != nil {
		return false
	}

	// Validate certchain in header
	leafCert, err := header.CertChain.verifyCertChain()
	if err != nil {
		// Invalid certchain
		return false
	}

	// Validate signature
	err = leafCert.CheckSignature(x509.SHA256WithRSA, []byte(jwtParts[0]+"."+jwtParts[1]), signature)
	if err != nil {
		return false
	}

	// Extract body from json
	body, err := newJwtBody(bodyJson)
	if err != nil {
		return false
	}

	// Validate jwt payload
	validPayload := body.verifyJWTBody()
	if !validPayload {
		return false
	}

	return true
}
