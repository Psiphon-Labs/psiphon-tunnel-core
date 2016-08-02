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
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
)

const (
	// Cert of the root certificate authority (GeoTrust Global CA)
	// which signs the intermediate certificate from Google (GIAG2)
	geotrustCert      = "-----BEGIN CERTIFICATE-----\nMIIDVDCCAjygAwIBAgIDAjRWMA0GCSqGSIb3DQEBBQUAMEIxCzAJBgNVBAYTAlVT\nMRYwFAYDVQQKEw1HZW9UcnVzdCBJbmMuMRswGQYDVQQDExJHZW9UcnVzdCBHbG9i\nYWwgQ0EwHhcNMDIwNTIxMDQwMDAwWhcNMjIwNTIxMDQwMDAwWjBCMQswCQYDVQQG\nEwJVUzEWMBQGA1UEChMNR2VvVHJ1c3QgSW5jLjEbMBkGA1UEAxMSR2VvVHJ1c3Qg\nR2xvYmFsIENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2swYYzD9\n9BcjGlZ+W988bDjkcbd4kdS8odhM+KhDtgPpTSEHCIjaWC9mOSm9BXiLnTjoBbdq\nfnGk5sRgprDvgOSJKA+eJdbtg/OtppHHmMlCGDUUna2YRpIuT8rxh0PBFpVXLVDv\niS2Aelet8u5fa9IAjbkU+BQVNdnARqN7csiRv8lVK83Qlz6cJmTM386DGXHKTubU\n1XupGc1V3sjs0l44U+VcT4wt/lAjNvxm5suOpDkZALeVAjmRCw7+OC7RHQWa9k0+\nbw8HHa8sHo9gOeL6NlMTOdReJivbPagUvTLrGAMoUgRx5aszPeE4uwc2hGKceeoW\nMPRfwCvocWvk+QIDAQABo1MwUTAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTA\nephojYn7qwVkDBF9qn1luMrMTjAfBgNVHSMEGDAWgBTAephojYn7qwVkDBF9qn1l\nuMrMTjANBgkqhkiG9w0BAQUFAAOCAQEANeMpauUvXVSOKVCUn5kaFOSPeCpilKIn\nZ57QzxpeR+nBsqTP3UEaBU6bS+5Kb1VSsyShNwrrZHYqLizz/Tt1kL/6cdjHPTfS\ntQWVYrmm3ok9Nns4d0iXrKYgjy6myQzCsplFAMfOEVEiIuCl6rYVSAlk6l5PdPcF\nPseKUgzbFbS9bZvlxrFUaKnjaZC2mqUPuLk/IH2uSrW4nOQdtqvmlKXBx4Ot2/Un\nhw4EbNX/3aBd7YdStysVAq45pmp06drE57xNNB6pXE0zX5IJL4hmXXeXxx12E6nV\n5fEWCRE11azbJHFwLJhWC9kXtNHjUStedejV0NxPNO3CBWaAocvmMw==\n-----END CERTIFICATE-----\n"
	maxLogFieldSize   = 64
	maxLogPayloadSize = 6144
	// base64 encoded sha256 hash of the license used to sign the android
	// client (.apk) https://psiphon.ca/en/faq.html#authentic-android
	//
	// keytool -printcert -file CERT.RSA
	// SHA256: 76:DB:EF:15:F6:77:26:D4:51:A1:23:59:B8:57:9C:0D:7A:9F:63:5D:52:6A:A3:74:24:DF:13:16:32:F1:78:10
	//
	// echo dtvvFfZ3JtRRoSNZuFecDXqfY11SaqN0JN8TFjLxeBA= | base64 -d | hexdump  -e '32/1 "%02X " "\n"'
	// 76 DB EF 15 F6 77 26 D4 51 A1 23 59 B8 57 9C 0D 7A 9F 63 5D 52 6A A3 74 24 DF 13 16 32 F1 78 10
	psiphon3Base64CertHash = "dtvvFfZ3JtRRoSNZuFecDXqfY11SaqN0JN8TFjLxeBA="
	safetynetCN            = "attest.android.com"
)

var psiphonApkPackagenames = []string{"com.psiphon3", "com.psiphon3.subscription"}

type X5C []string

type jwt struct {
	status  int
	payload string
}

func newJwt(token requestJSONObject) (jwt, error) {
	jwtObj := jwt{}

	if token["status"] == nil {
		return jwtObj, errors.New("Absent JWT status field")
	}
	status, ok := token["status"].(float64)
	if !ok {
		return jwtObj, errors.New("Malformed JWT status field. Expected float64 got " + reflect.TypeOf(token["status"]).String())
	}

	if token["payload"] == nil {
		return jwtObj, errors.New("Absent JWT payload field")
	}
	payload, ok := token["payload"].(string)
	if !ok {
		return jwtObj, errors.New("Malformed JWT payload field. Expected string got " + reflect.TypeOf(token["payload"]).String())
	}

	if len(payload) > maxLogPayloadSize {
		return jwtObj, errors.New("JWT of length " + strconv.Itoa(len(payload)) + " exceeds maximum expected length of " + strconv.Itoa(maxLogPayloadSize))
	}

	jwtObj.status = int(status)
	jwtObj.payload = payload
	return jwtObj, nil
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
	// Pointers are used because these fields may not
	// exist and the default values assigned when
	// unmarshalling into the corresponding non-pointer
	// struct would cause non-existing fields to be logged
	// in a manner that would make it impossible to distinguish
	// between a non-existing field and field of default value
	BasicIntegrity             *bool     `json:"basicIntegrity"`
	CtsProfileMatch            *bool     `json:"ctsProfileMatch"`
	TimestampMs                *int      `json:"timestampMs"`
	ApkDigestSha256            *string   `json:"apkDigestSha256"`
	ApkPackageName             *string   `json:"apkPackageName"`
	Error                      *string   `json:"error"`
	Extension                  *string   `json:"extension"`
	Nonce                      *string   `json:"nonce"`
	ApkCertificateDigestSha256 *[]string `json:"apkCertificateDigestSha256"`
}

func newJwtBody(jsonBytes []byte) (jwtBody, error) {
	var body jwtBody
	err := json.Unmarshal(jsonBytes, &body)

	return body, err
}

// Verify x509 certificate chain
func (x5c X5C) verifyCertChain() (leaf *x509.Certificate, validCN bool, err error) {
	if len(x5c) == 0 || len(x5c) > 10 {
		// OpenSSL's default maximum chain length is 10
		return nil, false, fmt.Errorf("Invalid certchain length of %d\n", len(x5c))
	}

	// Parse leaf certificate
	leafCertDer, err := base64.StdEncoding.DecodeString(x5c[0])
	if err != nil {
		return nil, false, err
	}
	leafCert, err := x509.ParseCertificate(leafCertDer)
	if err != nil {
		return nil, false, err
	}

	// Verify CN
	if leafCert.Subject.CommonName == safetynetCN {
		validCN = true
	}

	// Parse and add intermediate certificates
	intermediates := x509.NewCertPool()
	for i := 1; i < len(x5c); i++ {
		intermediateCertDer, err := base64.StdEncoding.DecodeString(x5c[i])
		if err != nil {
			return leafCert, false, err
		}

		intermediateCert, err := x509.ParseCertificate(intermediateCertDer)
		if err != nil {
			return leafCert, false, err
		}
		intermediates.AddCert(intermediateCert)
	}

	// Parse and verify root cert
	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM([]byte(geotrustCert))
	if !ok {
		return leafCert, false, fmt.Errorf("Failed to append GEOTRUST cert\n")
	}

	// Verify leaf certificate
	storeCtx := x509.VerifyOptions{
		Intermediates: intermediates,
		Roots:         roots,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	_, err = leafCert.Verify(storeCtx)
	if err != nil {
		return leafCert, false, err
	}

	return leafCert, validCN, nil
}

func (body *jwtBody) verifyJWTBody() (validApkCert, validApkPackageName bool) {
	// Verify apk certificate digest
	if body.ApkCertificateDigestSha256 != nil {
		if len(*body.ApkCertificateDigestSha256) > 0 && (*body.ApkCertificateDigestSha256)[0] == psiphon3Base64CertHash {
			validApkCert = true
		}
	}

	// Verify apk package name
	if body.ApkPackageName != nil && common.Contains(psiphonApkPackagenames, *body.ApkPackageName) {
		validApkPackageName = true
	}

	return
}

// Form log fields for debugging
func errorLogFields(err error, params requestJSONObject) LogFields {
	logFields := LogFields{
		// Must sanitize string. JSON unmarshalling exceptions
		// include the value of the field which failed to unmarshal.
		"error_message": sanitizeJwtString(err.Error()),
	}

	// Sanitize payload for logging
	payload, ok := params["payload"].(string)
	// Only log payload if it exists
	if ok {
		if len(payload) > maxLogPayloadSize {
			// Truncate if payload exceedingly long
			payload = payload[:maxLogPayloadSize]
			payload += ".."
		}
		logFields["payload"] = payload
	}

	return logFields
}

// Convert error to string for logging
func getError(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// Sanitize client / safetynet provided strings for logging
func sanitizeJwtString(s string) string {
	if len(s) > maxLogFieldSize {
		return s[:maxLogFieldSize]
	}
	return s
}

// Add log field if it exists (see comment accompanying jwtBody struct)
func (l LogFields) addJwtField(field string, input interface{}) {
	switch val := input.(type) {
	case *bool:
		if val != nil {
			l[field] = *val
		}
	case *int:
		if val != nil {
			if field == "verification_timestamp" {
				l[field] = time.Unix(0, int64(*val)*1e6).UTC().Format(time.RFC3339)
			} else {
				l[field] = *val
			}
		}
	case *string:
		if val != nil {
			l[field] = sanitizeJwtString(*val)
		}
	case *[]string:
		// Only concerned with ApkCertificateDigestSha256[0] for now
		if val != nil && len(*val) > 0 {
			l[field] = sanitizeJwtString((*val)[0])
		}
	default:
		// Do nothing
	}
}

// Validate JWT produced by safetynet
func verifySafetyNetPayload(params requestJSONObject) (bool, LogFields) {

	jwt, err := newJwt(params)
	if err != nil {
		// Malformed JWT
		return false, errorLogFields(err, params)
	}

	statusStrings := map[int]string{
		0: "API_REQUEST_OK",
		1: "API_REQUEST_FAILED",
		2: "API_CONNECT_FAILED",
	}

	statusString, ok := statusStrings[jwt.status]
	if !ok {
		statusString = "Expected status in range 0-2. Got " + strconv.Itoa(jwt.status)
	}

	// SafetyNet check failed
	if jwt.status != 0 {
		return false, errorLogFields(errors.New(statusString), params)
	}

	// Split into base64 encoded header, body, signature
	jwtParts := strings.Split(jwt.payload, ".")
	if len(jwtParts) != 3 {
		// Malformed payload
		return false, errorLogFields(errors.New("JWT does not have 3 parts"), params)
	}

	// Decode header, body, signature
	headerJson, err := base64.RawURLEncoding.DecodeString(jwtParts[0])
	if err != nil {
		return false, errorLogFields(err, params)
	}
	bodyJson, err := base64.RawURLEncoding.DecodeString(jwtParts[1])
	if err != nil {
		return false, errorLogFields(err, params)
	}
	signature, err := base64.RawURLEncoding.DecodeString(jwtParts[2])
	if err != nil {
		return false, errorLogFields(err, params)
	}

	// Extract header from json
	header, err := newJwtHeader(headerJson)
	if err != nil {
		return false, errorLogFields(err, params)
	}

	// Verify certchain in header
	leafCert, validCN, certChainErrors := header.CertChain.verifyCertChain()

	var signatureErrors error
	if leafCert == nil {
		signatureErrors = errors.New("Failed to parse leaf certificate")
	} else {
		// Verify signature over header and body
		signatureErrors = leafCert.CheckSignature(x509.SHA256WithRSA, []byte(jwtParts[0]+"."+jwtParts[1]), signature)
	}

	// Extract body from json
	body, err := newJwtBody(bodyJson)
	if err != nil {
		return false, errorLogFields(err, params)
	}

	// Validate jwt payload
	validApkCert, validApkPackageName := body.verifyJWTBody()

	validCertChain := certChainErrors == nil
	validSignature := signatureErrors == nil
	verified := validCN && validApkCert && validApkPackageName && validCertChain && validSignature

	// Add server generated fields for logging
	logFields := LogFields{
		"certchain_errors":      getError(certChainErrors),
		"signature_errors":      getError(signatureErrors),
		"status":                strconv.Itoa(jwt.status),
		"status_string":         statusString,
		"valid_cn":              validCN,
		"valid_apk_cert":        validApkCert,
		"valid_apk_packagename": validApkPackageName,
		"valid_certchain":       validCertChain,
		"valid_signature":       validSignature,
		"verified":              verified,
	}

	// Add client / safetynet generated fields for logging
	logFields.addJwtField("apk_certificate_digest_sha256", body.ApkCertificateDigestSha256)
	logFields.addJwtField("apk_digest_sha256", body.ApkDigestSha256)
	logFields.addJwtField("apk_package_name", body.ApkPackageName)
	logFields.addJwtField("basic_integrity", body.BasicIntegrity)
	logFields.addJwtField("cts_profile_match", body.CtsProfileMatch)
	logFields.addJwtField("error", body.Error)
	logFields.addJwtField("extension", body.Extension)
	logFields.addJwtField("nonce", body.Nonce)
	logFields.addJwtField("verification_timestamp", body.TimestampMs)

	return verified, logFields
}
