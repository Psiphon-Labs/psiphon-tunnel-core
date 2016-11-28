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

package common

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
)

// AuthenticatedDataPackage is a JSON record containing some Psiphon data
// payload, such as list of Psiphon server entries. As it may be downloaded
// from various sources, it is digitally signed so that the data may be
// authenticated.
type AuthenticatedDataPackage struct {
	Data                   string `json:"data"`
	SigningPublicKeyDigest []byte `json:"signingPublicKeyDigest"`
	Signature              []byte `json:"signature"`
}

// GenerateAuthenticatedDataPackageKeys generates a key pair
// be used to sign and verify AuthenticatedDataPackages.
func GenerateAuthenticatedDataPackageKeys() (string, string, error) {

	rsaKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return "", "", ContextError(err)
	}

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(rsaKey.Public())
	if err != nil {
		return "", "", ContextError(err)
	}

	privateKeyBytes := x509.MarshalPKCS1PrivateKey(rsaKey)

	return base64.StdEncoding.EncodeToString(publicKeyBytes),
		base64.StdEncoding.EncodeToString(privateKeyBytes),
		nil
}

func sha256sum(data string) []byte {
	hash := sha256.New()
	hash.Write([]byte(data))
	return hash.Sum(nil)
}

// WriteAuthenticatedDataPackage creates an AuthenticatedDataPackage
// containing the specified data and signed by the given key. The output
// conforms with the legacy format here:
// https://bitbucket.org/psiphon/psiphon-circumvention-system/src/c25d080f6827b141fe637050ce0d5bd0ae2e9db5/Automation/psi_ops_crypto_tools.py
func WriteAuthenticatedDataPackage(
	data string, signingPublicKey, signingPrivateKey string) ([]byte, error) {

	derEncodedPrivateKey, err := base64.StdEncoding.DecodeString(signingPrivateKey)
	if err != nil {
		return nil, ContextError(err)
	}
	rsaPrivateKey, err := x509.ParsePKCS1PrivateKey(derEncodedPrivateKey)
	if err != nil {
		return nil, ContextError(err)
	}

	signature, err := rsa.SignPKCS1v15(
		rand.Reader,
		rsaPrivateKey,
		crypto.SHA256,
		sha256sum(data))
	if err != nil {
		return nil, ContextError(err)
	}

	packageJSON, err := json.Marshal(
		&AuthenticatedDataPackage{
			Data: data,
			SigningPublicKeyDigest: sha256sum(signingPublicKey),
			Signature:              signature,
		})
	if err != nil {
		return nil, ContextError(err)
	}

	return packageJSON, nil
}

// ReadAuthenticatedDataPackage extracts and verifies authenticated
// data from an AuthenticatedDataPackage. The package must have been
// signed with the given key.
func ReadAuthenticatedDataPackage(
	packageJSON []byte, signingPublicKey string) (string, error) {

	var authenticatedDataPackage *AuthenticatedDataPackage
	err := json.Unmarshal(packageJSON, &authenticatedDataPackage)
	if err != nil {
		return "", ContextError(err)
	}

	derEncodedPublicKey, err := base64.StdEncoding.DecodeString(signingPublicKey)
	if err != nil {
		return "", ContextError(err)
	}
	publicKey, err := x509.ParsePKIXPublicKey(derEncodedPublicKey)
	if err != nil {
		return "", ContextError(err)
	}
	rsaPublicKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return "", ContextError(errors.New("unexpected signing public key type"))
	}

	if 0 != bytes.Compare(
		authenticatedDataPackage.SigningPublicKeyDigest,
		sha256sum(signingPublicKey)) {

		return "", ContextError(errors.New("unexpected signing public key digest"))
	}

	err = rsa.VerifyPKCS1v15(
		rsaPublicKey,
		crypto.SHA256,
		sha256sum(authenticatedDataPackage.Data),
		authenticatedDataPackage.Signature)
	if err != nil {
		return "", ContextError(err)
	}

	return authenticatedDataPackage.Data, nil
}
