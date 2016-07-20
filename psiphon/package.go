/*
 * Copyright (c) 2015, Psiphon Inc.
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

package psiphon

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
)

// AuthenticatedDataPackage is a JSON record containing some Psiphon data
// payload, such as list of Psiphon server entries. As it may be downloaded
// from various sources, it is digitally signed so that the data may be
// authenticated.
type AuthenticatedDataPackage struct {
	Data                   string `json:"data"`
	SigningPublicKeyDigest string `json:"signingPublicKeyDigest"`
	Signature              string `json:"signature"`
}

func ReadAuthenticatedDataPackage(
	rawPackage []byte, signingPublicKey string) (data string, err error) {

	var authenticatedDataPackage *AuthenticatedDataPackage
	err = json.Unmarshal(rawPackage, &authenticatedDataPackage)
	if err != nil {
		return "", common.ContextError(err)
	}

	derEncodedPublicKey, err := base64.StdEncoding.DecodeString(signingPublicKey)
	if err != nil {
		return "", common.ContextError(err)
	}
	publicKey, err := x509.ParsePKIXPublicKey(derEncodedPublicKey)
	if err != nil {
		return "", common.ContextError(err)
	}
	rsaPublicKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return "", common.ContextError(errors.New("unexpected signing public key type"))
	}
	signature, err := base64.StdEncoding.DecodeString(authenticatedDataPackage.Signature)
	if err != nil {
		return "", common.ContextError(err)
	}
	// TODO: can distinguish signed-with-different-key from other errors:
	// match digest(publicKey) against authenticatedDataPackage.SigningPublicKeyDigest
	hash := sha256.New()
	hash.Write([]byte(authenticatedDataPackage.Data))
	digest := hash.Sum(nil)
	err = rsa.VerifyPKCS1v15(rsaPublicKey, crypto.SHA256, digest, signature)
	if err != nil {
		return "", common.ContextError(err)
	}

	return authenticatedDataPackage.Data, nil
}
