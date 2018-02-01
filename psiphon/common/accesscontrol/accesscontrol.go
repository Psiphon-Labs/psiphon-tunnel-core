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

// Package accesscontrol implements an access control authorization scheme
// based on digital signatures.
//
// Authorizations for specified access types are issued by an entity that
// digitally signs each authorization. The digital signature is verified
// by service providers before granting the specified access type. Each
// authorization includes an expiry date and a unique ID that may be used
// to mitigate malicious reuse/sharing of authorizations.
//
// In a typical deployment, the signing keys will be present on issuing
// entities which are distinct from service providers. Only verification
// keys will be deployed to service providers.
//
// An authorization is represented in JSON, which is then base64-encoded
// for transport:
//
// {
//   "Authorization" : {
// 	 "ID" : <derived unique ID>,
// 	 "AccessType" : <access type name; e.g., "my-access">,
// 	 "Expires" : <RFC3339-encoded UTC time value>
//   },
//   "SigningKeyID" : <unique key ID>,
//   "Signature" : <Ed25519 digital signature>
// }
//
package accesscontrol

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/crypto/ed25519"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/crypto/hkdf"
)

const (
	keyIDLength              = 32
	authorizationIDKeyLength = 32
	authorizationIDLength    = 32
)

// SigningKey is the private key used to sign newly issued
// authorizations for the specified access type. The key ID
// is included in authorizations and identifies the
// corresponding verification keys.
//
// AuthorizationIDKey is used to produce a unique
// authentication ID that cannot be mapped back to its seed
// value.
type SigningKey struct {
	ID                 []byte
	AccessType         string
	AuthorizationIDKey []byte
	PrivateKey         []byte
}

// VerificationKey is the public key used to verify signed
// authentications issued for the specified access type. The
// authorization references the expected public key by ID.
type VerificationKey struct {
	ID         []byte
	AccessType string
	PublicKey  []byte
}

// NewKeyPair generates a new authorization signing key pair.
func NewKeyPair(
	accessType string) (*SigningKey, *VerificationKey, error) {

	ID, err := common.MakeSecureRandomBytes(keyIDLength)
	if err != nil {
		return nil, nil, common.ContextError(err)
	}

	authorizationIDKey, err := common.MakeSecureRandomBytes(authorizationIDKeyLength)
	if err != nil {
		return nil, nil, common.ContextError(err)
	}

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, common.ContextError(err)
	}

	signingKey := &SigningKey{
		ID:                 ID,
		AccessType:         accessType,
		AuthorizationIDKey: authorizationIDKey,
		PrivateKey:         privateKey,
	}

	verificationKey := &VerificationKey{
		ID:         ID,
		AccessType: accessType,
		PublicKey:  publicKey,
	}

	return signingKey, verificationKey, nil
}

// Authorization describes an authorization, with a unique ID,
// granting access to a specified access type, and expiring at
// the specified time.
//
// An Authorization is embedded within a digitally signed
// object. This wrapping object adds a signature and a signing
// key ID.
type Authorization struct {
	ID         []byte
	AccessType string
	Expires    time.Time
}

type signedAuthorization struct {
	Authorization json.RawMessage
	SigningKeyID  []byte
	Signature     []byte
}

// ValidateSigningKey checks that a signing key is correctly configured.
func ValidateSigningKey(signingKey *SigningKey) error {
	if len(signingKey.ID) != keyIDLength ||
		len(signingKey.AccessType) < 1 ||
		len(signingKey.AuthorizationIDKey) != authorizationIDKeyLength ||
		len(signingKey.PrivateKey) != ed25519.PrivateKeySize {
		return common.ContextError(errors.New("invalid signing key"))
	}
	return nil
}

// IssueAuthorization issues an authorization signed with the
// specified signing key.
//
// seedAuthorizationID should be a value that uniquely identifies
// the purchase, subscription, or transaction that backs the
// authorization; a distinct unique authorization ID will be derived
// from the seed without revealing the original value. The authorization
// ID is to be used to mitigate malicious authorization reuse/sharing.
//
// The return value is a base64-encoded, serialized JSON representation
// of the signed authorization that can be passed to VerifyAuthorization.
func IssueAuthorization(
	signingKey *SigningKey,
	seedAuthorizationID []byte,
	expires time.Time) (string, error) {

	err := ValidateSigningKey(signingKey)
	if err != nil {
		return "", common.ContextError(err)
	}

	hkdf := hkdf.New(sha256.New, signingKey.AuthorizationIDKey, nil, seedAuthorizationID)
	ID := make([]byte, authorizationIDLength)
	_, err = io.ReadFull(hkdf, ID)
	if err != nil {
		return "", common.ContextError(err)
	}

	auth := Authorization{
		ID:         ID,
		AccessType: signingKey.AccessType,
		Expires:    expires.UTC(),
	}

	authJSON, err := json.Marshal(auth)
	if err != nil {
		return "", common.ContextError(err)
	}

	signature := ed25519.Sign(signingKey.PrivateKey, authJSON)

	signedAuth := signedAuthorization{
		Authorization: authJSON,
		SigningKeyID:  signingKey.ID,
		Signature:     signature,
	}

	signedAuthJSON, err := json.Marshal(signedAuth)
	if err != nil {
		return "", common.ContextError(err)
	}

	encodedSignedAuth := base64.StdEncoding.EncodeToString(signedAuthJSON)

	return encodedSignedAuth, nil
}

// VerificationKeyRing is a set of verification keys to be deployed
// to a service provider for verifying access authorizations.
type VerificationKeyRing struct {
	Keys []*VerificationKey
}

// ValidateVerificationKeyRing checks that a verification key ring is
// correctly configured.
func ValidateVerificationKeyRing(keyRing *VerificationKeyRing) error {
	for _, key := range keyRing.Keys {
		if len(key.ID) != keyIDLength ||
			len(key.AccessType) < 1 ||
			len(key.PublicKey) != ed25519.PublicKeySize {
			return common.ContextError(errors.New("invalid verification key"))
		}
	}
	return nil
}

// VerifyAuthorization verifies the signed authorization and, when
// verified, returns the embedded Authorization struct with the
// access control information.
//
// The key ID in the signed authorization is used to select the
// appropriate verification key from the key ring.
func VerifyAuthorization(
	keyRing *VerificationKeyRing,
	encodedSignedAuthorization string) (*Authorization, error) {

	err := ValidateVerificationKeyRing(keyRing)
	if err != nil {
		return nil, common.ContextError(err)
	}

	signedAuthorizationJSON, err := base64.StdEncoding.DecodeString(
		encodedSignedAuthorization)
	if err != nil {
		return nil, common.ContextError(err)
	}

	var signedAuth signedAuthorization
	err = json.Unmarshal(signedAuthorizationJSON, &signedAuth)
	if err != nil {
		return nil, common.ContextError(err)
	}

	if len(signedAuth.SigningKeyID) != keyIDLength {
		return nil, common.ContextError(errors.New("invalid key ID length"))
	}

	if len(signedAuth.Signature) != ed25519.SignatureSize {
		return nil, common.ContextError(errors.New("invalid signature length"))
	}

	var verificationKey *VerificationKey

	for _, key := range keyRing.Keys {
		if subtle.ConstantTimeCompare(signedAuth.SigningKeyID, key.ID) == 1 {
			verificationKey = key
		}
	}

	if verificationKey == nil {
		return nil, common.ContextError(errors.New("invalid key ID"))
	}

	if !ed25519.Verify(
		verificationKey.PublicKey, signedAuth.Authorization, signedAuth.Signature) {
		return nil, common.ContextError(errors.New("invalid signature"))
	}

	var auth Authorization

	err = json.Unmarshal(signedAuth.Authorization, &auth)
	if err != nil {
		return nil, common.ContextError(err)
	}

	if len(auth.ID) == 0 {
		return nil, common.ContextError(errors.New("invalid authentication ID"))
	}

	if auth.AccessType != verificationKey.AccessType {
		return nil, common.ContextError(errors.New("invalid access type"))
	}

	if auth.Expires.IsZero() {
		return nil, common.ContextError(errors.New("invalid expiry"))
	}

	if auth.Expires.Before(time.Now().UTC()) {
		return nil, common.ContextError(errors.New("expired authentication"))
	}

	return &auth, nil
}
