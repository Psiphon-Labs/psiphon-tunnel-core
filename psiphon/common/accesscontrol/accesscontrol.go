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
//	{
//	  "Authorization" : {
//		 "ID" : <derived unique ID>,
//		 "AccessType" : <access type name; e.g., "my-access">,
//		 "Expires" : <RFC3339-encoded UTC time value>
//	  },
//	  "SigningKeyID" : <unique key ID>,
//	  "Signature" : <Ed25519 digital signature>
//	}
package accesscontrol

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"io"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/fxamacker/cbor/v2"
	"golang.org/x/crypto/hkdf"
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

	ID := make([]byte, keyIDLength)
	_, err := rand.Read(ID)
	if err != nil {
		return nil, nil, errors.Trace(err)
	}

	authorizationIDKey := make([]byte, authorizationIDKeyLength)
	_, err = rand.Read(authorizationIDKey)
	if err != nil {
		return nil, nil, errors.Trace(err)
	}

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, errors.Trace(err)
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
		return errors.TraceNew("invalid signing key")
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
// The first return value is a base64-encoded, serialized JSON representation
// of the signed authorization that can be passed to VerifyAuthorization. The
// second return value is the unique ID of the signed authorization returned in
// the first value.
func IssueAuthorization(
	signingKey *SigningKey,
	seedAuthorizationID []byte,
	expires time.Time) (string, []byte, error) {

	err := ValidateSigningKey(signingKey)
	if err != nil {
		return "", nil, errors.Trace(err)
	}

	hkdf := hkdf.New(sha256.New, signingKey.AuthorizationIDKey, nil, seedAuthorizationID)
	ID := make([]byte, authorizationIDLength)
	_, err = io.ReadFull(hkdf, ID)
	if err != nil {
		return "", nil, errors.Trace(err)
	}

	auth := Authorization{
		ID:         ID,
		AccessType: signingKey.AccessType,
		Expires:    expires.UTC(),
	}

	authJSON, err := json.Marshal(auth)
	if err != nil {
		return "", nil, errors.Trace(err)
	}

	signature := ed25519.Sign(signingKey.PrivateKey, authJSON)

	signedAuth := signedAuthorization{
		Authorization: authJSON,
		SigningKeyID:  signingKey.ID,
		Signature:     signature,
	}

	signedAuthJSON, err := json.Marshal(signedAuth)
	if err != nil {
		return "", nil, errors.Trace(err)
	}

	encodedSignedAuth := base64.StdEncoding.EncodeToString(signedAuthJSON)

	return encodedSignedAuth, ID, nil
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
			return errors.TraceNew("invalid verification key")
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
		return nil, errors.Trace(err)
	}

	signedAuthorizationJSON, err := base64.StdEncoding.DecodeString(
		encodedSignedAuthorization)
	if err != nil {
		return nil, errors.Trace(err)
	}

	var signedAuth signedAuthorization
	err = json.Unmarshal(signedAuthorizationJSON, &signedAuth)
	if err != nil {
		return nil, errors.Trace(err)
	}

	if len(signedAuth.SigningKeyID) != keyIDLength {
		return nil, errors.TraceNew("invalid key ID length")
	}

	if len(signedAuth.Signature) != ed25519.SignatureSize {
		return nil, errors.TraceNew("invalid signature length")
	}

	var verificationKey *VerificationKey

	for _, key := range keyRing.Keys {
		if subtle.ConstantTimeCompare(signedAuth.SigningKeyID, key.ID) == 1 {
			verificationKey = key
		}
	}

	if verificationKey == nil {
		return nil, errors.TraceNew("invalid key ID")
	}

	if !ed25519.Verify(
		verificationKey.PublicKey, signedAuth.Authorization, signedAuth.Signature) {
		return nil, errors.TraceNew("invalid signature")
	}

	var auth Authorization
	err = json.Unmarshal(signedAuth.Authorization, &auth)
	if err != nil {
		return nil, errors.Trace(err)
	}

	if len(auth.ID) == 0 {
		return nil, errors.TraceNew("invalid authorization ID")
	}

	if auth.AccessType != verificationKey.AccessType {
		return nil, errors.TraceNew("invalid access type")
	}

	if auth.Expires.IsZero() {
		return nil, errors.TraceNew("invalid expiry")
	}

	if auth.Expires.Before(time.Now().UTC()) {
		return nil, errors.TraceNew("expired authorization")
	}

	return &auth, nil
}

type packedAuthorization struct {
	ID           []byte    `cbor:"1,keyasint,omitempty"`
	AccessType   string    `cbor:"2,keyasint,omitempty"`
	Expires      time.Time `cbor:"3,keyasint,omitempty"`
	SigningKeyID []byte    `cbor:"4,keyasint,omitempty"`
	Signature    []byte    `cbor:"5,keyasint,omitempty"`
}

// PackAuthorizations re-encodes a list of authorizations using the more
// compact encoding that is used in protocol.EncodePackedAPIParameters.
func PackAuthorizations(
	auths []string,
	cborEncoding cbor.EncMode) ([]byte, error) {

	// Note: not using protocol.CBOREncoding directly due to import cycle.

	packedAuths := make([]packedAuthorization, len(auths))

	for i, authBase64 := range auths {

		authJSON, err := base64.StdEncoding.DecodeString(authBase64)
		if err != nil {
			return nil, errors.Trace(err)
		}

		var signedAuth signedAuthorization
		err = json.Unmarshal(authJSON, &signedAuth)
		if err != nil {
			return nil, errors.Trace(err)
		}

		var auth Authorization
		err = json.Unmarshal(signedAuth.Authorization, &auth)
		if err != nil {
			return nil, errors.Trace(err)
		}

		packedAuths[i] = packedAuthorization{
			ID:           auth.ID,
			AccessType:   auth.AccessType,
			Expires:      auth.Expires,
			SigningKeyID: signedAuth.SigningKeyID,
			Signature:    signedAuth.Signature,
		}
	}

	packedAuthsCBOR, err := cborEncoding.Marshal(packedAuths)
	if err != nil {
		return nil, errors.Trace(err)
	}

	return packedAuthsCBOR, nil
}

// UnpackAuthorizations re-encodes a list of authorizations encoded with
// PackAuthorizations back to the standard, IssueAuthorization encoding.
func UnpackAuthorizations(packedAuthsCBOR []byte) ([]string, error) {

	var packedAuths []packedAuthorization
	err := cbor.Unmarshal(packedAuthsCBOR, &packedAuths)
	if err != nil {
		return nil, errors.Trace(err)
	}

	auths := make([]string, len(packedAuths))

	for i, packedAuth := range packedAuths {

		auth := Authorization{
			ID:         packedAuth.ID,
			AccessType: packedAuth.AccessType,
			Expires:    packedAuth.Expires,
		}

		authJSON, err := json.Marshal(&auth)
		if err != nil {
			return nil, errors.Trace(err)
		}

		signedAuth := signedAuthorization{
			Authorization: authJSON,
			SigningKeyID:  packedAuth.SigningKeyID,
			Signature:     packedAuth.Signature,
		}

		signedAuthJSON, err := json.Marshal(&signedAuth)
		if err != nil {
			return nil, errors.Trace(err)
		}

		auths[i] = base64.StdEncoding.EncodeToString(signedAuthJSON)
	}

	return auths, nil
}
