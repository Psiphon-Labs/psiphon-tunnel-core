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

package accesscontrol

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

func TestAuthorization(t *testing.T) {

	correctAccess := "access1"
	otherAccess := "access2"

	correctSigningKey, correctVerificationKey, err := NewKeyPair(correctAccess)
	if err != nil {
		t.Fatalf("NewKeyPair failed: %s", err)
	}

	otherSigningKey, otherVerificationKey, err := NewKeyPair(otherAccess)
	if err != nil {
		t.Fatalf("NewKeyPair failed: %s", err)
	}

	invalidSigningKey, _, err := NewKeyPair(correctAccess)
	if err != nil {
		t.Fatalf("NewKeyPair failed: %s", err)
	}

	keyRing := &VerificationKeyRing{
		Keys: []*VerificationKey{correctVerificationKey, otherVerificationKey},
	}

	// Test: valid key

	err = ValidateSigningKey(correctSigningKey)
	if err != nil {
		t.Fatalf("ValidateSigningKey failed: %s", err)
	}

	// Test: invalid key

	err = ValidateSigningKey(&SigningKey{})
	if err == nil {
		t.Fatalf("ValidateSigningKey unexpected success")
	}

	// Test: valid key ring

	err = ValidateVerificationKeyRing(keyRing)
	if err != nil {
		t.Fatalf("ValidateVerificationKeyRing failed: %s", err)
	}

	// Test: invalid key ring

	invalidKeyRing := &VerificationKeyRing{
		Keys: []*VerificationKey{&VerificationKey{}},
	}

	err = ValidateVerificationKeyRing(invalidKeyRing)
	if err == nil {
		t.Fatalf("ValidateVerificationKeyRing unexpected success")
	}

	// Test: valid authorization

	id := []byte("0000000000000001")

	expires := time.Now().Add(10 * time.Second)

	auth, issuedID, err := IssueAuthorization(correctSigningKey, id, expires)
	if err != nil {
		t.Fatalf("IssueAuthorization failed: %s", err)
	}

	// Test: re-issuing authorization with the same seedAuthorizationID yields
	// the same value

	reauth, _, err := IssueAuthorization(correctSigningKey, id, expires)
	if err != nil {
		t.Fatalf("IssueAuthorization failed: %s", err)
	}

	if auth != reauth {
		t.Fatalf("unexpected difference in authorizations")
	}

	// Decode the signed authorization and check that the auth ID in the JSON
	// matches the one returned by IssueAuthorization.

	decodedAuthorization, err := base64.StdEncoding.DecodeString(auth)
	if err != nil {
		t.Fatalf("DecodeString failed: %s", err)
	}

	type partialSignedAuthorization struct {
		Authorization json.RawMessage
	}
	var partialSignedAuth partialSignedAuthorization
	err = json.Unmarshal(decodedAuthorization, &partialSignedAuth)
	if err != nil {
		t.Fatalf("Unmarshal failed: %s", err)
	}

	var unmarshaledAuth map[string]interface{}
	err = json.Unmarshal(partialSignedAuth.Authorization, &unmarshaledAuth)
	if err != nil {
		t.Fatalf("Unmarshal failed: %s", err)
	}

	authID, ok := unmarshaledAuth["ID"].(string)
	if !ok {
		t.Fatalf("Failed to find auth ID in unmarshaled auth: %s", unmarshaledAuth)
	}

	if string(authID) != base64.StdEncoding.EncodeToString(issuedID) {
		t.Fatalf("Expected auth ID in signed auth (%s) to match that returned by IssueAuthorization (%s)", string(authID), base64.StdEncoding.EncodeToString(issuedID))
	}

	fmt.Printf("encoded authorization length: %d\n", len(auth))

	verifiedAuth, err := VerifyAuthorization(keyRing, auth)
	if err != nil {
		t.Fatalf("VerifyAuthorization failed: %s", err)
	}

	if verifiedAuth.AccessType != correctAccess {
		t.Fatalf("unexpected access type: %s", verifiedAuth.AccessType)
	}

	// Test: expired authorization

	expires = time.Now().Add(-10 * time.Second)

	auth, _, err = IssueAuthorization(correctSigningKey, id, expires)
	if err != nil {
		t.Fatalf("IssueAuthorization failed: %s", err)
	}

	_, err = VerifyAuthorization(keyRing, auth)
	// TODO: check error message?
	if err == nil {
		t.Fatalf("VerifyAuthorization unexpected success")
	}

	// Test: authorization signed with key not in key ring

	expires = time.Now().Add(10 * time.Second)

	auth, _, err = IssueAuthorization(invalidSigningKey, id, expires)
	if err != nil {
		t.Fatalf("IssueAuthorization failed: %s", err)
	}

	_, err = VerifyAuthorization(keyRing, auth)
	// TODO: check error message?
	if err == nil {
		t.Fatalf("VerifyAuthorization unexpected success")
	}

	// Test: authorization signed with valid key, but hacked access type

	expires = time.Now().Add(10 * time.Second)

	auth, _, err = IssueAuthorization(otherSigningKey, id, expires)
	if err != nil {
		t.Fatalf("IssueAuthorization failed: %s", err)
	}

	decodedAuth, err := base64.StdEncoding.DecodeString(auth)
	if err != nil {
		t.Fatalf("DecodeString failed: %s", err)
	}

	var hackSignedAuth signedAuthorization
	err = json.Unmarshal(decodedAuth, &hackSignedAuth)
	if err != nil {
		t.Fatalf("Unmarshal failed: %s", err)
	}

	var hackAuth Authorization
	err = json.Unmarshal(hackSignedAuth.Authorization, &hackAuth)
	if err != nil {
		t.Fatalf("Unmarshal failed: %s", err)
	}

	hackAuth.AccessType = correctAccess

	marshaledAuth, err := json.Marshal(hackAuth)
	if err != nil {
		t.Fatalf("Marshall failed: %s", err)
	}

	hackSignedAuth.Authorization = marshaledAuth

	marshaledSignedAuth, err := json.Marshal(hackSignedAuth)
	if err != nil {
		t.Fatalf("Marshall failed: %s", err)
	}

	encodedSignedAuth := base64.StdEncoding.EncodeToString(marshaledSignedAuth)

	_, err = VerifyAuthorization(keyRing, encodedSignedAuth)
	// TODO: check error message?
	if err == nil {
		t.Fatalf("VerifyAuthorization unexpected success")
	}
}
