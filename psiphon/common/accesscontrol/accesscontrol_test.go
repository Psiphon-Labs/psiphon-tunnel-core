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
	"encoding/json"
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

	// Test: valid key ring

	err = ValidateKeyRing(keyRing)
	if err != nil {
		t.Fatalf("ValidateKeyRing failed: %s", err)
	}

	// Test: invalid key ring

	invalidKeyRing := &VerificationKeyRing{
		Keys: []*VerificationKey{&VerificationKey{}},
	}

	err = ValidateKeyRing(invalidKeyRing)
	if err == nil {
		t.Fatalf("ValidateKeyRing unexpected success")
	}

	// Test: valid authorization

	id := []byte("0000000000000001")

	expires := time.Now().Add(10 * time.Second)

	auth, err := IssueAuthorization(correctSigningKey, id, expires)
	if err != nil {
		t.Fatalf("IssueAuthorization failed: %s", err)
	}

	verifiedAuth, err := VerifyAuthorization(keyRing, auth)
	if err != nil {
		t.Fatalf("VerifyAuthorization failed: %s", err)
	}

	if verifiedAuth.AccessType != correctAccess {
		t.Fatalf("unexpected access type: %s", verifiedAuth.AccessType)
	}

	// Test: expired authorization

	expires = time.Now().Add(-10 * time.Second)

	auth, err = IssueAuthorization(correctSigningKey, id, expires)
	if err != nil {
		t.Fatalf("IssueAuthorization failed: %s", err)
	}

	verifiedAuth, err = VerifyAuthorization(keyRing, auth)
	// TODO: check error message?
	if err == nil {
		t.Fatalf("VerifyAuthorization unexpected success")
	}

	// Test: authorization signed with key not in key ring

	expires = time.Now().Add(10 * time.Second)

	auth, err = IssueAuthorization(invalidSigningKey, id, expires)
	if err != nil {
		t.Fatalf("IssueAuthorization failed: %s", err)
	}

	verifiedAuth, err = VerifyAuthorization(keyRing, auth)
	// TODO: check error message?
	if err == nil {
		t.Fatalf("VerifyAuthorization unexpected success")
	}

	// Test: authorization signed with valid key, but hacked access type

	expires = time.Now().Add(10 * time.Second)

	auth, err = IssueAuthorization(otherSigningKey, id, expires)
	if err != nil {
		t.Fatalf("IssueAuthorization failed: %s", err)
	}

	var hackSignedAuth signedAuthorization
	err = json.Unmarshal(auth, &hackSignedAuth)
	if err != nil {
		t.Fatalf("Unmarshal failed: %s", err)
	}

	var hackAuth Authorization
	err = json.Unmarshal(hackSignedAuth.Authorization, &hackAuth)
	if err != nil {
		t.Fatalf("Unmarshal failed: %s", err)
	}

	hackAuth.AccessType = correctAccess

	auth, err = json.Marshal(hackAuth)
	if err != nil {
		t.Fatalf("Marshall failed: %s", err)
	}

	hackSignedAuth.Authorization = auth

	signedAuth, err := json.Marshal(hackSignedAuth)
	if err != nil {
		t.Fatalf("Marshall failed: %s", err)
	}

	verifiedAuth, err = VerifyAuthorization(keyRing, signedAuth)
	// TODO: check error message?
	if err == nil {
		t.Fatalf("VerifyAuthorization unexpected success")
	}
}
