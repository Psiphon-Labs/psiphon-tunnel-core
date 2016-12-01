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
	"encoding/json"
	"testing"
)

func TestAuthenticatedPackage(t *testing.T) {

	var signingPublicKey, signingPrivateKey string

	t.Run("generate package keys", func(t *testing.T) {
		var err error
		signingPublicKey, signingPrivateKey, err = GenerateAuthenticatedDataPackageKeys()
		if err != nil {
			t.Fatalf("GenerateAuthenticatedDataPackageKeys failed: %s", err)
		}
	})

	expectedContent := "TestAuthenticatedPackage"
	var packagePayload []byte

	t.Run("write package", func(t *testing.T) {
		var err error
		packagePayload, err = WriteAuthenticatedDataPackage(
			expectedContent,
			signingPublicKey,
			signingPrivateKey)
		if err != nil {
			t.Fatalf("WriteAuthenticatedDataPackage failed: %s", err)
		}
	})

	t.Run("read package: success", func(t *testing.T) {
		content, err := ReadAuthenticatedDataPackage(
			packagePayload, signingPublicKey)
		if err != nil {
			t.Fatalf("ReadAuthenticatedDataPackage failed: %s", err)
		}
		if content != expectedContent {
			t.Fatalf(
				"unexpected package content: expected %s got %s",
				expectedContent, content)
		}
	})

	t.Run("read package: wrong signing key", func(t *testing.T) {
		wrongSigningPublicKey, _, err := GenerateAuthenticatedDataPackageKeys()
		if err != nil {
			t.Fatalf("GenerateAuthenticatedDataPackageKeys failed: %s", err)
		}
		_, err = ReadAuthenticatedDataPackage(
			packagePayload, wrongSigningPublicKey)
		if err == nil {
			t.Fatalf("ReadAuthenticatedDataPackage unexpectedly succeeded")
		}
	})

	t.Run("read package: tampered data", func(t *testing.T) {

		var authDataPackage AuthenticatedDataPackage
		err := json.Unmarshal(packagePayload, &authDataPackage)
		if err != nil {
			t.Fatalf("Unmarshal failed: %s", err)
		}
		authDataPackage.Data = "TamperedData"

		tamperedPackagePayload, err := json.Marshal(&authDataPackage)
		if err != nil {
			t.Fatalf("Marshal failed: %s", err)
		}

		_, err = ReadAuthenticatedDataPackage(
			tamperedPackagePayload, signingPublicKey)
		if err == nil {
			t.Fatalf("ReadAuthenticatedDataPackage unexpectedly succeeded")
		}
	})
}
