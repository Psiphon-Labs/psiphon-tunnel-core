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
	"encoding/base64"
	"encoding/json"
	"io"
	"io/ioutil"
	"math/rand"
	"os"
	"testing"
)

func TestAuthenticatedPackage(t *testing.T) {

	signingPublicKey, signingPrivateKey, err := GenerateAuthenticatedDataPackageKeys()
	if err != nil {
		t.Fatalf("GenerateAuthenticatedDataPackageKeys failed: %s", err)
	}

	expectedContent := "TestAuthenticatedPackage"

	packagePayload, err := WriteAuthenticatedDataPackage(
		expectedContent,
		signingPublicKey,
		signingPrivateKey)
	if err != nil {
		t.Fatalf("WriteAuthenticatedDataPackage failed: %s", err)
	}

	tempFileName, err := makeTempFile(packagePayload)
	if err != nil {
		t.Fatalf("makeTempFile failed: %s", err)
	}
	defer os.Remove(tempFileName)

	wrongSigningPublicKey, _, err := GenerateAuthenticatedDataPackageKeys()
	if err != nil {
		t.Fatalf("GenerateAuthenticatedDataPackageKeys failed: %s", err)
	}

	packageJSON, err := Decompress(packagePayload)
	if err != nil {
		t.Fatalf("Uncompress failed: %s", err)
	}

	var authDataPackage AuthenticatedDataPackage
	err = json.Unmarshal(packageJSON, &authDataPackage)
	if err != nil {
		t.Fatalf("Unmarshal failed: %s", err)
	}
	authDataPackage.Data = "TamperedData"

	tamperedPackageJSON, err := json.Marshal(&authDataPackage)
	if err != nil {
		t.Fatalf("Marshal failed: %s", err)
	}

	tamperedPackagePayload := Compress(tamperedPackageJSON)

	tamperedTempFileName, err := makeTempFile(tamperedPackagePayload)
	if err != nil {
		t.Fatalf("makeTempFile failed: %s", err)
	}
	defer os.Remove(tempFileName)

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

	t.Run("streaming read package: success", func(t *testing.T) {
		contentReader, err := StreamingReadAuthenticatedDataPackage(
			tempFileName, signingPublicKey)
		if err != nil {
			t.Fatalf("StreamingReadAuthenticatedDataPackage failed: %s", err)
		}
		content, err := ioutil.ReadAll(contentReader)
		if err != nil {
			t.Fatalf("ReadAll failed: %s", err)
		}
		if string(content) != expectedContent {
			t.Fatalf(
				"unexpected package content: expected %s got %s",
				expectedContent, content)
		}
	})

	t.Run("read package: wrong signing key", func(t *testing.T) {
		_, err = ReadAuthenticatedDataPackage(
			packagePayload, wrongSigningPublicKey)
		if err == nil {
			t.Fatalf("ReadAuthenticatedDataPackage unexpectedly succeeded")
		}
	})

	t.Run("streaming read package: wrong signing key", func(t *testing.T) {
		_, err = StreamingReadAuthenticatedDataPackage(
			tempFileName, wrongSigningPublicKey)
		if err == nil {
			t.Fatalf("StreamingReadAuthenticatedDataPackage unexpectedly succeeded")
		}
	})

	t.Run("read package: tampered data", func(t *testing.T) {
		_, err = ReadAuthenticatedDataPackage(
			tamperedPackagePayload, signingPublicKey)
		if err == nil {
			t.Fatalf("ReadAuthenticatedDataPackage unexpectedly succeeded")
		}
	})

	t.Run("streaming read package: tampered data", func(t *testing.T) {
		_, err = StreamingReadAuthenticatedDataPackage(
			tamperedTempFileName, signingPublicKey)
		if err == nil {
			t.Fatalf("StreamingReadAuthenticatedDataPackage unexpectedly succeeded")
		}
	})
}

func BenchmarkAuthenticatedPackage(b *testing.B) {

	signingPublicKey, signingPrivateKey, err := GenerateAuthenticatedDataPackageKeys()
	if err != nil {
		b.Fatalf("GenerateAuthenticatedDataPackageKeys failed: %s", err)
	}

	data := make([]byte, 104857600)
	rand.Read(data)

	packagePayload, err := WriteAuthenticatedDataPackage(
		base64.StdEncoding.EncodeToString(data),
		signingPublicKey,
		signingPrivateKey)
	if err != nil {
		b.Fatalf("WriteAuthenticatedDataPackage failed: %s", err)
	}

	tempFileName, err := makeTempFile(packagePayload)
	if err != nil {
		b.Fatalf("makeTempFile failed: %s", err)
	}
	defer os.Remove(tempFileName)

	b.Run("read package", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := ReadAuthenticatedDataPackage(
				packagePayload, signingPublicKey)
			if err != nil {
				b.Fatalf("ReadAuthenticatedDataPackage failed: %s", err)
			}
		}
	})

	b.Run("streaming read package", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			contentReader, err := StreamingReadAuthenticatedDataPackage(
				tempFileName, signingPublicKey)
			if err != nil {
				b.Fatalf("StreamingReadAuthenticatedDataPackage failed: %s", err)
			}
			_, err = io.Copy(ioutil.Discard, contentReader)
			if err != nil {
				b.Fatalf("Read failed: %s", err)
			}
		}
	})
}

func makeTempFile(data []byte) (string, error) {
	file, err := ioutil.TempFile("", "authPackage_test")
	if err != nil {
		return "", ContextError(err)
	}
	defer file.Close()
	_, err = file.Write(data)
	if err != nil {
		return "", ContextError(err)
	}
	return file.Name(), nil
}
