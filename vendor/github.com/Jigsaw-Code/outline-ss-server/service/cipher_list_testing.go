// Copyright 2018 Jigsaw Operations LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package service

import (
	"container/list"
	"fmt"

	"github.com/Jigsaw-Code/outline-sdk/transport/shadowsocks"
)

// MakeTestCiphers creates a CipherList containing one fresh AEAD cipher
// for each secret in `secrets`.
func MakeTestCiphers(secrets []string) (CipherList, error) {
	l := list.New()
	for i := 0; i < len(secrets); i++ {
		cipherID := fmt.Sprintf("id-%v", i)
		cipher, err := shadowsocks.NewEncryptionKey(shadowsocks.CHACHA20IETFPOLY1305, secrets[i])
		if err != nil {
			return nil, fmt.Errorf("failed to create cipher %v: %w", i, err)
		}
		entry := MakeCipherEntry(cipherID, cipher, secrets[i])
		l.PushBack(&entry)
	}
	cipherList := NewCipherList()
	cipherList.Update(l)
	return cipherList, nil
}

// makeTestPayload returns a slice of `size` arbitrary bytes.
func makeTestPayload(size int) []byte {
	payload := make([]byte, size)
	for i := 0; i < size; i++ {
		payload[i] = byte(i)
	}
	return payload
}

// makeTestSecrets returns a slice of `n` test passwords.  Not secure!
func makeTestSecrets(n int) []string {
	secrets := make([]string, n)
	for i := 0; i < n; i++ {
		secrets[i] = fmt.Sprintf("secret-%v", i)
	}
	return secrets
}
