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
	"net/netip"
	"sync"

	"github.com/Jigsaw-Code/outline-sdk/transport/shadowsocks"
)

// Don't add a tag if it would reduce the salt entropy below this amount.
const minSaltEntropy = 16

// CipherEntry holds a Cipher with an identifier.
// The public fields are constant, but lastClientIP is mutable under cipherList.mu.
type CipherEntry struct {
	ID            string
	CryptoKey     *shadowsocks.EncryptionKey
	SaltGenerator ServerSaltGenerator
	lastClientIP  netip.Addr
}

// MakeCipherEntry constructs a CipherEntry.
func MakeCipherEntry(id string, cryptoKey *shadowsocks.EncryptionKey, secret string) CipherEntry {
	var saltGenerator ServerSaltGenerator
	if cryptoKey.SaltSize()-serverSaltMarkLen >= minSaltEntropy {
		// Mark salts with a tag for reverse replay protection.
		saltGenerator = NewServerSaltGenerator(secret)
	} else {
		// Adding a tag would leave too little randomness to protect
		// against accidental salt reuse, so don't mark the salts.
		saltGenerator = RandomServerSaltGenerator
	}
	return CipherEntry{
		ID:            id,
		CryptoKey:     cryptoKey,
		SaltGenerator: saltGenerator,
	}
}

// CipherList is a thread-safe collection of CipherEntry elements that allows for
// snapshotting and moving to front.
type CipherList interface {
	// Returns a snapshot of the cipher list optimized for this client IP
	SnapshotForClientIP(clientIP netip.Addr) []*list.Element
	MarkUsedByClientIP(e *list.Element, clientIP netip.Addr)
	// Update replaces the current contents of the CipherList with `contents`,
	// which is a List of *CipherEntry.  Update takes ownership of `contents`,
	// which must not be read or written after this call.
	Update(contents *list.List)
}

type cipherList struct {
	CipherList
	list *list.List
	mu   sync.RWMutex
}

// NewCipherList creates an empty CipherList
func NewCipherList() CipherList {
	return &cipherList{list: list.New()}
}

func matchesIP(e *list.Element, clientIP netip.Addr) bool {
	c := e.Value.(*CipherEntry)
	return clientIP != netip.Addr{} && clientIP == c.lastClientIP
}

func (cl *cipherList) SnapshotForClientIP(clientIP netip.Addr) []*list.Element {
	cl.mu.RLock()
	defer cl.mu.RUnlock()
	cipherArray := make([]*list.Element, cl.list.Len())
	i := 0
	// First pass: put all ciphers with matching last known IP at the front.
	for e := cl.list.Front(); e != nil; e = e.Next() {
		if matchesIP(e, clientIP) {
			cipherArray[i] = e
			i++
		}
	}
	// Second pass: include all remaining ciphers in recency order.
	for e := cl.list.Front(); e != nil; e = e.Next() {
		if !matchesIP(e, clientIP) {
			cipherArray[i] = e
			i++
		}
	}
	return cipherArray
}

func (cl *cipherList) MarkUsedByClientIP(e *list.Element, clientIP netip.Addr) {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	cl.list.MoveToFront(e)

	c := e.Value.(*CipherEntry)
	c.lastClientIP = clientIP
}

func (cl *cipherList) Update(src *list.List) {
	cl.mu.Lock()
	cl.list = src
	cl.mu.Unlock()
}
