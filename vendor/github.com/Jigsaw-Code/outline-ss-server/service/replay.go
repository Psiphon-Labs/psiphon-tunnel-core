// Copyright 2020 Jigsaw Operations LLC
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
	"encoding/binary"
	"errors"
	"sync"
)

// MaxCapacity is the largest allowed size of ReplayCache.
//
// Capacities in excess of 20,000 are not recommended, due to the false
// positive rate of up to 2 * capacity / 2^32 = 1 / 100,000.  If larger
// capacities are desired, the key type should be changed to uint64.
const MaxCapacity = 20_000

type empty struct{}

// ReplayCache allows us to check whether a handshake salt was used within
// the last `capacity` handshakes.  It requires approximately 20*capacity
// bytes of memory (as measured by BenchmarkReplayCache_Creation).
//
// The nil and zero values represent a cache with capacity 0, i.e. no cache.
type ReplayCache struct {
	mutex    sync.Mutex
	capacity int
	active   map[uint32]empty
	archive  map[uint32]empty
}

// NewReplayCache returns a fresh ReplayCache that promises to remember at least
// the most recent `capacity` handshakes.
func NewReplayCache(capacity int) ReplayCache {
	if capacity > MaxCapacity {
		panic("ReplayCache capacity would result in too many false positives")
	}
	return ReplayCache{
		capacity: capacity,
		active:   make(map[uint32]empty, capacity),
		// `archive` is read-only and initially empty.
	}
}

// Trivially reduces the key and salt to a uint32, avoiding collisions
// in case of salts with a shared prefix or suffix.  Salts are normally
// random, but in principle a client might use a counter instead, so
// using only the prefix or suffix is not sufficient.  Including the key
// ID in the hash avoids accidental collisions when the same salt is used
// by different access keys, as might happen in the case of a counter.
//
// Secure hashing is not required, because only authenticated handshakes
// are added to the cache.  A hostile client could produce colliding salts,
// but this would not impact other users.  Each map uses a new random hash
// function, so it is not trivial for a hostile client to mount an
// algorithmic complexity attack with nearly-colliding hashes:
// https://dave.cheney.net/2018/05/29/how-the-go-runtime-implements-maps-efficiently-without-generics
func preHash(id string, salt []byte) uint32 {
	buf := [4]byte{}
	for i := 0; i < len(id); i++ {
		buf[i&0x3] ^= id[i]
	}
	for i, v := range salt {
		buf[i&0x3] ^= v
	}
	return binary.BigEndian.Uint32(buf[:])
}

// Add a handshake with this key ID and salt to the cache.
// Returns false if it is already present.
func (c *ReplayCache) Add(id string, salt []byte) bool {
	if c == nil || c.capacity == 0 {
		// Cache is disabled, so every salt is new.
		return true
	}
	hash := preHash(id, salt)
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if _, ok := c.active[hash]; ok {
		// Fast replay: `salt` is already in the active set.
		return false
	}
	_, inArchive := c.archive[hash]
	if len(c.active) >= c.capacity {
		// Discard the archive and move active to archive.
		c.archive = c.active
		c.active = make(map[uint32]empty, c.capacity)
	}
	c.active[hash] = empty{}
	return !inArchive
}

// Resize adjusts the capacity of the ReplayCache.
func (c *ReplayCache) Resize(capacity int) error {
	if capacity > MaxCapacity {
		return errors.New("ReplayCache capacity would result in too many false positives")
	}
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.capacity = capacity
	// NOTE: The active handshakes and archive lists are not explicitly shrunk.
	// Their sizes will naturally adjust as new handshakes are added and the cache
	// adheres to the updated capacity.
	return nil
}
