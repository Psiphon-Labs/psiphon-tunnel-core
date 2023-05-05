/*
 * Copyright (c) 2023, Psiphon Inc.
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

package inproxy

import (
	"net"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	lrucache "github.com/cognusion/go-cache-lru"
)

// dtlsSeedCacheTTL should be long enough for the seed to remain available in
// the cache between when it's first set at the start of WebRTC operations,
// and until all DTLS dials have completed.

const (
	dtlsSeedCacheTTL     = 60 * time.Second
	dtlsSeedCacheMaxSize = 10000
)

// SetDTLSSeed establishes a cached common/prng seed to be used when
// randomizing DTLS ClientHellos.
//
// The seed is keyed by the specified conn's local address. This allows a fork
// of pion/dtls to fetch the seed and apply randomization without having to
// fork many pion layers to pass in seeds. Concurrent dials must use distinct
// conns with distinct local addresses (including port number).
//
// Both sides of a WebRTC connection may randomize their ClientHello. isOffer
// allows the same seed to be used, but produce two distinct random streams.
// The client generates or replays an obfuscation secret used to derive the
// seed, and the obfuscation secret is relayed to the proxy by the Broker.
//
// The caller may specify TTL, which can be used to retain the cached key for
// a dial timeout duration; when TTL is <= 0, a default TTL is used.
func SetDTLSSeed(conn net.PacketConn, obfuscationSecret ObfuscationSecret, isOffer bool, TTL time.Duration) error {

	if len(obfuscationSecret) != prng.SEED_LENGTH {
		return errors.TraceNew("unexpected obfuscation secret length")
	}

	var baseSeed prng.Seed
	copy(baseSeed[:], obfuscationSecret[:])

	salt := "inproxy-client-DTLS-seed"
	if !isOffer {
		salt = "inproxy-proxy-DTLS-seed"
	}

	seed, err := prng.NewSaltedSeed(&baseSeed, salt)
	if err != nil {
		return errors.Trace(err)
	}

	if TTL <= 0 {
		TTL = lrucache.DefaultExpiration
	}

	// In the case where a previously used local port number is reused in a
	// new dial, this will replace the previous seed.

	dtlsSeedCache.Set(conn.LocalAddr().String(), seed, TTL)

	return nil
}

// GetDTLSSeed fetches a seed established by SetDTLSSeed, or returns an error
// if no seed is found for the specified conn.
func GetDTLSSeed(conn *net.UDPConn) (*prng.Seed, error) {
	seed, ok := dtlsSeedCache.Get(conn.LocalAddr().String())
	if !ok {
		return nil, errors.TraceNew("missing seed")
	}
	return seed.(*prng.Seed), nil
}

var dtlsSeedCache *lrucache.Cache

func init() {
	dtlsSeedCache = lrucache.NewWithLRU(
		dtlsSeedCacheTTL, 1*time.Minute, dtlsSeedCacheMaxSize)
}
