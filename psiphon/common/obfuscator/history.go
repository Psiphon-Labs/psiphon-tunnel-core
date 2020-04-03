/*
 * Copyright (c) 2020, Psiphon Inc.
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

package obfuscator

import (
	"encoding/hex"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	lrucache "github.com/cognusion/go-cache-lru"
)

const (
	HISTORY_SEED_TTL              = 24 * time.Hour
	HISTORY_SEED_MAX_ENTRIES      = 1000000
	HISTORY_CLIENT_IP_TTL         = 2 * time.Minute
	HISTORY_CLIENT_IP_MAX_ENTRIES = 10000
)

// SeedHistory maintains a history of recently observed obfuscation seed values.
// This history is used to identify duplicate seed messages.
//
// As a heurististic to exclude expected duplicates, due to, for example, meek
// retries, the source client IP is retained for comparison for a short
// duration -- long enough to cover meek retries without retaining client
// IPs in memory long past a client connection lifetime.
type SeedHistory struct {
	seedTTL        time.Duration
	seedToTime     *lrucache.Cache
	seedToClientIP *lrucache.Cache
}

type SeedHistoryConfig struct {
	SeedTTL            time.Duration
	SeedMaxEntries     int
	ClientIPTTL        time.Duration
	ClientIPMaxEntries int
}

// NewSeedHistory creates a new SeedHistory. Config is optional.
func NewSeedHistory(config *SeedHistoryConfig) *SeedHistory {

	// Default TTL and MAX_ENTRIES are tuned to provide an effective history size
	// while bounding the amount of memory that will be used. While a
	// probabilistic data structure such as a Bloom filter would provide a
	// smaller memory footprint, we wish to avoid the associated risk of false
	// positives.
	//
	// Limitation: As go-cache-lru does not currently support iterating over all
	// items (without making a full copy of the enture cache), the client IP with
	// shorter TTL is stored in a second, smaller cache instead of the same cache
	// with a a pruner. This incurs some additional overhead, as the seed key is
	// stored twice, once in each cache.

	useConfig := SeedHistoryConfig{
		SeedTTL:            HISTORY_SEED_TTL,
		SeedMaxEntries:     HISTORY_SEED_MAX_ENTRIES,
		ClientIPTTL:        HISTORY_CLIENT_IP_TTL,
		ClientIPMaxEntries: HISTORY_CLIENT_IP_MAX_ENTRIES,
	}

	if config != nil {
		if config.SeedTTL != 0 {
			useConfig.SeedTTL = config.SeedTTL
		}
		if config.SeedMaxEntries != 0 {
			useConfig.SeedMaxEntries = config.SeedMaxEntries
		}
		if config.ClientIPTTL != 0 {
			useConfig.ClientIPTTL = config.ClientIPTTL
		}
		if config.ClientIPMaxEntries != 0 {
			useConfig.ClientIPMaxEntries = config.ClientIPMaxEntries
		}
	}

	return &SeedHistory{
		seedTTL: useConfig.SeedTTL,

		seedToTime: lrucache.NewWithLRU(
			useConfig.SeedTTL,
			1*time.Minute,
			useConfig.SeedMaxEntries),

		seedToClientIP: lrucache.NewWithLRU(
			useConfig.ClientIPTTL,
			30*time.Second,
			useConfig.ClientIPMaxEntries),
	}
}

// AddNew adds a new seed value to the history. If the seed value is already
// in the history, and an expected case such as a meek retry is ruled out (or
// strictMode is on), AddNew returns false.
//
// When a duplicate seed is found, a common.LogFields instance is returned,
// populated with event data. Log fields may be returned in either the false
// or true case.
func (h *SeedHistory) AddNew(
	strictMode bool,
	clientIP string,
	seedType string,
	seed []byte) (bool, *common.LogFields) {

	key := string(seed)

	// Limitation: go-cache-lru does not currently support atomically setting if
	// a key is unset and otherwise _returning the corresponding value_. There is
	// an unlikely possibility that this Add and the following Get don't see the
	// same existing key/value state.

	if h.seedToTime.Add(key, time.Now(), 0) == nil {
		// Seed was not already in cache
		h.seedToClientIP.Set(key, clientIP, 0)
		return true, nil
	}

	previousTime, ok := h.seedToTime.Get(key)
	if !ok {
		// Inconsistent Add/Get state: assume cache item just expired.
		previousTime = h.seedTTL
	}

	logFields := common.LogFields{
		"duplicate_seed":            hex.EncodeToString(seed),
		"duplicate_seed_type":       seedType,
		"duplicate_elapsed_time_ms": int64(time.Since(previousTime.(time.Time)) / time.Millisecond),
	}

	previousClientIP, ok := h.seedToClientIP.Get(key)
	if ok {
		if clientIP == previousClientIP.(string) {
			logFields["duplicate_client_ip"] = "equal"
			return !strictMode, &logFields
		} else {
			logFields["duplicate_client_ip"] = "unequal"
			return false, &logFields
		}
	}

	logFields["duplicate_client_ip"] = "unknown"
	return false, &logFields
}
