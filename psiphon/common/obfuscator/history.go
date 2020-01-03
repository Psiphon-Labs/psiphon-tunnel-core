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
	"time"

	lrucache "github.com/cognusion/go-cache-lru"
)

const (
	OBFUSCATE_SEED_HISTORY_TTL         = 24 * time.Hour
	OBFUSCATE_SEED_HISTORY_MAX_ENTRIES = 1000000
)

// SeedHistory maintains a history of recently observed obfuscation seed values.
type SeedHistory struct {
	history *lrucache.Cache
}

// NewSeedHistory creates a new SeedHistory.
func NewSeedHistory() *SeedHistory {

	// TTL and MAX_ENTRIES are tuned to provide an effective history size while
	// bounding the amount of memory that will be used. While a probabilistic
	// data structure such as a Bloom filter would provide a smaller memory
	// footprint, we wish to avoid the associated risk of false positives.

	return &SeedHistory{
		history: lrucache.NewWithLRU(
			OBFUSCATE_SEED_HISTORY_TTL,
			1*time.Minute,
			OBFUSCATE_SEED_HISTORY_MAX_ENTRIES),
	}
}

// AddNew adds a new seed value to the history. If the seed value is already
// in the history, AddNew returns false.
func (s *SeedHistory) AddNew(seed []byte) bool {
	err := s.history.Add(string(seed), true, 0)
	return err == nil
}
