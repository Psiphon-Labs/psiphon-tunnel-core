/*
 * Copyright (c) 2019, Psiphon Inc.
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

package parameters

import (
	"encoding/json"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
)

// KeyValues represents a set of name/JSON pairs.
type KeyValues map[string]json.RawMessage

// Validate checks that the JSON values are well-formed.
func (keyValues KeyValues) Validate() error {
	for _, value := range keyValues {
		var v interface{}
		err := json.Unmarshal(value, &v)
		if err != nil {
			return errors.Trace(err)
		}
	}
	return nil
}

// KeyStrings represents a set of key/strings pairs.
type KeyStrings map[string][]string

// Validates that the keys and values are well formed.
func (keyStrings KeyStrings) Validate() error {
	// Always succeeds because KeyStrings is generic and does not impose any
	// restrictions on keys/values. Consider imposing limits like maximum
	// map/array/string sizes.
	return nil
}

// KeyDurations represents a set of key/duration pairs.
type KeyDurations map[string]string

// Validates that the keys and durations are well formed.
func (keyDurations KeyDurations) Validate() error {
	for _, value := range keyDurations {
		_, err := time.ParseDuration(value)
		if err != nil {
			return errors.Trace(err)
		}
	}
	return nil
}
