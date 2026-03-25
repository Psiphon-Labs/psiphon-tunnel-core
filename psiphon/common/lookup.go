/*
 * Copyright (c) 2026, Psiphon Inc.
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
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
)

// StringLookup provides a simple string list lookup. The underlying data
// structure is selected for optimal performance based on the size of the
// input.
type StringLookup struct {
	list   []string
	lookup map[string]struct{}
}

// For small lists, a linear slice search is faster and uses less memory. For
// larger lists, a map lookup is faster. See benchmark tests.
const stringLookupThreshold = 5

// NewStringLookup initializes a new StringLookup. No reference to the input
// slice is retained. Input list entries are assumed to be unique.
func NewStringLookup(list []string) StringLookup {
	if len(list) >= stringLookupThreshold {
		lookup := make(map[string]struct{}, len(list))
		for _, item := range list {
			lookup[item] = struct{}{}
		}
		return StringLookup{lookup: lookup}
	} else {
		return StringLookup{list: append([]string(nil), list...)}
	}
}

// Contains indicates if the target is in the list.
func (lookup StringLookup) Contains(target string) bool {
	if lookup.lookup != nil {
		_, ok := lookup.lookup[target]
		return ok
	}
	return Contains(lookup.list, target)
}

// StringValueLookup provides a simple string key/value lookup. The underlying
// data structure is selected for optimal performance based on the size of
// the input.
type StringValueLookup[T any] struct {
	keys   []string
	values []T
	lookup map[string]T
}

// NewStringValueLookup initializes a new StringValueLookup. No reference to
// the input slices are retained. Input keys are assumed to be unique; it's
// the caller's responsibility to ensure this is the case.
func NewStringValueLookup[T any](
	keys []string,
	values []T) (StringValueLookup[T], error) {

	var lookup StringValueLookup[T]

	if len(keys) != len(values) {
		return lookup, errors.TraceNew("invalid input")
	}
	if len(keys) >= stringLookupThreshold {

		lookup.lookup = make(map[string]T, len(keys))
		for i, key := range keys {
			lookup.lookup[key] = values[i]
		}

	} else {

		for i, key := range keys {
			lookup.keys = append(lookup.keys, key)
			lookup.values = append(lookup.values, values[i])
		}
	}

	return lookup, nil
}

// Get returns the value for the given key, if found.
func (lookup StringValueLookup[T]) Get(key string) (T, bool) {
	if lookup.lookup != nil {
		value, ok := lookup.lookup[key]
		return value, ok
	}
	for i, candidateKey := range lookup.keys {
		if candidateKey == key {
			return lookup.values[i], true
		}
	}
	var zero T
	return zero, false
}
