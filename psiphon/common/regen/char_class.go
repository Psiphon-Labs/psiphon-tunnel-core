/*
Copyright 2014 Zachary Klippenstein

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

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

package regen

import (
	"fmt"
	"math"
)

// CharClass represents a regular expression character class as a list of ranges.
// The runes contained in the class can be accessed by index.
type tCharClass struct {
	Ranges    []tCharClassRange
	TotalSize int32
}

// CharClassRange represents a single range of characters in a character class.
type tCharClassRange struct {
	Start rune
	Size  int32
}

// NewCharClass creates a character class with a single range.
func newCharClass(start rune, end rune) *tCharClass {
	charRange := newCharClassRange(start, end)
	return &tCharClass{
		Ranges:    []tCharClassRange{charRange},
		TotalSize: charRange.Size,
	}
}

/*
ParseCharClass parses a character class as represented by syntax.Parse into a slice of CharClassRange structs.

Char classes are encoded as pairs of runes representing ranges:
[0-9] = 09, [a0] = aa00 (2 1-len ranges).

e.g.

"[a0-9]" -> "aa09" -> a, 0-9

"[^a-z]" -> "…" -> 0-(a-1), (z+1)-(max rune)
*/
func parseCharClass(runes []rune) *tCharClass {
	var totalSize int32
	numRanges := len(runes) / 2
	ranges := make([]tCharClassRange, numRanges)

	for i := 0; i < numRanges; i++ {
		start := runes[i*2]
		end := runes[i*2+1]

		// indicates a negative class
		if start == 0 {
			// doesn't make sense to generate null bytes, so all ranges must start at
			// no less than 1.
			start = 1
		}

		r := newCharClassRange(start, end)

		ranges[i] = r
		totalSize += r.Size
	}

	return &tCharClass{ranges, totalSize}
}

// parseByteClass parses character classes only for byte values (0-255).
// Returns nil if runes does not contain any byte values.
//
// Note:
// If an end range is greater than 255, it is truncated to 255.
func parseByteClass(runes []rune) *tCharClass {
	var totalSize int32

	var ranges []tCharClassRange
	for i := 0; i < len(runes)-1; i += 2 {
		start := runes[i]
		end := runes[i+1]

		var r tCharClassRange

		if start <= math.MaxUint8 {
			if end > math.MaxUint8 {
				end = math.MaxUint8
			}
			r = newCharClassRange(start, end)
			ranges = append(ranges, r)
			totalSize += r.Size
		}
	}

	if len(ranges) == 0 {
		return nil
	}

	return &tCharClass{ranges, totalSize}
}

// GetRuneAt gets a rune from CharClass as a contiguous array of runes.
func (class *tCharClass) GetRuneAt(i int32) rune {
	for _, r := range class.Ranges {
		if i < r.Size {
			return r.Start + rune(i)
		}
		i -= r.Size
	}
	panic("index out of bounds")
}

func (class *tCharClass) String() string {
	return fmt.Sprintf("%s", class.Ranges)
}

func newCharClassRange(start rune, end rune) tCharClassRange {
	size := end - start + 1

	if size < 1 {
		panic("char class range size must be at least 1")
	}

	return tCharClassRange{
		Start: start,
		Size:  size,
	}
}

func (r tCharClassRange) String() string {
	if r.Size == 1 {
		return fmt.Sprintf("%s:1", runesToUTF8(r.Start))
	}
	return fmt.Sprintf("%s-%s:%d", runesToUTF8(r.Start), runesToUTF8(r.Start+rune(r.Size-1)), r.Size)

}
