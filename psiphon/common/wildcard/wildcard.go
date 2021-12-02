/*
 * Copyright (c) 2018, Psiphon Inc.
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

// Package wildcard implements a very simple wildcard matcher which supports
// only the term '*', which matches any sequence of characters. The match
// function, WildcardMatch, both parses the pattern and matches the target;
// there is no compile stage and WildcardMatch can be a drop in replacement
// anywhere a normal string comparison is done.
//
// This package is very similar to and inspired by github.com/ryanuber/go-
// glob, but with performance optimizations; github.com/gobwas/glob offers a
// much richer glob syntax and faster performance for cases where a compiled
// glob state can be maintained.
//
// Performance comparison:
//
// wildcard:
//
// BenchmarkFixedMatch-4               100000000        14.0 ns/op
// BenchmarkPrefixMatch-4               50000000        26.2 ns/op
// BenchmarkSuffixMatch-4               50000000        25.8 ns/op
// BenchmarkMultipleMatch-4             10000000       167 ns/op
//
// github.com/ryanuber/go-glob:
//
// BenchmarkFixedGoGlob-4              30000000         58.3 ns/op
// BenchmarkPrefixGoGlob-4              20000000       106 ns/op
// BenchmarkSuffixGoGlob-4              20000000       105 ns/op
// BenchmarkMultipleGoGlob-4             5000000       270 ns/op
//
// github.com/gobwas/glob with precompile:
//
// BenchmarkFixedGlobPrecompile-4       100000000       14.1 ns/op
// BenchmarkPrefixGlobPrecompile-4      200000000        6.66 ns/op
// BenchmarkSuffixGlobPrecompile-4      200000000        7.31 ns/op
// BenchmarkMultipleGlobPrecompile-4    10000000       151 ns/op
//
// github.com/gobwas/glob with compile-and-match:
//
// BenchmarkFixedGlob-4                   300000      4120 ns/op
// BenchmarkPrefixGlob-4                 1000000      1502 ns/op
// BenchmarkSuffixGlob-4                 1000000      1501 ns/op
// BenchmarkMultipleGlob-4                300000      5203 ns/op
//
package wildcard

import (
	"strings"
)

func Match(pattern, target string) bool {

	wildcard := "*"

	// Pattern and target inputs are advanced as substring matches are found,
	// and each iteration operates on the remaining pattern and target.

	for n := 0; ; n++ {

		if pattern == wildcard {

			// Any remaining target matches the remaining "*" pattern.

			return true
		}

		i := strings.Index(pattern, wildcard)

		if n == 0 {

			// First wildcard.

			if i == -1 {

				// No wildcard, so the target must exactly match the pattern.

				return pattern == target

			} else if i == 0 {

				// For the pattern "*abc...", advance the pattern to search for
				// "abc..."

				pattern = pattern[i+1:]

			} else if i > 0 {

				// For the pattern "a*bc...", the target must begin with "a";
				// advance the target past "a" and advance the pattern to
				// search for "bc..."

				if !strings.HasPrefix(target, pattern[:i]) {
					return false
				}
				target = target[i:]
				pattern = pattern[i+1:]
			}

		} else {

			// After advancing from a previous wildcard.
			//
			// In the following cases, the previous wildcard may match the
			// characters still at the start of the remaining target.

			if i == -1 {

				// No further wildcard, so the remaining target must end in
				// the remaining pattern.

				return strings.HasSuffix(target, pattern)

			} else if i == 0 {

				// If the previous iteration found "**abc...", then "*abc..."
				// is found in this case; advance to search for "abc..."

				pattern = pattern[i+1:]

			} else if i > 0 {

				// For the remaining pattern "a*bc...", the remaining target
				// must contain "a"; advance the target past the first "a"
				// and advance the pattern to search for "bc..."

				j := strings.Index(target, pattern[:i])
				if j == -1 {
					return false
				}
				target = target[j+i:]
				pattern = pattern[i+1:]
			}

		}
	}
}
