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
	"strconv"
	"testing"
)

func TestStringLookup(t *testing.T) {

	if stringLookupThreshold != 5 {
		t.Fatalf("unexpected stringLookupThreshold")
	}

	// Short list

	lookup := NewStringLookup([]string{"a", "b", "c"})

	if !lookup.Contains("b") {
		t.Fatal("expected item not found")
	}

	if lookup.Contains("g") {
		t.Fatal("unexpected item found")
	}

	// Long list

	lookup = NewStringLookup([]string{"a", "b", "c", "d", "e", "f"})

	if !lookup.Contains("b") {
		t.Fatal("expected item not found")
	}

	if lookup.Contains("g") {
		t.Fatal("unexpected item found")
	}
}

func TestStringValueLookup(t *testing.T) {

	if stringLookupThreshold != 5 {
		t.Fatalf("unexpected stringLookupThreshold")
	}

	// Short list

	lookup, err := NewStringValueLookup(
		[]string{"a", "b", "c"},
		[]int{1, 2, 3})
	if err != nil {
		t.Fatalf("NewStringValueLookup failed: %v", err)
	}

	value, ok := lookup.Get("b")
	if !ok || value != 2 {
		t.Fatal("expected item not found")
	}

	_, ok = lookup.Get("g")
	if ok {
		t.Fatal("unexpected item found")
	}

	// Long list

	lookup, err = NewStringValueLookup(
		[]string{"a", "b", "c", "d", "e", "f"},
		[]int{1, 2, 3, 4, 5, 6})
	if err != nil {
		t.Fatalf("NewStringValueLookup failed: %v", err)
	}

	value, ok = lookup.Get("b")
	if !ok || value != 2 {
		t.Fatal("expected item not found")
	}

	_, ok = lookup.Get("g")
	if ok {
		t.Fatal("unexpected item found")
	}

	// Invalid input

	_, err = NewStringValueLookup(
		[]string{"a", "b"},
		[]int{1})
	if err == nil {
		t.Fatal("expected error")
	}
}

// BenchmarkStringLookupThreshold compares explicit slice and map lookups for
// string set membership:
//
// BenchmarkStringLookupThreshold/1/slice-24   621419152   1.753 ns/op
// BenchmarkStringLookupThreshold/1/map-24     203286823   5.783 ns/op
// BenchmarkStringLookupThreshold/2/slice-24   276744469   4.318 ns/op
// BenchmarkStringLookupThreshold/2/map-24     198714043   6.153 ns/op
// BenchmarkStringLookupThreshold/3/slice-24   202580096   5.988 ns/op
// BenchmarkStringLookupThreshold/3/map-24     172023608   6.977 ns/op
// BenchmarkStringLookupThreshold/4/slice-24   160556595   7.356 ns/op
// BenchmarkStringLookupThreshold/4/map-24     170483857   7.069 ns/op
// BenchmarkStringLookupThreshold/5/slice-24   134401921   8.829 ns/op
// BenchmarkStringLookupThreshold/5/map-24     148379280   7.360 ns/op
// BenchmarkStringLookupThreshold/6/slice-24   100000000  10.28 ns/op
// BenchmarkStringLookupThreshold/6/map-24     150823329   7.870 ns/op
// BenchmarkStringLookupThreshold/7/slice-24    96649803  11.89 ns/op
// BenchmarkStringLookupThreshold/7/map-24     147167034   7.980 ns/op
// BenchmarkStringLookupThreshold/8/slice-24    91328829  13.19 ns/op
// BenchmarkStringLookupThreshold/8/map-24     144020220   8.523 ns/op
// BenchmarkStringLookupThreshold/9/slice-24    77003080  14.89 ns/op
// BenchmarkStringLookupThreshold/9/map-24     193728640   7.090 ns/op
// BenchmarkStringLookupThreshold/10/slice-24   74999019  16.30 ns/op
// BenchmarkStringLookupThreshold/10/map-24    171881683   6.392 ns/op
//
// The threshold of 5 is used since slice lookup at 5 is almost as fast as 4
// and uses less memory than a map.
func BenchmarkStringLookupThreshold(b *testing.B) {
	for size := 1; size <= 10; size++ {
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			items := make([]string, size)
			for i := range items {
				items[i] = strconv.Itoa(i)
			}

			target := strconv.Itoa(size - 1)

			b.Run("slice", func(b *testing.B) {
				b.ResetTimer()

				for i := 0; i < b.N; i++ {
					Contains(items, target)
				}
			})

			b.Run("map", func(b *testing.B) {
				lookup := make(map[string]struct{}, len(items))
				for _, item := range items {
					lookup[item] = struct{}{}
				}

				b.ResetTimer()

				for i := 0; i < b.N; i++ {
					_, _ = lookup[target]
				}
			})
		})
	}
}

// BenchmarkStringValueLookupThreshold compares explicit slice and map lookups
// for string-keyed int values:
//
// BenchmarkStringValueLookupThreshold/1/slice-24   615814766   1.742 ns/op
// BenchmarkStringValueLookupThreshold/1/map-24     205255656   5.826 ns/op
// BenchmarkStringValueLookupThreshold/2/slice-24   277585812   4.319 ns/op
// BenchmarkStringValueLookupThreshold/2/map-24     198539451   6.047 ns/op
// BenchmarkStringValueLookupThreshold/3/slice-24   204164994   5.872 ns/op
// BenchmarkStringValueLookupThreshold/3/map-24     181355518   6.692 ns/op
// BenchmarkStringValueLookupThreshold/4/slice-24   161289120   7.277 ns/op
// BenchmarkStringValueLookupThreshold/4/map-24     171215845   6.896 ns/op
// BenchmarkStringValueLookupThreshold/5/slice-24   137768595   8.631 ns/op
// BenchmarkStringValueLookupThreshold/5/map-24     164473335   7.350 ns/op
// BenchmarkStringValueLookupThreshold/6/slice-24   100000000  10.17 ns/op
// BenchmarkStringValueLookupThreshold/6/map-24     160589246   7.489 ns/op
// BenchmarkStringValueLookupThreshold/7/slice-24   100000000  11.50 ns/op
// BenchmarkStringValueLookupThreshold/7/map-24     154226338   7.841 ns/op
// BenchmarkStringValueLookupThreshold/8/slice-24    92986017  12.99 ns/op
// BenchmarkStringValueLookupThreshold/8/map-24     148890540   8.105 ns/op
// BenchmarkStringValueLookupThreshold/9/slice-24    83703896  14.82 ns/op
// BenchmarkStringValueLookupThreshold/9/map-24     185361762   6.284 ns/op
// BenchmarkStringValueLookupThreshold/10/slice-24   73670662  15.95 ns/op
// BenchmarkStringValueLookupThreshold/10/map-24    186481200   8.970 ns/op
//
// The threshold of 5 is used since slice lookup at 5 is close to the 4-item
// crossover point and uses less memory than a map for smaller lists.
func BenchmarkStringValueLookupThreshold(b *testing.B) {
	for size := 1; size <= 10; size++ {
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			keys := make([]string, size)
			values := make([]int, size)
			for i := range keys {
				keys[i] = strconv.Itoa(i)
				values[i] = i
			}

			target := strconv.Itoa(size - 1)

			b.Run("slice", func(b *testing.B) {
				b.ResetTimer()

				for i := 0; i < b.N; i++ {
					for j, key := range keys {
						if key == target {
							_ = values[j]
							break
						}
					}
				}
			})

			b.Run("map", func(b *testing.B) {
				lookup := make(map[string]int, len(keys))
				for i, key := range keys {
					lookup[key] = values[i]
				}

				b.ResetTimer()

				for i := 0; i < b.N; i++ {
					_, _ = lookup[target]
				}
			})
		})
	}
}
