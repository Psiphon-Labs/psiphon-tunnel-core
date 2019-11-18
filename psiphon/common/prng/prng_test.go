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

package prng

import (
	"bytes"
	crypto_rand "crypto/rand"
	"fmt"
	"math"
	"math/big"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestSeed(t *testing.T) {

	seed, err := NewSeed()
	if err != nil {
		t.Fatalf("NewSeed failed: %s", err)
	}

	prng1 := NewPRNGWithSeed(seed)
	prng2 := NewPRNGWithSeed(seed)

	for i := 1; i < 10000; i++ {

		bytes1 := make([]byte, i)
		prng1.Read(bytes1)

		bytes2 := make([]byte, i)
		prng2.Read(bytes2)

		zeroes := make([]byte, i)
		if bytes.Equal(zeroes, bytes1) {
			t.Fatalf("unexpected zero bytes")
		}

		if !bytes.Equal(bytes1, bytes2) {
			t.Fatalf("unexpected different bytes")
		}
	}

	prng1 = NewPRNGWithSeed(seed)

	prng3, err := NewPRNGWithSaltedSeed(seed, "3")
	if err != nil {
		t.Fatalf("NewPRNGWithSaltedSeed failed: %s", err)
	}

	prng4, err := NewPRNGWithSaltedSeed(seed, "4")
	if err != nil {
		t.Fatalf("NewPRNGWithSaltedSeed failed: %s", err)
	}

	for i := 1; i < 10000; i++ {

		bytes1 := make([]byte, i)
		prng1.Read(bytes1)

		bytes3 := make([]byte, i)
		prng3.Read(bytes3)

		bytes4 := make([]byte, i)
		prng4.Read(bytes4)

		if bytes.Equal(bytes1, bytes3) {
			t.Fatalf("unexpected identical bytes")
		}

		if bytes.Equal(bytes3, bytes4) {
			t.Fatalf("unexpected identical bytes")
		}
	}
}

func TestFlipWeightedCoin(t *testing.T) {

	runs := 100000
	tolerance := 1000

	testCases := []struct {
		weight        float64
		expectedTrues int
	}{
		{0.333, runs / 3},
		{0.5, runs / 2},
		{1.0, runs},
		{0.0, 0},
	}

	for _, testCase := range testCases {
		t.Run(fmt.Sprintf("%f", testCase.weight), func(t *testing.T) {

			p, err := NewPRNG()
			if err != nil {
				t.Fatalf("NewPRNG failed: %s", err)
			}

			trues := 0
			for i := 0; i < runs; i++ {
				if p.FlipWeightedCoin(testCase.weight) {
					trues++
				}
			}

			min := testCase.expectedTrues - tolerance
			if min < 0 {
				min = 0
			}
			max := testCase.expectedTrues + tolerance

			if trues < min || trues > max {
				t.Errorf("unexpected coin flip outcome: %f %d (+/-%d) %d",
					testCase.weight, testCase.expectedTrues, tolerance, trues)
			}
		})
	}
}

func TestPerm(t *testing.T) {

	p, err := NewPRNG()
	if err != nil {
		t.Fatalf("NewPRNG failed: %s", err)
	}

	for n := 0; n < 1000; n++ {

		perm := p.Perm(n)
		if len(perm) != n {
			t.Error("unexpected permutation size")
		}

		sum := 0
		for i := 0; i < n; i++ {
			sum += perm[i]
		}

		expectedSum := (n * (n - 1)) / 2
		if sum != expectedSum {
			t.Error("unexpected permutation")
		}
	}
}

func TestRange(t *testing.T) {

	p, err := NewPRNG()
	if err != nil {
		t.Fatalf("NewPRNG failed: %s", err)
	}

	min := 1
	max := 19
	var gotMin, gotMax bool
	for n := 0; n < 1000; n++ {

		i := p.Range(min, max)

		if i < min || i > max {
			t.Error("out of range")
		}

		if i == min {
			gotMin = true
		}
		if i == max {
			gotMax = true
		}
	}

	if !gotMin {
		t.Error("missing min")
	}
	if !gotMax {
		t.Error("missing max")
	}
}

func TestPeriod(t *testing.T) {

	p, err := NewPRNG()
	if err != nil {
		t.Fatalf("NewPRNG failed: %s", err)
	}

	min := 1 * time.Nanosecond
	max := 10000 * time.Nanosecond

	different := 0

	for n := 0; n < 1000; n++ {

		res1 := p.Period(min, max)

		if res1 < min {
			t.Error("duration should not be less than min")
		}

		if res1 > max {
			t.Error("duration should not be more than max")
		}

		res2 := p.Period(min, max)

		if res1 != res2 {
			different += 1
		}
	}

	// res1 and res2 should be different most of the time, but it's possible
	// to get the same result twice in a row.
	if different < 900 {
		t.Error("duration insufficiently random")
	}
}

func TestJitter(t *testing.T) {

	testCases := []struct {
		n           int64
		factor      float64
		expectedMin int64
		expectedMax int64
	}{
		{100, 0.1, 90, 110},
		{1000, 0.3, 700, 1300},
	}

	for _, testCase := range testCases {
		t.Run(fmt.Sprintf("Jitter case: %+v", testCase), func(t *testing.T) {

			p, err := NewPRNG()
			if err != nil {
				t.Fatalf("NewPRNG failed: %s", err)
			}

			min := int64(math.MaxInt64)
			max := int64(0)

			for i := 0; i < 100000; i++ {

				x := p.Jitter(testCase.n, testCase.factor)
				if x < min {
					min = x
				}
				if x > max {
					max = x
				}
			}

			if min != testCase.expectedMin {
				t.Errorf("unexpected minimum jittered value: %d", min)
			}

			if max != testCase.expectedMax {
				t.Errorf("unexpected maximum jittered value: %d", max)
			}
		})
	}
}

func TestIntn(t *testing.T) {

	p, err := NewPRNG()
	if err != nil {
		t.Fatalf("NewPRNG failed: %s", err)
	}

	for max := 0; max <= 255; max++ {

		counts := make(map[int]int)
		repeats := 200000

		for r := 0; r < repeats; r++ {
			value := p.Intn(max)
			if value < 0 || value > max {
				t.Fatalf("unexpected value: max = %d, value = %d", max, value)
			}
			counts[value] += 1
		}

		expected := repeats / (max + 1)

		for i := 0; i < max; i++ {
			if counts[i] < (expected/10)*8 {
				t.Logf("max = %d, counts = %+v", max, counts)
				t.Fatalf("unexpected low count: max = %d, i = %d, count = %d", max, i, counts[i])
			}
		}
	}
}

func TestExpFloat64Range(t *testing.T) {

	testCases := []struct {
		min, max, lambda float64
		factor           int
	}{
		{1.0, 3.0, 2.0, 5},
		{0.0, 1.0, 2.0, 5},
		{-2.0, -1.0, 2.0, 5},
	}

	for _, testCase := range testCases {
		t.Run(fmt.Sprintf("ExpFloat64Range case: %+v", testCase), func(t *testing.T) {

			p, err := NewPRNG()
			if err != nil {
				t.Fatalf("NewPRNG failed: %s", err)
			}

			buckets := make(map[float64]int)

			for i := 0; i < 100000; i++ {

				value := p.ExpFloat64Range(testCase.min, testCase.max, testCase.lambda)

				if value < testCase.min || value > testCase.max {
					t.Fatalf(
						"unexpected value: %f [%f, %f]", value, testCase.min, testCase.max)
				}

				buckets[float64(int(10.0*(value)))/10.0] += 1
			}

			keys := make([]float64, 0)
			for k := range buckets {
				keys = append(keys, k)
			}

			sort.Float64s(keys)

			strs := make([]string, 0)
			for _, k := range keys {
				strs = append(strs, fmt.Sprintf("%0.2f: %d", k, buckets[k]))
			}

			t.Logf(strings.Join(strs, ","))

			for i := 0; i < len(keys)-1; i++ {
				if buckets[keys[i]] <= buckets[keys[i+1]] {
					t.Fatalf("unexpected distribution")
				}
			}

			// First bucket should have at least "factor" times more items than last
			// bucket.
			if buckets[keys[0]]/buckets[keys[len(keys)-1]] < testCase.factor {
				t.Fatalf("unexpected distribution")
			}

		})
	}
}

//lint:ignore U1000 intentionally unused
func Disabled_TestRandomStreamLimit(t *testing.T) {

	// This test takes up to ~2 minute to complete, so it's disabled by default.

	p, err := NewPRNG()
	if err != nil {
		t.Fatalf("NewPRNG failed: %s", err)
	}

	// Use large blocks to get close to the key stream limit.

	var b [2 * 1024 * 1024 * 1024]byte
	n := int64(0)

	for i := 0; i < 127; i++ {
		p.Read(b[:])
		n += int64(len(b))
	}

	// Stop using large blocks 64 bytes short of the limit, 2^38-64.

	p.Read(b[0 : len(b)-128])
	n += int64(len(b) - 128)

	// Invoke byte at a time across the limit boundary to ensure we
	// don't jump over the limit case.

	for i := 0; i < 192; i++ {
		p.Read(b[0:1])
		n += int64(1)
	}
}

func BenchmarkIntn(b *testing.B) {

	p, err := NewPRNG()
	if err != nil {
		b.Fatalf("NewPRNG failed: %s", err)
	}

	max := 255

	b.Run("PRNG", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			_ = p.Intn(n % max)
		}
	})

	b.Run("getrandom()", func(b *testing.B) {
		for n := 0; n < b.N; n++ {

			_, err := crypto_rand.Int(crypto_rand.Reader, big.NewInt(int64(max)))
			if err != nil {
				b.Fatalf("crypto_rand.Int failed: %s", err)
			}
		}
	})
}
