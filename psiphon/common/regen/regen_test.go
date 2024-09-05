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
	"math/rand"
	"os"
	"regexp"
	"regexp/syntax"
	"strings"
	"testing"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
)

const (
	// Each expression is generated and validated this many times.
	SampleSize = 999

	// Arbitrary limit in the standard package.
	// See https://golang.org/src/regexp/syntax/parse.go?s=18885:18935#L796
	MaxSupportedRepeatCount = 1000
)

func ExampleGenerateString() {
	pattern := "[ab]{5}"
	bytes, _ := GenerateString(pattern)

	if matched, _ := regexp.MatchString(pattern, string(bytes)); matched {
		fmt.Println("Matches!")
	}

	// Output:
	// Matches!
}

func ExampleNewGenerator() {
	pattern := "[ab]{5}"

	// Note that this uses a constant seed, so the generated string
	// will always be the same across different runs of the program.
	// Use a more random seed for real use (e.g. time-based).
	generator, _ := NewGenerator(pattern, &GeneratorArgs{
		RngSource: rand.NewSource(0),
	})

	bytes, err := generator.Generate()
	if err != nil {
		fmt.Println(err)
		return
	}

	if matched, _ := regexp.MatchString(pattern, string(bytes)); matched {
		fmt.Println("Matches!")
	}

	// Output:
	// Matches!
}

func ExampleNewGenerator_perl() {
	pattern := `\d{5}`

	generator, _ := NewGenerator(pattern, &GeneratorArgs{
		Flags: syntax.Perl,
	})

	bytes, err := generator.Generate()
	if err != nil {
		fmt.Println(err)
		return
	}

	if matched, _ := regexp.MatchString("[[:digit:]]{5}", string(bytes)); matched {
		fmt.Println("Matches!")
	}
	// Output:
	// Matches!
}

func ExampleCaptureGroupHandler() {
	pattern := `Hello, (?P<firstname>[A-Z][a-z]{2,10}) (?P<lastname>[A-Z][a-z]{2,10})`

	generator, _ := NewGenerator(pattern, &GeneratorArgs{
		Flags: syntax.Perl,
		CaptureGroupHandler: func(index int, name string, group *syntax.Regexp, generator Generator, args *GeneratorArgs) ([]byte, error) {
			value, err := generator.Generate()
			if err != nil {
				return nil, err
			}
			if name == "firstname" {
				return []byte(fmt.Sprintf("FirstName (e.g. %s)", string(value))), nil
			}
			return []byte(fmt.Sprintf("LastName (e.g. %s)", string(value))), nil
		},
	})

	// Print to stderr since we're generating random output and can't assert equality.
	value, err := generator.Generate()
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Fprintln(os.Stderr, value)

	// Needed for "go test" to run this example. (Must be a blank line before.)

	// Output:
}

func TestGeneratorArgs(t *testing.T) {
	t.Parallel()

	t.Run("Handle empty struct", func(t *testing.T) {
		shouldNotPanic(t, func() {
			args := GeneratorArgs{}

			err := args.initialize()
			if err != nil {
				t.Fatal(err)
			}
		})
	})

	t.Run("Unicode groups not supported", func(t *testing.T) {
		args := &GeneratorArgs{
			Flags: syntax.UnicodeGroups,
		}

		err := args.initialize()
		if err == nil {
			t.Fatal("expected error")
		}
		if err.Error() != "UnicodeGroups not supported" {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("Error if repeat bounds are invalid", func(t *testing.T) {
		args := &GeneratorArgs{
			MinUnboundedRepeatCount: 2,
			MaxUnboundedRepeatCount: 1,
		}

		err := args.initialize()
		if err.Error() != "MinUnboundedRepeatCount(2) > MaxUnboundedRepeatCount(1)" {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("Allow equal repeat bounds", func(t *testing.T) {
		args := &GeneratorArgs{
			MinUnboundedRepeatCount: 1,
			MaxUnboundedRepeatCount: 1,
		}

		shouldNotPanic(t, func() {
			err := args.initialize()
			if err != nil {
				t.Fatal(err)
			}
		})
	})

	t.Run("Rng", func(t *testing.T) {

		t.Run("Error if called before initialize", func(t *testing.T) {
			args := &GeneratorArgs{}

			_, err := args.Rng()
			if err == nil {
				t.Fatal("expected error")
			}
		})

		t.Run("Non-nil after initialize", func(t *testing.T) {
			args := GeneratorArgs{}
			err := args.initialize()
			if err != nil {
				t.Fatal(err)
			}
			rng, err := args.Rng()
			if err != nil {
				t.Fatal(err)
			}
			if rng == nil {
				t.Fatal("expected non-nil")
			}
		})

	})
}

func TestNewGenerator(t *testing.T) {
	t.Parallel()

	t.Run("Handles nil GeneratorArgs", func(t *testing.T) {
		generator, err := NewGenerator("", nil)
		if generator == nil {
			t.Fatal("expected non-nil")
		}
		if err != nil {
			t.Fatal(err)
		}
	})

	t.Run("Handles empty GeneratorArgs", func(t *testing.T) {
		generator, err := NewGenerator("", &GeneratorArgs{})
		if generator == nil {
			t.Fatal("expected non-nil")
		}
		if err != nil {
			t.Fatal(err)
		}
	})

	t.Run("Forwards errors from arsg initialization", func(t *testing.T) {
		args := &GeneratorArgs{
			Flags: syntax.UnicodeGroups,
		}

		_, err := NewGenerator("", args)
		if err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestGenEmpty(t *testing.T) {
	t.Parallel()

	args := &GeneratorArgs{
		RngSource: rand.NewSource(0),
	}

	testGeneratesStringMatching(t, args, "", "^$")
}

func TestGenLiterals(t *testing.T) {
	t.Parallel()

	testGeneratesStringMatchingItself(t, nil,
		"a",
		"abc",
	)
}

func TestGenDotNotNl(t *testing.T) {
	t.Parallel()

	t.Run("DotNotNl", func(t *testing.T) {
		testGeneratesStringMatchingItself(t, nil, ".")
	})

	t.Run("No newlines are generated", func(t *testing.T) {
		generator, _ := NewGenerator(".", nil)

		// Not a very strong assertion, but not sure how to do better. Exploring the entire
		// generation space (2^32) takes far too long for a unit test.
		for i := 0; i < SampleSize; i++ {
			value, err := generator.Generate()
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(value), "\n") {
				t.Fatalf("unexpected newline in %q", value)
			}
		}
	})

}

func TestGenStringStartEnd(t *testing.T) {
	t.Parallel()

	args := &GeneratorArgs{
		RngSource: rand.NewSource(0),
		Flags:     0,
	}

	testGeneratesStringMatching(t, args, "^abc$", "^abc$")
	testGeneratesStringMatching(t, args, "$abc^", "^abc$")
	testGeneratesStringMatching(t, args, "a^b$c", "^abc$")
}

func TestGenQuestionMark(t *testing.T) {
	t.Parallel()

	testGeneratesStringMatchingItself(t, nil,
		"a?",
		"(abc)?",
		"[ab]?",
		".?",
	)
}

func TestGenPlus(t *testing.T) {
	t.Parallel()

	testGeneratesStringMatchingItself(t, nil, "a+")
}

func TestGenStar(t *testing.T) {
	t.Parallel()

	t.Run("HitsDefaultMin", func(t *testing.T) {
		regexp := "a*"
		args := &GeneratorArgs{
			RngSource: rand.NewSource(0),
		}
		counts := generateLenHistogram(regexp, DefaultMaxUnboundedRepeatCount, args)

		if counts[0] == 0 {
			t.Fatalf("count should be > 0")
		}
	})

	t.Run("HitsCustomMin", func(t *testing.T) {
		regexp := "a*"
		args := &GeneratorArgs{
			RngSource:               rand.NewSource(0),
			MinUnboundedRepeatCount: 200,
		}
		counts := generateLenHistogram(regexp, DefaultMaxUnboundedRepeatCount, args)

		if counts[200] == 0 {
			t.Fatalf("count should be > 0")
		}
		for i := 0; i < 200; i++ {
			if counts[i] != 0 {
				t.Fatalf("count should be 0")
			}
		}
	})

	t.Run("HitsDefaultMax", func(t *testing.T) {
		regexp := "a*"
		args := &GeneratorArgs{
			RngSource: rand.NewSource(0),
		}
		counts := generateLenHistogram(regexp, DefaultMaxUnboundedRepeatCount, args)

		if len(counts) != DefaultMaxUnboundedRepeatCount+1 {
			t.Fatalf("count should be %d", DefaultMaxUnboundedRepeatCount+1)
		}
		if counts[DefaultMaxUnboundedRepeatCount] == 0 {
			t.Fatalf("count should be > 0")
		}
	})

	t.Run("HitsCustomMax", func(t *testing.T) {
		regexp := "a*"
		args := &GeneratorArgs{
			RngSource:               rand.NewSource(0),
			MaxUnboundedRepeatCount: 200,
		}
		counts := generateLenHistogram(regexp, 200, args)

		if len(counts) != 201 {
			t.Fatalf("count should be 201")
		}
		if counts[200] == 0 {
			t.Fatalf("count should be > 0")
		}
	})
}

func TestGenCharClassNotNl(t *testing.T) {
	t.Parallel()

	testGeneratesStringMatchingItself(t, nil,
		"[a]",
		"[abc]",
		"[a-d]",
		"[ac]",
		"[0-9]",
		"[a-z0-9]",
	)

	t.Run("No newlines are generated", func(t *testing.T) {

		generator, _ := NewGenerator("[^a-zA-Z0-9]", nil)
		for i := 0; i < SampleSize; i++ {
			value, err := generator.Generate()
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(value), "\n") {
				t.Fatalf("unexpected newline in %q", value)
			}
		}

	})

}

func TestGenNegativeCharClass(t *testing.T) {
	t.Parallel()

	testGeneratesStringMatchingItself(t, nil, "[^a-zA-Z0-9]")
}

func TestGenAlternative(t *testing.T) {
	t.Parallel()

	testGeneratesStringMatchingItself(t, nil,
		"a|b",
		"abc|def|ghi",
		"[ab]|[cd]",
		"foo|bar|baz", // rewrites to foo|ba[rz]
	)
}

func TestGenCapture(t *testing.T) {
	t.Parallel()

	testGeneratesStringMatching(t, nil, "(abc)", "^abc$")
	testGeneratesStringMatching(t, nil, "(a)(b)(c)", "^abc$")
	testGeneratesStringMatching(t, nil, "()", "^$")
}

func TestGenConcat(t *testing.T) {
	t.Parallel()

	testGeneratesStringMatchingItself(t, nil, "[ab][cd]")
}

func TestGenRepeat(t *testing.T) {
	t.Parallel()

	t.Run("Unbounded", func(t *testing.T) {
		testGeneratesStringMatchingItself(t, nil, `a{1,}`)

		t.Run("HitsDefaultMax", func(t *testing.T) {
			regexp := "a{0,}"
			args := &GeneratorArgs{
				RngSource: rand.NewSource(0),
			}
			counts := generateLenHistogram(regexp, DefaultMaxUnboundedRepeatCount, args)

			if len(counts) != DefaultMaxUnboundedRepeatCount+1 {
				t.Fatalf("count should be %d", DefaultMaxUnboundedRepeatCount+1)
			}
			if counts[DefaultMaxUnboundedRepeatCount] == 0 {
				t.Fatalf("count should be > 0")
			}
		})

		t.Run("HitsCustomMax", func(t *testing.T) {
			regexp := "a{0,}"
			args := &GeneratorArgs{
				RngSource:               rand.NewSource(0),
				MaxUnboundedRepeatCount: 200,
			}
			counts := generateLenHistogram(regexp, 200, args)

			if len(counts) != 201 {
				t.Fatalf("count should be 201")
			}
			if counts[200] == 0 {
				t.Fatalf("count should be > 0")
			}
		})
	})

	t.Run("HitsMin", func(t *testing.T) {
		regexp := "a{0,3}"
		args := &GeneratorArgs{
			RngSource: rand.NewSource(0),
		}
		counts := generateLenHistogram(regexp, 3, args)

		if len(counts) != 4 {
			t.Fatalf("count should be 4")
		}
		if counts[0] == 0 {
			t.Fatalf("count should be > 0")
		}
	})

	t.Run("HitsMax", func(t *testing.T) {
		regexp := "a{0,3}"
		args := &GeneratorArgs{
			RngSource: rand.NewSource(0),
		}
		counts := generateLenHistogram(regexp, 3, args)

		if len(counts) != 4 {
			t.Fatalf("count should be 4")
		}
		if counts[3] == 0 {
			t.Fatalf("count should be > 0")
		}
	})

	t.Run("IsWithinBounds", func(t *testing.T) {
		regexp := "a{5,10}"
		args := &GeneratorArgs{
			RngSource: rand.NewSource(0),
		}
		counts := generateLenHistogram(regexp, 10, args)

		if len(counts) != 11 {
			t.Fatalf("count should be 11")
		}

		for i := 0; i < 11; i++ {
			if i < 5 {
				if counts[i] != 0 {
					t.Fatalf("count should be 0")
				}
			} else if i < 11 {
				if counts[i] == 0 {
					t.Fatalf("count should be > 0")
				}
			}
		}
	})

}

func TestGenCharClasses(t *testing.T) {
	t.Parallel()

	t.Run("Ascii", func(t *testing.T) {
		testGeneratesStringMatchingItself(t, nil,
			"[[:alnum:]]",
			"[[:alpha:]]",
			"[[:ascii:]]",
			"[[:blank:]]",
			"[[:cntrl:]]",
			"[[:digit:]]",
			"[[:graph:]]",
			"[[:lower:]]",
			"[[:print:]]",
			"[[:punct:]]",
			"[[:space:]]",
			"[[:upper:]]",
			"[[:word:]]",
			"[[:xdigit:]]",
			"[[:^alnum:]]",
			"[[:^alpha:]]",
			"[[:^ascii:]]",
			"[[:^blank:]]",
			"[[:^cntrl:]]",
			"[[:^digit:]]",
			"[[:^graph:]]",
			"[[:^lower:]]",
			"[[:^print:]]",
			"[[:^punct:]]",
			"[[:^space:]]",
			"[[:^upper:]]",
			"[[:^word:]]",
			"[[:^xdigit:]]",
		)
	})

	t.Run("Perl", func(t *testing.T) {
		args := &GeneratorArgs{
			Flags: syntax.Perl,
		}

		testGeneratesStringMatchingItself(t, args,
			`\d`,
			`\s`,
			`\w`,
			`\D`,
			`\S`,
			`\W`,
		)
	})
}

func TestCaptureGroupHandler(t *testing.T) {
	t.Parallel()

	callCount := 0

	gen, err := NewGenerator(`(?:foo) (bar) (?P<name>baz)`, &GeneratorArgs{
		Flags: syntax.PerlX,
		CaptureGroupHandler: func(index int, name string, group *syntax.Regexp, generator Generator, args *GeneratorArgs) ([]byte, error) {
			callCount++

			if index >= 2 {
				t.Fatalf("index should be < 2")
			}

			if index == 0 {
				if name != "" {
					t.Fatalf("name should be empty")
				}
				if group.String() != "bar" {
					t.Fatalf("group should be 'bar'")
				}
				value, err := generator.Generate()
				if err != nil {
					t.Fatalf("err should be nil")
				}
				if string(value) != "bar" {
					t.Fatalf("value should be 'bar'")
				}
				return []byte("one"), nil
			}

			// Index 1
			if name != "name" {
				t.Fatalf("name should be 'name'")
			}
			if group.String() != "baz" {
				t.Fatalf("group should be 'baz'")
			}
			value, err := generator.Generate()
			if err != nil {
				t.Fatalf("err should be nil")
			}
			if string(value) != "baz" {
				t.Fatalf("value should be 'baz'")
			}
			return []byte("two"), nil
		},
	})
	if err != nil {
		t.Fatalf("err should be nil")
	}

	value, _ := gen.Generate()

	if string(value) != "foo one two" {
		t.Fatalf("value should be 'foo one two'")
	}
	if callCount != 2 {
		t.Fatalf("callCount should be 2")
	}
}

// Byte mode tests

func TestByteModeUniform(t *testing.T) {
	t.Parallel()

	type test struct {
		name         string
		pattern      string
		length       int   // length of generated bytes
		uniformRange []int // [min, max] byte values expected to be unfiformly generated
		flags        syntax.Flags
	}

	tests := []test{
		{name: "any byte not NL", pattern: ".", length: 1},
		{name: "any byte", pattern: ".", length: 1, flags: syntax.MatchNL},
		{name: "class range", pattern: `[\x00-\xff]`, length: 1},
		{name: "class multi range", pattern: `[\x00-\x7f\x80-\xff]`, length: 1},
		{name: "grouping", pattern: `([\x00-\xff])`, length: 1},
		{name: "empty strings", pattern: `^[\x00-\xff]$`, length: 1},
		{name: "exactly 1", pattern: `[\x00-\xff]{1}`, length: 1},
		{name: "exactly 10", pattern: `[\x00-\xff]{10}`, length: 10},
		{name: "repetition 1", pattern: `[\x00-\xff]{1,1}`, length: 1},
		{name: "alteration", pattern: `([[:ascii:]]|[\x80-\xff])`, length: 1},
		{
			name:         "printable ascii",
			pattern:      `[[:print:]]`,
			length:       1,
			uniformRange: []int{' ', '~'},
		},
		{
			name:         "digits",
			pattern:      `[0-9]{5}`,
			length:       5,
			uniformRange: []int{'0', '9'},
		},
		{
			name:         "digits ascii char class",
			pattern:      `[[:digit:]]`,
			length:       1,
			uniformRange: []int{'0', '9'},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			buckets := make([]int, 256)
			iters := 200_000

			rng, err := prng.NewPRNG()
			if err != nil {
				t.Fatal(err)
			}

			gen, err := NewGenerator(tt.pattern, &GeneratorArgs{
				RngSource: rng,
				Flags:     tt.flags,
				ByteMode:  true,
			})

			if err != nil {
				t.Fatal(err)
			}

			for i := 0; i < iters; i++ {
				value, err := gen.Generate()
				if err != nil {
					t.Fatal(err)
				}
				if len(value) != tt.length {
					t.Fatalf("expected length %d, got %d", tt.length, len(value))
				}
				for _, b := range value {
					buckets[int(b)]++
				}
			}

			uniformRange := []int{0, 255}
			if tt.uniformRange != nil {
				if len(tt.uniformRange) != 2 {
					t.Fatal("expected uniformRange to be a slice of length 2")
				}
				uniformRange = tt.uniformRange
			}

			// Checks if generated bytes are uniformly distributed across
			// the buckets in the range uniformBuckets[0] to uniformBuckets[1].
			expectedCount := iters * tt.length / (uniformRange[1] - uniformRange[0] + 1)
			if !isUniform(buckets[uniformRange[0]:uniformRange[1]+1], expectedCount) {
				t.Fatalf("expected uniform distribution: %v", buckets[uniformRange[0]:uniformRange[1]+1])
			}
		})
	}

}

func TestByteModeNegatedClasses(t *testing.T) {
	t.Parallel()

	patterns := []string{
		"[^0-9]",
		"\\P",
		"\\D",
		"\\S",
		"\\W",
		"[^[:ascii:]]",
		"[[:^ascii:]]",
	}

	errStr := "negated character classes are not supported"

	for _, pattern := range patterns {
		gen, err := NewGenerator(pattern, &GeneratorArgs{
			ByteMode: true,
		})
		if gen != nil {
			t.Fatalf("expected error for %s", pattern)
		}
		if err.Error() != errStr {
			t.Fatalf("expected error %q, got %q", errStr, err.Error())
		}
	}
}

func testGeneratesStringMatchingItself(t *testing.T, args *GeneratorArgs, patterns ...string) {
	t.Helper()
	for _, pattern := range patterns {
		t.Run(fmt.Sprintf("String generated from /%s/ matches itself", pattern), func(t *testing.T) {
			err := shouldGenerateStringMatching(pattern, pattern, args)
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func testGeneratesStringMatching(t *testing.T, args *GeneratorArgs, pattern, expectedPattern string) {
	t.Helper()
	t.Run(fmt.Sprintf("String generated from /%s/ matches /%s/", pattern, expectedPattern), func(t *testing.T) {
		err := shouldGenerateStringMatching(pattern, expectedPattern, args)
		if err != nil {
			t.Fatal(err)
		}
	})
}

func shouldGenerateStringMatching(pattern, expectedPattern string, args *GeneratorArgs) error {
	return shouldGenerateStringMatchingTimes(pattern, expectedPattern, args, SampleSize)
}

func shouldGenerateStringMatchingTimes(pattern, expectedPattern string, args *GeneratorArgs, times int) error {

	generator, err := NewGenerator(pattern, args)
	if err != nil {
		panic(err)
	}

	for i := 0; i < times; i++ {
		result, err := generator.Generate()
		if err != nil {
			panic(err)
		}
		matched, err := regexp.MatchString(expectedPattern, string(result))
		if err != nil {
			panic(err)
		}
		if !matched {
			return fmt.Errorf("string “%s” generated from /%s/ did not match /%s/.",
				result, pattern, expectedPattern)
		}
	}

	return nil
}

func generateLenHistogram(regexp string, maxLen int, args *GeneratorArgs) (counts []int) {
	generator, err := NewGenerator(regexp, args)
	if err != nil {
		panic(err)
	}

	iterations := max(maxLen*4, SampleSize)

	for i := 0; i < iterations; i++ {
		value, err := generator.Generate()
		if err != nil {
			panic(err)
		}
		str := string(value)
		// Grow the slice if necessary.
		if len(str) >= len(counts) {
			newCounts := make([]int, len(str)+1)
			copy(newCounts, counts)
			counts = newCounts
		}

		counts[len(str)]++
	}

	return
}

// isUnifrom performs a chi-squared test with 0.025 significance.
// Each bucket in xs is compared against the expected_value.
func isUniform(xs []int, expected_value int) bool {
	critical_squared := float64(25.24) // = 5.024 ^ 2 at 0.025
	for _, x := range xs {
		chi_squared := math.Pow(float64(x-expected_value), 2) / float64(expected_value)
		if chi_squared > critical_squared {
			return false
		}
	}
	return true
}

func max(values ...int) int {
	m := values[0]
	for _, v := range values {
		if v > m {
			m = v
		}
	}
	return m
}

func shouldNotPanic(t *testing.T, f func()) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Error("should not have panicked")
		}
	}()
	f()
}
