/*
 * Copyright (c) 2014, Psiphon Inc.
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
	"bytes"
	"context"
	"encoding/json"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
)

func TestGetStringSlice(t *testing.T) {

	originalSlice := []string{"a", "b", "c"}

	j, err := json.Marshal(originalSlice)
	if err != nil {
		t.Errorf("json.Marshal failed: %s", err)
	}

	var value interface{}

	err = json.Unmarshal(j, &value)
	if err != nil {
		t.Errorf("json.Unmarshal failed: %s", err)
	}

	newSlice, ok := GetStringSlice(value)
	if !ok {
		t.Errorf("GetStringSlice failed")
	}

	if !reflect.DeepEqual(originalSlice, newSlice) {
		t.Errorf("unexpected GetStringSlice output")
	}
}

func TestCompress(t *testing.T) {

	for _, compression := range []int32{CompressionNone, CompressionZlib} {

		originalData := []byte("test data")

		compressedData, err := Compress(compression, originalData)
		if err != nil {
			t.Errorf("Compress failed: %s", err)
		}

		decompressedData, err := Decompress(compression, compressedData)
		if err != nil {
			t.Errorf("Decompress failed: %s", err)
		}

		if !bytes.Equal(originalData, decompressedData) {
			t.Error("decompressed data doesn't match original data")
		}
	}
}

func TestFormatByteCount(t *testing.T) {

	testCases := []struct {
		n              uint64
		expectedOutput string
	}{
		{500, "500B"},
		{1024, "1.0K"},
		{10000, "9.8K"},
		{1024*1024 + 1, "1.0M"},
		{100*1024*1024 + 99999, "100.1M"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.expectedOutput, func(t *testing.T) {
			output := FormatByteCount(testCase.n)
			if output != testCase.expectedOutput {
				t.Errorf("unexpected output: %s", output)
			}
		})
	}
}

func TestSafeParseURL(t *testing.T) {

	invalidURL := "https://invalid url"

	_, err := url.Parse(invalidURL)

	if err == nil {
		t.Error("unexpected parse success")
	}

	if strings.Index(err.Error(), invalidURL) == -1 {
		t.Error("URL not in error string")
	}

	_, err = SafeParseURL(invalidURL)

	if err == nil {
		t.Error("unexpected parse success")
	}

	if strings.Index(err.Error(), invalidURL) != -1 {
		t.Error("URL in error string")
	}
}

func TestSafeParseRequestURI(t *testing.T) {

	invalidURL := "https://invalid url"

	_, err := url.ParseRequestURI(invalidURL)

	if err == nil {
		t.Error("unexpected parse success")
	}

	if strings.Index(err.Error(), invalidURL) == -1 {
		t.Error("URL not in error string")
	}

	_, err = SafeParseRequestURI(invalidURL)

	if err == nil {
		t.Error("unexpected parse success")
	}

	if strings.Index(err.Error(), invalidURL) != -1 {
		t.Error("URL in error string")
	}
}

func TestSleepWithContext(t *testing.T) {

	start := time.Now()
	SleepWithContext(context.Background(), 100*time.Millisecond)
	duration := time.Since(start)
	// Allows for 100-109ms actual elapsed time.
	if duration/time.Millisecond/10 != 10 {
		t.Errorf("unexpected duration: %v", duration)
	}

	start = time.Now()
	ctx, cancelFunc := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancelFunc()
	SleepWithContext(ctx, 50*time.Millisecond)
	duration = time.Since(start)
	if duration/time.Millisecond/10 != 5 {
		t.Errorf("unexpected duration: %v", duration)
	}
}

func TestToRandomCasing(t *testing.T) {
	s := "test.to.random.ascii.casing.aaaa.bbbb.c" // 32 Unicode letters

	seed, err := prng.NewSeed()
	if err != nil {
		t.Errorf("NewPRNG failed: %s", err)
	}

	randomized := ToRandomASCIICasing(s, seed)

	// Note: there's a (1/2)^32 chance that the randomized string has the same
	// casing as the input string.
	if strings.Compare(s, randomized) == 0 {
		t.Errorf("expected random casing")
	}

	if strings.Compare(strings.ToLower(s), strings.ToLower(randomized)) != 0 {
		t.Errorf("expected strings to be identical minus casing")
	}

	replaySameSeed := ToRandomASCIICasing(s, seed)

	if strings.Compare(randomized, replaySameSeed) != 0 {
		t.Errorf("expected randomized string with same seed to be identical")
	}
}
