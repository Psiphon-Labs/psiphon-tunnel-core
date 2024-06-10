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

package parameters

import (
	"encoding/base64"
	"testing"
)

func TestTransferURLs(t *testing.T) {

	decodedA := "a.example.com"
	encodedA := base64.StdEncoding.EncodeToString([]byte(decodedA))
	encodedB := base64.StdEncoding.EncodeToString([]byte("b.example.com"))
	encodedC := base64.StdEncoding.EncodeToString([]byte("c.example.com"))

	testCases := []struct {
		description                string
		transferURLs               TransferURLs
		attempts                   int
		expectedValid              bool
		expectedCanonicalURL       string
		expectedDistinctSelections int
	}{
		{
			"missing OnlyAfterAttempts = 0",
			TransferURLs{
				{
					URL:               encodedA,
					OnlyAfterAttempts: 1,
				},
			},
			1,
			false,
			decodedA,
			0,
		},
		{
			"single URL, multiple attempts",
			TransferURLs{
				{
					URL:               encodedA,
					OnlyAfterAttempts: 0,
				},
			},
			2,
			true,
			decodedA,
			1,
		},
		{
			"multiple URLs, single attempt",
			TransferURLs{
				{
					URL:               encodedA,
					OnlyAfterAttempts: 0,
				},
				{
					URL:               encodedB,
					OnlyAfterAttempts: 1,
				},
				{
					URL:               encodedC,
					OnlyAfterAttempts: 1,
				},
			},
			1,
			true,
			decodedA,
			1,
		},
		{
			"multiple URLs, multiple attempts",
			TransferURLs{
				{
					URL:               encodedA,
					OnlyAfterAttempts: 0,
				},
				{
					URL:               encodedB,
					OnlyAfterAttempts: 1,
				},
				{
					URL:               encodedC,
					OnlyAfterAttempts: 1,
				},
			},
			2,
			true,
			decodedA,
			3,
		},
		{
			"multiple URLs, multiple attempts",
			TransferURLs{
				{
					URL:               encodedA,
					OnlyAfterAttempts: 0,
				},
				{
					URL:               encodedB,
					OnlyAfterAttempts: 1,
				},
				{
					URL:               encodedC,
					OnlyAfterAttempts: 3,
				},
			},
			4,
			true,
			decodedA,
			3,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.description, func(t *testing.T) {

			err := testCase.transferURLs.DecodeAndValidate()

			if testCase.expectedValid {
				if err != nil {
					t.Fatalf("unexpected validation error: %s", err)
				}
			} else {
				if err == nil {
					t.Fatalf("expected validation error")
				}
				return
			}

			// Track distinct selections for each attempt; the
			// expected number of distinct should be for at least
			// one particular attempt.
			attemptDistinctSelections := make(map[int]map[string]int)
			for i := 0; i < testCase.attempts; i++ {
				attemptDistinctSelections[i] = make(map[string]int)
			}

			// Perform enough runs to account for random selection.
			runs := 1000

			attempt := 0
			for i := 0; i < runs; i++ {
				canonicalURL := testCase.transferURLs.CanonicalURL()
				if canonicalURL != testCase.expectedCanonicalURL {
					t.Fatalf("unexpected canonical URL: %s", canonicalURL)
				}
				transferUrl := testCase.transferURLs.Select(attempt)
				if transferUrl.SkipVerify {
					t.Fatalf("unexpected skipVerify")
				}
				attemptDistinctSelections[attempt][transferUrl.URL] += 1
				attempt = (attempt + 1) % testCase.attempts
			}

			maxDistinctSelections := 0
			for _, m := range attemptDistinctSelections {
				if len(m) > maxDistinctSelections {
					maxDistinctSelections = len(m)
				}
			}

			if maxDistinctSelections != testCase.expectedDistinctSelections {
				t.Fatalf("got %d distinct selections, expected %d",
					maxDistinctSelections,
					testCase.expectedDistinctSelections)
			}
		})
	}

}
