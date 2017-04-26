/*
 * Copyright (c) 2017, Psiphon Inc.
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

package server

import (
	"bytes"
	"fmt"
	"math/rand"
	"sync"
	"testing"
	"time"
)

func TestMeekResiliency(t *testing.T) {
	// TODO: implement
}

func TestCachedResponse(t *testing.T) {

	rand.Seed(time.Now().Unix())

	KB := 1024
	MB := KB * KB

	testCases := []struct {
		concurrentResponses int
		responseSize        int
		bufferSize          int
		extendedBufferSize  int
		extendedBufferCount int
		minBytesPerWrite    int
		maxBytesPerWrite    int
		copyPosition        int
		expectedSuccess     bool
	}{
		{1, 16, 16, 0, 0, 1, 1, 0, true},

		{1, 31, 16, 0, 0, 1, 1, 15, true},

		{1, 16, 2, 2, 7, 1, 1, 0, true},

		{1, 31, 15, 3, 5, 1, 1, 1, true},

		{1, 10 * MB, 64 * KB, 64 * KB, 158, 1, 32 * KB, 0, false},

		{1, 10 * MB, 64 * KB, 64 * KB, 159, 1, 32 * KB, 0, true},

		{1, 10 * MB, 64 * KB, 64 * KB, 160, 1, 32 * KB, 0, true},

		{1, 128 * KB, 64 * KB, 0, 0, 1, 1 * KB, 64 * KB, true},

		{1, 128 * KB, 64 * KB, 0, 0, 1, 1 * KB, 63 * KB, false},

		{1, 200 * KB, 64 * KB, 0, 0, 1, 1 * KB, 136 * KB, true},

		{10, 10 * MB, 64 * KB, 64 * KB, 1589, 1, 32 * KB, 0, false},

		{10, 10 * MB, 64 * KB, 64 * KB, 1590, 1, 32 * KB, 0, true},
	}

	for _, testCase := range testCases {
		description := fmt.Sprintf("test case: %+v", testCase)
		t.Run(description, func(t *testing.T) {

			pool := NewCachedResponseBufferPool(testCase.extendedBufferSize, testCase.extendedBufferCount)

			responses := make([]*CachedResponse, testCase.concurrentResponses)
			for i := 0; i < testCase.concurrentResponses; i++ {
				responses[i] = NewCachedResponse(testCase.bufferSize, pool)
			}

			// Repeats exercise CachedResponse.Reset() and CachedResponseBufferPool replacement
			for repeat := 0; repeat < 2; repeat++ {

				t.Logf("repeat %d", repeat)

				responseData := make([]byte, testCase.responseSize)
				_, _ = rand.Read(responseData)

				waitGroup := new(sync.WaitGroup)

				// Goroutines exercise concurrent access to CachedResponseBufferPool
				for _, response := range responses {
					waitGroup.Add(1)
					go func(response *CachedResponse) {
						defer waitGroup.Done()

						remainingSize := testCase.responseSize
						for remainingSize > 0 {

							writeSize := testCase.minBytesPerWrite
							writeSize += rand.Intn(testCase.maxBytesPerWrite - testCase.minBytesPerWrite + 1)
							if writeSize > remainingSize {
								writeSize = remainingSize
							}

							offset := len(responseData) - remainingSize

							response.Write(responseData[offset : offset+writeSize])

							remainingSize -= writeSize
						}
					}(response)
				}

				waitGroup.Wait()

				atLeastOneFailure := false

				for i, response := range responses {

					cachedResponseData := new(bytes.Buffer)

					err := response.CopyFromPosition(testCase.copyPosition, cachedResponseData)

					if testCase.expectedSuccess {

						if err != nil {
							t.Fatalf("CopyFromPosition unexpectedly failed for response %d: %s", i, err)
						}

						if bytes.Compare(responseData[testCase.copyPosition:], cachedResponseData.Bytes()) != 0 {

							t.Fatalf("cached response data mismatch for response %d", i)
						}
					} else {
						atLeastOneFailure = true
					}
				}

				if !testCase.expectedSuccess && !atLeastOneFailure {
					t.Fatalf("CopyFromPosition unexpectedly succeeded for all responses")
				}

				for _, response := range responses {
					response.Reset()
				}
			}
		})
	}
}
