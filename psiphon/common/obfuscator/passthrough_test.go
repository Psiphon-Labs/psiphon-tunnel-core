/*
 * Copyright (c) 2020, Psiphon Inc.
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

package obfuscator

import (
	"bytes"
	"fmt"
	"testing"
	"time"
)

func TestTLSPassthrough(t *testing.T) {

	// Use artificially low time factor period for test
	timePeriodSeconds = 2

	correctMasterKey := "correct-master-key"
	incorrectMasterKey := "incorrect-master-key"

	for _, useTimeFactor := range []bool{false, true} {

		t.Run(fmt.Sprintf("useTimeFactor: %v", useTimeFactor), func(t *testing.T) {

			// test: valid passthrough message

			validMessage, err := MakeTLSPassthroughMessage(useTimeFactor, correctMasterKey)
			if err != nil {
				t.Fatalf("MakeTLSPassthroughMessage failed: %s", err)
			}

			startTime := time.Now()

			if !VerifyTLSPassthroughMessage(useTimeFactor, correctMasterKey, validMessage) {
				t.Fatalf("unexpected invalid passthrough message")
			}

			correctElapsedTime := time.Now().Sub(startTime)

			// test: passthrough messages are not identical

			anotherValidMessage, err := MakeTLSPassthroughMessage(useTimeFactor, correctMasterKey)
			if err != nil {
				t.Fatalf("MakeTLSPassthroughMessage failed: %s", err)
			}

			if bytes.Equal(validMessage, anotherValidMessage) {
				t.Fatalf("unexpected identical passthrough messages")
			}

			// test: valid passthrough message still valid within time factor period

			time.Sleep(1 * time.Millisecond)

			if !VerifyTLSPassthroughMessage(useTimeFactor, correctMasterKey, validMessage) {
				t.Fatalf("unexpected invalid delayed passthrough message")
			}

			// test: valid passthrough message now invalid after time factor period

			time.Sleep(time.Duration(timePeriodSeconds)*time.Second + time.Millisecond)

			verified := VerifyTLSPassthroughMessage(useTimeFactor, correctMasterKey, validMessage)

			if verified && useTimeFactor {
				t.Fatalf("unexpected replayed passthrough message")
			}

			// test: invalid passthrough message with incorrect key

			invalidMessage, err := MakeTLSPassthroughMessage(useTimeFactor, incorrectMasterKey)
			if err != nil {
				t.Fatalf("MakeTLSPassthroughMessage failed: %s", err)
			}

			startTime = time.Now()

			if VerifyTLSPassthroughMessage(useTimeFactor, correctMasterKey, invalidMessage) {
				t.Fatalf("unexpected valid passthrough message")
			}

			incorrectElapsedTime := time.Now().Sub(startTime)

			// test: valid/invalid elapsed times are nearly identical

			timeDiff := correctElapsedTime - incorrectElapsedTime
			if timeDiff < 0 {
				timeDiff = -timeDiff
			}

			if timeDiff.Microseconds() > 500 {
				t.Fatalf("unexpected elapsed time difference: %v", timeDiff)
			}

			// test: invalid message length and elapsed time

			startTime = time.Now()

			if VerifyTLSPassthroughMessage(useTimeFactor, correctMasterKey, invalidMessage[:16]) {
				t.Fatalf("unexpected valid passthrough message with invalid length")
			}

			incorrectElapsedTime = time.Now().Sub(startTime)

			timeDiff = correctElapsedTime - incorrectElapsedTime
			if timeDiff < 0 {
				timeDiff = -timeDiff
			}

			if timeDiff.Microseconds() > 100 {
				t.Fatalf("unexpected elapsed time difference")
			}
		})
	}
}
