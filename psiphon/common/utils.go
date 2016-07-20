/*
 * Copyright (c) 2016, Psiphon Inc.
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
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"runtime"
	"strings"
	"time"
)

// Contains is a helper function that returns true
// if the target string is in the list.
func Contains(list []string, target string) bool {
	for _, listItem := range list {
		if listItem == target {
			return true
		}
	}
	return false
}

// FlipCoin is a helper function that randomly
// returns true or false. If the underlying random
// number generator fails, FlipCoin still returns
// a result.
func FlipCoin() bool {
	randomInt, _ := MakeSecureRandomInt(2)
	return randomInt == 1
}

// MakeSecureRandomInt is a helper function that wraps
// MakeSecureRandomInt64.
func MakeSecureRandomInt(max int) (int, error) {
	randomInt, err := MakeSecureRandomInt64(int64(max))
	return int(randomInt), err
}

// MakeSecureRandomInt64 is a helper function that wraps
// crypto/rand.Int, which returns a uniform random value in [0, max).
func MakeSecureRandomInt64(max int64) (int64, error) {
	randomInt, err := rand.Int(rand.Reader, big.NewInt(max))
	if err != nil {
		return 0, ContextError(err)
	}
	return randomInt.Int64(), nil
}

// MakeSecureRandomBytes is a helper function that wraps
// crypto/rand.Read.
func MakeSecureRandomBytes(length int) ([]byte, error) {
	randomBytes := make([]byte, length)
	n, err := rand.Read(randomBytes)
	if err != nil {
		return nil, ContextError(err)
	}
	if n != length {
		return nil, ContextError(errors.New("insufficient random bytes"))
	}
	return randomBytes, nil
}

// MakeSecureRandomPadding selects a random padding length in the indicated
// range and returns a random byte array of the selected length.
// In the unlikely case where an underlying MakeRandom functions fails,
// the padding is length 0.
func MakeSecureRandomPadding(minLength, maxLength int) ([]byte, error) {
	var padding []byte
	paddingSize, err := MakeSecureRandomInt(maxLength - minLength)
	if err != nil {
		return nil, ContextError(err)
	}
	paddingSize += minLength
	padding, err = MakeSecureRandomBytes(paddingSize)
	if err != nil {
		return nil, ContextError(err)
	}
	return padding, nil
}

// MakeRandomPeriod returns a random duration, within a given range.
// In the unlikely case where an  underlying MakeRandom functions fails,
// the period is the minimum.
func MakeRandomPeriod(min, max time.Duration) (time.Duration, error) {
	period, err := MakeSecureRandomInt64(max.Nanoseconds() - min.Nanoseconds())
	if err != nil {
		return 0, ContextError(err)
	}
	return min + time.Duration(period), nil
}

// MakeRandomStringHex returns a hex encoded random string.
// byteLength specifies the pre-encoded data length.
func MakeRandomStringHex(byteLength int) (string, error) {
	bytes, err := MakeSecureRandomBytes(byteLength)
	if err != nil {
		return "", ContextError(err)
	}
	return hex.EncodeToString(bytes), nil
}

// MakeRandomStringBase64 returns a base64 encoded random string.
// byteLength specifies the pre-encoded data length.
func MakeRandomStringBase64(byteLength int) (string, error) {
	bytes, err := MakeSecureRandomBytes(byteLength)
	if err != nil {
		return "", ContextError(err)
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

// GetCurrentTimestamp returns the current time in UTC as
// an RFC 3339 formatted string.
func GetCurrentTimestamp() string {
	return time.Now().UTC().Format(time.RFC3339)
}

// TruncateTimestampToHour truncates an RFC 3339 formatted string
// to hour granularity. If the input is not a valid format, the
// result is "".
func TruncateTimestampToHour(timestamp string) string {
	t, err := time.Parse(time.RFC3339, timestamp)
	if err != nil {
		return ""
	}
	return t.Truncate(1 * time.Hour).Format(time.RFC3339)
}

// getFunctionName is a helper that extracts a simple function name from
// full name returned byruntime.Func.Name(). This is used to declutter
// log messages containing function names.
func getFunctionName(pc uintptr) string {
	funcName := runtime.FuncForPC(pc).Name()
	index := strings.LastIndex(funcName, "/")
	if index != -1 {
		funcName = funcName[index+1:]
	}
	return funcName
}

// GetParentContext returns the parent function name and source file
// line number.
func GetParentContext() string {
	pc, _, line, _ := runtime.Caller(2)
	return fmt.Sprintf("%s#%d", getFunctionName(pc), line)
}

// ContextError prefixes an error message with the current function
// name and source file line number.
func ContextError(err error) error {
	if err == nil {
		return nil
	}
	pc, _, line, _ := runtime.Caller(1)
	return fmt.Errorf("%s#%d: %s", getFunctionName(pc), line, err)
}
