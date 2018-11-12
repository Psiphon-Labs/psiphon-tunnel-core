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
	"bytes"
	"compress/zlib"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math"
	"math/big"
	"runtime"
	"strings"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/wildcard"
)

const RFC3339Milli = "2006-01-02T15:04:05.000Z07:00"

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

// ContainsWildcard returns true if target matches
// any of the patterns. Patterns may contain the
// '*' wildcard.
func ContainsWildcard(patterns []string, target string) bool {
	for _, pattern := range patterns {
		if wildcard.Match(pattern, target) {
			return true
		}
	}
	return false
}

// ContainsAny returns true if any string in targets
// is present in the list.
func ContainsAny(list, targets []string) bool {
	for _, target := range targets {
		if Contains(list, target) {
			return true
		}
	}
	return false
}

// ContainsInt returns true if the target int is
// in the list.
func ContainsInt(list []int, target int) bool {
	for _, listItem := range list {
		if listItem == target {
			return true
		}
	}
	return false
}

// GetStringSlice converts an interface{} which is
// of type []interace{}, and with the type of each
// element a string, to []string.
func GetStringSlice(value interface{}) ([]string, bool) {
	slice, ok := value.([]interface{})
	if !ok {
		return nil, false
	}
	strSlice := make([]string, len(slice))
	for index, element := range slice {
		str, ok := element.(string)
		if !ok {
			return nil, false
		}
		strSlice[index] = str
	}
	return strSlice, true
}

// FlipCoin is a helper function that randomly
// returns true or false.
//
// If the underlying random number generator fails,
// FlipCoin still returns false.
func FlipCoin() bool {
	randomInt, _ := MakeSecureRandomInt(2)
	return randomInt == 1
}

// FlipWeightedCoin returns the result of a weighted
// random coin flip. If the weight is 0.5, the outcome
// is equally likely to be true or false. If the weight
// is 1.0, the outcome is always true, and if the
// weight is 0.0, the outcome is always false.
//
// Input weights > 1.0 are treated as 1.0.
//
// If the underlying random number generator fails,
// FlipWeightedCoin still returns a result.
func FlipWeightedCoin(weight float64) bool {
	if weight > 1.0 {
		weight = 1.0
	}
	n, _ := MakeSecureRandomInt64(math.MaxInt64)
	f := float64(n) / float64(math.MaxInt64)
	return f > 1.0-weight
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
	if max <= 0 {
		return 0, nil
	}
	randomInt, err := rand.Int(rand.Reader, big.NewInt(max))
	if err != nil {
		return 0, ContextError(err)
	}
	return randomInt.Int64(), nil
}

// MakeSecureRandomPerm returns a random permutation of [0,max).
func MakeSecureRandomPerm(max int) ([]int, error) {
	// Based on math/rand.Rand.Perm:
	// https://github.com/golang/go/blob/release-branch.go1.9/src/math/rand/rand.go#L189
	perm := make([]int, max)
	for i := 1; i < max; i++ {
		j, err := MakeSecureRandomInt(i + 1)
		if err != nil {
			return nil, ContextError(err)
		}
		perm[i] = perm[j]
		perm[j] = i
	}
	return perm, nil
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

// MakeSecureRandomRange selects a random int in [min, max].
// If min < 0, min is set to 0. If max < min, min is returned.
func MakeSecureRandomRange(min, max int) (int, error) {
	if min < 0 {
		min = 0
	}
	if max < min {
		return min, nil
	}
	n, err := MakeSecureRandomInt(max - min + 1)
	if err != nil {
		return 0, ContextError(err)
	}
	n += min
	return n, nil
}

// MakeSecureRandomPadding selects a random padding length in the indicated
// range and returns a random byte array of the selected length.
// If maxLength <= minLength, the padding is minLength.
func MakeSecureRandomPadding(minLength, maxLength int) ([]byte, error) {
	paddingSize, err := MakeSecureRandomRange(minLength, maxLength)
	if err != nil {
		return nil, ContextError(err)
	}
	padding, err := MakeSecureRandomBytes(paddingSize)
	if err != nil {
		return nil, ContextError(err)
	}
	return padding, nil
}

// MakeSecureRandomPeriod returns a random duration, within a given range.
// If max <= min, the duration is min.
func MakeSecureRandomPeriod(min, max time.Duration) (time.Duration, error) {
	period, err := MakeSecureRandomInt64(max.Nanoseconds() - min.Nanoseconds())
	if err != nil {
		return 0, ContextError(err)
	}
	return min + time.Duration(period), nil
}

// MakeSecureRandomStringHex returns a hex encoded random string.
// byteLength specifies the pre-encoded data length.
func MakeSecureRandomStringHex(byteLength int) (string, error) {
	bytes, err := MakeSecureRandomBytes(byteLength)
	if err != nil {
		return "", ContextError(err)
	}
	return hex.EncodeToString(bytes), nil
}

// MakeSecureRandomStringBase64 returns a base64 encoded random string.
// byteLength specifies the pre-encoded data length.
func MakeSecureRandomStringBase64(byteLength int) (string, error) {
	bytes, err := MakeSecureRandomBytes(byteLength)
	if err != nil {
		return "", ContextError(err)
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

// Jitter returns n +/- the given factor.
// For example, for n = 100 and factor = 0.1, the
// return value will be in the range [90, 110].
func Jitter(n int64, factor float64) int64 {
	a := int64(math.Ceil(float64(n) * factor))
	r, _ := MakeSecureRandomInt64(2*a + 1)
	return n + r - a
}

// JitterDuration is a helper function that wraps Jitter.
func JitterDuration(
	d time.Duration, factor float64) time.Duration {
	return time.Duration(Jitter(int64(d), factor))
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

// Compress returns zlib compressed data
func Compress(data []byte) []byte {
	var compressedData bytes.Buffer
	writer := zlib.NewWriter(&compressedData)
	writer.Write(data)
	writer.Close()
	return compressedData.Bytes()
}

// Decompress returns zlib decompressed data
func Decompress(data []byte) ([]byte, error) {
	reader, err := zlib.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, ContextError(err)
	}
	uncompressedData, err := ioutil.ReadAll(reader)
	reader.Close()
	if err != nil {
		return nil, ContextError(err)
	}
	return uncompressedData, nil
}

// FormatByteCount returns a string representation of the specified
// byte count in conventional, human-readable format.
func FormatByteCount(bytes uint64) string {
	// Based on: https://bitbucket.org/psiphon/psiphon-circumvention-system/src/b2884b0d0a491e55420ed1888aea20d00fefdb45/Android/app/src/main/java/com/psiphon3/psiphonlibrary/Utils.java?at=default#Utils.java-646
	base := uint64(1024)
	if bytes < base {
		return fmt.Sprintf("%dB", bytes)
	}
	exp := int(math.Log(float64(bytes)) / math.Log(float64(base)))
	return fmt.Sprintf(
		"%.1f%c", float64(bytes)/math.Pow(float64(base), float64(exp)), "KMGTPEZ"[exp-1])
}

func CopyNBuffer(dst io.Writer, src io.Reader, n int64, buf []byte) (written int64, err error) {
	// Based on io.CopyN:
	// https://github.com/golang/go/blob/release-branch.go1.11/src/io/io.go#L339
	written, err = io.CopyBuffer(dst, io.LimitReader(src, n), buf)
	if written == n {
		return n, nil
	}
	if written < n && err == nil {
		err = io.EOF
	}
	return
}
