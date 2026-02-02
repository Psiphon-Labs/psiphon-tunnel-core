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
	"context"
	"crypto/rand"
	std_errors "errors"
	"fmt"
	"io"
	"io/ioutil"
	"math"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
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

// MakeSecureRandomBytes is a helper function that wraps
// crypto/rand.Read.
func MakeSecureRandomBytes(length int) ([]byte, error) {
	randomBytes := make([]byte, length)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return nil, errors.Trace(err)
	}
	return randomBytes, nil
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

// ParseTimeOfDayMinutes parses a time of day in HH:MM 24-hour format and
// returns the number of minutes since midnight.
func ParseTimeOfDayMinutes(value string) (int, error) {
	t, err := time.Parse("15:04", value)
	if err != nil {
		return 0, errors.Trace(err)
	}
	return t.Hour()*60 + t.Minute(), nil
}

const (
	CompressionNone = int32(0)
	CompressionZlib = int32(1)
)

// Compress compresses data with the specified algorithm.
func Compress(compression int32, data []byte) ([]byte, error) {
	if compression == CompressionNone {
		return data, nil
	}
	if compression != CompressionZlib {
		return nil, errors.TraceNew("unknown compression algorithm")
	}
	var compressedData bytes.Buffer
	writer := zlib.NewWriter(&compressedData)
	_, err := writer.Write(data)
	if err != nil {
		return nil, errors.Trace(err)
	}
	_ = writer.Close()
	return compressedData.Bytes(), nil
}

// Decompress decompresses data with the specified algorithm.
func Decompress(compression int32, data []byte) ([]byte, error) {
	if compression == CompressionNone {
		return data, nil
	}
	if compression != CompressionZlib {
		return nil, errors.TraceNew("unknown compression algorithm")
	}
	reader, err := zlib.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, errors.Trace(err)
	}
	uncompressedData, err := ioutil.ReadAll(reader)
	_ = reader.Close()
	if err != nil {
		return nil, errors.Trace(err)
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

// CopyBuffer calls io.CopyBuffer, masking out any src.WriteTo or dst.ReadFrom
// to force use of the specified buf.
func CopyBuffer(dst io.Writer, src io.Reader, buf []byte) (written int64, err error) {
	return io.CopyBuffer(struct{ io.Writer }{dst}, struct{ io.Reader }{src}, buf)
}

func CopyNBuffer(dst io.Writer, src io.Reader, n int64, buf []byte) (written int64, err error) {
	// Based on io.CopyN:
	// https://github.com/golang/go/blob/release-branch.go1.11/src/io/io.go#L339
	written, err = CopyBuffer(dst, io.LimitReader(src, n), buf)
	if written == n {
		return n, nil
	}
	if written < n && err == nil {
		err = io.EOF
	}
	return
}

// FileExists returns true if a file, or directory, exists at the given path.
func FileExists(filePath string) bool {
	if _, err := os.Stat(filePath); err != nil && os.IsNotExist(err) {
		return false
	}
	return true
}

// SafeParseURL wraps url.Parse, stripping the input URL from any error
// message. This allows logging url.Parse errors without unintentially logging
// PII that may appear in the input URL.
func SafeParseURL(rawurl string) (*url.URL, error) {
	parsedURL, err := url.Parse(rawurl)
	if err != nil {
		// Unwrap yields just the url.Error error field without the url.Error URL
		// and operation fields.
		err = std_errors.Unwrap(err)
		if err == nil {
			err = std_errors.New("SafeParseURL: Unwrap failed")
		} else {
			err = fmt.Errorf("url.Parse: %v", err)
		}
	}
	return parsedURL, err
}

// SafeParseRequestURI wraps url.ParseRequestURI, stripping the input URL from
// any error message. This allows logging url.ParseRequestURI errors without
// unintentially logging PII that may appear in the input URL.
func SafeParseRequestURI(rawurl string) (*url.URL, error) {
	parsedURL, err := url.ParseRequestURI(rawurl)
	if err != nil {
		err = std_errors.Unwrap(err)
		if err == nil {
			err = std_errors.New("SafeParseRequestURI: Unwrap failed")
		} else {
			err = fmt.Errorf("url.ParseRequestURI: %v", err)
		}
	}
	return parsedURL, err
}

// SleepWithContext returns after the specified duration or once the input ctx
// is done, whichever is first.
func SleepWithContext(ctx context.Context, duration time.Duration) {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
	}
}

// SleepWithJitter returns after the specified duration, with random jitter
// applied, or once the input ctx is done, whichever is first.
func SleepWithJitter(ctx context.Context, duration time.Duration, jitter float64) {
	timer := time.NewTimer(prng.JitterDuration(duration, jitter))
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	}
}

// ValueOrDefault returns the input value, or, when value is the zero value of
// its type, defaultValue.
func ValueOrDefault[T comparable](value, defaultValue T) T {
	var zero T
	if value == zero {
		return defaultValue
	}
	return value
}

// MergeContextCancel returns a context which has the properties of the 1st
// input content and merges in the cancellation signal of the 2nd context, so
// the returned context is cancelled when either input context is cancelled.
//
// See (and adapted from): https://pkg.go.dev/context#example-AfterFunc-Merge
func MergeContextCancel(ctx, cancelCtx context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancelCause(ctx)
	stop := context.AfterFunc(cancelCtx, func() {
		cancel(context.Cause(cancelCtx))
	})
	return ctx, func() {
		stop()
		cancel(context.Canceled)
	}
}

// MaxDuration returns the maximum duration in durations or 0 if durations is
// empty.
func MaxDuration(durations ...time.Duration) time.Duration {
	if len(durations) == 0 {
		return 0
	}

	max := durations[0]
	for _, d := range durations[1:] {
		if d > max {
			max = d
		}
	}
	return max
}

// ToRandomASCIICasing returns s with each ASCII letter randomly mapped to
// either its upper or lower case.
func ToRandomASCIICasing(s string, seed *prng.Seed) string {

	PRNG := prng.NewPRNGWithSeed(seed)

	var b strings.Builder
	b.Grow(len(s))

	for _, r := range s {
		isLower := ('a' <= r && r <= 'z')
		isUpper := ('A' <= r && r <= 'Z')
		if (isLower || isUpper) && PRNG.FlipCoin() {
			b.WriteRune(r ^ 0x20)
		} else {
			b.WriteRune(r)
		}
	}

	return b.String()
}
