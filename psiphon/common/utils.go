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
	"fmt"
	"io"
	"io/ioutil"
	"math"
	"os"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
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
		return nil, errors.Trace(err)
	}
	uncompressedData, err := ioutil.ReadAll(reader)
	reader.Close()
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

// FileMigration represents the action of moving a file, or directory, to a new
// location.
type FileMigration struct {

	// OldPath is the current location of the file.
	OldPath string

	// NewPath is the location that the file should be moved to.
	NewPath string

	// IsDir should be set to true if the file is a directory.
	IsDir bool
}

// DoFileMigration performs the specified file move operation. An error will be
// returned and the operation will not performed if: a file is expected, but a
// directory is found; a directory is expected, but a file is found; or a file,
// or directory, already exists at the target path of the move operation.
func DoFileMigration(migration FileMigration) error {
	if !FileExists(migration.OldPath) {
		return errors.Tracef("%s does not exist", migration.OldPath)
	}
	info, err := os.Stat(migration.OldPath)
	if err != nil {
		return errors.Tracef("error getting file info of %s: %s", migration.OldPath, err.Error())
	}
	if info.IsDir() != migration.IsDir {
		if migration.IsDir {
			return errors.Tracef("expected directory %s to be directory but found file", migration.OldPath)
		}

		return errors.Tracef("expected %s to be file but found directory",
			migration.OldPath)
	}

	if FileExists(migration.NewPath) {
		return errors.Tracef("%s already exists, will not overwrite", migration.NewPath)
	}

	err = os.Rename(migration.OldPath, migration.NewPath)
	if err != nil {
		return errors.Tracef("renaming %s as %s failed with error %s", migration.OldPath, migration.NewPath, err.Error())
	}

	return nil
}
