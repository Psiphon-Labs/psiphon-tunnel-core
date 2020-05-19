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

package server

import (
	"fmt"
	"io"
	"strings"
	"sync/atomic"
)

// IntentionalPanicError is an error type that is used
// when calling panic() in a situation where recovers
// should propagate the panic.
type IntentionalPanicError struct {
	message string
}

// NewIntentionalPanicError creates a new IntentionalPanicError.
func NewIntentionalPanicError(errorMessage string) error {
	return IntentionalPanicError{
		message: fmt.Sprintf("intentional panic error: %s", errorMessage)}
}

// Error implements the error interface.
func (err IntentionalPanicError) Error() string {
	return err.message
}

// PanickingLogWriter wraps an io.Writer and intentionally
// panics when a Write() fails.
type PanickingLogWriter struct {
	name   string
	writer io.Writer
}

// NewPanickingLogWriter creates a new PanickingLogWriter.
func NewPanickingLogWriter(
	name string, writer io.Writer) *PanickingLogWriter {

	return &PanickingLogWriter{
		name:   name,
		writer: writer,
	}
}

// Write implements the io.Writer interface.
func (w *PanickingLogWriter) Write(p []byte) (n int, err error) {
	n, err = w.writer.Write(p)
	if err != nil {
		panic(
			NewIntentionalPanicError(
				fmt.Sprintf("fatal write to %s failed: %s", w.name, err)))
	}
	return
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func greaterThanSwapInt64(addr *int64, new int64) bool {
	old := atomic.LoadInt64(addr)
	if new > old {
		return atomic.CompareAndSwapInt64(addr, old, new)
	}
	return false
}

var expectedTunnelIOErrorSubstrings = []string{
	"EOF",
	"use of closed network connection",
	"connection reset by peer",
	"connection has closed",
	"broken pipe",
	"i/o timeout",
	"deadline exceeded",
	"NetworkIdleTimeout",
	"PeerGoingAway",
	"Application error 0x0",
	"No recent network activity",
}

// isExpectedTunnelIOError checks if the error indicates failure due to tunnel
// I/O timing out, use of a closed tunnel, etc. This is used to avoid logging
// noise in cases where sending messages through the tunnel fail due regular,
// expected tunnel failure conditions.
//
// Limitations introduced by error type wrapping and lack of common error
// types across all network protcol layers means this function uses
// heuristical error text substring matching and may fall out of sync with new
// protocols/error messages. As such, this function should only be used for
// the intended log noise purpose.
func isExpectedTunnelIOError(err error) bool {
	errString := err.Error()
	for _, substring := range expectedTunnelIOErrorSubstrings {
		if strings.Contains(errString, substring) {
			return true
		}
	}
	return false
}
