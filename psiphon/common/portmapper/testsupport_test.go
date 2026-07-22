//go:build !js

/*
 * Copyright (c) 2026, Psiphon Inc.
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

// This file provides test-only helpers for the portmapper package tests. It is
// not part of the Tailscale hard fork; it replaces the Tailscale-internal test
// utilities (the tstest WhileTestRunningLogger, MemLogger, and the eventbus
// Mapping assertions) that the upstream tests relied on.

package portmapper

import (
	"bytes"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// whileTestRunningLogf returns a logf that calls tb.Logf while the test is
// running, but becomes a no-op once the test finishes. This avoids "Log in
// goroutine after test completed" panics from the TestIGD server goroutines,
// which may still be running when a test returns. It replaces the tstest
// WhileTestRunningLogger helper.
func whileTestRunningLogf(tb testing.TB) func(string, ...any) {
	var mu sync.Mutex
	done := false
	tb.Cleanup(func() {
		mu.Lock()
		done = true
		mu.Unlock()
	})
	return func(format string, args ...any) {
		mu.Lock()
		defer mu.Unlock()
		if done {
			return
		}
		tb.Logf(format, args...)
	}
}

// memLogger is a logf that accumulates log output in a buffer, line by line. It
// is a zero-value-usable replacement for the tstest MemLogger helper.
type memLogger struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

// Logf formats and appends a log line, ensuring a trailing newline.
func (m *memLogger) Logf(format string, args ...any) {
	m.mu.Lock()
	defer m.mu.Unlock()
	fmt.Fprintf(&m.buf, format, args...)
	if !strings.HasSuffix(format, "\n") {
		m.buf.WriteByte('\n')
	}
}

// String returns the accumulated log output.
func (m *memLogger) String() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.buf.String()
}

// waitForMapping polls c.HaveMapping every ~10ms up to timeout, returning true
// if a mapping appears. It replaces the eventbus Mapping assertions used by the
// upstream tests.
func waitForMapping(tb testing.TB, c *Client, timeout time.Duration) bool {
	tb.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if c.HaveMapping() {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return c.HaveMapping()
}
