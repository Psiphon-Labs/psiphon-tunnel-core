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
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"

	"github.com/Psiphon-Inc/ratelimit"
)

// RateLimits specify the rate limits for a ThrottledConn.
type RateLimits struct {

	// ReadUnthrottledBytes specifies the number of bytes to
	// read, approximately, before starting rate limiting.
	ReadUnthrottledBytes int64

	// ReadBytesPerSecond specifies a rate limit for read
	// data transfer. The default, 0, is no limit.
	ReadBytesPerSecond int64

	// WriteUnthrottledBytes specifies the number of bytes to
	// write, approximately, before starting rate limiting.
	WriteUnthrottledBytes int64

	// WriteBytesPerSecond specifies a rate limit for write
	// data transfer. The default, 0, is no limit.
	WriteBytesPerSecond int64

	// CloseAfterExhausted indicates that the underlying
	// net.Conn should be closed once either the read or
	// write unthrottled bytes have been exhausted. In this
	// case, throttling is never applied.
	CloseAfterExhausted bool
}

// ThrottledConn wraps a net.Conn with read and write rate limiters.
// Rates are specified as bytes per second. Optional unlimited byte
// counts allow for a number of bytes to read or write before
// applying rate limiting. Specify limit values of 0 to set no rate
// limit (unlimited counts are ignored in this case).
// The underlying rate limiter uses the token bucket algorithm to
// calculate delay times for read and write operations.
type ThrottledConn struct {
	// Note: 64-bit ints used with atomic operations are at placed
	// at the start of struct to ensure 64-bit alignment.
	// (https://golang.org/pkg/sync/atomic/#pkg-note-BUG)
	readUnthrottledBytes  int64
	readBytesPerSecond    int64
	writeUnthrottledBytes int64
	writeBytesPerSecond   int64
	closeAfterExhausted   int32
	readLock              sync.Mutex
	throttledReader       io.Reader
	writeLock             sync.Mutex
	throttledWriter       io.Writer
	net.Conn
}

// NewThrottledConn initializes a new ThrottledConn.
func NewThrottledConn(conn net.Conn, limits RateLimits) *ThrottledConn {
	throttledConn := &ThrottledConn{Conn: conn}
	throttledConn.SetLimits(limits)
	return throttledConn
}

// SetLimits modifies the rate limits of an existing
// ThrottledConn. It is safe to call SetLimits while
// other goroutines are calling Read/Write. This function
// will not block, and the new rate limits will be
// applied within Read/Write, but not necessarily until
// some futher I/O at previous rates.
func (conn *ThrottledConn) SetLimits(limits RateLimits) {

	// Using atomic instead of mutex to avoid blocking
	// this function on throttled I/O in an ongoing
	// read or write. Precise synchronized application
	// of the rate limit values is not required.

	// Negative rates are invalid and -1 is a special
	// value to used to signal throttling initialized
	// state. Silently normalize negative values to 0.
	rate := limits.ReadBytesPerSecond
	if rate < 0 {
		rate = 0
	}
	atomic.StoreInt64(&conn.readBytesPerSecond, rate)
	atomic.StoreInt64(&conn.readUnthrottledBytes, limits.ReadUnthrottledBytes)

	rate = limits.WriteBytesPerSecond
	if rate < 0 {
		rate = 0
	}
	atomic.StoreInt64(&conn.writeBytesPerSecond, rate)
	atomic.StoreInt64(&conn.writeUnthrottledBytes, limits.WriteUnthrottledBytes)

	closeAfterExhausted := int32(0)
	if limits.CloseAfterExhausted {
		closeAfterExhausted = 1
	}
	atomic.StoreInt32(&conn.closeAfterExhausted, closeAfterExhausted)
}

func (conn *ThrottledConn) Read(buffer []byte) (int, error) {

	// A mutex is used to ensure conformance with net.Conn
	// concurrency semantics. The atomic.SwapInt64 and
	// subsequent assignment of throttledReader could be
	// a race condition with concurrent reads.
	conn.readLock.Lock()
	defer conn.readLock.Unlock()

	// Use the base conn until the unthrottled count is
	// exhausted. This is only an approximate enforcement
	// since this read, or concurrent reads, could exceed
	// the remaining count.
	if atomic.LoadInt64(&conn.readUnthrottledBytes) > 0 {
		n, err := conn.Conn.Read(buffer)
		atomic.AddInt64(&conn.readUnthrottledBytes, -int64(n))
		return n, err
	}

	if atomic.LoadInt32(&conn.closeAfterExhausted) == 1 {
		conn.Conn.Close()
		return 0, errors.New("throttled conn exhausted")
	}

	rate := atomic.SwapInt64(&conn.readBytesPerSecond, -1)

	if rate != -1 {
		// SetLimits has been called and a new rate limiter
		// must be initialized. When no limit is specified,
		// the reader/writer is simply the base conn.
		// No state is retained from the previous rate limiter,
		// so a pending I/O throttle sleep may be skipped when
		// the old and new rate are similar.
		if rate == 0 {
			conn.throttledReader = conn.Conn
		} else {
			conn.throttledReader = ratelimit.Reader(
				conn.Conn,
				ratelimit.NewBucketWithRate(float64(rate), rate))
		}
	}

	return conn.throttledReader.Read(buffer)
}

func (conn *ThrottledConn) Write(buffer []byte) (int, error) {

	// See comments in Read.

	conn.writeLock.Lock()
	defer conn.writeLock.Unlock()

	if atomic.LoadInt64(&conn.writeUnthrottledBytes) > 0 {
		n, err := conn.Conn.Write(buffer)
		atomic.AddInt64(&conn.writeUnthrottledBytes, -int64(n))
		return n, err
	}

	if atomic.LoadInt32(&conn.closeAfterExhausted) == 1 {
		conn.Conn.Close()
		return 0, errors.New("throttled conn exhausted")
	}

	rate := atomic.SwapInt64(&conn.writeBytesPerSecond, -1)

	if rate != -1 {
		if rate == 0 {
			conn.throttledWriter = conn.Conn
		} else {
			conn.throttledWriter = ratelimit.Writer(
				conn.Conn,
				ratelimit.NewBucketWithRate(float64(rate), rate))
		}
	}

	return conn.throttledWriter.Write(buffer)
}
