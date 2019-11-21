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
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/juju/ratelimit"
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
	// Note: 64-bit ints used with atomic operations are placed
	// at the start of struct to ensure 64-bit alignment.
	// (https://golang.org/pkg/sync/atomic/#pkg-note-BUG)
	readUnthrottledBytes  int64
	readBytesPerSecond    int64
	writeUnthrottledBytes int64
	writeBytesPerSecond   int64
	closeAfterExhausted   int32
	readLock              sync.Mutex
	readRateLimiter       *ratelimit.Bucket
	readDelayTimer        *time.Timer
	writeLock             sync.Mutex
	writeRateLimiter      *ratelimit.Bucket
	writeDelayTimer       *time.Timer
	isClosed              int32
	stopBroadcast         chan struct{}
	net.Conn
}

// NewThrottledConn initializes a new ThrottledConn.
func NewThrottledConn(conn net.Conn, limits RateLimits) *ThrottledConn {
	throttledConn := &ThrottledConn{
		Conn:          conn,
		stopBroadcast: make(chan struct{}),
	}
	throttledConn.SetLimits(limits)
	return throttledConn
}

// SetLimits modifies the rate limits of an existing
// ThrottledConn. It is safe to call SetLimits while
// other goroutines are calling Read/Write. This function
// will not block, and the new rate limits will be
// applied within Read/Write, but not necessarily until
// some further I/O at previous rates.
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

	// A mutex is used to ensure conformance with net.Conn concurrency semantics.
	// The atomic.SwapInt64 and subsequent assignment of readRateLimiter or
	// readDelayTimer could be a race condition with concurrent reads.
	conn.readLock.Lock()
	defer conn.readLock.Unlock()

	select {
	case <-conn.stopBroadcast:
		return 0, errors.TraceNew("throttled conn closed")
	default:
	}

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
		return 0, errors.TraceNew("throttled conn exhausted")
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
			conn.readRateLimiter = nil
		} else {
			conn.readRateLimiter =
				ratelimit.NewBucketWithRate(float64(rate), rate)
		}
	}

	n, err := conn.Conn.Read(buffer)

	// Sleep to enforce the rate limit. This is the same logic as implemented in
	// ratelimit.Reader, but using a timer and a close signal instead of an
	// uninterruptible time.Sleep.
	//
	// The readDelayTimer is always expired/stopped and drained after this code
	// block and is ready to be Reset on the next call.

	if n >= 0 && conn.readRateLimiter != nil {
		sleepDuration := conn.readRateLimiter.Take(int64(n))
		if sleepDuration > 0 {
			if conn.readDelayTimer == nil {
				conn.readDelayTimer = time.NewTimer(sleepDuration)
			} else {
				conn.readDelayTimer.Reset(sleepDuration)
			}
			select {
			case <-conn.readDelayTimer.C:
			case <-conn.stopBroadcast:
				if !conn.readDelayTimer.Stop() {
					<-conn.readDelayTimer.C
				}
			}
		}
	}

	return n, errors.Trace(err)
}

func (conn *ThrottledConn) Write(buffer []byte) (int, error) {

	// See comments in Read.

	conn.writeLock.Lock()
	defer conn.writeLock.Unlock()

	select {
	case <-conn.stopBroadcast:
		return 0, errors.TraceNew("throttled conn closed")
	default:
	}

	if atomic.LoadInt64(&conn.writeUnthrottledBytes) > 0 {
		n, err := conn.Conn.Write(buffer)
		atomic.AddInt64(&conn.writeUnthrottledBytes, -int64(n))
		return n, err
	}

	if atomic.LoadInt32(&conn.closeAfterExhausted) == 1 {
		conn.Conn.Close()
		return 0, errors.TraceNew("throttled conn exhausted")
	}

	rate := atomic.SwapInt64(&conn.writeBytesPerSecond, -1)

	if rate != -1 {
		if rate == 0 {
			conn.writeRateLimiter = nil
		} else {
			conn.writeRateLimiter =
				ratelimit.NewBucketWithRate(float64(rate), rate)
		}
	}

	if len(buffer) >= 0 && conn.writeRateLimiter != nil {
		sleepDuration := conn.writeRateLimiter.Take(int64(len(buffer)))
		if sleepDuration > 0 {
			if conn.writeDelayTimer == nil {
				conn.writeDelayTimer = time.NewTimer(sleepDuration)
			} else {
				conn.writeDelayTimer.Reset(sleepDuration)
			}
			select {
			case <-conn.writeDelayTimer.C:
			case <-conn.stopBroadcast:
				if !conn.writeDelayTimer.Stop() {
					<-conn.writeDelayTimer.C
				}
			}
		}
	}

	n, err := conn.Conn.Write(buffer)

	return n, errors.Trace(err)
}

func (conn *ThrottledConn) Close() error {

	// Ensure close channel only called once.
	if !atomic.CompareAndSwapInt32(&conn.isClosed, 0, 1) {
		return nil
	}

	close(conn.stopBroadcast)

	return errors.Trace(conn.Conn.Close())
}
