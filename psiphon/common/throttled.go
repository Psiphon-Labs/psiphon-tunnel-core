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
	"golang.org/x/time/rate"
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
	net.Conn
	readUnthrottledBytes  atomic.Int64
	readBytesPerSecond    atomic.Int64
	writeUnthrottledBytes atomic.Int64
	writeBytesPerSecond   atomic.Int64
	closeAfterExhausted   int32
	readLock              sync.Mutex
	readRateLimiter       *rate.Limiter
	readDelayTimer        *time.Timer
	writeLock             sync.Mutex
	writeRateLimiter      *rate.Limiter
	writeDelayTimer       *time.Timer
	isClosed              int32
	stopBroadcast         chan struct{}
	isStream              bool
}

// NewThrottledConn initializes a new ThrottledConn.
//
// Set isStreamConn to true when conn is stream-oriented, such as TCP, and
// false when the conn is packet-oriented, such as UDP. When conn is a
// stream, reads and writes may be split to accomodate rate limits.
func NewThrottledConn(
	conn net.Conn, isStream bool, limits RateLimits) *ThrottledConn {

	throttledConn := &ThrottledConn{
		Conn:          conn,
		isStream:      isStream,
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
	conn.readBytesPerSecond.Store(rate)
	conn.readUnthrottledBytes.Store(limits.ReadUnthrottledBytes)

	rate = limits.WriteBytesPerSecond
	if rate < 0 {
		rate = 0
	}
	conn.writeBytesPerSecond.Store(rate)
	conn.writeUnthrottledBytes.Store(limits.WriteUnthrottledBytes)

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

	if atomic.LoadInt32(&conn.isClosed) == 1 {
		return 0, errors.TraceNew("throttled conn closed")
	}

	// Use the base conn until the unthrottled count is
	// exhausted. This is only an approximate enforcement
	// since this read, or concurrent reads, could exceed
	// the remaining count.
	if conn.readUnthrottledBytes.Load() > 0 {
		n, err := conn.Conn.Read(buffer)
		conn.readUnthrottledBytes.Add(-int64(n))
		return n, err
	}

	if atomic.LoadInt32(&conn.closeAfterExhausted) == 1 {
		conn.Conn.Close()
		return 0, errors.TraceNew("throttled conn exhausted")
	}

	readRate := conn.readBytesPerSecond.Swap(-1)

	if readRate != -1 {
		// SetLimits has been called and a new rate limiter
		// must be initialized. When no limit is specified,
		// the reader/writer is simply the base conn.
		// No state is retained from the previous rate limiter,
		// so a pending I/O throttle sleep may be skipped when
		// the old and new rate are similar.
		if readRate == 0 {
			conn.readRateLimiter = nil
		} else {
			conn.readRateLimiter =
				rate.NewLimiter(rate.Limit(readRate), int(readRate))
		}
	}

	// The number of bytes read cannot exceed the rate limiter burst size,
	// which is enforced by rate.Limiter.ReserveN. Reduce any read buffer
	// size to be at most the burst size.
	//
	// Read should still return as soon as read bytes are available; and the
	// number of bytes that will be received is unknown; so there is no loop
	// here to read more bytes. Reducing the read buffer size minimizes
	// latency for the up-to-burst-size bytes read, whereas allowing a full
	// read followed by multiple ReserveN calls and sleeps would increase
	// latency.
	//
	// In practise, with Psiphon tunnels, throttling is not applied until
	// after the Psiphon API handshake, so read buffer reductions won't
	// impact early obfuscation traffic shaping; and reads are on the order
	// of one SSH "packet", up to 32K, unlikely to be split for all but the
	// most restrictive of rate limits.

	if conn.readRateLimiter != nil {
		burst := conn.readRateLimiter.Burst()
		if len(buffer) > burst {
			if !conn.isStream {
				return 0, errors.TraceNew("non-stream read buffer exceeds burst")
			}
			buffer = buffer[:burst]
		}
	}

	n, err := conn.Conn.Read(buffer)

	if n > 0 && conn.readRateLimiter != nil {

		// While rate.Limiter.WaitN would be simpler to use, internally Wait
		// creates a new timer for every call which must sleep, which is
		// expected to be most calls. Instead, call ReserveN to get the sleep
		// time and reuse one timer without allocation.
		//
		// TODO: avoid allocation: ReserveN allocates a *Reservation; while
		// the internal reserveN returns a struct, not a pointer.

		reservation := conn.readRateLimiter.ReserveN(time.Now(), n)
		if !reservation.OK() {
			// This error is not expected, given the buffer size adjustment.
			return 0, errors.TraceNew("burst size exceeded")
		}
		sleepDuration := reservation.Delay()
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

	// Don't wrap I/O errors
	return n, err
}

func (conn *ThrottledConn) Write(buffer []byte) (int, error) {

	// See comments in Read.

	conn.writeLock.Lock()
	defer conn.writeLock.Unlock()

	if atomic.LoadInt32(&conn.isClosed) == 1 {
		return 0, errors.TraceNew("throttled conn closed")
	}

	if conn.writeUnthrottledBytes.Load() > 0 {
		n, err := conn.Conn.Write(buffer)
		conn.writeUnthrottledBytes.Add(-int64(n))
		return n, err
	}

	if atomic.LoadInt32(&conn.closeAfterExhausted) == 1 {
		conn.Conn.Close()
		return 0, errors.TraceNew("throttled conn exhausted")
	}

	writeRate := conn.writeBytesPerSecond.Swap(-1)

	if writeRate != -1 {
		if writeRate == 0 {
			conn.writeRateLimiter = nil
		} else {
			conn.writeRateLimiter =
				rate.NewLimiter(rate.Limit(writeRate), int(writeRate))
		}
	}

	if conn.writeRateLimiter == nil {
		n, err := conn.Conn.Write(buffer)
		// Don't wrap I/O errors
		return n, err
	}

	// The number of bytes written cannot exceed the rate limiter burst size,
	// which is enforced by rate.Limiter.ReserveN. Split writes to be at most
	// the burst size.
	//
	// Splitting writes may have some effect on the shape of TCP packets sent
	// on the network.
	//
	// In practise, with Psiphon tunnels, throttling is not applied until
	// after the Psiphon API handshake, so write splits won't impact early
	// obfuscation traffic shaping; and writes are on the order of one
	// SSH "packet", up to 32K, unlikely to be split for all but the most
	// restrictive of rate limits.

	burst := conn.writeRateLimiter.Burst()
	if !conn.isStream && len(buffer) > burst {
		return 0, errors.TraceNew("non-stream write exceeds burst")
	}
	totalWritten := 0
	for i := 0; i < len(buffer); i += burst {

		j := i + burst
		if j > len(buffer) {
			j = len(buffer)
		}
		b := buffer[i:j]

		// See comment in Read regarding rate.Limiter.ReserveN vs.
		// rate.Limiter.WaitN.

		reservation := conn.writeRateLimiter.ReserveN(time.Now(), len(b))
		if !reservation.OK() {
			// This error is not expected, given the write split adjustments.
			return 0, errors.TraceNew("burst size exceeded")
		}
		sleepDuration := reservation.Delay()
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

		n, err := conn.Conn.Write(b)
		totalWritten += n
		if err != nil {
			// Don't wrap I/O errors
			return totalWritten, err
		}
	}

	return totalWritten, nil
}

func (conn *ThrottledConn) Close() error {

	// Ensure close channel only called once.
	if !atomic.CompareAndSwapInt32(&conn.isClosed, 0, 1) {
		return nil
	}

	close(conn.stopBroadcast)

	return errors.Trace(conn.Conn.Close())
}
