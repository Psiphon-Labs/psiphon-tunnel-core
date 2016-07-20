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
	"io"
	"net"
	"sync/atomic"

	"github.com/Psiphon-Inc/ratelimit"
)

// RateLimits specify the rate limits for a ThrottledConn.
type RateLimits struct {

	// DownstreamUnlimitedBytes specifies the number of downstream
	// bytes to transfer, approximately, before starting rate
	// limiting.
	DownstreamUnlimitedBytes int64

	// DownstreamBytesPerSecond specifies a rate limit for downstream
	// data transfer. The default, 0, is no limit.
	DownstreamBytesPerSecond int64

	// UpstreamUnlimitedBytes specifies the number of upstream
	// bytes to transfer, approximately, before starting rate
	// limiting.
	UpstreamUnlimitedBytes int64

	// UpstreamBytesPerSecond specifies a rate limit for upstream
	// data transfer. The default, 0, is no limit.
	UpstreamBytesPerSecond int64
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
	unlimitedReadBytes  int64
	limitingReads       int32
	limitedReader       io.Reader
	unlimitedWriteBytes int64
	limitingWrites      int32
	limitedWriter       io.Writer
}

// NewThrottledConn initializes a new ThrottledConn.
func NewThrottledConn(conn net.Conn, limits RateLimits) *ThrottledConn {

	// When no limit is specified, the rate limited reader/writer
	// is simply the base reader/writer.

	var reader io.Reader
	if limits.DownstreamBytesPerSecond == 0 {
		reader = conn
	} else {
		reader = ratelimit.Reader(conn,
			ratelimit.NewBucketWithRate(
				float64(limits.DownstreamBytesPerSecond),
				limits.DownstreamBytesPerSecond))
	}

	var writer io.Writer
	if limits.UpstreamBytesPerSecond == 0 {
		writer = conn
	} else {
		writer = ratelimit.Writer(conn,
			ratelimit.NewBucketWithRate(
				float64(limits.UpstreamBytesPerSecond),
				limits.UpstreamBytesPerSecond))
	}

	return &ThrottledConn{
		Conn:                conn,
		unlimitedReadBytes:  limits.DownstreamUnlimitedBytes,
		limitingReads:       0,
		limitedReader:       reader,
		unlimitedWriteBytes: limits.UpstreamUnlimitedBytes,
		limitingWrites:      0,
		limitedWriter:       writer,
	}
}

func (conn *ThrottledConn) Read(buffer []byte) (int, error) {

	// Use the base reader until the unlimited count is exhausted.
	if atomic.LoadInt32(&conn.limitingReads) == 0 {
		if atomic.AddInt64(&conn.unlimitedReadBytes, -int64(len(buffer))) <= 0 {
			atomic.StoreInt32(&conn.limitingReads, 1)
		} else {
			return conn.Read(buffer)
		}
	}

	return conn.limitedReader.Read(buffer)
}

func (conn *ThrottledConn) Write(buffer []byte) (int, error) {

	// Use the base writer until the unlimited count is exhausted.
	if atomic.LoadInt32(&conn.limitingWrites) == 0 {
		if atomic.AddInt64(&conn.unlimitedWriteBytes, -int64(len(buffer))) <= 0 {
			atomic.StoreInt32(&conn.limitingWrites, 1)
		} else {
			return conn.Write(buffer)
		}
	}

	return conn.limitedWriter.Write(buffer)
}
