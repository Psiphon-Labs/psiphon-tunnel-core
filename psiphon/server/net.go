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
	"container/list"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Psiphon-Inc/ratelimit"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon"
)

// LRUConns is a concurrency-safe list of net.Conns ordered
// by recent activity. Its purpose is to facilitate closing
// the oldest connection in a set of connections.
//
// New connections added are referenced by a LRUConnsEntry,
// which is used to Touch() active connections, which
// promotes them to the front of the order and to Remove()
// connections that are no longer LRU candidates.
//
// CloseOldest() will remove the oldest connection from the
// list and call net.Conn.Close() on the connection.
//
// After an entry has been removed, LRUConnsEntry Touch()
// and Remove() will have no effect.
type LRUConns struct {
	mutex sync.Mutex
	list  *list.List
}

// NewLRUConns initializes a new LRUConns.
func NewLRUConns() *LRUConns {
	return &LRUConns{list: list.New()}
}

// Add inserts a net.Conn as the freshest connection
// in a LRUConns and returns an LRUConnsEntry to be
// used to freshen the connection or remove the connection
// from the LRU list.
func (conns *LRUConns) Add(conn net.Conn) *LRUConnsEntry {
	conns.mutex.Lock()
	defer conns.mutex.Unlock()
	return &LRUConnsEntry{
		lruConns: conns,
		element:  conns.list.PushFront(conn),
	}
}

// CloseOldest closes the oldest connection in a
// LRUConns. It calls net.Conn.Close() on the
// connection.
func (conns *LRUConns) CloseOldest() {
	conns.mutex.Lock()
	oldest := conns.list.Back()
	conn, ok := oldest.Value.(net.Conn)
	if oldest != nil {
		conns.list.Remove(oldest)
	}
	// Release mutex before closing conn
	conns.mutex.Unlock()
	if ok {
		conn.Close()
	}
}

// LRUConnsEntry is an entry in a LRUConns list.
type LRUConnsEntry struct {
	lruConns *LRUConns
	element  *list.Element
}

// Remove deletes the connection referenced by the
// LRUConnsEntry from the associated LRUConns.
// Has no effect if the entry was not initialized
// or previously removed.
func (entry *LRUConnsEntry) Remove() {
	if entry.lruConns == nil || entry.element == nil {
		return
	}
	entry.lruConns.mutex.Lock()
	defer entry.lruConns.mutex.Unlock()
	entry.lruConns.list.Remove(entry.element)
}

// Touch promotes the connection referenced by the
// LRUConnsEntry to the front of the associated LRUConns.
// Has no effect if the entry was not initialized
// or previously removed.
func (entry *LRUConnsEntry) Touch() {
	if entry.lruConns == nil || entry.element == nil {
		return
	}
	entry.lruConns.mutex.Lock()
	defer entry.lruConns.mutex.Unlock()
	entry.lruConns.list.MoveToFront(entry.element)
}

// ActivityMonitoredConn wraps a net.Conn, adding logic to deal with
// events triggered by I/O activity.
//
// When an inactivity timeout is specified, the network I/O will
// timeout after the specified period of read inactivity. Optionally,
// ActivityMonitoredConn will also consider the connection active when
// data is written to it.
//
// When a LRUConnsEntry is specified, then the LRU entry is promoted on
// either a successful read or write.
//
type ActivityMonitoredConn struct {
	net.Conn
	inactivityTimeout    time.Duration
	activeOnWrite        bool
	startTime            int64
	lastReadActivityTime int64
	lruEntry             *LRUConnsEntry
}

func NewActivityMonitoredConn(
	conn net.Conn,
	inactivityTimeout time.Duration,
	activeOnWrite bool,
	lruEntry *LRUConnsEntry) (*ActivityMonitoredConn, error) {

	if inactivityTimeout > 0 {
		err := conn.SetDeadline(time.Now().Add(inactivityTimeout))
		if err != nil {
			return nil, psiphon.ContextError(err)
		}
	}

	now := time.Now().UnixNano()

	return &ActivityMonitoredConn{
		Conn:                 conn,
		inactivityTimeout:    inactivityTimeout,
		activeOnWrite:        activeOnWrite,
		startTime:            now,
		lastReadActivityTime: now,
		lruEntry:             lruEntry,
	}, nil
}

// GetStartTime gets the time when the ActivityMonitoredConn was
// initialized.
func (conn *ActivityMonitoredConn) GetStartTime() time.Time {
	return time.Unix(0, conn.startTime)
}

// GetActiveDuration returns the time elapsed between the initialization
// of the ActivityMonitoredConn and the last Read. Only reads are used
// for this calculation since writes may succeed locally due to buffering.
func (conn *ActivityMonitoredConn) GetActiveDuration() time.Duration {
	return time.Duration(atomic.LoadInt64(&conn.lastReadActivityTime) - conn.startTime)
}

func (conn *ActivityMonitoredConn) Read(buffer []byte) (int, error) {
	n, err := conn.Conn.Read(buffer)
	if err == nil {

		if conn.inactivityTimeout > 0 {
			err = conn.Conn.SetDeadline(time.Now().Add(conn.inactivityTimeout))
			if err != nil {
				return n, psiphon.ContextError(err)
			}
		}
		if conn.lruEntry != nil {
			conn.lruEntry.Touch()
		}

		atomic.StoreInt64(&conn.lastReadActivityTime, time.Now().UnixNano())

	}
	// Note: no context error to preserve error type
	return n, err
}

func (conn *ActivityMonitoredConn) Write(buffer []byte) (int, error) {
	n, err := conn.Conn.Write(buffer)
	if err == nil && conn.activeOnWrite {

		if conn.inactivityTimeout > 0 {
			err = conn.Conn.SetDeadline(time.Now().Add(conn.inactivityTimeout))
			if err != nil {
				return n, psiphon.ContextError(err)
			}
		}

		if conn.lruEntry != nil {
			conn.lruEntry.Touch()
		}

	}
	// Note: no context error to preserve error type
	return n, err
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
func NewThrottledConn(
	conn net.Conn,
	unlimitedReadBytes, limitReadBytesPerSecond,
	unlimitedWriteBytes, limitWriteBytesPerSecond int64) *ThrottledConn {

	// When no limit is specified, the rate limited reader/writer
	// is simply the base reader/writer.

	var reader io.Reader
	if limitReadBytesPerSecond == 0 {
		reader = conn
	} else {
		reader = ratelimit.Reader(conn,
			ratelimit.NewBucketWithRate(
				float64(limitReadBytesPerSecond), limitReadBytesPerSecond))
	}

	var writer io.Writer
	if limitWriteBytesPerSecond == 0 {
		writer = conn
	} else {
		writer = ratelimit.Writer(conn,
			ratelimit.NewBucketWithRate(
				float64(limitWriteBytesPerSecond), limitWriteBytesPerSecond))
	}

	return &ThrottledConn{
		Conn:                conn,
		unlimitedReadBytes:  unlimitedReadBytes,
		limitingReads:       0,
		limitedReader:       reader,
		unlimitedWriteBytes: unlimitedWriteBytes,
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
