/*
 * Copyright (c) 2020, Psiphon Inc.
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
	"sync/atomic"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/monotime"
)

// ActivityMonitoredConn wraps a net.Conn, adding logic to deal with events
// triggered by I/O activity.
//
// ActivityMonitoredConn uses lock-free concurrency synronization, avoiding an
// additional mutex resource, making it suitable for wrapping many net.Conns
// (e.g, each Psiphon port forward).
//
// When an inactivity timeout is specified, the network I/O will timeout after
// the specified period of read inactivity. Optionally, for the purpose of
// inactivity only, ActivityMonitoredConn will also consider the connection
// active when data is written to it.
//
// When a LRUConnsEntry is specified, then the LRU entry is promoted on either
// a successful read or write.
//
// When an ActivityUpdater is set, then its UpdateActivity method is called on
// each read and write with the number of bytes transferred. The
// durationNanoseconds, which is the time since the last read, is reported
// only on reads.
type ActivityMonitoredConn struct {
	net.Conn
	monotonicStartTime   int64
	lastReadActivityTime atomic.Int64
	realStartTime        time.Time
	inactivityTimeout    time.Duration
	activeOnWrite        bool
	activityUpdaters     []ActivityUpdater
	lruEntry             *LRUConnsEntry
}

// ActivityUpdater defines an interface for receiving updates for
// ActivityMonitoredConn activity. Values passed to UpdateProgress are bytes
// transferred and conn duration since the previous UpdateProgress.
type ActivityUpdater interface {
	UpdateProgress(bytesRead, bytesWritten, durationNanoseconds int64)
}

// NewActivityMonitoredConn creates a new ActivityMonitoredConn.
func NewActivityMonitoredConn(
	conn net.Conn,
	inactivityTimeout time.Duration,
	activeOnWrite bool,
	lruEntry *LRUConnsEntry,
	activityUpdaters ...ActivityUpdater) (*ActivityMonitoredConn, error) {

	if inactivityTimeout > 0 {
		err := conn.SetDeadline(time.Now().Add(inactivityTimeout))
		if err != nil {
			return nil, errors.Trace(err)
		}
	}

	// The "monotime" package is still used here as its time value is an int64,
	// which is compatible with atomic operations.

	now := int64(monotime.Now())

	activityConn := &ActivityMonitoredConn{
		Conn:               conn,
		inactivityTimeout:  inactivityTimeout,
		activeOnWrite:      activeOnWrite,
		realStartTime:      time.Now(),
		monotonicStartTime: now,
		lruEntry:           lruEntry,
		activityUpdaters:   activityUpdaters,
	}
	activityConn.lastReadActivityTime.Store(now)
	return activityConn, nil
}

// GetStartTime gets the time when the ActivityMonitoredConn was initialized.
// Reported time is UTC.
func (conn *ActivityMonitoredConn) GetStartTime() time.Time {
	return conn.realStartTime.UTC()
}

// GetActiveDuration returns the time elapsed between the initialization of
// the ActivityMonitoredConn and the last Read. Only reads are used for this
// calculation since writes may succeed locally due to buffering.
func (conn *ActivityMonitoredConn) GetActiveDuration() time.Duration {
	return time.Duration(conn.lastReadActivityTime.Load() - conn.monotonicStartTime)
}

func (conn *ActivityMonitoredConn) Read(buffer []byte) (int, error) {
	n, err := conn.Conn.Read(buffer)
	if n > 0 {

		if conn.inactivityTimeout > 0 {
			err = conn.Conn.SetDeadline(time.Now().Add(conn.inactivityTimeout))
			if err != nil {
				return n, errors.Trace(err)
			}
		}

		lastReadActivityTime := conn.lastReadActivityTime.Load()
		readActivityTime := int64(monotime.Now())

		conn.lastReadActivityTime.Store(readActivityTime)

		for _, activityUpdater := range conn.activityUpdaters {
			activityUpdater.UpdateProgress(
				int64(n), 0, readActivityTime-lastReadActivityTime)
		}

		if conn.lruEntry != nil {
			conn.lruEntry.Touch()
		}
	}
	// Note: no trace error to preserve error type
	return n, err
}

func (conn *ActivityMonitoredConn) Write(buffer []byte) (int, error) {
	n, err := conn.Conn.Write(buffer)
	if n > 0 {

		// Bytes written are reported regardless of activeOnWrite. Inactivity
		// deadline extension and LRU updates are conditional on activeOnWrite.

		for _, activityUpdater := range conn.activityUpdaters {
			activityUpdater.UpdateProgress(0, int64(n), 0)
		}

		if conn.activeOnWrite {

			if conn.inactivityTimeout > 0 {
				err = conn.Conn.SetDeadline(time.Now().Add(conn.inactivityTimeout))
				if err != nil {
					return n, errors.Trace(err)
				}
			}

			if conn.lruEntry != nil {
				conn.lruEntry.Touch()
			}
		}
	}
	// Note: no trace error to preserve error type
	return n, err
}

// IsClosed implements the Closer iterface. The return value indicates whether
// the underlying conn has been closed.
func (conn *ActivityMonitoredConn) IsClosed() bool {
	closer, ok := conn.Conn.(Closer)
	if !ok {
		return false
	}
	return closer.IsClosed()
}
