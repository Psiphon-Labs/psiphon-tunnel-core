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
	"sync"
	"time"
)

// BurstMonitoredConn wraps a net.Conn and monitors for data transfer bursts.
// Upstream (read) and downstream (write) bursts are tracked independently.
//
// A burst is defined as a transfer of "target" bytes, possibly across
// multiple I/O operations, where the total time elapsed does not exceed
// "deadline". Both a non-zero deadline and theshold must be set to enable
// monitoring. Four bursts are reported: the first, the last, the min (by
// rate) and max.
//
// The burst monitoring is heuristical in nature and may not capture all
// bursts. The reported rates will be more accurate for larger target values
// and shorter deadlines, but these settings may fail to register bursts on
// slower connections. Tune the deadline/target as required. The threshold
// should be set to account for buffering (e.g, the local host socket
// send/receive buffer) but this is not enforced by BurstMonitoredConn.
//
// Overhead: BurstMonitoredConn adds mutexes but does not use timers.
type BurstMonitoredConn struct {
	net.Conn
	isServer         bool
	readTargetBytes  int64
	readDeadline     time.Duration
	writeTargetBytes int64
	writeDeadline    time.Duration

	readMutex        sync.Mutex
	currentReadBurst burst
	readBursts       burstHistory

	writeMutex        sync.Mutex
	currentWriteBurst burst
	writeBursts       burstHistory
}

// NewBurstMonitoredConn creates a new BurstMonitoredConn.
func NewBurstMonitoredConn(
	conn net.Conn,
	isServer bool,
	upstreamTargetBytes int64,
	upstreamDeadline time.Duration,
	downstreamTargetBytes int64,
	downstreamDeadline time.Duration) *BurstMonitoredConn {

	burstConn := &BurstMonitoredConn{
		Conn:     conn,
		isServer: isServer,
	}

	if isServer {
		burstConn.readTargetBytes = upstreamTargetBytes
		burstConn.readDeadline = upstreamDeadline
		burstConn.writeTargetBytes = downstreamTargetBytes
		burstConn.writeDeadline = downstreamDeadline
	} else {
		burstConn.readTargetBytes = downstreamTargetBytes
		burstConn.readDeadline = downstreamDeadline
		burstConn.writeTargetBytes = upstreamTargetBytes
		burstConn.writeDeadline = upstreamDeadline
	}

	return burstConn
}

type burst struct {
	startTime time.Time
	endTime   time.Time
	bytes     int64
}

func (b *burst) isZero() bool {
	return b.startTime.IsZero()
}

func (b *burst) offset(baseTime time.Time) time.Duration {
	offset := b.startTime.Sub(baseTime)
	if offset <= 0 {
		return 0
	}
	return offset
}

func (b *burst) duration() time.Duration {
	duration := b.endTime.Sub(b.startTime)
	if duration <= 0 {
		return 0
	}
	return duration
}

func (b *burst) rate() int64 {
	duration := b.duration()
	if duration <= 0 {
		return 0
	}
	return int64(
		(float64(b.bytes) * float64(time.Second)) /
			float64(duration))
}

func (b *burst) reset() {
	b.startTime = time.Time{}
	b.endTime = time.Time{}
	b.bytes = 0
}

type burstHistory struct {
	first burst
	last  burst
	min   burst
	max   burst
}

func (conn *BurstMonitoredConn) Read(buffer []byte) (int, error) {

	if conn.readTargetBytes <= 0 || conn.readDeadline <= 0 {
		return conn.Conn.Read(buffer)
	}

	start := time.Now()
	n, err := conn.Conn.Read(buffer)
	end := time.Now()

	if n > 0 {
		conn.readMutex.Lock()
		conn.updateBurst(
			start,
			end,
			int64(n),
			conn.readTargetBytes,
			conn.readDeadline,
			&conn.currentReadBurst,
			&conn.readBursts)
		conn.readMutex.Unlock()
	}

	// Note: no context error to preserve error type
	return n, err
}

func (conn *BurstMonitoredConn) Write(buffer []byte) (int, error) {

	if conn.writeTargetBytes <= 0 || conn.writeDeadline <= 0 {
		return conn.Conn.Write(buffer)
	}

	start := time.Now()
	n, err := conn.Conn.Write(buffer)
	end := time.Now()

	if n > 0 {
		conn.writeMutex.Lock()
		conn.updateBurst(
			start,
			end,
			int64(n),
			conn.writeTargetBytes,
			conn.writeDeadline,
			&conn.currentWriteBurst,
			&conn.writeBursts)
		conn.writeMutex.Unlock()
	}

	// Note: no context error to preserve error type
	return n, err
}

// IsClosed implements the Closer iterface. The return value indicates whether
// the underlying conn has been closed.
func (conn *BurstMonitoredConn) IsClosed() bool {
	closer, ok := conn.Conn.(Closer)
	if !ok {
		return false
	}
	return closer.IsClosed()
}

// GetMetrics returns log fields with burst metrics for the first, last, min
// (by rate), and max bursts for this conn. Time/duration values are reported
// in milliseconds. Rate is reported in bytes per second.
func (conn *BurstMonitoredConn) GetMetrics(baseTime time.Time) LogFields {
	logFields := make(LogFields)

	addFields := func(prefix string, burst *burst) {
		if burst.isZero() {
			return
		}
		logFields[prefix+"offset"] = int64(burst.offset(baseTime) / time.Millisecond)
		logFields[prefix+"duration"] = int64(burst.duration() / time.Millisecond)
		logFields[prefix+"bytes"] = burst.bytes
		logFields[prefix+"rate"] = burst.rate()
	}

	addHistory := func(prefix string, history *burstHistory) {
		addFields(prefix+"first_", &history.first)
		addFields(prefix+"last_", &history.last)
		addFields(prefix+"min_", &history.min)
		addFields(prefix+"max_", &history.max)
	}

	var upstreamBursts *burstHistory
	var downstreamBursts *burstHistory

	if conn.isServer {
		upstreamBursts = &conn.readBursts
		downstreamBursts = &conn.writeBursts
	} else {
		upstreamBursts = &conn.writeBursts
		downstreamBursts = &conn.readBursts
	}

	addHistory("burst_upstream_", upstreamBursts)
	addHistory("burst_downstream_", downstreamBursts)

	return logFields
}

func (conn *BurstMonitoredConn) updateBurst(
	operationStart time.Time,
	operationEnd time.Time,
	operationBytes int64,
	thresholdBytes int64,
	deadline time.Duration,
	currentBurst *burst,
	history *burstHistory) {

	// Assumes the associated mutex is locked.

	if !currentBurst.isZero() &&
		operationEnd.Sub(currentBurst.startTime) > deadline {
		// Partial burst failed to reach the target, so discard it.
		currentBurst.reset()
	}

	if operationEnd.Sub(operationStart) > deadline {
		// Operation exceeded deadline, so no burst.
		return
	}

	if currentBurst.isZero() {
		// Start a new burst.
		currentBurst.startTime = operationStart
	}

	currentBurst.bytes += operationBytes

	if currentBurst.bytes >= thresholdBytes {

		// Burst completed. Bytes in excess of the target are included in the burst
		// for a more accurate rate calculation: we know, roughly, when the last
		// byte arrived, but not the last target byte. For the same reason, we do
		// not count the excess bytes towards a subsequent burst.

		currentBurst.endTime = operationEnd

		if history.first.isZero() {
			history.first = *currentBurst
		}
		history.last = *currentBurst
		rate := currentBurst.rate()
		if history.min.isZero() || history.min.rate() > rate {
			history.min = *currentBurst
		}
		if history.max.isZero() || history.max.rate() < rate {
			history.max = *currentBurst
		}

		currentBurst.reset()
	}
}
