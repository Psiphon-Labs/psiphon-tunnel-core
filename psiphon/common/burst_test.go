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
	"testing"
	"time"
)

func TestBurstMonitoredConn(t *testing.T) {

	upstreamTargetBytes := int64(100000)
	downstreamTargetBytes := int64(1000000)
	burstDeadline := 1 * time.Second

	baseTime := time.Now()

	dummy := &dummyConn{}

	conn := NewBurstMonitoredConn(
		dummy,
		true,
		upstreamTargetBytes,
		burstDeadline,
		downstreamTargetBytes,
		burstDeadline)

	// Simulate 128KB/s up, 1MB/s down; transmit >= min bytes in segments; sets "first" and "min"

	dummy.SetRateLimits(131072, 1048576)

	segments := 10

	b := make([]byte, int(upstreamTargetBytes)/segments)
	firstReadStart := time.Now()
	for i := 0; i < segments; i++ {
		conn.Read(b)
	}
	firstReadEnd := time.Now()

	b = make([]byte, int(downstreamTargetBytes)/segments)
	firstWriteStart := time.Now()
	for i := 0; i < segments; i++ {
		conn.Write(b)
	}
	firstWriteEnd := time.Now()

	time.Sleep(burstDeadline * 2)

	// Simulate 1MB/s up, 10MB/s down; repeatedly transmit < min bytes before deadline; ignored

	dummy.SetRateLimits(1048576, 10485760)

	b = make([]byte, 1)
	segments = 1000
	for i := 0; i < segments; i++ {
		conn.Read(b)
	}
	for i := 0; i < segments; i++ {
		conn.Write(b)
	}

	time.Sleep(burstDeadline * 2)

	// Simulate 512Kb/s up, 5MB/s down; transmit >= min bytes; sets "max"

	dummy.SetRateLimits(524288, 5242880)

	maxReadStart := time.Now()
	conn.Read(make([]byte, upstreamTargetBytes))
	maxReadEnd := time.Now()

	maxWriteStart := time.Now()
	conn.Write(make([]byte, downstreamTargetBytes))
	maxWriteEnd := time.Now()

	time.Sleep(burstDeadline * 2)

	// Simulate 256Kb/s up, 2MB/s down;, transmit >= min bytes; sets "last"

	dummy.SetRateLimits(262144, 2097152)

	lastReadStart := time.Now()
	conn.Read(make([]byte, upstreamTargetBytes))
	lastReadEnd := time.Now()

	lastWriteStart := time.Now()
	conn.Write(make([]byte, downstreamTargetBytes))
	lastWriteEnd := time.Now()

	time.Sleep(burstDeadline * 2)

	conn.Close()

	t.Logf("upstream first:    %d bytes in %s; %d bytes/s",
		conn.readBursts.first.bytes, conn.readBursts.first.duration(), conn.readBursts.first.rate())
	t.Logf("upstream last:     %d bytes in %s; %d bytes/s",
		conn.readBursts.last.bytes, conn.readBursts.last.duration(), conn.readBursts.last.rate())
	t.Logf("upstream min:      %d bytes in %s; %d bytes/s",
		conn.readBursts.min.bytes, conn.readBursts.min.duration(), conn.readBursts.min.rate())
	t.Logf("upstream max:      %d bytes in %s; %d bytes/s",
		conn.readBursts.max.bytes, conn.readBursts.max.duration(), conn.readBursts.max.rate())
	t.Logf("downstream first:  %d bytes in %s; %d bytes/s",
		conn.writeBursts.first.bytes, conn.writeBursts.first.duration(), conn.writeBursts.first.rate())
	t.Logf("downstream last:   %d bytes in %s; %d bytes/s",
		conn.writeBursts.last.bytes, conn.writeBursts.last.duration(), conn.writeBursts.last.rate())
	t.Logf("downstream min:    %d bytes in %s; %d bytes/s",
		conn.writeBursts.min.bytes, conn.writeBursts.min.duration(), conn.writeBursts.min.rate())
	t.Logf("downstream max:    %d bytes in %s; %d bytes/s",
		conn.writeBursts.max.bytes, conn.writeBursts.max.duration(), conn.writeBursts.max.rate())

	logFields := conn.GetMetrics(baseTime)

	if len(logFields) != 32 {
		t.Errorf("unexpected metric count: %d", len(logFields))
	}

	for name, expectedValue := range map[string]int64{
		"burst_upstream_first_offset":     int64(firstReadStart.Sub(baseTime) / time.Millisecond),
		"burst_upstream_first_duration":   int64(firstReadEnd.Sub(firstReadStart) / time.Millisecond),
		"burst_upstream_first_bytes":      upstreamTargetBytes,
		"burst_upstream_first_rate":       131072,
		"burst_upstream_last_offset":      int64(lastReadStart.Sub(baseTime) / time.Millisecond),
		"burst_upstream_last_duration":    int64(lastReadEnd.Sub(lastReadStart) / time.Millisecond),
		"burst_upstream_last_bytes":       upstreamTargetBytes,
		"burst_upstream_last_rate":        262144,
		"burst_upstream_min_offset":       int64(firstReadStart.Sub(baseTime) / time.Millisecond),
		"burst_upstream_min_duration":     int64(firstReadEnd.Sub(firstReadStart) / time.Millisecond),
		"burst_upstream_min_bytes":        upstreamTargetBytes,
		"burst_upstream_min_rate":         131072,
		"burst_upstream_max_offset":       int64(maxReadStart.Sub(baseTime) / time.Millisecond),
		"burst_upstream_max_duration":     int64(maxReadEnd.Sub(maxReadStart) / time.Millisecond),
		"burst_upstream_max_bytes":        upstreamTargetBytes,
		"burst_upstream_max_rate":         524288,
		"burst_downstream_first_offset":   int64(firstWriteStart.Sub(baseTime) / time.Millisecond),
		"burst_downstream_first_duration": int64(firstWriteEnd.Sub(firstWriteStart) / time.Millisecond),
		"burst_downstream_first_bytes":    downstreamTargetBytes,
		"burst_downstream_first_rate":     1048576,
		"burst_downstream_last_offset":    int64(lastWriteStart.Sub(baseTime) / time.Millisecond),
		"burst_downstream_last_duration":  int64(lastWriteEnd.Sub(lastWriteStart) / time.Millisecond),
		"burst_downstream_last_bytes":     downstreamTargetBytes,
		"burst_downstream_last_rate":      2097152,
		"burst_downstream_min_offset":     int64(firstWriteStart.Sub(baseTime) / time.Millisecond),
		"burst_downstream_min_duration":   int64(firstWriteEnd.Sub(firstWriteStart) / time.Millisecond),
		"burst_downstream_min_bytes":      downstreamTargetBytes,
		"burst_downstream_min_rate":       1048576,
		"burst_downstream_max_offset":     int64(maxWriteStart.Sub(baseTime) / time.Millisecond),
		"burst_downstream_max_duration":   int64(maxWriteEnd.Sub(maxWriteStart) / time.Millisecond),
		"burst_downstream_max_bytes":      downstreamTargetBytes,
		"burst_downstream_max_rate":       5242880,
	} {
		value, ok := logFields[name]
		if !ok {
			t.Errorf("missing expected metric: %s", name)
			continue
		}
		valueInt64, ok := value.(int64)
		if !ok {
			t.Errorf("missing expected metric type: %s (%T)", name, value)
			continue
		}
		minAcceptable := int64(float64(expectedValue) * 0.90)
		maxAcceptable := int64(float64(expectedValue) * 1.10)
		if valueInt64 < minAcceptable || valueInt64 > maxAcceptable {
			t.Errorf("unexpected metric value: %s (%v <= %v <= %v)",
				name, minAcceptable, valueInt64, maxAcceptable)
			continue
		}
	}
}
