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
	"testing/iotest"
	"time"

	"github.com/Psiphon-Labs/goarista/monotime"
)

func TestActivityMonitoredConn(t *testing.T) {
	buffer := make([]byte, 1024)

	conn, err := NewActivityMonitoredConn(
		&dummyConn{},
		200*time.Millisecond,
		true,
		nil,
		nil)
	if err != nil {
		t.Fatalf("NewActivityMonitoredConn failed")
	}

	realStartTime := time.Now().UTC()

	monotonicStartTime := monotime.Now()

	time.Sleep(100 * time.Millisecond)

	_, err = conn.Read(buffer)
	if err != nil {
		t.Fatalf("read before initial timeout failed")
	}

	time.Sleep(100 * time.Millisecond)

	_, err = conn.Read(buffer)
	if err != nil {
		t.Fatalf("previous read failed to extend timeout")
	}

	time.Sleep(100 * time.Millisecond)

	_, err = conn.Write(buffer)
	if err != nil {
		t.Fatalf("previous read failed to extend timeout")
	}

	time.Sleep(100 * time.Millisecond)

	_, err = conn.Read(buffer)
	if err != nil {
		t.Fatalf("previous write failed to extend timeout")
	}

	lastSuccessfulReadTime := monotime.Now()

	time.Sleep(100 * time.Millisecond)

	_, err = conn.Write(buffer)
	if err != nil {
		t.Fatalf("previous read failed to extend timeout")
	}

	time.Sleep(300 * time.Millisecond)

	_, err = conn.Read(buffer)
	if err != iotest.ErrTimeout {
		t.Fatalf("failed to timeout")
	}

	if realStartTime.Round(time.Millisecond) != conn.GetStartTime().Round(time.Millisecond) {
		t.Fatalf("unexpected GetStartTime")
	}

	diff := lastSuccessfulReadTime.Sub(monotonicStartTime).Nanoseconds() - conn.GetActiveDuration().Nanoseconds()
	if diff < 0 {
		diff = -diff
	}
	if diff > (1 * time.Millisecond).Nanoseconds() {
		t.Fatalf("unexpected GetActiveDuration")
	}
}

func TestActivityMonitoredLRUConns(t *testing.T) {

	lruConns := NewLRUConns()

	dummy1 := &dummyConn{}
	conn1, err := NewActivityMonitoredConn(dummy1, 0, true, nil, lruConns.Add(dummy1))
	if err != nil {
		t.Fatalf("NewActivityMonitoredConn failed")
	}

	dummy2 := &dummyConn{}
	conn2, err := NewActivityMonitoredConn(dummy2, 0, true, nil, lruConns.Add(dummy2))
	if err != nil {
		t.Fatalf("NewActivityMonitoredConn failed")
	}

	dummy3 := &dummyConn{}
	conn3, err := NewActivityMonitoredConn(dummy3, 0, true, nil, lruConns.Add(dummy3))
	if err != nil {
		t.Fatalf("NewActivityMonitoredConn failed")
	}

	buffer := make([]byte, 1024)

	conn1.Read(buffer)
	conn2.Read(buffer)
	conn3.Read(buffer)

	conn3.Write(buffer)
	conn2.Write(buffer)
	conn1.Write(buffer)

	if dummy1.IsClosed() || dummy2.IsClosed() || dummy3.IsClosed() {
		t.Fatalf("unexpected IsClosed state")
	}

	lruConns.CloseOldest()

	if dummy1.IsClosed() || dummy2.IsClosed() || !dummy3.IsClosed() {
		t.Fatalf("unexpected IsClosed state")
	}

	lruConns.CloseOldest()

	if dummy1.IsClosed() || !dummy2.IsClosed() || !dummy3.IsClosed() {
		t.Fatalf("unexpected IsClosed state")
	}

	lruConns.CloseOldest()

	if !dummy1.IsClosed() || !dummy2.IsClosed() || !dummy3.IsClosed() {
		t.Fatalf("unexpected IsClosed state")
	}
}
