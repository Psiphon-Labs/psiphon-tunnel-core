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
	"sync/atomic"
	"testing"
	"testing/iotest"
	"time"

	"github.com/Psiphon-Inc/goarista/monotime"
)

type dummyConn struct {
	t        *testing.T
	timeout  *time.Timer
	isClosed int32
}

func (c *dummyConn) Read(b []byte) (n int, err error) {
	if c.timeout != nil {
		select {
		case <-c.timeout.C:
			return 0, iotest.ErrTimeout
		default:
		}
	}
	return len(b), nil
}

func (c *dummyConn) Write(b []byte) (n int, err error) {
	if c.timeout != nil {
		select {
		case <-c.timeout.C:
			return 0, iotest.ErrTimeout
		default:
		}
	}
	return len(b), nil
}

func (c *dummyConn) Close() error {
	atomic.StoreInt32(&c.isClosed, 1)
	return nil
}

func (c *dummyConn) IsClosed() bool {
	return atomic.LoadInt32(&c.isClosed) == 1
}

func (c *dummyConn) LocalAddr() net.Addr {
	c.t.Fatal("LocalAddr not implemented")
	return nil
}

func (c *dummyConn) RemoteAddr() net.Addr {
	c.t.Fatal("RemoteAddr not implemented")
	return nil
}

func (c *dummyConn) SetDeadline(t time.Time) error {
	duration := t.Sub(time.Now())
	if c.timeout == nil {
		c.timeout = time.NewTimer(duration)
	} else {
		if !c.timeout.Stop() {
			<-c.timeout.C
		}
		c.timeout.Reset(duration)
	}
	return nil
}

func (c *dummyConn) SetReadDeadline(t time.Time) error {
	c.t.Fatal("SetReadDeadline not implemented")
	return nil
}

func (c *dummyConn) SetWriteDeadline(t time.Time) error {
	c.t.Fatal("SetWriteDeadline not implemented")
	return nil
}

func TestActivityMonitoredConn(t *testing.T) {
	buffer := make([]byte, 1024)

	conn, err := NewActivityMonitoredConn(
		&dummyConn{},
		200*time.Millisecond,
		true,
		nil)
	if err != nil {
		t.Fatalf("NewActivityMonitoredConn failed")
	}

	realStartTime := time.Now()

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

	if int64(lastSuccessfulReadTime)/int64(time.Millisecond) !=
		int64(conn.GetLastActivityMonotime())/int64(time.Millisecond) {
		t.Fatalf("unexpected GetLastActivityTime")
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
	conn1, err := NewActivityMonitoredConn(dummy1, 0, true, lruConns.Add(dummy1))
	if err != nil {
		t.Fatalf("NewActivityMonitoredConn failed")
	}

	dummy2 := &dummyConn{}
	conn2, err := NewActivityMonitoredConn(dummy2, 0, true, lruConns.Add(dummy2))
	if err != nil {
		t.Fatalf("NewActivityMonitoredConn failed")
	}

	dummy3 := &dummyConn{}
	conn3, err := NewActivityMonitoredConn(dummy3, 0, true, lruConns.Add(dummy3))
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

func TestLRUConns(t *testing.T) {
	lruConns := NewLRUConns()

	dummy1 := &dummyConn{}
	entry1 := lruConns.Add(dummy1)

	dummy2 := &dummyConn{}
	entry2 := lruConns.Add(dummy2)

	dummy3 := &dummyConn{}
	entry3 := lruConns.Add(dummy3)

	entry3.Touch()
	entry2.Touch()
	entry1.Touch()

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

	entry1.Remove()

	lruConns.CloseOldest()

	if dummy1.IsClosed() || !dummy2.IsClosed() || !dummy3.IsClosed() {
		t.Fatalf("unexpected IsClosed state")
	}
}
