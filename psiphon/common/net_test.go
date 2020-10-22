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

	"github.com/Psiphon-Labs/goarista/monotime"
	"github.com/miekg/dns"
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

func TestBurstMonitoredConn(t *testing.T) {

	burstDeadline := 100 * time.Millisecond
	upstreamThresholdBytes := int64(100000)
	downstreamThresholdBytes := int64(1000000)

	baseTime := time.Now()

	dummy := &dummyConn{}

	conn := NewBurstMonitoredConn(
		dummy,
		burstDeadline,
		upstreamThresholdBytes,
		burstDeadline,
		downstreamThresholdBytes)

	// Simulate 128KB/s up, 1MB/s down; transmit >= min bytes in segments; sets "first" and "min"

	dummy.SetRateLimits(131072, 1048576)

	segments := 10

	b := make([]byte, int(upstreamThresholdBytes)/segments)
	firstReadStart := time.Now()
	for i := 0; i < segments; i++ {
		conn.Read(b)
	}
	firstReadEnd := time.Now()

	b = make([]byte, int(downstreamThresholdBytes)/segments)
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
	conn.Read(make([]byte, upstreamThresholdBytes))
	maxReadEnd := time.Now()

	maxWriteStart := time.Now()
	conn.Write(make([]byte, downstreamThresholdBytes))
	maxWriteEnd := time.Now()

	time.Sleep(burstDeadline * 2)

	// Simulate 256Kb/s up, 2MB/s down;, transmit >= min bytes; sets "last"

	dummy.SetRateLimits(262144, 2097152)

	lastReadStart := time.Now()
	conn.Read(make([]byte, upstreamThresholdBytes))
	lastReadEnd := time.Now()

	lastWriteStart := time.Now()
	conn.Write(make([]byte, downstreamThresholdBytes))
	lastWriteEnd := time.Now()

	time.Sleep(burstDeadline * 2)

	conn.Close()

	t.Logf("upstream first:    %d bytes in %s; %d bytes/s",
		conn.upstreamBursts.first.bytes, conn.upstreamBursts.first.duration(), conn.upstreamBursts.first.rate())
	t.Logf("upstream last:     %d bytes in %s; %d bytes/s",
		conn.upstreamBursts.last.bytes, conn.upstreamBursts.last.duration(), conn.upstreamBursts.last.rate())
	t.Logf("upstream min:      %d bytes in %s; %d bytes/s",
		conn.upstreamBursts.min.bytes, conn.upstreamBursts.min.duration(), conn.upstreamBursts.min.rate())
	t.Logf("upstream max:      %d bytes in %s; %d bytes/s",
		conn.upstreamBursts.max.bytes, conn.upstreamBursts.max.duration(), conn.upstreamBursts.max.rate())
	t.Logf("downstream first:  %d bytes in %s; %d bytes/s",
		conn.downstreamBursts.first.bytes, conn.downstreamBursts.first.duration(), conn.downstreamBursts.first.rate())
	t.Logf("downstream last:   %d bytes in %s; %d bytes/s",
		conn.downstreamBursts.last.bytes, conn.downstreamBursts.last.duration(), conn.downstreamBursts.last.rate())
	t.Logf("downstream min:    %d bytes in %s; %d bytes/s",
		conn.downstreamBursts.min.bytes, conn.downstreamBursts.min.duration(), conn.downstreamBursts.min.rate())
	t.Logf("downstream max:    %d bytes in %s; %d bytes/s",
		conn.downstreamBursts.max.bytes, conn.downstreamBursts.max.duration(), conn.downstreamBursts.max.rate())

	logFields := conn.GetMetrics(baseTime)

	if len(logFields) != 32 {
		t.Errorf("unexpected metric count: %d", len(logFields))
	}

	for name, expectedValue := range map[string]int64{
		"burst_upstream_first_offset":     int64(firstReadStart.Sub(baseTime) / time.Millisecond),
		"burst_upstream_first_duration":   int64(firstReadEnd.Sub(firstReadStart) / time.Millisecond),
		"burst_upstream_first_bytes":      upstreamThresholdBytes,
		"burst_upstream_first_rate":       131072,
		"burst_upstream_last_offset":      int64(lastReadStart.Sub(baseTime) / time.Millisecond),
		"burst_upstream_last_duration":    int64(lastReadEnd.Sub(lastReadStart) / time.Millisecond),
		"burst_upstream_last_bytes":       upstreamThresholdBytes,
		"burst_upstream_last_rate":        262144,
		"burst_upstream_min_offset":       int64(firstReadStart.Sub(baseTime) / time.Millisecond),
		"burst_upstream_min_duration":     int64(firstReadEnd.Sub(firstReadStart) / time.Millisecond),
		"burst_upstream_min_bytes":        upstreamThresholdBytes,
		"burst_upstream_min_rate":         131072,
		"burst_upstream_max_offset":       int64(maxReadStart.Sub(baseTime) / time.Millisecond),
		"burst_upstream_max_duration":     int64(maxReadEnd.Sub(maxReadStart) / time.Millisecond),
		"burst_upstream_max_bytes":        upstreamThresholdBytes,
		"burst_upstream_max_rate":         524288,
		"burst_downstream_first_offset":   int64(firstWriteStart.Sub(baseTime) / time.Millisecond),
		"burst_downstream_first_duration": int64(firstWriteEnd.Sub(firstWriteStart) / time.Millisecond),
		"burst_downstream_first_bytes":    downstreamThresholdBytes,
		"burst_downstream_first_rate":     1048576,
		"burst_downstream_last_offset":    int64(lastWriteStart.Sub(baseTime) / time.Millisecond),
		"burst_downstream_last_duration":  int64(lastWriteEnd.Sub(lastWriteStart) / time.Millisecond),
		"burst_downstream_last_bytes":     downstreamThresholdBytes,
		"burst_downstream_last_rate":      2097152,
		"burst_downstream_min_offset":     int64(firstWriteStart.Sub(baseTime) / time.Millisecond),
		"burst_downstream_min_duration":   int64(firstWriteEnd.Sub(firstWriteStart) / time.Millisecond),
		"burst_downstream_min_bytes":      downstreamThresholdBytes,
		"burst_downstream_min_rate":       1048576,
		"burst_downstream_max_offset":     int64(maxWriteStart.Sub(baseTime) / time.Millisecond),
		"burst_downstream_max_duration":   int64(maxWriteEnd.Sub(maxWriteStart) / time.Millisecond),
		"burst_downstream_max_bytes":      downstreamThresholdBytes,
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
		minAcceptable := int64(float64(expectedValue) * 0.95)
		maxAcceptable := int64(float64(expectedValue) * 1.05)
		if valueInt64 < minAcceptable || valueInt64 > maxAcceptable {
			t.Errorf("unexpected metric value: %s (%v <= %v <= %v)",
				name, minAcceptable, valueInt64, maxAcceptable)
			continue
		}
	}
}

func TestIsBogon(t *testing.T) {
	if IsBogon(net.ParseIP("8.8.8.8")) {
		t.Errorf("unexpected bogon")
	}
	if !IsBogon(net.ParseIP("127.0.0.1")) {
		t.Errorf("unexpected non-bogon")
	}
	if !IsBogon(net.ParseIP("192.168.0.1")) {
		t.Errorf("unexpected non-bogon")
	}
	if !IsBogon(net.ParseIP("::1")) {
		t.Errorf("unexpected non-bogon")
	}
	if !IsBogon(net.ParseIP("fc00::")) {
		t.Errorf("unexpected non-bogon")
	}
}

func BenchmarkIsBogon(b *testing.B) {
	for i := 0; i < b.N; i++ {
		IsBogon(net.ParseIP("8.8.8.8"))
	}
}

func makeDNSQuery(domain string) ([]byte, error) {
	query := new(dns.Msg)
	query.SetQuestion(domain, dns.TypeA)
	query.RecursionDesired = true
	msg, err := query.Pack()
	if err != nil {
		return nil, err
	}
	return msg, nil
}

func TestParseDNSQuestion(t *testing.T) {

	domain := dns.Fqdn("www.example.com")
	msg, err := makeDNSQuery(domain)
	if err != nil {
		t.Fatalf("makeDNSQuery failed: %s", err)
	}

	checkDomain, err := ParseDNSQuestion(msg)
	if err != nil {
		t.Fatalf("ParseDNSQuestion failed: %s", err)
	}

	if checkDomain != domain {
		t.Fatalf("unexpected domain")
	}
}

func BenchmarkParseDNSQuestion(b *testing.B) {

	domain := dns.Fqdn("www.example.com")
	msg, err := makeDNSQuery(domain)
	if err != nil {
		b.Fatalf("makeDNSQuery failed: %s", err)
	}

	for i := 0; i < b.N; i++ {
		ParseDNSQuestion(msg)
	}
}

type dummyConn struct {
	t                   *testing.T
	timeout             *time.Timer
	readBytesPerSecond  int64
	writeBytesPerSecond int64
	isClosed            int32
}

func (c *dummyConn) Read(b []byte) (n int, err error) {
	if c.readBytesPerSecond > 0 {
		sleep := time.Duration(float64(int64(len(b))*int64(time.Second)) / float64(c.readBytesPerSecond))
		time.Sleep(sleep)
	}
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
	if c.writeBytesPerSecond > 0 {
		sleep := time.Duration(float64(int64(len(b))*int64(time.Second)) / float64(c.writeBytesPerSecond))
		time.Sleep(sleep)
	}
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
	duration := time.Until(t)
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

func (c *dummyConn) SetRateLimits(readBytesPerSecond, writeBytesPerSecond int64) {
	c.readBytesPerSecond = readBytesPerSecond
	c.writeBytesPerSecond = writeBytesPerSecond
}
