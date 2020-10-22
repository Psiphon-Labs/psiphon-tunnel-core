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
	"container/list"
	"context"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Psiphon-Labs/goarista/monotime"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"github.com/miekg/dns"
	"github.com/wader/filtertransport"
)

// NetDialer mimicks the net.Dialer interface.
type NetDialer interface {
	Dial(network, address string) (net.Conn, error)
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// Closer defines the interface to a type, typically a net.Conn, that can be
// closed.
type Closer interface {
	IsClosed() bool
}

// CloseWriter defines the interface to a type, typically a net.TCPConn, that
// implements CloseWrite.
type CloseWriter interface {
	CloseWrite() error
}

// IrregularIndicator defines the interface for a type, typically a net.Conn,
// that detects and reports irregular conditions during initial network
// connection establishment.
type IrregularIndicator interface {
	IrregularTunnelError() error
}

// UnderlyingTCPAddrSource defines the interface for a type, typically a
// net.Conn, such as a server meek Conn, which has an underlying TCP conn(s),
// providing access to the LocalAddr and RemoteAddr properties of the
// underlying TCP conn.
type UnderlyingTCPAddrSource interface {

	// GetUnderlyingTCPAddrs returns the LocalAddr and RemoteAddr properties of
	// the underlying TCP conn.
	GetUnderlyingTCPAddrs() (*net.TCPAddr, *net.TCPAddr, bool)
}

// FragmentorReplayAccessor defines the interface for accessing replay properties
// of a fragmentor Conn.
type FragmentorReplayAccessor interface {
	SetReplay(*prng.PRNG)
	GetReplay() (*prng.Seed, bool)
}

// TerminateHTTPConnection sends a 404 response to a client and also closes
// the persistent connection.
func TerminateHTTPConnection(
	responseWriter http.ResponseWriter, request *http.Request) {

	http.NotFound(responseWriter, request)

	hijack, ok := responseWriter.(http.Hijacker)
	if !ok {
		return
	}
	conn, buffer, err := hijack.Hijack()
	if err != nil {
		return
	}
	buffer.Flush()
	conn.Close()
}

// IPAddressFromAddr is a helper which extracts an IP address
// from a net.Addr or returns "" if there is no IP address.
func IPAddressFromAddr(addr net.Addr) string {
	ipAddress := ""
	if addr != nil {
		host, _, err := net.SplitHostPort(addr.String())
		if err == nil {
			ipAddress = host
		}
	}
	return ipAddress
}

// PortFromAddr is a helper which extracts a port number from a net.Addr or
// returns 0 if there is no port number.
func PortFromAddr(addr net.Addr) int {
	port := 0
	if addr != nil {
		_, portStr, err := net.SplitHostPort(addr.String())
		if err == nil {
			port, _ = strconv.Atoi(portStr)
		}
	}
	return port
}

// Conns is a synchronized list of Conns that is used to coordinate
// interrupting a set of goroutines establishing connections, or
// close a set of open connections, etc.
// Once the list is closed, no more items may be added to the
// list (unless it is reset).
type Conns struct {
	mutex    sync.Mutex
	isClosed bool
	conns    map[net.Conn]bool
}

// NewConns initializes a new Conns.
func NewConns() *Conns {
	return &Conns{}
}

func (conns *Conns) Reset() {
	conns.mutex.Lock()
	defer conns.mutex.Unlock()
	conns.isClosed = false
	conns.conns = make(map[net.Conn]bool)
}

func (conns *Conns) Add(conn net.Conn) bool {
	conns.mutex.Lock()
	defer conns.mutex.Unlock()
	if conns.isClosed {
		return false
	}
	if conns.conns == nil {
		conns.conns = make(map[net.Conn]bool)
	}
	conns.conns[conn] = true
	return true
}

func (conns *Conns) Remove(conn net.Conn) {
	conns.mutex.Lock()
	defer conns.mutex.Unlock()
	delete(conns.conns, conn)
}

func (conns *Conns) CloseAll() {
	conns.mutex.Lock()
	defer conns.mutex.Unlock()
	conns.isClosed = true
	for conn := range conns.conns {
		conn.Close()
	}
	conns.conns = make(map[net.Conn]bool)
}

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
	if oldest != nil {
		conns.list.Remove(oldest)
	}
	// Release mutex before closing conn
	conns.mutex.Unlock()
	if oldest != nil {
		oldest.Value.(net.Conn).Close()
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
	// Note: 64-bit ints used with atomic operations are placed
	// at the start of struct to ensure 64-bit alignment.
	// (https://golang.org/pkg/sync/atomic/#pkg-note-BUG)
	monotonicStartTime   int64
	lastReadActivityTime int64
	realStartTime        time.Time
	net.Conn
	inactivityTimeout time.Duration
	activeOnWrite     bool
	activityUpdater   ActivityUpdater
	lruEntry          *LRUConnsEntry
}

// ActivityUpdater defines an interface for receiving updates for
// ActivityMonitoredConn activity. Values passed to UpdateProgress are bytes
// transferred and conn duration since the previous UpdateProgress.
type ActivityUpdater interface {
	UpdateProgress(bytesRead, bytesWritten int64, durationNanoseconds int64)
}

// NewActivityMonitoredConn creates a new ActivityMonitoredConn.
func NewActivityMonitoredConn(
	conn net.Conn,
	inactivityTimeout time.Duration,
	activeOnWrite bool,
	activityUpdater ActivityUpdater,
	lruEntry *LRUConnsEntry) (*ActivityMonitoredConn, error) {

	if inactivityTimeout > 0 {
		err := conn.SetDeadline(time.Now().Add(inactivityTimeout))
		if err != nil {
			return nil, errors.Trace(err)
		}
	}

	// The "monotime" package is still used here as its time value is an int64,
	// which is compatible with atomic operations.

	now := int64(monotime.Now())

	return &ActivityMonitoredConn{
		Conn:                 conn,
		inactivityTimeout:    inactivityTimeout,
		activeOnWrite:        activeOnWrite,
		realStartTime:        time.Now(),
		monotonicStartTime:   now,
		lastReadActivityTime: now,
		activityUpdater:      activityUpdater,
		lruEntry:             lruEntry,
	}, nil
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
	return time.Duration(atomic.LoadInt64(&conn.lastReadActivityTime) - conn.monotonicStartTime)
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

		lastReadActivityTime := atomic.LoadInt64(&conn.lastReadActivityTime)
		readActivityTime := int64(monotime.Now())

		atomic.StoreInt64(&conn.lastReadActivityTime, readActivityTime)

		if conn.activityUpdater != nil {
			conn.activityUpdater.UpdateProgress(
				int64(n), 0, readActivityTime-lastReadActivityTime)
		}

		if conn.lruEntry != nil {
			conn.lruEntry.Touch()
		}
	}
	// Note: no context error to preserve error type
	return n, err
}

func (conn *ActivityMonitoredConn) Write(buffer []byte) (int, error) {
	n, err := conn.Conn.Write(buffer)
	if n > 0 && conn.activeOnWrite {

		if conn.inactivityTimeout > 0 {
			err = conn.Conn.SetDeadline(time.Now().Add(conn.inactivityTimeout))
			if err != nil {
				return n, errors.Trace(err)
			}
		}

		if conn.activityUpdater != nil {
			conn.activityUpdater.UpdateProgress(0, int64(n), 0)
		}

		if conn.lruEntry != nil {
			conn.lruEntry.Touch()
		}

	}
	// Note: no context error to preserve error type
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

// BurstMonitoredConn wraps a net.Conn and monitors for data transfer bursts.
// Upstream (read) and downstream (write) bursts are tracked independently.
//
// A burst is defined as a transfer of at least "threshold" bytes, across
// multiple I/O operations where the delay between operations does not exceed
// "deadline". Both a non-zero deadline and theshold must be set to enable
// monitoring. Four bursts are reported: the first, the last, the min (by
// rate) and max.
//
// The reported rates will be more accurate for larger data transfers,
// especially for higher transfer rates. Tune the deadline/threshold as
// required. The threshold should be set to account for buffering (e.g, the
// local host socket send/receive buffer) but this is not enforced by
// BurstMonitoredConn.
//
// Close must be called to complete any outstanding bursts. For complete
// results, call GetMetrics only after Close is called.
//
// Overhead: BurstMonitoredConn adds mutexes but does not use timers.
type BurstMonitoredConn struct {
	net.Conn
	upstreamDeadline         time.Duration
	upstreamThresholdBytes   int64
	downstreamDeadline       time.Duration
	downstreamThresholdBytes int64

	readMutex            sync.Mutex
	currentUpstreamBurst burst
	upstreamBursts       burstHistory

	writeMutex             sync.Mutex
	currentDownstreamBurst burst
	downstreamBursts       burstHistory
}

// NewBurstMonitoredConn creates a new BurstMonitoredConn.
func NewBurstMonitoredConn(
	conn net.Conn,
	upstreamDeadline time.Duration,
	upstreamThresholdBytes int64,
	downstreamDeadline time.Duration,
	downstreamThresholdBytes int64) *BurstMonitoredConn {

	return &BurstMonitoredConn{
		Conn:                     conn,
		upstreamDeadline:         upstreamDeadline,
		upstreamThresholdBytes:   upstreamThresholdBytes,
		downstreamDeadline:       downstreamDeadline,
		downstreamThresholdBytes: downstreamThresholdBytes,
	}
}

type burst struct {
	startTime    time.Time
	lastByteTime time.Time
	bytes        int64
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
	duration := b.lastByteTime.Sub(b.startTime)
	if duration <= 0 {
		return 0
	}
	return duration
}

func (b *burst) rate() int64 {
	return int64(
		(float64(b.bytes) * float64(time.Second)) /
			float64(b.duration()))
}

type burstHistory struct {
	first burst
	last  burst
	min   burst
	max   burst
}

func (conn *BurstMonitoredConn) Read(buffer []byte) (int, error) {

	start := time.Now()
	n, err := conn.Conn.Read(buffer)
	end := time.Now()

	if n > 0 &&
		conn.upstreamDeadline > 0 && conn.upstreamThresholdBytes > 0 {

		conn.readMutex.Lock()
		conn.updateBurst(
			start,
			end,
			int64(n),
			conn.upstreamDeadline,
			conn.upstreamThresholdBytes,
			&conn.currentUpstreamBurst,
			&conn.upstreamBursts)
		conn.readMutex.Unlock()
	}

	// Note: no context error to preserve error type
	return n, err
}

func (conn *BurstMonitoredConn) Write(buffer []byte) (int, error) {

	start := time.Now()
	n, err := conn.Conn.Write(buffer)
	end := time.Now()

	if n > 0 &&
		conn.downstreamDeadline > 0 && conn.downstreamThresholdBytes > 0 {

		conn.writeMutex.Lock()
		conn.updateBurst(
			start,
			end,
			int64(n),
			conn.downstreamDeadline,
			conn.downstreamThresholdBytes,
			&conn.currentDownstreamBurst,
			&conn.downstreamBursts)
		conn.writeMutex.Unlock()
	}

	// Note: no context error to preserve error type
	return n, err
}

func (conn *BurstMonitoredConn) Close() error {
	err := conn.Conn.Close()

	conn.readMutex.Lock()
	conn.endBurst(
		conn.upstreamThresholdBytes,
		&conn.currentUpstreamBurst,
		&conn.upstreamBursts)
	conn.readMutex.Unlock()

	conn.writeMutex.Lock()
	conn.endBurst(
		conn.downstreamThresholdBytes,
		&conn.currentDownstreamBurst,
		&conn.downstreamBursts)
	conn.writeMutex.Unlock()

	// Note: no context error to preserve error type
	return err
}

// GetMetrics returns log fields with burst metrics for the first, last, min
// (by rate), and max bursts for this conn. Time/duration values are reported
// in milliseconds.
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

	addHistory("burst_upstream_", &conn.upstreamBursts)
	addHistory("burst_downstream_", &conn.downstreamBursts)

	return logFields
}

func (conn *BurstMonitoredConn) updateBurst(
	operationStart time.Time,
	operationEnd time.Time,
	operationBytes int64,
	deadline time.Duration,
	thresholdBytes int64,
	currentBurst *burst,
	history *burstHistory) {

	// Assumes the associated mutex is locked.

	if currentBurst.isZero() {
		currentBurst.startTime = operationStart
		currentBurst.lastByteTime = operationEnd
		currentBurst.bytes = operationBytes

	} else {

		if operationStart.Sub(currentBurst.lastByteTime) >
			deadline {

			conn.endBurst(thresholdBytes, currentBurst, history)
			currentBurst.startTime = operationStart
		}

		currentBurst.lastByteTime = operationEnd
		currentBurst.bytes += operationBytes
	}

}

func (conn *BurstMonitoredConn) endBurst(
	thresholdBytes int64,
	currentBurst *burst,
	history *burstHistory) {

	// Assumes the associated mutex is locked.

	if currentBurst.isZero() {
		return
	}

	burst := *currentBurst

	currentBurst.startTime = time.Time{}
	currentBurst.lastByteTime = time.Time{}
	currentBurst.bytes = 0

	if burst.bytes < thresholdBytes {
		return
	}

	if history.first.isZero() {
		history.first = burst
	}

	history.last = burst

	if history.min.isZero() || history.min.rate() > burst.rate() {
		history.min = burst
	}

	if history.max.isZero() || history.max.rate() < burst.rate() {
		history.max = burst
	}
}

// IsBogon checks if the specified IP is a bogon (loopback, private addresses,
// link-local addresses, etc.)
func IsBogon(IP net.IP) bool {
	return filtertransport.FindIPNet(
		filtertransport.DefaultFilteredNetworks, IP)
}

// ParseDNSQuestion parses a DNS message. When the message is a query,
// the first question, a fully-qualified domain name, is returned.
//
// For other valid DNS messages, "" is returned. An error is returned only
// for invalid DNS messages.
//
// Limitations:
// - Only the first Question field is extracted.
// - ParseDNSQuestion only functions for plaintext DNS and cannot
//   extract domains from DNS-over-TLS/HTTPS, etc.
func ParseDNSQuestion(request []byte) (string, error) {
	m := new(dns.Msg)
	err := m.Unpack(request)
	if err != nil {
		return "", errors.Trace(err)
	}
	if len(m.Question) > 0 {
		return m.Question[0].Name, nil
	}
	return "", nil
}
