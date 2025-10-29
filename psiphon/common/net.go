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
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"github.com/miekg/dns"
	"github.com/wader/filtertransport"
)

// Dialer is a custom network dialer.
type Dialer func(context.Context, string, string) (net.Conn, error)

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

// FragmentorAccessor defines the interface for accessing properties
// of a fragmentor Conn.
type FragmentorAccessor interface {
	SetReplay(*prng.PRNG)
	GetReplay() (*prng.Seed, bool)
	StopFragmenting()
}

// HTTPRoundTripper is an adapter that allows using a function as a
// http.RoundTripper.
type HTTPRoundTripper struct {
	roundTrip func(*http.Request) (*http.Response, error)
}

// NewHTTPRoundTripper creates a new HTTPRoundTripper, using the specified
// roundTrip function for HTTP round trips.
func NewHTTPRoundTripper(
	roundTrip func(*http.Request) (*http.Response, error)) *HTTPRoundTripper {
	return &HTTPRoundTripper{roundTrip: roundTrip}
}

// RoundTrip implements http.RoundTripper RoundTrip.
func (h HTTPRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return h.roundTrip(request)
}

// TerminateHTTPConnection sends a 404 response to a client and also closes
// the persistent connection.
func TerminateHTTPConnection(
	responseWriter http.ResponseWriter, request *http.Request) {

	responseWriter.Header().Set("Content-Length", "0")
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
type Conns[T interface {
	comparable
	io.Closer
}] struct {
	mutex    sync.Mutex
	isClosed bool
	conns    map[T]bool
}

// NewConns initializes a new Conns.
func NewConns[T interface {
	comparable
	io.Closer
}]() *Conns[T] {
	return &Conns[T]{}
}

func (conns *Conns[T]) Reset() {
	conns.mutex.Lock()
	defer conns.mutex.Unlock()
	conns.isClosed = false
	conns.conns = make(map[T]bool)
}

func (conns *Conns[T]) Add(conn T) bool {
	conns.mutex.Lock()
	defer conns.mutex.Unlock()
	if conns.isClosed {
		return false
	}
	if conns.conns == nil {
		conns.conns = make(map[T]bool)
	}
	conns.conns[conn] = true
	return true
}

func (conns *Conns[T]) Remove(conn T) {
	conns.mutex.Lock()
	defer conns.mutex.Unlock()
	delete(conns.conns, conn)
}

func (conns *Conns[T]) CloseAll() {

	conns.mutex.Lock()
	conns.isClosed = true
	closeConns := conns.conns
	conns.conns = make(map[T]bool)
	conns.mutex.Unlock()

	// Close is invoked outside of the mutex in case a member conn's Close
	// invokes Remove.
	for conn := range closeConns {
		_ = conn.Close()
	}
}

func (conns *Conns[T]) IsClosed() bool {
	conns.mutex.Lock()
	defer conns.mutex.Unlock()
	return conns.isClosed
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

// CloseAll closes all the connections in a
// LRUConns.
func (conns *LRUConns) CloseAll() {
	conns.mutex.Lock()
	defer conns.mutex.Unlock()
	for conn := conns.list.Front(); conn != nil; {
		next := conn.Next()
		_ = conn.Value.(net.Conn).Close()
		conns.list.Remove(conn)
		conn = next
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
//   - Only the first Question field is extracted.
//   - ParseDNSQuestion only functions for plaintext DNS and cannot
//     extract domains from DNS-over-TLS/HTTPS, etc.
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

// WriteTimeoutUDPConn sets write deadlines before each UDP packet write.
//
// Generally, a UDP packet write doesn't block. However, Go's
// internal/poll.FD.WriteMsg continues to loop when syscall.SendmsgN fails
// with EAGAIN, which indicates that an OS socket buffer is currently full;
// in certain OS states this may cause WriteMsgUDP/etc. to block
// indefinitely. In this scenario, we want to instead behave as if the packet
// were dropped, so we set a write deadline which will eventually interrupt
// any EAGAIN loop.
type WriteTimeoutUDPConn struct {
	*net.UDPConn
}

func (conn *WriteTimeoutUDPConn) Write(b []byte) (int, error) {

	err := conn.SetWriteDeadline(time.Now().Add(UDP_PACKET_WRITE_TIMEOUT))
	if err != nil {
		return 0, errors.Trace(err)
	}

	// Do not wrap any I/O err returned by UDPConn
	return conn.UDPConn.Write(b)
}

func (conn *WriteTimeoutUDPConn) WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (int, int, error) {

	err := conn.SetWriteDeadline(time.Now().Add(UDP_PACKET_WRITE_TIMEOUT))
	if err != nil {
		return 0, 0, errors.Trace(err)
	}

	// Do not wrap any I/O err returned by UDPConn
	return conn.UDPConn.WriteMsgUDP(b, oob, addr)
}

func (conn *WriteTimeoutUDPConn) WriteMsgUDPAddrPort(b, oob []byte, addr netip.AddrPort) (int, int, error) {

	err := conn.SetWriteDeadline(time.Now().Add(UDP_PACKET_WRITE_TIMEOUT))
	if err != nil {
		return 0, 0, errors.Trace(err)
	}

	// Do not wrap any I/O err returned by UDPConn
	return conn.UDPConn.WriteMsgUDPAddrPort(b, oob, addr)
}

func (conn *WriteTimeoutUDPConn) WriteTo(b []byte, addr net.Addr) (int, error) {

	err := conn.SetWriteDeadline(time.Now().Add(UDP_PACKET_WRITE_TIMEOUT))
	if err != nil {
		return 0, errors.Trace(err)
	}

	// Do not wrap any I/O err returned by UDPConn
	return conn.UDPConn.WriteTo(b, addr)
}

func (conn *WriteTimeoutUDPConn) WriteToUDPAddrPort(b []byte, addr netip.AddrPort) (int, error) {

	err := conn.SetWriteDeadline(time.Now().Add(UDP_PACKET_WRITE_TIMEOUT))
	if err != nil {
		return 0, errors.Trace(err)
	}

	// Do not wrap any I/O err returned by UDPConn
	return conn.UDPConn.WriteToUDPAddrPort(b, addr)
}

func (conn *WriteTimeoutUDPConn) WriteToUDP(b []byte, addr *net.UDPAddr) (int, error) {

	err := conn.SetWriteDeadline(time.Now().Add(UDP_PACKET_WRITE_TIMEOUT))
	if err != nil {
		return 0, errors.Trace(err)
	}

	// Do not wrap any I/O err returned by UDPConn
	return conn.UDPConn.WriteToUDP(b, addr)
}

// WriteTimeoutPacketConn is the equivilent of WriteTimeoutUDPConn for
// non-*net.UDPConns.
type WriteTimeoutPacketConn struct {
	net.PacketConn
}

const UDP_PACKET_WRITE_TIMEOUT = 1 * time.Second

func (conn *WriteTimeoutPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {

	err := conn.SetWriteDeadline(time.Now().Add(UDP_PACKET_WRITE_TIMEOUT))
	if err != nil {
		return 0, errors.Trace(err)
	}

	// Do not wrap any I/O err returned by PacketConn
	return conn.PacketConn.WriteTo(b, addr)
}

// GetMetrics implements the common.MetricsSource interface.
func (conn *WriteTimeoutPacketConn) GetMetrics() LogFields {

	logFields := make(LogFields)

	// Include metrics, such as inproxy and fragmentor metrics, from the
	// underlying dial conn.
	underlyingMetrics, ok := conn.PacketConn.(MetricsSource)
	if ok {
		logFields.Add(underlyingMetrics.GetMetrics())
	}

	return logFields
}
