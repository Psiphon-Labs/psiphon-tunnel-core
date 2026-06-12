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

func mustParseCIDR(s string) net.IPNet {
	_, IPNet, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return *IPNet
}

// bogonNetworks are loopback, private, link-local, and other reserved
// networks. The list is copied from
// https://github.com/realclientip/realclientip-go (0BSD licensed).
var bogonNetworks = []net.IPNet{
	mustParseCIDR("10.0.0.0/8"),         // RFC1918
	mustParseCIDR("172.16.0.0/12"),      // private
	mustParseCIDR("192.168.0.0/16"),     // private
	mustParseCIDR("127.0.0.0/8"),        // RFC5735
	mustParseCIDR("0.0.0.0/8"),          // RFC1122 Section 3.2.1.3
	mustParseCIDR("169.254.0.0/16"),     // RFC3927
	mustParseCIDR("192.0.0.0/24"),       // RFC 5736
	mustParseCIDR("192.0.2.0/24"),       // RFC 5737
	mustParseCIDR("198.51.100.0/24"),    // Assigned as TEST-NET-2
	mustParseCIDR("203.0.113.0/24"),     // Assigned as TEST-NET-3
	mustParseCIDR("192.88.99.0/24"),     // RFC 3068
	mustParseCIDR("198.18.0.0/15"),      // RFC 2544
	mustParseCIDR("224.0.0.0/4"),        // RFC 3171
	mustParseCIDR("240.0.0.0/4"),        // RFC 1112
	mustParseCIDR("255.255.255.255/32"), // RFC 919 Section 7
	mustParseCIDR("100.64.0.0/10"),      // RFC 6598
	mustParseCIDR("::/128"),             // RFC 4291: Unspecified Address
	mustParseCIDR("::1/128"),            // RFC 4291: Loopback Address
	mustParseCIDR("100::/64"),           // RFC 6666: Discard Address Block
	mustParseCIDR("2001::/23"),          // RFC 2928: IETF Protocol Assignments
	mustParseCIDR("2001:2::/48"),        // RFC 5180: Benchmarking
	mustParseCIDR("2001:db8::/32"),      // RFC 3849: Documentation
	mustParseCIDR("2001::/32"),          // RFC 4380: TEREDO
	mustParseCIDR("fc00::/7"),           // RFC 4193: Unique-Local
	mustParseCIDR("fe80::/10"),          // RFC 4291: Section 2.5.6 Link-Scoped Unicast
	mustParseCIDR("ff00::/8"),           // RFC 4291: Section 2.7
	mustParseCIDR("2002::/16"),          // RFC 7526: 6to4 anycast prefix deprecated
}

// IsBogon checks if the specified IP is a bogon (loopback, private addresses,
// link-local addresses, etc.)
func IsBogon(IP net.IP) bool {
	for _, network := range bogonNetworks {
		if network.Contains(IP) {
			return true
		}
	}
	return false
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

// GetRateLimitIP returns the IP address key to use for rate limiting. IPv6
// addresses are rate limited by /56.
func GetRateLimitIP(strIP string) string {

	IP := net.ParseIP(strIP)
	if IP == nil || IP.To4() != nil {
		return strIP
	}

	// With IPv6, individual users or sites are commonly allocated a /64
	// or /56, so rate limit by /56.
	return IP.Mask(net.CIDRMask(56, 128)).String()
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
