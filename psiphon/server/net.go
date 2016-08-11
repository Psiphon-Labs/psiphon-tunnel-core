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

// for HTTPSServer.ServeTLS:
/*
Copyright (c) 2012 The Go Authors. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

   * Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.
   * Redistributions in binary form must reproduce the above
copyright notice, this list of conditions and the following disclaimer
in the documentation and/or other materials provided with the
distribution.
   * Neither the name of Google Inc. nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

package server

import (
	"container/list"
	"crypto/tls"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
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
	// Note: 64-bit ints used with atomic operations are at placed
	// at the start of struct to ensure 64-bit alignment.
	// (https://golang.org/pkg/sync/atomic/#pkg-note-BUG)
	startTime            int64
	lastReadActivityTime int64
	net.Conn
	inactivityTimeout time.Duration
	activeOnWrite     bool
	lruEntry          *LRUConnsEntry
}

func NewActivityMonitoredConn(
	conn net.Conn,
	inactivityTimeout time.Duration,
	activeOnWrite bool,
	lruEntry *LRUConnsEntry) (*ActivityMonitoredConn, error) {

	if inactivityTimeout > 0 {
		err := conn.SetDeadline(time.Now().Add(inactivityTimeout))
		if err != nil {
			return nil, common.ContextError(err)
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
				return n, common.ContextError(err)
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
				return n, common.ContextError(err)
			}
		}

		if conn.lruEntry != nil {
			conn.lruEntry.Touch()
		}

	}
	// Note: no context error to preserve error type
	return n, err
}

// HTTPSServer is a wrapper around http.Server which adds the
// ServeTLS function.
type HTTPSServer struct {
	http.Server
}

// ServeTLS is a offers the equivalent interface as http.Serve.
// The http package has both ListenAndServe and ListenAndServeTLS higher-
// level interfaces, but only Serve (not TLS) offers a lower-level interface that
// allows the caller to keep a refererence to the Listener, allowing for external
// shutdown. ListenAndServeTLS also requires the TLS cert and key to be in files
// and we avoid that here.
// tcpKeepAliveListener is used in http.ListenAndServeTLS but not exported,
// so we use a copy from https://golang.org/src/net/http/server.go.
func (server *HTTPSServer) ServeTLS(listener net.Listener) error {
	tlsListener := tls.NewListener(tcpKeepAliveListener{listener.(*net.TCPListener)}, server.TLSConfig)
	return server.Serve(tlsListener)
}

type tcpKeepAliveListener struct {
	*net.TCPListener
}

func (ln tcpKeepAliveListener) Accept() (c net.Conn, err error) {
	tc, err := ln.AcceptTCP()
	if err != nil {
		return
	}
	tc.SetKeepAlive(true)
	tc.SetKeepAlivePeriod(3 * time.Minute)
	return tc, nil
}
