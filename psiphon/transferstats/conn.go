/*
 * Copyright (c) 2015, Psiphon Inc.
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

// Package stats counts and keeps track of session stats. These are per-domain
// bytes transferred and total bytes transferred.
package transferstats

/*
Assumption: The same connection will not be used to access different hostnames
	(even if, say, those hostnames map to the same server). If this does occur, we
	will mis-attribute some bytes.
Assumption: Enough of the first HTTP will be present in the first Write() call
	for us to a) recognize that it is HTTP, and b) parse the hostname.
		- If this turns out to not be generally true we will need to add buffering.
*/

import (
	"net"
	"sync/atomic"
)

// Conn is to be used as an intermediate link in a chain of net.Conn objects.
// It inspects requests and responses and derives stats from them.
type Conn struct {
	net.Conn
	serverID       string
	firstWrite     int32
	hostnameParsed int32
	hostname       string
	regexps        *Regexps
}

// NewConn creates a Conn. serverID can be anything that uniquely
// identifies the server; it will be passed to TakeOutStatsForServer() when
// retrieving the accumulated stats.
func NewConn(nextConn net.Conn, serverID string, regexps *Regexps) *Conn {
	return &Conn{
		Conn:           nextConn,
		serverID:       serverID,
		firstWrite:     1,
		hostnameParsed: 0,
		regexps:        regexps,
	}
}

// Write is called when requests are being written out through the tunnel to
// the remote server.
func (conn *Conn) Write(buffer []byte) (n int, err error) {
	// First pass the data down the chain.
	n, err = conn.Conn.Write(buffer)

	// Count stats before we check the error condition. It could happen that the
	// buffer was partially written and then an error occurred.
	if n > 0 {
		// If this is the first request, try to determine the hostname to associate
		// with this connection.
		if atomic.CompareAndSwapInt32(&conn.firstWrite, 1, 0) {

			hostname, ok := getHostname(buffer)
			if ok {
				// Get the hostname value that will be stored in stats by
				// regexing the real hostname.
				conn.hostname = regexHostname(hostname, conn.regexps)
				atomic.StoreInt32(&conn.hostnameParsed, 1)
			}
		}

		recordStat(&statsUpdate{
			conn.serverID,
			conn.hostname,
			int64(n),
			0},
			false)
	}

	return
}

// Read is called when responses to requests are being read from the remote server.
func (conn *Conn) Read(buffer []byte) (n int, err error) {
	n, err = conn.Conn.Read(buffer)

	var hostname string
	if 1 == atomic.LoadInt32(&conn.hostnameParsed) {
		hostname = conn.hostname
	} else {
		hostname = ""
	}

	// Count bytes without checking the error condition. It could happen that the
	// buffer was partially read and then an error occurred.
	recordStat(&statsUpdate{
		conn.serverID,
		hostname,
		0,
		int64(n)},
		false)

	return
}
