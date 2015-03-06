// +build windows

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

package psiphon

import (
	"errors"
	"net"
)

// interruptibleTCPSocket simulates interruptible semantics on Windows. A call
// to interruptibleTCPClose doesn't actually interrupt a connect in progress,
// but abandons a dial that's running in a goroutine.
// Interruptible semantics are required by the controller for timely component
// state changes.
// TODO: implement true interruptible semantics on Windows; use syscall and
// a HANDLE similar to how TCPConn_unix uses a file descriptor?
type interruptibleTCPSocket struct {
	results chan *interruptibleDialResult
}

type interruptibleDialResult struct {
	netConn net.Conn
	err     error
}

// interruptibleTCPDial establishes a TCP network connection. A conn is added
// to config.PendingConns before blocking on network IO, which enables interruption.
// The caller is responsible for removing an established conn from PendingConns.
func interruptibleTCPDial(addr string, config *DialConfig) (conn *TCPConn, err error) {
	if config.DeviceBinder != nil {
		return nil, ContextError(errors.New("psiphon.interruptibleTCPDial with DeviceBinder not supported on Windows"))
	}

	// Enable interruption
	conn = &TCPConn{
		interruptible: interruptibleTCPSocket{results: make(chan *interruptibleDialResult, 2)},
		readTimeout:   config.ReadTimeout,
		writeTimeout:  config.WriteTimeout}

	if !config.PendingConns.Add(conn) {
		return nil, ContextError(errors.New("pending connections already closed"))
	}

	// Call the blocking Dial in a goroutine
	results := conn.interruptible.results
	go func() {

		// When using an upstream HTTP proxy, first connect to the proxy,
		// then use HTTP CONNECT to connect to the original destination.
		dialAddr := addr
		if config.UpstreamHttpProxyAddress != "" {
			dialAddr = config.UpstreamHttpProxyAddress
		}

		netConn, err := net.DialTimeout("tcp", dialAddr, config.ConnectTimeout)

		if err == nil && config.UpstreamHttpProxyAddress != "" {
			err = HttpProxyConnect(netConn, addr)
		}
		if err != nil {
			netConn = nil
		}

		results <- &interruptibleDialResult{netConn, err}
	}()

	// Block until Dial completes (or times out) or until interrupt
	result := <-conn.interruptible.results
	if result.err != nil {
		return nil, ContextError(result.err)
	}
	conn.Conn = result.netConn

	return conn, nil
}

func interruptibleTCPClose(interruptible interruptibleTCPSocket) error {
	interruptible.results <- &interruptibleDialResult{nil, errors.New("socket interrupted")}
	return nil
}
