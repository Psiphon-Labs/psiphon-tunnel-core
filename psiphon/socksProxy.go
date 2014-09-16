/*
 * Copyright (c) 2014, Psiphon Inc.
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
	"git.torproject.org/pluggable-transports/goptlib.git"
	"io"
	"log"
	"net"
	"sync"
)

// SocksServer is a SOCKS server that accepts local host connections
// and, for each connection, establishes a port forward through
// the tunnel SSH client and relays traffic through the port
// forward.
type SocksServer struct {
	tunnel        *Tunnel
	failureSignal chan bool
	listener      *pt.SocksListener
	waitGroup     *sync.WaitGroup
}

// NewSocksServer initializes, but does not start, a SocksServer.
func NewSocksServer(tunnel *Tunnel, failureSignal chan bool) *SocksServer {
	return &SocksServer{tunnel: tunnel, failureSignal: failureSignal}
}

// Run begins listening for connections, starts a goroutine
// that runs an accept loop, and returns leaving the accept
// loop running.
func (server *SocksServer) Run() error {
	listener, err := pt.ListenSocks("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	log.Printf("local SOCKS proxy running on port %s", listener.Addr())
	server.listener = listener
	server.waitGroup = new(sync.WaitGroup)
	server.waitGroup.Add(1)
	go server.acceptSocksConnections()
	return nil
}

// Close terminates the listener and waits for the accept loop
// goroutine to complete.
func (server *SocksServer) Close() {
	server.listener.Close()
	server.waitGroup.Wait()
}

func socksConnectionHandler(tunnel *Tunnel, localSocksConn *pt.SocksConn) (err error) {
	defer localSocksConn.Close()
	remoteAddr := localSocksConn.Req.Target
	remoteSshForward, err := tunnel.sshClient.Dial("tcp", remoteAddr)
	if err != nil {
		return err
	}
	defer remoteSshForward.Close()
	// TODO: page view stats would be done here
	// TODO: poll quit signal (x, ok := <-ch)
	waitGroup := new(sync.WaitGroup)
	waitGroup.Add(1)
	go func() {
		defer waitGroup.Done()
		_, err = io.Copy(localSocksConn, remoteSshForward)
		if err != nil {
			log.Printf("ssh port forward downstream error: %s", err)
		}
	}()
	_, err = io.Copy(remoteSshForward, localSocksConn)
	if err != nil {
		log.Printf("ssh port forward upstream error: %s", err)
	}
	waitGroup.Wait()
	return nil
}

func (server *SocksServer) acceptSocksConnections() (err error) {
	defer server.listener.Close()
	defer server.waitGroup.Done()
	for {
		// TODO: poll quit signal (x, ok := <-ch)
		socksConnection, err := server.listener.AcceptSocks()
		if err != nil {
			log.Printf("SOCKS accept error: %s", err)
			if e, ok := err.(net.Error); ok && !e.Temporary() {
				select {
				case server.failureSignal <- true:
				default:
				}
				return err
			}
			continue
		}
		go func() {
			err := socksConnectionHandler(server.tunnel, socksConnection)
			if err != nil {
				log.Printf("SOCKS connection error: %s", err)
			}
		}()
	}
	return nil
}
