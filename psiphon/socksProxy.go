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
	"fmt"
	socks "github.com/Psiphon-Inc/goptlib"
	"io"
	"net"
	"sync"
)

// SocksProxy is a SOCKS server that accepts local host connections
// and, for each connection, establishes a port forward through
// the tunnel SSH client and relays traffic through the port
// forward.
type SocksProxy struct {
	tunnel        *Tunnel
	stoppedSignal chan struct{}
	listener      *socks.SocksListener
	waitGroup     *sync.WaitGroup
	openConns     *Conns
}

// NewSocksProxy initializes a new SOCKS server. It begins listening for
// connections, starts a goroutine that runs an accept loop, and returns
// leaving the accept loop running.
func NewSocksProxy(listenPort int, tunnel *Tunnel, stoppedSignal chan struct{}) (proxy *SocksProxy, err error) {
	listener, err := socks.ListenSocks("tcp", fmt.Sprintf("127.0.0.1:%d", listenPort))
	if err != nil {
		return nil, err
	}
	proxy = &SocksProxy{
		tunnel:        tunnel,
		stoppedSignal: stoppedSignal,
		listener:      listener,
		waitGroup:     new(sync.WaitGroup),
		openConns:     new(Conns),
	}
	proxy.waitGroup.Add(1)
	go proxy.acceptSocksConnections()
	Notice(NOTICE_SOCKS_PROXY, "local SOCKS proxy running at address %s", proxy.listener.Addr().String())
	return proxy, nil
}

// Close terminates the listener and waits for the accept loop
// goroutine to complete.
func (proxy *SocksProxy) Close() {
	proxy.listener.Close()
	proxy.waitGroup.Wait()
	proxy.openConns.CloseAll()
}

func (proxy *SocksProxy) socksConnectionHandler(tunnel *Tunnel, localSocksConn *socks.SocksConn) (err error) {
	defer localSocksConn.Close()
	defer proxy.openConns.Remove(localSocksConn)
	proxy.openConns.Add(localSocksConn)
	remoteSshForward, err := tunnel.sshClient.Dial("tcp", localSocksConn.Req.Target)
	if err != nil {
		return ContextError(err)
	}
	defer remoteSshForward.Close()
	err = localSocksConn.Grant(&net.TCPAddr{IP: net.ParseIP("0.0.0.0"), Port: 0})
	if err != nil {
		return ContextError(err)
	}
	relayPortForward(localSocksConn, remoteSshForward)
	return nil
}

// relayPortForward is also used by HttpProxy
func relayPortForward(local, remote net.Conn) {
	// TODO: page view stats would be done here
	// TODO: interrupt and stop on proxy.Close()
	waitGroup := new(sync.WaitGroup)
	waitGroup.Add(1)
	go func() {
		defer waitGroup.Done()
		_, err := io.Copy(local, remote)
		if err != nil {
			Notice(NOTICE_ALERT, "%s", ContextError(err))
		}
	}()
	_, err := io.Copy(remote, local)
	if err != nil {
		Notice(NOTICE_ALERT, "%s", ContextError(err))
	}
	waitGroup.Wait()
}

func (proxy *SocksProxy) acceptSocksConnections() {
	defer proxy.listener.Close()
	defer proxy.waitGroup.Done()
	for {
		// Note: will be interrupted by listener.Close() call made by proxy.Close()
		socksConnection, err := proxy.listener.AcceptSocks()
		if err != nil {
			Notice(NOTICE_ALERT, "SOCKS proxy accept error: %s", err)
			if e, ok := err.(net.Error); ok && !e.Temporary() {
				select {
				case proxy.stoppedSignal <- *new(struct{}):
				default:
				}
				// Fatal error, stop the proxy
				break
			}
			// Temporary error, keep running
			continue
		}
		go func() {
			err := proxy.socksConnectionHandler(proxy.tunnel, socksConnection)
			if err != nil {
				Notice(NOTICE_ALERT, "%s", ContextError(err))
			}
		}()
	}
	Notice(NOTICE_SOCKS_PROXY, "SOCKS proxy stopped")
}
