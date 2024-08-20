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
	"net"
	"strings"
	"sync"

	socks "github.com/Psiphon-Labs/goptlib"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
)

// SocksProxy is a SOCKS server that accepts local host connections
// and, for each connection, establishes a port forward through
// the tunnel SSH client and relays traffic through the port
// forward.
type SocksProxy struct {
	config                 *Config
	tunneler               Tunneler
	listener               *socks.SocksListener
	serveWaitGroup         *sync.WaitGroup
	openConns              *common.Conns[net.Conn]
	stopListeningBroadcast chan struct{}
}

var _SOCKS_PROXY_TYPE = "SOCKS"

// NewSocksProxy initializes a new SOCKS server. It begins listening for
// connections, starts a goroutine that runs an accept loop, and returns
// leaving the accept loop running.
func NewSocksProxy(
	config *Config,
	tunneler Tunneler,
	listenIP string) (proxy *SocksProxy, err error) {

	listener, portInUse, err := makeLocalProxyListener(
		listenIP, config.LocalSocksProxyPort)
	if err != nil {
		if portInUse {
			NoticeSocksProxyPortInUse(config.LocalSocksProxyPort)
		}
		return nil, errors.Trace(err)
	}
	proxy = &SocksProxy{
		config:                 config,
		tunneler:               tunneler,
		listener:               socks.NewSocksListener(listener),
		serveWaitGroup:         new(sync.WaitGroup),
		openConns:              common.NewConns[net.Conn](),
		stopListeningBroadcast: make(chan struct{}),
	}
	proxy.serveWaitGroup.Add(1)
	go proxy.serve()
	NoticeListeningSocksProxyPort(proxy.listener.Addr().(*net.TCPAddr).Port)
	return proxy, nil
}

// Close terminates the listener and waits for the accept loop
// goroutine to complete.
func (proxy *SocksProxy) Close() {
	close(proxy.stopListeningBroadcast)
	proxy.listener.Close()
	proxy.serveWaitGroup.Wait()
	proxy.openConns.CloseAll()
}

func (proxy *SocksProxy) socksConnectionHandler(localConn *socks.SocksConn) (err error) {
	defer localConn.Close()
	defer proxy.openConns.Remove(localConn)

	proxy.openConns.Add(localConn)

	// Using downstreamConn so localConn.Close() will be called when remoteConn.Close() is called.
	// This ensures that the downstream client (e.g., web browser) doesn't keep waiting on the
	// open connection for data which will never arrive.
	remoteConn, err := proxy.tunneler.Dial(localConn.Req.Target, localConn)

	if err != nil {
		reason := byte(socks.SocksRepGeneralFailure)

		// "ssh: rejected" is the prefix of ssh.OpenChannelError
		// TODO: retain error type and check for ssh.OpenChannelError
		if strings.Contains(err.Error(), "ssh: rejected") {
			reason = byte(socks.SocksRepConnectionRefused)
		}

		_ = localConn.RejectReason(reason)
		return errors.Trace(err)
	}

	defer remoteConn.Close()

	err = localConn.Grant(&net.TCPAddr{IP: net.ParseIP("0.0.0.0"), Port: 0})
	if err != nil {
		return errors.Trace(err)
	}

	LocalProxyRelay(proxy.config, _SOCKS_PROXY_TYPE, localConn, remoteConn)

	return nil
}

func (proxy *SocksProxy) serve() {
	defer proxy.listener.Close()
	defer proxy.serveWaitGroup.Done()
loop:
	for {
		// Note: will be interrupted by listener.Close() call made by proxy.Close()
		socksConnection, err := proxy.listener.AcceptSocks()
		// Can't check for the exact error that Close() will cause in Accept(),
		// (see: https://code.google.com/p/go/issues/detail?id=4373). So using an
		// explicit stop signal to stop gracefully.
		select {
		case <-proxy.stopListeningBroadcast:
			break loop
		default:
		}
		if err != nil {
			NoticeWarning("SOCKS proxy accept error: %s", err)
			if e, ok := err.(net.Error); ok && e.Temporary() {
				// Temporary error, keep running
				continue
			}
			// Fatal error, stop the proxy
			proxy.tunneler.SignalComponentFailure()
			break loop
		}
		go func() {
			err := proxy.socksConnectionHandler(socksConnection)
			if err != nil {
				NoticeLocalProxyError(_SOCKS_PROXY_TYPE, errors.Trace(err))
			}
		}()
	}
	NoticeInfo("SOCKS proxy stopped")
}
