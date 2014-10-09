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
	"bytes"
	"code.google.com/p/go.crypto/ssh"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

const (
	TUNNEL_PROTOCOL_SSH            = "SSH"
	TUNNEL_PROTOCOL_OBFUSCATED_SSH = "OSSH"
	TUNNEL_PROTOCOL_UNFRONTED_MEEK = "UNFRONTED-MEEK"
	TUNNEL_PROTOCOL_FRONTED_MEEK   = "FRONTED-MEEK"
)

// This is a list of supported tunnel protocols, in default preference order
var SupportedTunnelProtocols = []string{
	TUNNEL_PROTOCOL_FRONTED_MEEK,
	TUNNEL_PROTOCOL_UNFRONTED_MEEK,
	TUNNEL_PROTOCOL_OBFUSCATED_SSH,
	TUNNEL_PROTOCOL_SSH,
}

// Tunnel is a connection to a Psiphon server. An established
// tunnel includes a network connection to the specified server
// and an SSH session built on top of that transport.
type Tunnel struct {
	serverEntry      *ServerEntry
	protocol         string
	conn             Conn
	sshClient        *ssh.Client
	sshKeepAliveQuit chan struct{}
}

// Close terminates the tunnel.
func (tunnel *Tunnel) Close() {
	if tunnel.sshKeepAliveQuit != nil {
		close(tunnel.sshKeepAliveQuit)
	}
	if tunnel.conn != nil {
		tunnel.conn.Close()
	}
}

// EstablishTunnel first makes a network transport connection to the
// Psiphon server and then establishes an SSH client session on top of
// that transport. The SSH server is authenticated using the public
// key in the server entry.
// Depending on the server's capabilities, the connection may use
// plain SSH over TCP, obfuscated SSH over TCP, or obfuscated SSH over
// HTTP (meek protocol).
// When requiredProtocol is not blank, that protocol is used. Otherwise,
// the first protocol in SupportedTunnelProtocols that's also in the
// server capabilities is used.
func EstablishTunnel(
	requiredProtocol, sessionId string,
	serverEntry *ServerEntry,
	pendingConns *PendingConns) (tunnel *Tunnel, err error) {
	// Select the protocol
	var selectedProtocol string
	if requiredProtocol != "" {
		if !Contains(serverEntry.Capabilities, requiredProtocol) {
			return nil, ContextError(fmt.Errorf("server does not have required capability"))
		}
		selectedProtocol = requiredProtocol
	} else {
		// Order of SupportedTunnelProtocols is default preference order
		for _, protocol := range SupportedTunnelProtocols {
			if Contains(serverEntry.Capabilities, protocol) {
				selectedProtocol = protocol
				break
			}
		}
		if selectedProtocol == "" {
			return nil, ContextError(fmt.Errorf("server does not have any supported capabilities"))
		}
	}
	// The meek protocols tunnel obfuscated SSH. Obfuscated SSH is layered on top of SSH.
	// So depending on which protocol is used, multiple layers are initialized.
	port := 0
	useMeek := false
	useFronting := false
	useObfuscatedSsh := false
	switch selectedProtocol {
	case TUNNEL_PROTOCOL_FRONTED_MEEK:
		useMeek = true
		useFronting = true
		useObfuscatedSsh = true
	case TUNNEL_PROTOCOL_UNFRONTED_MEEK:
		useMeek = true
		useObfuscatedSsh = true
		port = serverEntry.SshObfuscatedPort
	case TUNNEL_PROTOCOL_OBFUSCATED_SSH:
		useObfuscatedSsh = true
		port = serverEntry.SshObfuscatedPort
	case TUNNEL_PROTOCOL_SSH:
		port = serverEntry.SshPort
	}
	// Create the base transport: meek or direct connection
	var conn Conn
	if useMeek {
		conn, err = NewMeekConn(
			serverEntry, sessionId, useFronting,
			TUNNEL_CONNECT_TIMEOUT, TUNNEL_READ_TIMEOUT, TUNNEL_WRITE_TIMEOUT,
			pendingConns)
		if err != nil {
			return nil, ContextError(err)
		}
	} else {
		conn, err = DirectDial(
			fmt.Sprintf("%s:%d", serverEntry.IpAddress, port),
			TUNNEL_CONNECT_TIMEOUT, TUNNEL_READ_TIMEOUT, TUNNEL_WRITE_TIMEOUT,
			pendingConns)
		if err != nil {
			return nil, ContextError(err)
		}
	}
	defer func() {
		// Cleanup on error
		if err != nil {
			conn.Close()
		}
	}()
	// Add obfuscated SSH layer
	var sshConn net.Conn
	sshConn = conn
	if useObfuscatedSsh {
		sshConn, err = NewObfuscatedSshConn(conn, serverEntry.SshObfuscatedKey)
		if err != nil {
			return nil, ContextError(err)
		}
	}
	// Now establish the SSH session over the sshConn transport
	expectedPublicKey, err := base64.StdEncoding.DecodeString(serverEntry.SshHostKey)
	if err != nil {
		return nil, ContextError(err)
	}
	sshCertChecker := &ssh.CertChecker{
		HostKeyFallback: func(addr string, remote net.Addr, publicKey ssh.PublicKey) error {
			if !bytes.Equal(expectedPublicKey, publicKey.Marshal()) {
				return ContextError(errors.New("unexpected host public key"))
			}
			return nil
		},
	}
	sshClientConfig := &ssh.ClientConfig{
		User: serverEntry.SshUsername,
		Auth: []ssh.AuthMethod{
			ssh.Password(serverEntry.SshPassword),
		},
		HostKeyCallback: sshCertChecker.CheckHostKey,
	}
	// The folowing is adapted from ssh.Dial(), here using a custom conn
	sshAddress := strings.Join([]string{serverEntry.IpAddress, ":", strconv.Itoa(serverEntry.SshPort)}, "")
	sshClientConn, sshChans, sshReqs, err := ssh.NewClientConn(sshConn, sshAddress, sshClientConfig)
	if err != nil {
		return nil, ContextError(err)
	}
	sshClient := ssh.NewClient(sshClientConn, sshChans, sshReqs)
	// Run a goroutine to periodically execute SSH keepalive
	sshKeepAliveQuit := make(chan struct{})
	sshKeepAliveTicker := time.NewTicker(TUNNEL_SSH_KEEP_ALIVE_PERIOD)
	go func() {
		for {
			select {
			case <-sshKeepAliveTicker.C:
				_, _, err := sshClient.SendRequest("keepalive@openssh.com", true, nil)
				if err != nil {
					Notice(NOTICE_ALERT, "ssh keep alive failed: %s", err)
					// TODO: call Tunnel.Close()?
					sshKeepAliveTicker.Stop()
					conn.Close()
				}
			case <-sshKeepAliveQuit:
				sshKeepAliveTicker.Stop()
				return
			}
		}
	}()
	return &Tunnel{
			serverEntry:      serverEntry,
			protocol:         selectedProtocol,
			conn:             conn,
			sshClient:        sshClient,
			sshKeepAliveQuit: sshKeepAliveQuit},
		nil
}
