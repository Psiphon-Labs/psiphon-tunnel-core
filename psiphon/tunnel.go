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
)

const (
	PROTOCOL_SSH            = "SSH"
	PROTOCOL_OBFUSCATED_SSH = "OSSH"
)

// Tunnel is a connection to a Psiphon server. An established
// tunnel includes a network connection to the specified server
// and an SSH session built on top of that transport.
type Tunnel struct {
	serverEntry *ServerEntry
	protocol    string
	conn        *Conn
	sshClient   *ssh.Client
}

// Close terminates the tunnel.
func (tunnel *Tunnel) Close() {
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
func EstablishTunnel(serverEntry *ServerEntry, pendingConns *PendingConns) (tunnel *Tunnel, err error) {
	// First connect the transport
	// TODO: meek
	sshCapable := Contains(serverEntry.Capabilities, PROTOCOL_SSH)
	obfuscatedSshCapable := Contains(serverEntry.Capabilities, PROTOCOL_OBFUSCATED_SSH)
	if !sshCapable && !obfuscatedSshCapable {
		return nil, fmt.Errorf("server does not have sufficient capabilities")
	}
	selectedProtocol := PROTOCOL_SSH
	port := serverEntry.SshPort
	if obfuscatedSshCapable {
		selectedProtocol = PROTOCOL_OBFUSCATED_SSH
		port = serverEntry.SshObfuscatedPort
	}
	conn, err := Dial(serverEntry.IpAddress, port, 0, CONNECTION_CANDIDATE_TIMEOUT, pendingConns)
	if err != nil {
		return nil, err
	}
	defer func() {
		pendingConns.Remove(conn)
		if err != nil {
			conn.Close()
		}
	}()
	var netConn net.Conn
	netConn = conn
	if obfuscatedSshCapable {
		netConn, err = NewObfuscatedSshConn(conn, serverEntry.SshObfuscatedKey)
		if err != nil {
			return nil, err
		}
	}
	// Now establish the SSH session
	expectedPublicKey, err := base64.StdEncoding.DecodeString(serverEntry.SshHostKey)
	if err != nil {
		return nil, err
	}
	sshCertChecker := &ssh.CertChecker{
		HostKeyFallback: func(addr string, remote net.Addr, publicKey ssh.PublicKey) error {
			if !bytes.Equal(expectedPublicKey, publicKey.Marshal()) {
				return errors.New("unexpected host public key")
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
	sshConn, sshChans, sshReqs, err := ssh.NewClientConn(netConn, sshAddress, sshClientConfig)
	if err != nil {
		return nil, err
	}
	sshClient := ssh.NewClient(sshConn, sshChans, sshReqs)
	return &Tunnel{serverEntry, selectedProtocol, conn, sshClient}, nil
}
