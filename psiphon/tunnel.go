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

// Tunnel is a connection to a Psiphon server. An established
// tunnel includes a network connection to the specified server
// and an SSH session built on top of that transport.
type Tunnel struct {
	serverEntry *ServerEntry
	conn        *Conn
	sshClient   *ssh.Client
}

// Close terminates the tunnel SSH client session and the
// underlying network transport.
func (tunnel *Tunnel) Close() {
	if tunnel.sshClient != nil {
		tunnel.sshClient.Close()
		tunnel.sshClient = nil
	}
	if tunnel.conn != nil {
		tunnel.conn.Close()
		tunnel.conn = nil
	}
}

// EstablishTunnel first makes a network transport connection to the
// Psiphon server and then establishes an SSH client session on top of
// that transport. The SSH server is authenticated using the public
// key in the server entry.
// Depending on the server's capabilities, the connection may use
// plain SSH over TCP, obfuscated SSH over TCP, or obfuscated SSH over
// HTTP (meek protocol).
func EstablishTunnel(tunnel *Tunnel) (err error) {
	if tunnel.conn != nil {
		return errors.New("tunnel already connected")
	}
	if tunnel.sshClient != nil {
		return errors.New("ssh client already established")
	}
	// First connect the transport
	// TODO: meek
	sshCapable := Contains(tunnel.serverEntry.Capabilities, "SSH")
	obfuscatedSshCapable := false //Contains(tunnel.serverEntry.Capabilities, "OSSH")
	if !sshCapable && !obfuscatedSshCapable {
		return fmt.Errorf("server does not have sufficient capabilities")
	}
	port := tunnel.serverEntry.SshPort
	conn, err := NewConn(0, CONNECTION_CANDIDATE_TIMEOUT, "")
	if err != nil {
		return err
	}
	var netConn net.Conn
	netConn = conn
	if obfuscatedSshCapable {
		port = tunnel.serverEntry.SshObfuscatedPort
		netConn, err = NewObfuscatedSshConn(conn, tunnel.serverEntry.SshObfuscatedKey)
		if err != nil {
			return err
		}
	}
	err = conn.Connect(tunnel.serverEntry.IpAddress, port)
	if err != nil {
		return err
	}
	// Now establish the SSH session
	expectedPublicKey, err := base64.StdEncoding.DecodeString(tunnel.serverEntry.SshHostKey)
	if err != nil {
		return err
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
		User: tunnel.serverEntry.SshUsername,
		Auth: []ssh.AuthMethod{
			ssh.Password(tunnel.serverEntry.SshPassword),
		},
		HostKeyCallback: sshCertChecker.CheckHostKey,
	}
	// The folowing is adapted from ssh.Dial(), here using a custom conn
	sshAddress := strings.Join([]string{tunnel.serverEntry.IpAddress, ":", strconv.Itoa(tunnel.serverEntry.SshPort)}, "")
	sshConn, sshChans, sshReqs, err := ssh.NewClientConn(netConn, sshAddress, sshClientConfig)
	if err != nil {
		return err
	}
	sshClient := ssh.NewClient(sshConn, sshChans, sshReqs)
	tunnel.sshClient = sshClient
	return nil
}
