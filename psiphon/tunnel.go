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
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// Tunneler specifies the interface required by components that use a tunnel.
// Components which use this interface may be serviced by a single Tunnel instance,
// or a Controller which manages a pool of tunnels, or any other object which
// implements Tunneler.
type Tunneler interface {
	Dial(remoteAddr string) (conn net.Conn, err error)
	SignalComponentFailure()
}

// TunnerOwner specifies the interface required by Tunnel to notify its
// owner when it has failed. The owner may, as in the case of the Controller,
// remove the tunnel from its list of active tunnels.
type TunnelOwner interface {
	SignalTunnelFailure(tunnel *Tunnel)
}

const (
	TUNNEL_PROTOCOL_SSH            = "SSH"
	TUNNEL_PROTOCOL_OBFUSCATED_SSH = "OSSH"
	TUNNEL_PROTOCOL_UNFRONTED_MEEK = "UNFRONTED-MEEK-OSSH"
	TUNNEL_PROTOCOL_FRONTED_MEEK   = "FRONTED-MEEK-OSSH"
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
	serverEntry              *ServerEntry
	session                  *Session
	protocol                 string
	conn                     Conn
	sshClient                *ssh.Client
	operateWaitGroup         *sync.WaitGroup
	shutdownOperateBroadcast chan struct{}
	portForwardFailures      chan int
	portForwardFailureTotal  int
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
	config *Config,
	pendingConns *Conns,
	serverEntry *ServerEntry,
	tunnelOwner TunnelOwner) (tunnel *Tunnel, err error) {

	selectedProtocol, err := selectProtocol(config, serverEntry)
	if err != nil {
		return nil, ContextError(err)
	}
	Notice(NOTICE_INFO, "connecting to %s in region %s using %s",
		serverEntry.IpAddress, serverEntry.Region, selectedProtocol)

	// Generate a session Id for the Psiphon server API. This is generated now so
	// that it can be sent with the SSH password payload, which helps the server
	// associate client geo location, used in server API stats, with the session ID.
	sessionId, err := MakeSessionId()
	if err != nil {
		return nil, ContextError(err)
	}

	// Build transport layers and establish SSH connection
	conn, sshClient, err := dialSsh(config, pendingConns, serverEntry, selectedProtocol, sessionId)
	if err != nil {
		return nil, ContextError(err)
	}

	// Cleanup on error
	defer func() {
		if err != nil {
			conn.Close()
		}
	}()

	// The tunnel is now connected
	tunnel = &Tunnel{
		serverEntry:              serverEntry,
		protocol:                 selectedProtocol,
		conn:                     conn,
		sshClient:                sshClient,
		operateWaitGroup:         new(sync.WaitGroup),
		shutdownOperateBroadcast: make(chan struct{}),
		// portForwardFailures buffer size is large enough to receive the thresold number
		// of failure reports without blocking. Senders can drop failures without blocking.
		portForwardFailures: make(chan int, config.PortForwardFailureThreshold)}

	// Create a new Psiphon API session for this tunnel
	Notice(NOTICE_INFO, "starting session for %s", tunnel.serverEntry.IpAddress)
	tunnel.session, err = NewSession(config, tunnel, sessionId)
	if err != nil {
		return nil, ContextError(fmt.Errorf("error starting session for %s: %s", tunnel.serverEntry.IpAddress, err))
	}

	// Now that network operations are complete, cancel interruptibility
	pendingConns.Remove(conn)

	// Promote this successful tunnel to first rank so it's one
	// of the first candidates next time establish runs.
	PromoteServerEntry(tunnel.serverEntry.IpAddress)

	// Spawn the operateTunnel goroutine, which monitors the tunnel and handles periodic stats updates.
	tunnel.operateWaitGroup.Add(1)
	go tunnel.operateTunnel(config, tunnelOwner)

	return tunnel, nil
}

// Close stops operating the tunnel and closes the underlying connection.
// Note: unlike Conn, this currently only supports a single to Close().
func (tunnel *Tunnel) Close() {
	close(tunnel.shutdownOperateBroadcast)
	tunnel.operateWaitGroup.Wait()
	tunnel.conn.Close()
}

// Dial establishes a port forward connection through the tunnel
func (tunnel *Tunnel) Dial(remoteAddr string) (conn net.Conn, err error) {
	// TODO: should this track port forward failures as in Controller.DialWithTunnel?
	return tunnel.sshClient.Dial("tcp", remoteAddr)
}

// SignalComponentFailure notifies the tunnel that an associated component has failed.
// This will terminate the tunnel.
func (tunnel *Tunnel) SignalComponentFailure() {
	Notice(NOTICE_ALERT, "tunnel received component failure signal")
	tunnel.Close()
}

// selectProtocol is a helper that picks the tunnel protocol
func selectProtocol(config *Config, serverEntry *ServerEntry) (selectedProtocol string, err error) {
	// TODO: properly handle protocols (e.g. FRONTED-MEEK-OSSH) vs. capabilities (e.g., {FRONTED-MEEK, OSSH})
	// for now, the code is simply assuming that MEEK capabilities imply OSSH capability.
	if config.TunnelProtocol != "" {
		requiredCapability := strings.TrimSuffix(config.TunnelProtocol, "-OSSH")
		if !Contains(serverEntry.Capabilities, requiredCapability) {
			return "", ContextError(fmt.Errorf("server does not have required capability"))
		}
		selectedProtocol = config.TunnelProtocol
	} else {
		// Order of SupportedTunnelProtocols is default preference order
		for _, protocol := range SupportedTunnelProtocols {
			requiredCapability := strings.TrimSuffix(protocol, "-OSSH")
			if Contains(serverEntry.Capabilities, requiredCapability) {
				selectedProtocol = protocol
				break
			}
		}
		if selectedProtocol == "" {
			return "", ContextError(fmt.Errorf("server does not have any supported capabilities"))
		}
	}
	return selectedProtocol, nil
}

// dialSsh is a helper that builds the transport layers and establishes the SSH connection
func dialSsh(
	config *Config, pendingConns *Conns, serverEntry *ServerEntry,
	selectedProtocol, sessionId string) (conn Conn, sshClient *ssh.Client, err error) {

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
	dialConfig := &DialConfig{
		ConnectTimeout:        TUNNEL_CONNECT_TIMEOUT,
		ReadTimeout:           TUNNEL_READ_TIMEOUT,
		WriteTimeout:          TUNNEL_WRITE_TIMEOUT,
		PendingConns:          pendingConns,
		BindToDeviceProvider:  config.BindToDeviceProvider,
		BindToDeviceDnsServer: config.BindToDeviceDnsServer,
	}
	if useMeek {
		conn, err = DialMeek(serverEntry, sessionId, useFronting, dialConfig)
		if err != nil {
			return nil, nil, ContextError(err)
		}
	} else {
		conn, err = DialTCP(fmt.Sprintf("%s:%d", serverEntry.IpAddress, port), dialConfig)
		if err != nil {
			return nil, nil, ContextError(err)
		}
	}

	cleanupConn := conn
	defer func() {
		// Cleanup on error
		if err != nil {
			cleanupConn.Close()
		}
	}()

	// Add obfuscated SSH layer
	var sshConn net.Conn
	sshConn = conn
	if useObfuscatedSsh {
		sshConn, err = NewObfuscatedSshConn(conn, serverEntry.SshObfuscatedKey)
		if err != nil {
			return nil, nil, ContextError(err)
		}
	}

	// Now establish the SSH session over the sshConn transport
	expectedPublicKey, err := base64.StdEncoding.DecodeString(serverEntry.SshHostKey)
	if err != nil {
		return nil, nil, ContextError(err)
	}
	sshCertChecker := &ssh.CertChecker{
		HostKeyFallback: func(addr string, remote net.Addr, publicKey ssh.PublicKey) error {
			if !bytes.Equal(expectedPublicKey, publicKey.Marshal()) {
				return ContextError(errors.New("unexpected host public key"))
			}
			return nil
		},
	}
	sshPasswordPayload, err := json.Marshal(
		struct {
			SessionId   string `json:"SessionId"`
			SshPassword string `json:"SshPassword"`
		}{sessionId, serverEntry.SshPassword})
	if err != nil {
		return nil, nil, ContextError(err)
	}
	sshClientConfig := &ssh.ClientConfig{
		User: serverEntry.SshUsername,
		Auth: []ssh.AuthMethod{
			ssh.Password(string(sshPasswordPayload)),
		},
		HostKeyCallback: sshCertChecker.CheckHostKey,
	}
	// The folowing is adapted from ssh.Dial(), here using a custom conn
	// The sshAddress is passed through to host key verification callbacks; we don't use it.
	sshAddress := ""
	sshClientConn, sshChans, sshReqs, err := ssh.NewClientConn(sshConn, sshAddress, sshClientConfig)
	if err != nil {
		return nil, nil, ContextError(err)
	}
	sshClient = ssh.NewClient(sshClientConn, sshChans, sshReqs)

	return conn, sshClient, nil
}

// operateTunnel periodically sends stats updates to the Psiphon API and
// monitors the tunnel for failures:
//
// 1. Overall tunnel failure: the tunnel sends a signal to the ClosedSignal
// channel on keep-alive failure and other transport I/O errors. In case
// of such a failure, the tunnel is marked as failed.
//
// 2. Tunnel port forward failures: the tunnel connection may stay up but
// the client may still fail to establish port forwards due to server load
// and other conditions. After a threshold number of such failures, the
// overall tunnel is marked as failed.
//
// TODO: currently, any connect (dial), read, or write error associated with
// a port forward is counted as a failure. It may be important to differentiate
// between failures due to Psiphon server conditions and failures due to the
// origin/target server (in the latter case, the tunnel is healthy). Here are
// some typical error messages to consider matching against (or ignoring):
//
// - "ssh: rejected: administratively prohibited (open failed)"
// - "ssh: rejected: connect failed (Connection timed out)"
// - "write tcp ... broken pipe"
// - "read tcp ... connection reset by peer"
// - "ssh: unexpected packet in response to channel open: <nil>"
//
func (tunnel *Tunnel) operateTunnel(config *Config, tunnelOwner TunnelOwner) {
	defer tunnel.operateWaitGroup.Done()

	tunnelClosedSignal := make(chan struct{}, 1)
	err := tunnel.conn.SetClosedSignal(tunnelClosedSignal)
	if err != nil {
		err = fmt.Errorf("failed to set closed signal: %s", err)
	}

	// Note: not using a Ticker since NextSendPeriod() is not a fixed time period
	statsTimer := time.NewTimer(NextSendPeriod())
	defer statsTimer.Stop()

	sshKeepAliveTicker := time.NewTicker(TUNNEL_SSH_KEEP_ALIVE_PERIOD)
	defer sshKeepAliveTicker.Stop()

	for err == nil {
		select {
		case <-statsTimer.C:
			sendStats(tunnel, false)
			statsTimer.Reset(NextSendPeriod())

		case <-sshKeepAliveTicker.C:
			_, _, err := tunnel.sshClient.SendRequest("keepalive@openssh.com", true, nil)
			err = fmt.Errorf("ssh keep alive failed: %s", err)

		case failures := <-tunnel.portForwardFailures:
			// Note: no mutex on portForwardFailureTotal; only referenced here
			tunnel.portForwardFailureTotal += failures
			Notice(
				NOTICE_INFO, "port forward failures for %s: %d",
				tunnel.serverEntry.IpAddress, tunnel.portForwardFailureTotal)
			if tunnel.portForwardFailureTotal > config.PortForwardFailureThreshold {
				err = errors.New("tunnel exceeded port forward failure threshold")
			}

		case <-tunnelClosedSignal:
			err = errors.New("tunnel closed unexpectedly")

		case <-tunnel.shutdownOperateBroadcast:
			// Send final stats
			sendStats(tunnel, true)
			Notice(NOTICE_INFO, "shutdown operate tunnel")
			return
		}
	}

	if err != nil {
		Notice(NOTICE_ALERT, "operate tunnel error for %s: %s", tunnel.serverEntry.IpAddress, err)
		tunnelOwner.SignalTunnelFailure(tunnel)
	}
}

// sendStats is a helper for sending session stats to the server.
func sendStats(tunnel *Tunnel, final bool) {
	payload := GetForServer(tunnel.serverEntry.IpAddress)
	if payload != nil {
		err := tunnel.session.DoStatusRequest(payload, final)
		if err != nil {
			Notice(NOTICE_ALERT, "DoStatusRequest failed for %s: %s", tunnel.serverEntry.IpAddress, err)
			PutBack(tunnel.serverEntry.IpAddress, payload)
		}
	}
}
