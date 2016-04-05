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

package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sync"

	log "github.com/Psiphon-Inc/logrus"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon"
	"golang.org/x/crypto/ssh"
)

type sshServer struct {
	config          *Config
	sshConfig       *ssh.ServerConfig
	clientMutex     sync.Mutex
	stoppingClients bool
	clients         map[string]ssh.Conn
}

func RunSSH(config *Config, shutdownBroadcast <-chan struct{}) error {

	sshServer := &sshServer{
		config: config,
	}

	sshServer.sshConfig = &ssh.ServerConfig{
		PasswordCallback: sshServer.passwordCallback,
		AuthLogCallback:  sshServer.authLogCallback,
		ServerVersion:    config.SSHServerVersion,
	}

	privateKey, err := ssh.ParseRawPrivateKey([]byte(config.SSHPrivateKey))
	if err != nil {
		return psiphon.ContextError(err)
	}

	// TODO: use cert (ssh.NewCertSigner) for anti-fingerprint?
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		return psiphon.ContextError(err)
	}

	sshServer.sshConfig.AddHostKey(signer)

	listener, err := net.Listen(
		"tcp", fmt.Sprintf("%s:%d", config.ServerIPAddress, config.SSHPort))
	if err != nil {
		return psiphon.ContextError(err)
	}

	log.Info("RunSSH: starting server")

	err = nil
	errors := make(chan error)
	waitGroup := new(sync.WaitGroup)

	waitGroup.Add(1)
	go func() {
		defer waitGroup.Done()

	loop:
		for {
			conn, err := listener.Accept()

			select {
			case <-shutdownBroadcast:
				break loop
			default:
			}

			if err != nil {
				if e, ok := err.(net.Error); ok && e.Temporary() {
					log.Warning("RunSSH accept error: %s", err)
					// Temporary error, keep running
					continue
				}

				select {
				case errors <- psiphon.ContextError(err):
				default:
				}

				break loop
			}

			// process each client connection concurrently
			go sshServer.handleClient(conn)
		}

		sshServer.stopClients()

		log.Info("RunSSH: server stopped")
	}()

	select {
	case <-shutdownBroadcast:
	case err = <-errors:
	}

	listener.Close()

	waitGroup.Wait()

	log.Info("RunSSH: exiting")

	return err
}

func (sshServer *sshServer) passwordCallback(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	var sshPasswordPayload struct {
		SessionId   string `json:"SessionId"`
		SshPassword string `json:"SshPassword"`
	}
	err := json.Unmarshal(password, &sshPasswordPayload)
	if err != nil {
		return nil, psiphon.ContextError(fmt.Errorf("invalid password payload for %q", conn.User()))
	}

	if conn.User() == sshServer.config.SSHUserName &&
		sshPasswordPayload.SshPassword == sshServer.config.SSHPassword {
		return nil, nil
	}

	return nil, psiphon.ContextError(fmt.Errorf("invalid password for %q", conn.User()))
}

func (sshServer *sshServer) authLogCallback(conn ssh.ConnMetadata, method string, err error) {
	errMsg := "success"
	if err != nil {
		errMsg = err.Error()
	}
	log.Warning("ssh: %s authentication attempt %s", method, errMsg)
}

func (sshServer *sshServer) registerClient(sshConn ssh.Conn) bool {
	sshServer.clientMutex.Lock()
	defer sshServer.clientMutex.Unlock()
	if sshServer.stoppingClients {
		return false
	}
	existingSshConn := sshServer.clients[string(sshConn.SessionID())]
	if existingSshConn != nil {
		log.Warning("sshServer.registerClient: unexpected existing connection")
		existingSshConn.Close()
		existingSshConn.Wait()
	}
	sshServer.clients[string(sshConn.SessionID())] = sshConn
	return true
}

func (sshServer *sshServer) unregisterClient(sshConn ssh.Conn) {
	sshServer.clientMutex.Lock()
	if sshServer.stoppingClients {
		return
	}
	delete(sshServer.clients, string(sshConn.SessionID()))
	sshServer.clientMutex.Unlock()
	sshConn.Close()
}

func (sshServer *sshServer) stopClients() {
	sshServer.clientMutex.Lock()
	sshServer.stoppingClients = true
	sshServer.clientMutex.Unlock()
	for _, sshConn := range sshServer.clients {
		sshConn.Close()
		sshConn.Wait()
	}
}

func (sshServer *sshServer) handleClient(conn net.Conn) {

	// TODO: does this block on SSH handshake (so should be in goroutine)?
	sshConn, channels, requests, err := ssh.NewServerConn(conn, sshServer.sshConfig)
	if err != nil {
		conn.Close()
		log.Error("sshServer.handleClient: ssh establish connection failed: %s", err)
		return
	}

	if !sshServer.registerClient(sshConn) {
		sshConn.Close()
		log.Error("sshServer.handleClient: failed to register client")
		return
	}
	defer sshServer.unregisterClient(sshConn)

	// TODO: don't record IP; do GeoIP
	log.Info("connection from %s", sshConn.RemoteAddr())

	go ssh.DiscardRequests(requests)

	for newChannel := range channels {

		if newChannel.ChannelType() != "direct-tcpip" {
			sshServer.rejectNewChannel(newChannel, ssh.Prohibited, "unknown or unsupported channel type")
			return
		}

		// process each port forward concurrently
		go sshServer.handleNewDirectTcpipChannel(newChannel)
	}
}

func (sshServer *sshServer) rejectNewChannel(newChannel ssh.NewChannel, reason ssh.RejectionReason, message string) {
	// TODO: log more details?
	log.Warning("ssh reject new channel: %s: %d: %s", newChannel.ChannelType(), reason, message)
	newChannel.Reject(reason, message)
}

func (sshServer *sshServer) handleNewDirectTcpipChannel(newChannel ssh.NewChannel) {

	// http://tools.ietf.org/html/rfc4254#section-7.2
	var directTcpipExtraData struct {
		HostToConnect       string
		PortToConnect       uint32
		OriginatorIPAddress string
		OriginatorPort      uint32
	}

	err := ssh.Unmarshal(newChannel.ExtraData(), &directTcpipExtraData)
	if err != nil {
		sshServer.rejectNewChannel(newChannel, ssh.Prohibited, "invalid extra data")
		return
	}

	targetAddr := fmt.Sprintf("%s:%d",
		directTcpipExtraData.HostToConnect,
		directTcpipExtraData.PortToConnect)

	log.Debug("sshServer.handleNewDirectTcpipChannel: dialing %s", targetAddr)

	// TODO: port forward dial timeout
	// TODO: report ssh.ResourceShortage when appropriate
	fwdConn, err := net.Dial("tcp", targetAddr)
	if err != nil {
		sshServer.rejectNewChannel(newChannel, ssh.ConnectionFailed, err.Error())
		return
	}
	defer fwdConn.Close()

	fwdChannel, requests, err := newChannel.Accept()
	if err != nil {
		log.Warning("sshServer.handleNewDirectTcpipChannel: accept new channel failed: %s", err)
		return
	}

	log.Debug("sshServer.handleNewDirectTcpipChannel: relaying %s", targetAddr)

	go ssh.DiscardRequests(requests)

	defer fwdChannel.Close()

	// relay channel to forwarded connection

	// TODO: use a low-memory io.Copy?
	// TODO: relay errors to fwdChannel.Stderr()?

	relayWaitGroup := new(sync.WaitGroup)
	relayWaitGroup.Add(1)
	go func() {
		defer relayWaitGroup.Done()
		_, err := io.Copy(fwdConn, fwdChannel)
		if err != nil {
			log.Warning("sshServer.handleNewDirectTcpipChannel: upstream relay failed: %s", err)
		}
	}()
	_, err = io.Copy(fwdChannel, fwdConn)
	if err != nil {
		log.Warning("sshServer.handleNewDirectTcpipChannel: downstream relay failed: %s", err)
	}
	fwdChannel.CloseWrite()
	relayWaitGroup.Wait()

	log.Info("sshServer.handleNewDirectTcpipChannel: exiting %s", targetAddr)
}
