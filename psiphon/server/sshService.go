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
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon"
	"golang.org/x/crypto/ssh"
)

func RunSSHServer(config *Config, shutdownBroadcast <-chan struct{}) error {
	return runSSHServer(config, false, shutdownBroadcast)
}

func RunObfuscatedSSHServer(config *Config, shutdownBroadcast <-chan struct{}) error {
	return runSSHServer(config, true, shutdownBroadcast)
}

type sshServer struct {
	config            *Config
	useObfuscation    bool
	shutdownBroadcast <-chan struct{}
	sshConfig         *ssh.ServerConfig
	clientMutex       sync.Mutex
	stoppingClients   bool
	clients           map[string]ssh.Conn
}

func runSSHServer(
	config *Config, useObfuscation bool, shutdownBroadcast <-chan struct{}) error {

	sshServer := &sshServer{
		config:            config,
		useObfuscation:    useObfuscation,
		shutdownBroadcast: shutdownBroadcast,
		clients:           make(map[string]ssh.Conn),
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

	var serverPort int
	if useObfuscation {
		serverPort = config.ObfuscatedSSHServerPort
	} else {
		serverPort = config.SSHServerPort
	}

	listener, err := net.Listen(
		"tcp", fmt.Sprintf("%s:%d", config.ServerIPAddress, serverPort))
	if err != nil {
		return psiphon.ContextError(err)
	}

	log.WithContextFields(
		LogFields{
			"useObfuscation": useObfuscation,
			"port":           serverPort,
		}).Info("starting")

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
				if err == nil {
					conn.Close()
				}
				break loop
			default:
			}

			if err != nil {
				if e, ok := err.(net.Error); ok && e.Temporary() {
					log.WithContextFields(LogFields{"error": err}).Error("accept failed")
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

		log.WithContextFields(
			LogFields{"useObfuscation": useObfuscation}).Info("stopped")
	}()

	select {
	case <-shutdownBroadcast:
	case err = <-errors:
	}

	listener.Close()

	waitGroup.Wait()

	log.WithContextFields(
		LogFields{"useObfuscation": useObfuscation}).Info("exiting")

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
	if err != nil {
		log.WithContextFields(LogFields{"error": err, "method": method}).Warning("authentication failed")
	} else {
		log.WithContextFields(LogFields{"error": err, "method": method}).Info("authentication success")
	}
}

func (sshServer *sshServer) registerClient(sshConn ssh.Conn) bool {
	sshServer.clientMutex.Lock()
	defer sshServer.clientMutex.Unlock()
	if sshServer.stoppingClients {
		return false
	}
	existingSshConn := sshServer.clients[string(sshConn.SessionID())]
	if existingSshConn != nil {
		log.WithContext().Warning("unexpected existing connection")
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

	// Run the initial [obfuscated] SSH handshake in a goroutine
	// so we can both respect shutdownBroadcast and implement a
	// handshake timeout. The timeout is to reclaim network
	// resources in case the handshake takes too long.

	type sshNewServerConnResult struct {
		conn     net.Conn
		sshConn  *ssh.ServerConn
		channels <-chan ssh.NewChannel
		requests <-chan *ssh.Request
		err      error
	}

	resultChannel := make(chan *sshNewServerConnResult, 2)

	if SSH_HANDSHAKE_TIMEOUT > 0 {
		time.AfterFunc(time.Duration(SSH_HANDSHAKE_TIMEOUT), func() {
			resultChannel <- &sshNewServerConnResult{err: errors.New("ssh handshake timeout")}
		})
	}

	go func() {
		result := &sshNewServerConnResult{}
		if sshServer.useObfuscation {
			result.conn, result.err = psiphon.NewObfuscatedSshConn(
				psiphon.OBFUSCATION_CONN_MODE_SERVER, conn, sshServer.config.ObfuscatedSSHKey)
		} else {
			result.conn = conn
		}
		if result.err == nil {
			result.sshConn, result.channels,
				result.requests, result.err = ssh.NewServerConn(result.conn, sshServer.sshConfig)
		}
		resultChannel <- result
	}()

	var result *sshNewServerConnResult
	select {
	case result = <-resultChannel:
	case <-sshServer.shutdownBroadcast:
		// Close() will interrupt an ongoing handshake
		// TODO: wait for goroutine to exit before returning?
		conn.Close()
		return
	}

	if result.err != nil {
		conn.Close()
		log.WithContextFields(LogFields{"error": result.err}).Warning("handshake failed")
		return
	}

	if !sshServer.registerClient(result.sshConn) {
		result.sshConn.Close()
		log.WithContext().Warning("register failed")
		return
	}
	defer sshServer.unregisterClient(result.sshConn)

	// TODO: don't record IP; do GeoIP
	log.WithContextFields(
		LogFields{"remoteAddr": result.sshConn.RemoteAddr()}).Warning("connection accepted")

	go ssh.DiscardRequests(result.requests)

	for newChannel := range result.channels {

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
	log.WithContextFields(
		LogFields{
			"channelType":   newChannel.ChannelType(),
			"rejectMessage": message,
			"rejectReason":  reason,
		}).Warning("reject new channel")
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

	log.WithContextFields(LogFields{"target": targetAddr}).Debug("dialing")

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
		log.WithContextFields(LogFields{"error": err}).Warning("accept new channel failed")
		return
	}

	log.WithContextFields(LogFields{"target": targetAddr}).Debug("relaying")

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
			log.WithContextFields(LogFields{"error": err}).Warning("upstream relay failed")
		}
	}()
	_, err = io.Copy(fwdChannel, fwdConn)
	if err != nil {
		log.WithContextFields(LogFields{"error": err}).Warning("downstream relay failed")
	}
	fwdChannel.CloseWrite()
	relayWaitGroup.Wait()

	log.WithContextFields(LogFields{"target": targetAddr}).Debug("exiting")
}
