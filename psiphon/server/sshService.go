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
	"crypto/subtle"
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

// RunSSHServer runs an ssh server with plain SSH protocol.
func RunSSHServer(config *Config, shutdownBroadcast <-chan struct{}) error {
	return runSSHServer(config, false, shutdownBroadcast)
}

// RunSSHServer runs an ssh server with Obfuscated SSH protocol.
func RunObfuscatedSSHServer(config *Config, shutdownBroadcast <-chan struct{}) error {
	return runSSHServer(config, true, shutdownBroadcast)
}

// runSSHServer runs an SSH or Obfuscated SSH server. In the Obfuscated SSH case, an
// ObfuscatedSSHConn is layered in front of the client TCP connection; otherwise, both
// modes are identical.
//
// runSSHServer listens on the designated port and spawns new goroutines to handle
// each client connection. It halts when shutdownBroadcast is signaled. A list of active
// clients is maintained, and when halting all clients are first shutdown.
//
// Each client goroutine handles its own obfuscation (optional), SSH handshake, SSH
// authentication, and then looping on client new channel requests. At this time, only
// "direct-tcpip" channels, dynamic port fowards, are expected and supported.
//
// A new goroutine is spawned to handle each port forward. Each port forward tracks its
// bytes transferred. Overall per-client stats for connection duration, GeoIP, number of
// port forwards, and bytes transferred are tracked and logged when the client shuts down.
func runSSHServer(
	config *Config, useObfuscation bool, shutdownBroadcast <-chan struct{}) error {

	privateKey, err := ssh.ParseRawPrivateKey([]byte(config.SSHPrivateKey))
	if err != nil {
		return psiphon.ContextError(err)
	}

	// TODO: use cert (ssh.NewCertSigner) for anti-fingerprint?
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		return psiphon.ContextError(err)
	}

	sshServer := &sshServer{
		config:            config,
		useObfuscation:    useObfuscation,
		shutdownBroadcast: shutdownBroadcast,
		sshHostKey:        signer,
		nextClientID:      1,
		clients:           make(map[sshClientID]*sshClient),
	}

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
			go sshServer.handleClient(conn.(*net.TCPConn))
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

type sshClientID uint64

type sshServer struct {
	config            *Config
	useObfuscation    bool
	shutdownBroadcast <-chan struct{}
	sshHostKey        ssh.Signer
	nextClientID      sshClientID
	clientsMutex      sync.Mutex
	stoppingClients   bool
	clients           map[sshClientID]*sshClient
}

func (sshServer *sshServer) registerClient(client *sshClient) (sshClientID, bool) {

	sshServer.clientsMutex.Lock()
	defer sshServer.clientsMutex.Unlock()

	if sshServer.stoppingClients {
		return 0, false
	}

	clientID := sshServer.nextClientID
	sshServer.nextClientID += 1

	sshServer.clients[clientID] = client

	return clientID, true
}

func (sshServer *sshServer) unregisterClient(clientID sshClientID) {

	sshServer.clientsMutex.Lock()
	client := sshServer.clients[clientID]
	delete(sshServer.clients, clientID)
	sshServer.clientsMutex.Unlock()

	if client != nil {
		sshServer.stopClient(client)
	}
}

func (sshServer *sshServer) stopClient(client *sshClient) {

	client.sshConn.Close()
	client.sshConn.Wait()

	client.Lock()
	log.WithContextFields(
		LogFields{
			"startTime":                     client.startTime,
			"duration":                      time.Now().Sub(client.startTime),
			"psiphonSessionID":              client.psiphonSessionID,
			"country":                       client.geoIPData.Country,
			"city":                          client.geoIPData.City,
			"ISP":                           client.geoIPData.ISP,
			"bytesUp":                       client.bytesUp,
			"bytesDown":                     client.bytesDown,
			"portForwardCount":              client.portForwardCount,
			"maxConcurrentPortForwardCount": client.maxConcurrentPortForwardCount,
		}).Info("tunnel closed")
	client.Unlock()
}

func (sshServer *sshServer) stopClients() {

	sshServer.clientsMutex.Lock()
	sshServer.stoppingClients = true
	sshServer.clients = make(map[sshClientID]*sshClient)
	sshServer.clientsMutex.Unlock()

	for _, client := range sshServer.clients {
		sshServer.stopClient(client)
	}
}

func (sshServer *sshServer) handleClient(tcpConn *net.TCPConn) {

	sshClient := &sshClient{
		sshServer: sshServer,
		startTime: time.Now(),
		geoIPData: GeoIPLookup(psiphon.IPAddressFromAddr(tcpConn.RemoteAddr())),
	}

	// Wrap the base TCP connection in a TimeoutTCPConn which will terminate
	// the connection if it's idle for too long. This timeout is in effect for
	// the entire duration of the SSH connection. Clients must actively use
	// the connection or send SSH keep alive requests to keep the connection
	// active.

	conn := psiphon.NewTimeoutTCPConn(tcpConn, SSH_CONNECTION_READ_DEADLINE)

	// Run the initial [obfuscated] SSH handshake in a goroutine so we can both
	// respect shutdownBroadcast and implement a specific handshake timeout.
	// The timeout is to reclaim network resources in case the handshake takes
	// too long.

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

			sshServerConfig := &ssh.ServerConfig{
				PasswordCallback: sshClient.passwordCallback,
				AuthLogCallback:  sshClient.authLogCallback,
				ServerVersion:    sshServer.config.SSHServerVersion,
			}
			sshServerConfig.AddHostKey(sshServer.sshHostKey)

			result.sshConn, result.channels, result.requests, result.err =
				ssh.NewServerConn(result.conn, sshServerConfig)
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

	sshClient.Lock()
	sshClient.sshConn = result.sshConn
	sshClient.Unlock()

	clientID, ok := sshServer.registerClient(sshClient)
	if !ok {
		tcpConn.Close()
		log.WithContext().Warning("register failed")
		return
	}
	defer sshServer.unregisterClient(clientID)

	go ssh.DiscardRequests(result.requests)

	sshClient.handleChannels(result.channels)
}

type sshClient struct {
	sync.Mutex
	sshServer                     *sshServer
	sshConn                       ssh.Conn
	startTime                     time.Time
	geoIPData                     GeoIPData
	psiphonSessionID              string
	bytesUp                       int64
	bytesDown                     int64
	portForwardCount              int64
	concurrentPortForwardCount    int64
	maxConcurrentPortForwardCount int64
}

func (sshClient *sshClient) handleChannels(channels <-chan ssh.NewChannel) {
	for newChannel := range channels {

		if newChannel.ChannelType() != "direct-tcpip" {
			sshClient.rejectNewChannel(newChannel, ssh.Prohibited, "unknown or unsupported channel type")
			return
		}

		// process each port forward concurrently
		go sshClient.handleNewDirectTcpipChannel(newChannel)
	}
}

func (sshClient *sshClient) rejectNewChannel(newChannel ssh.NewChannel, reason ssh.RejectionReason, message string) {
	// TODO: log more details?
	log.WithContextFields(
		LogFields{
			"channelType":   newChannel.ChannelType(),
			"rejectMessage": message,
			"rejectReason":  reason,
		}).Warning("reject new channel")
	newChannel.Reject(reason, message)
}

func (sshClient *sshClient) handleNewDirectTcpipChannel(newChannel ssh.NewChannel) {

	// http://tools.ietf.org/html/rfc4254#section-7.2
	var directTcpipExtraData struct {
		HostToConnect       string
		PortToConnect       uint32
		OriginatorIPAddress string
		OriginatorPort      uint32
	}

	err := ssh.Unmarshal(newChannel.ExtraData(), &directTcpipExtraData)
	if err != nil {
		sshClient.rejectNewChannel(newChannel, ssh.Prohibited, "invalid extra data")
		return
	}

	targetAddr := fmt.Sprintf("%s:%d",
		directTcpipExtraData.HostToConnect,
		directTcpipExtraData.PortToConnect)

	log.WithContextFields(LogFields{"target": targetAddr}).Debug("dialing")

	// TODO: port forward dial timeout
	// TODO: report ssh.ResourceShortage when appropriate
	// TODO: IPv6 support
	fwdConn, err := net.Dial("tcp4", targetAddr)
	if err != nil {
		sshClient.rejectNewChannel(newChannel, ssh.ConnectionFailed, err.Error())
		return
	}
	defer fwdConn.Close()

	fwdChannel, requests, err := newChannel.Accept()
	if err != nil {
		log.WithContextFields(LogFields{"error": err}).Warning("accept new channel failed")
		return
	}

	sshClient.Lock()
	sshClient.portForwardCount += 1
	sshClient.concurrentPortForwardCount += 1
	if sshClient.concurrentPortForwardCount > sshClient.maxConcurrentPortForwardCount {
		sshClient.maxConcurrentPortForwardCount = sshClient.concurrentPortForwardCount
	}
	sshClient.Unlock()

	log.WithContextFields(LogFields{"target": targetAddr}).Debug("relaying")

	go ssh.DiscardRequests(requests)

	defer fwdChannel.Close()

	// relay channel to forwarded connection

	// TODO: use a low-memory io.Copy?
	// TODO: relay errors to fwdChannel.Stderr()?

	var bytesUp, bytesDown int64

	relayWaitGroup := new(sync.WaitGroup)
	relayWaitGroup.Add(1)
	go func() {
		defer relayWaitGroup.Done()
		var err error
		bytesUp, err = io.Copy(fwdConn, fwdChannel)
		if err != nil {
			log.WithContextFields(LogFields{"error": err}).Warning("upstream relay failed")
		}
	}()
	bytesDown, err = io.Copy(fwdChannel, fwdConn)
	if err != nil {
		log.WithContextFields(LogFields{"error": err}).Warning("downstream relay failed")
	}
	fwdChannel.CloseWrite()
	relayWaitGroup.Wait()

	sshClient.Lock()
	sshClient.concurrentPortForwardCount -= 1
	sshClient.bytesUp += bytesUp
	sshClient.bytesDown += bytesDown
	sshClient.Unlock()

	log.WithContextFields(LogFields{"target": targetAddr}).Debug("exiting")
}

func (sshClient *sshClient) passwordCallback(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	var sshPasswordPayload struct {
		SessionId   string `json:"SessionId"`
		SshPassword string `json:"SshPassword"`
	}
	err := json.Unmarshal(password, &sshPasswordPayload)
	if err != nil {
		return nil, psiphon.ContextError(fmt.Errorf("invalid password payload for %q", conn.User()))
	}

	userOk := (subtle.ConstantTimeCompare(
		[]byte(conn.User()), []byte(sshClient.sshServer.config.SSHUserName)) == 1)

	passwordOk := (subtle.ConstantTimeCompare(
		[]byte(sshPasswordPayload.SshPassword), []byte(sshClient.sshServer.config.SSHPassword)) == 1)

	if !userOk || !passwordOk {
		return nil, psiphon.ContextError(fmt.Errorf("invalid password for %q", conn.User()))
	}

	psiphonSessionID := sshPasswordPayload.SessionId

	sshClient.Lock()
	sshClient.psiphonSessionID = psiphonSessionID
	geoIPData := sshClient.geoIPData
	sshClient.Unlock()

	if sshClient.sshServer.config.UseRedis() {
		err = UpdateRedisForLegacyPsiWeb(psiphonSessionID, geoIPData)
		if err != nil {
			log.WithContextFields(LogFields{
				"psiphonSessionID": psiphonSessionID,
				"error":            err}).Warning("UpdateRedisForLegacyPsiWeb failed")
			// Allow the connection to proceed; legacy psi_web will not get accurate GeoIP values.
		}
	}

	return nil, nil
}

func (sshClient *sshClient) authLogCallback(conn ssh.ConnMetadata, method string, err error) {
	if err != nil {
		log.WithContextFields(LogFields{"error": err, "method": method}).Warning("authentication failed")
	} else {
		log.WithContextFields(LogFields{"error": err, "method": method}).Info("authentication success")
	}
}
