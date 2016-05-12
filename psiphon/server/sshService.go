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
			"startTime":                         client.startTime,
			"duration":                          time.Now().Sub(client.startTime),
			"psiphonSessionID":                  client.psiphonSessionID,
			"country":                           client.geoIPData.Country,
			"city":                              client.geoIPData.City,
			"ISP":                               client.geoIPData.ISP,
			"bytesUpTCP":                        client.tcpTrafficState.bytesUp,
			"bytesDownTCP":                      client.tcpTrafficState.bytesDown,
			"portForwardCountTCP":               client.tcpTrafficState.portForwardCount,
			"peakConcurrentPortForwardCountTCP": client.tcpTrafficState.peakConcurrentPortForwardCount,
			"bytesUpUDP":                        client.udpTrafficState.bytesUp,
			"bytesDownUDP":                      client.udpTrafficState.bytesDown,
			"portForwardCountUDP":               client.udpTrafficState.portForwardCount,
			"peakConcurrentPortForwardCountUDP": client.udpTrafficState.peakConcurrentPortForwardCount,
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

	geoIPData := GeoIPLookup(psiphon.IPAddressFromAddr(tcpConn.RemoteAddr()))

	sshClient := &sshClient{
		sshServer:       sshServer,
		startTime:       time.Now(),
		geoIPData:       geoIPData,
		trafficRules:    sshServer.config.GetTrafficRules(geoIPData.Country),
		tcpTrafficState: &trafficState{},
		udpTrafficState: &trafficState{},
	}

	// Wrap the base TCP connection with an IdleTimeoutConn which will terminate
	// the connection if no data is received before the deadline. This timeout is
	// in effect for the entire duration of the SSH connection. Clients must actively
	// use the connection or send SSH keep alive requests to keep the connection
	// active.

	var conn net.Conn

	conn = psiphon.NewIdleTimeoutConn(tcpConn, SSH_CONNECTION_READ_DEADLINE, false)

	// Further wrap the connection in a rate limiting ThrottledConn.

	conn = psiphon.NewThrottledConn(
		conn,
		int64(sshClient.trafficRules.LimitDownstreamBytesPerSecond),
		int64(sshClient.trafficRules.LimitUpstreamBytesPerSecond))

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
		conn.Close()
		log.WithContext().Warning("register failed")
		return
	}
	defer sshServer.unregisterClient(clientID)

	go ssh.DiscardRequests(result.requests)

	sshClient.handleChannels(result.channels)
}

type sshClient struct {
	sync.Mutex
	sshServer        *sshServer
	sshConn          ssh.Conn
	startTime        time.Time
	geoIPData        GeoIPData
	psiphonSessionID string
	udpChannel       ssh.Channel
	trafficRules     TrafficRules
	tcpTrafficState  *trafficState
	udpTrafficState  *trafficState
}

type trafficState struct {
	bytesUp                        int64
	bytesDown                      int64
	portForwardCount               int64
	concurrentPortForwardCount     int64
	peakConcurrentPortForwardCount int64
}

func (sshClient *sshClient) handleChannels(channels <-chan ssh.NewChannel) {
	for newChannel := range channels {

		if newChannel.ChannelType() != "direct-tcpip" {
			sshClient.rejectNewChannel(newChannel, ssh.Prohibited, "unknown or unsupported channel type")
			return
		}

		// process each port forward concurrently
		go sshClient.handleNewPortForwardChannel(newChannel)
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

func (sshClient *sshClient) handleNewPortForwardChannel(newChannel ssh.NewChannel) {

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

	// Intercept TCP port forwards to a specified udpgw server and handle directly.
	// TODO: also support UDP explicitly, e.g. with a custom "direct-udp" channel type?
	isUDPChannel := sshClient.sshServer.config.UdpgwServerAddress != "" &&
		sshClient.sshServer.config.UdpgwServerAddress ==
			fmt.Sprintf("%s:%d",
				directTcpipExtraData.HostToConnect,
				directTcpipExtraData.PortToConnect)

	if isUDPChannel {
		sshClient.handleUDPChannel(newChannel)
	} else {
		sshClient.handleTCPChannel(
			directTcpipExtraData.HostToConnect, int(directTcpipExtraData.PortToConnect), newChannel)
	}
}

func (sshClient *sshClient) isPortForwardPermitted(
	port int, allowPorts []int, denyPorts []int) bool {

	// TODO: faster lookup?
	if allowPorts != nil {
		for _, allowPort := range allowPorts {
			if port == allowPort {
				return true
			}
		}
		return false
	}
	if denyPorts != nil {
		for _, denyPort := range denyPorts {
			if port == denyPort {
				return false
			}
		}
	}
	return true
}

func (sshClient *sshClient) isPortForwardLimitExceeded(
	state *trafficState, maxPortForwardCount int) bool {

	limitExceeded := false
	if maxPortForwardCount > 0 {
		sshClient.Lock()
		limitExceeded = state.portForwardCount >= int64(maxPortForwardCount)
		sshClient.Unlock()
	}
	return limitExceeded
}

func (sshClient *sshClient) establishedPortForward(
	state *trafficState) {

	sshClient.Lock()
	state.portForwardCount += 1
	state.concurrentPortForwardCount += 1
	if state.concurrentPortForwardCount > state.peakConcurrentPortForwardCount {
		state.peakConcurrentPortForwardCount = state.concurrentPortForwardCount
	}
	sshClient.Unlock()
}

func (sshClient *sshClient) closedPortForward(
	state *trafficState, bytesUp, bytesDown int64) {

	sshClient.Lock()
	state.concurrentPortForwardCount -= 1
	state.bytesUp += bytesUp
	state.bytesDown += bytesDown
	sshClient.Unlock()
}

func (sshClient *sshClient) handleTCPChannel(
	hostToConnect string,
	portToConnect int,
	newChannel ssh.NewChannel) {

	if !sshClient.isPortForwardPermitted(
		portToConnect,
		sshClient.trafficRules.AllowTCPPorts,
		sshClient.trafficRules.DenyTCPPorts) {

		sshClient.rejectNewChannel(
			newChannel, ssh.Prohibited, "port forward not permitted")
		return
	}

	// TODO: close LRU connection (after successful Dial) instead of rejecting new connection?
	if sshClient.isPortForwardLimitExceeded(
		sshClient.tcpTrafficState,
		sshClient.trafficRules.MaxTCPPortForwardCount) {

		sshClient.rejectNewChannel(
			newChannel, ssh.Prohibited, "maximum port forward limit exceeded")
		return
	}

	targetAddr := fmt.Sprintf("%s:%d", hostToConnect, portToConnect)

	log.WithContextFields(LogFields{"target": targetAddr}).Debug("dialing")

	// TODO: on EADDRNOTAVAIL, temporarily suspend new clients
	// TODO: port forward dial timeout
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
	go ssh.DiscardRequests(requests)
	defer fwdChannel.Close()

	sshClient.establishedPortForward(sshClient.tcpTrafficState)

	log.WithContextFields(LogFields{"target": targetAddr}).Debug("relaying")

	// When idle port forward traffic rules are in place, wrap fwdConn
	// in an IdleTimeoutConn configured to reset idle on writes as well
	// as read. This ensures the port forward idle timeout only happens
	// when both upstream and downstream directions are are idle.

	if sshClient.trafficRules.IdlePortForwardTimeoutMilliseconds > 0 {
		fwdConn = psiphon.NewIdleTimeoutConn(
			fwdConn,
			time.Duration(sshClient.trafficRules.IdlePortForwardTimeoutMilliseconds)*time.Millisecond,
			true)
	}

	// relay channel to forwarded connection
	// TODO: relay errors to fwdChannel.Stderr()?
	// TODO: use a low-memory io.Copy?

	var bytesUp, bytesDown int64

	relayWaitGroup := new(sync.WaitGroup)
	relayWaitGroup.Add(1)
	go func() {
		defer relayWaitGroup.Done()
		var err error
		bytesUp, err = io.Copy(fwdConn, fwdChannel)
		if err != nil {
			log.WithContextFields(LogFields{"error": err}).Warning("upstream TCP relay failed")
		}
	}()
	bytesDown, err = io.Copy(fwdChannel, fwdConn)
	if err != nil {
		log.WithContextFields(LogFields{"error": err}).Warning("downstream TCP relay failed")
	}
	fwdChannel.CloseWrite()
	relayWaitGroup.Wait()

	sshClient.closedPortForward(sshClient.tcpTrafficState, bytesUp, bytesDown)

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
		if sshClient.sshServer.config.UseFail2Ban() {
			clientIPAddress := psiphon.IPAddressFromAddr(conn.RemoteAddr())
			if clientIPAddress != "" {
				LogFail2Ban(clientIPAddress)
			}
		}
		log.WithContextFields(LogFields{"error": err, "method": method}).Warning("authentication failed")
	} else {
		log.WithContextFields(LogFields{"error": err, "method": method}).Info("authentication success")
	}
}
