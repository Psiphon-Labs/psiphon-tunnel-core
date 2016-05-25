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
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon"
	"golang.org/x/crypto/ssh"
)

// RunSSHServer runs an SSH server, the core tunneling component of the Psiphon
// server. The SSH server runs a selection of listeners that handle connections
// using various, optional obfuscation protocols layered on top of SSH.
// (Currently, just Obfuscated SSH).
//
// RunSSHServer listens on the designated port(s) and spawns new goroutines to handle
// each client connection. It halts when shutdownBroadcast is signaled. A list of active
// clients is maintained, and when halting all clients are first shutdown.
//
// Each client goroutine handles its own obfuscation (optional), SSH handshake, SSH
// authentication, and then looping on client new channel requests. At this time, only
// "direct-tcpip" channels, dynamic port fowards, are expected and supported.
//
// A new goroutine is spawned to handle each port forward for each client. Each port
// forward tracks its bytes transferred. Overall per-client stats for connection duration,
// GeoIP, number of port forwards, and bytes transferred are tracked and logged when the
// client shuts down.
func RunSSHServer(
	config *Config, shutdownBroadcast <-chan struct{}) error {

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
		runWaitGroup:      new(sync.WaitGroup),
		listenerError:     make(chan error),
		shutdownBroadcast: shutdownBroadcast,
		sshHostKey:        signer,
		nextClientID:      1,
		clients:           make(map[sshClientID]*sshClient),
	}

	type sshListener struct {
		net.Listener
		localAddress   string
		tunnelProtocol string
	}

	var listeners []*sshListener

	if config.RunSSHServer() {
		listeners = append(listeners, &sshListener{
			localAddress: fmt.Sprintf(
				"%s:%d", config.ServerIPAddress, config.SSHServerPort),
			tunnelProtocol: psiphon.TUNNEL_PROTOCOL_SSH,
		})
	}

	if config.RunObfuscatedSSHServer() {
		listeners = append(listeners, &sshListener{
			localAddress: fmt.Sprintf(
				"%s:%d", config.ServerIPAddress, config.ObfuscatedSSHServerPort),
			tunnelProtocol: psiphon.TUNNEL_PROTOCOL_OBFUSCATED_SSH,
		})
	}

	// TODO: add additional protocol listeners here (e.g, meek)

	for i, listener := range listeners {
		var err error
		listener.Listener, err = net.Listen("tcp", listener.localAddress)
		if err != nil {
			for j := 0; j < i; j++ {
				listener.Listener.Close()
			}
			return psiphon.ContextError(err)
		}
		log.WithContextFields(
			LogFields{
				"localAddress":   listener.localAddress,
				"tunnelProtocol": listener.tunnelProtocol,
			}).Info("listening")
	}

	for _, listener := range listeners {
		sshServer.runWaitGroup.Add(1)
		go func(listener *sshListener) {
			defer sshServer.runWaitGroup.Done()

			sshServer.runListener(
				listener.Listener, listener.tunnelProtocol)

			log.WithContextFields(
				LogFields{
					"localAddress":   listener.localAddress,
					"tunnelProtocol": listener.tunnelProtocol,
				}).Info("stopping")

		}(listener)
	}

	if config.RunLoadMonitor() {
		sshServer.runWaitGroup.Add(1)
		go func() {
			defer sshServer.runWaitGroup.Done()
			sshServer.runLoadMonitor()
		}()
	}

	err = nil
	select {
	case <-sshServer.shutdownBroadcast:
	case err = <-sshServer.listenerError:
	}

	for _, listener := range listeners {
		listener.Close()
	}
	sshServer.stopClients()
	sshServer.runWaitGroup.Wait()

	log.WithContext().Info("stopped")

	return err
}

type sshClientID uint64

type sshServer struct {
	config            *Config
	runWaitGroup      *sync.WaitGroup
	listenerError     chan error
	shutdownBroadcast <-chan struct{}
	sshHostKey        ssh.Signer
	nextClientID      sshClientID
	clientsMutex      sync.Mutex
	stoppingClients   bool
	clients           map[sshClientID]*sshClient
}

func (sshServer *sshServer) runListener(
	listener net.Listener, tunnelProtocol string) {

	for {
		conn, err := listener.Accept()

		if err == nil && tunnelProtocol == psiphon.TUNNEL_PROTOCOL_OBFUSCATED_SSH {
			conn, err = psiphon.NewObfuscatedSshConn(
				psiphon.OBFUSCATION_CONN_MODE_SERVER,
				conn,
				sshServer.config.ObfuscatedSSHKey)
		}

		select {
		case <-sshServer.shutdownBroadcast:
			if err == nil {
				conn.Close()
			}
			return
		default:
		}

		if err != nil {
			if e, ok := err.(net.Error); ok && e.Temporary() {
				log.WithContextFields(LogFields{"error": err}).Error("accept failed")
				// Temporary error, keep running
				continue
			}

			select {
			case sshServer.listenerError <- psiphon.ContextError(err):
			default:
			}

			return
		}

		// process each client connection concurrently
		go sshServer.handleClient(tunnelProtocol, conn)
	}
}

func (sshServer *sshServer) runLoadMonitor() {
	ticker := time.NewTicker(
		time.Duration(sshServer.config.LoadMonitorPeriodSeconds) * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-sshServer.shutdownBroadcast:
			return
		case <-ticker.C:
			var memStats runtime.MemStats
			runtime.ReadMemStats(&memStats)
			fields := LogFields{
				"goroutines":    runtime.NumGoroutine(),
				"memAlloc":      memStats.Alloc,
				"memTotalAlloc": memStats.TotalAlloc,
				"memSysAlloc":   memStats.Sys,
			}
			for tunnelProtocol, count := range sshServer.countClients() {
				fields[tunnelProtocol] = count
			}
			log.WithContextFields(fields).Info("load")
		}
	}
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
		client.stop()
	}
}

func (sshServer *sshServer) countClients() map[string]int {

	sshServer.clientsMutex.Lock()
	defer sshServer.clientsMutex.Unlock()

	counts := make(map[string]int)
	for _, client := range sshServer.clients {
		counts[client.tunnelProtocol] += 1
	}
	return counts
}

func (sshServer *sshServer) stopClients() {

	sshServer.clientsMutex.Lock()
	sshServer.stoppingClients = true
	sshServer.clients = make(map[sshClientID]*sshClient)
	sshServer.clientsMutex.Unlock()

	for _, client := range sshServer.clients {
		client.stop()
	}
}

func (sshServer *sshServer) handleClient(tunnelProtocol string, clientConn net.Conn) {

	geoIPData := GeoIPLookup(psiphon.IPAddressFromAddr(clientConn.RemoteAddr()))

	sshClient := newSshClient(
		sshServer,
		tunnelProtocol,
		geoIPData,
		sshServer.config.GetTrafficRules(geoIPData.Country))

	// Wrap the base client connection with an IdleTimeoutConn which will terminate
	// the connection if no data is received before the deadline. This timeout is
	// in effect for the entire duration of the SSH connection. Clients must actively
	// use the connection or send SSH keep alive requests to keep the connection
	// active.

	var conn net.Conn

	conn = psiphon.NewIdleTimeoutConn(clientConn, SSH_CONNECTION_READ_DEADLINE, false)

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

	go func(conn net.Conn) {
		sshServerConfig := &ssh.ServerConfig{
			PasswordCallback: sshClient.passwordCallback,
			AuthLogCallback:  sshClient.authLogCallback,
			ServerVersion:    sshServer.config.SSHServerVersion,
		}
		sshServerConfig.AddHostKey(sshServer.sshHostKey)

		sshConn, channels, requests, err :=
			ssh.NewServerConn(conn, sshServerConfig)

		resultChannel <- &sshNewServerConnResult{
			conn:     conn,
			sshConn:  sshConn,
			channels: channels,
			requests: requests,
			err:      err,
		}
	}(conn)

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
	sshServer               *sshServer
	tunnelProtocol          string
	sshConn                 ssh.Conn
	startTime               time.Time
	geoIPData               GeoIPData
	psiphonSessionID        string
	udpChannel              ssh.Channel
	trafficRules            TrafficRules
	tcpTrafficState         *trafficState
	udpTrafficState         *trafficState
	channelHandlerWaitGroup *sync.WaitGroup
	stopBroadcast           chan struct{}
}

type trafficState struct {
	bytesUp                        int64
	bytesDown                      int64
	portForwardCount               int64
	concurrentPortForwardCount     int64
	peakConcurrentPortForwardCount int64
}

func newSshClient(
	sshServer *sshServer, tunnelProtocol string, geoIPData GeoIPData, trafficRules TrafficRules) *sshClient {
	return &sshClient{
		sshServer:               sshServer,
		tunnelProtocol:          tunnelProtocol,
		startTime:               time.Now(),
		geoIPData:               geoIPData,
		trafficRules:            trafficRules,
		tcpTrafficState:         &trafficState{},
		udpTrafficState:         &trafficState{},
		channelHandlerWaitGroup: new(sync.WaitGroup),
		stopBroadcast:           make(chan struct{}),
	}
}

func (sshClient *sshClient) handleChannels(channels <-chan ssh.NewChannel) {
	for newChannel := range channels {

		if newChannel.ChannelType() != "direct-tcpip" {
			sshClient.rejectNewChannel(newChannel, ssh.Prohibited, "unknown or unsupported channel type")
			continue
		}

		// process each port forward concurrently
		sshClient.channelHandlerWaitGroup.Add(1)
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
	defer sshClient.channelHandlerWaitGroup.Done()

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

func (sshClient *sshClient) openedPortForward(
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

	var bytesUp, bytesDown int64
	sshClient.openedPortForward(sshClient.tcpTrafficState)
	defer sshClient.closedPortForward(
		sshClient.tcpTrafficState, atomic.LoadInt64(&bytesUp), atomic.LoadInt64(&bytesDown))

	// TOCTOU note: important to increment the port forward count (via
	// openPortForward) _before_ checking isPortForwardLimitExceeded
	// otherwise, the client could potentially consume excess resources
	// by initiating many port forwards concurrently.
	// TODO: close LRU connection (after successful Dial) instead of
	// rejecting new connection?
	if sshClient.isPortForwardLimitExceeded(
		sshClient.tcpTrafficState,
		sshClient.trafficRules.MaxTCPPortForwardCount) {

		sshClient.rejectNewChannel(
			newChannel, ssh.Prohibited, "maximum port forward limit exceeded")
		return
	}

	remoteAddr := fmt.Sprintf("%s:%d", hostToConnect, portToConnect)

	log.WithContextFields(LogFields{"remoteAddr": remoteAddr}).Debug("dialing")

	type dialTcpResult struct {
		conn net.Conn
		err  error
	}

	resultChannel := make(chan *dialTcpResult, 1)

	go func() {
		// TODO: on EADDRNOTAVAIL, temporarily suspend new clients
		// TODO: IPv6 support
		conn, err := net.DialTimeout(
			"tcp4", remoteAddr, SSH_TCP_PORT_FORWARD_DIAL_TIMEOUT)
		resultChannel <- &dialTcpResult{conn, err}
	}()

	var result *dialTcpResult
	select {
	case result = <-resultChannel:
	case <-sshClient.stopBroadcast:
		// Note: may leave dial in progress
		return
	}

	if result.err != nil {
		sshClient.rejectNewChannel(newChannel, ssh.ConnectionFailed, result.err.Error())
		return
	}

	fwdConn := result.conn
	defer fwdConn.Close()

	fwdChannel, requests, err := newChannel.Accept()
	if err != nil {
		log.WithContextFields(LogFields{"error": err}).Warning("accept new channel failed")
		return
	}
	go ssh.DiscardRequests(requests)
	defer fwdChannel.Close()

	log.WithContextFields(LogFields{"remoteAddr": remoteAddr}).Debug("relaying")

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

	relayWaitGroup := new(sync.WaitGroup)
	relayWaitGroup.Add(1)
	go func() {
		defer relayWaitGroup.Done()
		bytes, err := io.Copy(fwdChannel, fwdConn)
		atomic.AddInt64(&bytesDown, bytes)
		if err != nil && err != io.EOF {
			// Debug since errors such as "connection reset by peer" occur during normal operation
			log.WithContextFields(LogFields{"error": err}).Debug("downstream TCP relay failed")
		}
	}()
	bytes, err := io.Copy(fwdConn, fwdChannel)
	atomic.AddInt64(&bytesUp, bytes)
	if err != nil && err != io.EOF {
		log.WithContextFields(LogFields{"error": err}).Debug("upstream TCP relay failed")
	}

	// Shutdown special case: fwdChannel will be closed and return EOF when
	// the SSH connection is closed, but we need to explicitly close fwdConn
	// to interrupt the downstream io.Copy, which may be blocked on a
	// fwdConn.Read().
	fwdConn.Close()

	relayWaitGroup.Wait()

	log.WithContextFields(
		LogFields{
			"remoteAddr": remoteAddr,
			"bytesUp":    atomic.LoadInt64(&bytesUp),
			"bytesDown":  atomic.LoadInt64(&bytesDown)}).Debug("exiting")
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

func (sshClient *sshClient) stop() {

	sshClient.sshConn.Close()
	sshClient.sshConn.Wait()

	close(sshClient.stopBroadcast)
	sshClient.channelHandlerWaitGroup.Wait()

	sshClient.Lock()
	log.WithContextFields(
		LogFields{
			"startTime":                         sshClient.startTime,
			"duration":                          time.Now().Sub(sshClient.startTime),
			"psiphonSessionID":                  sshClient.psiphonSessionID,
			"country":                           sshClient.geoIPData.Country,
			"city":                              sshClient.geoIPData.City,
			"ISP":                               sshClient.geoIPData.ISP,
			"bytesUpTCP":                        sshClient.tcpTrafficState.bytesUp,
			"bytesDownTCP":                      sshClient.tcpTrafficState.bytesDown,
			"portForwardCountTCP":               sshClient.tcpTrafficState.portForwardCount,
			"peakConcurrentPortForwardCountTCP": sshClient.tcpTrafficState.peakConcurrentPortForwardCount,
			"bytesUpUDP":                        sshClient.udpTrafficState.bytesUp,
			"bytesDownUDP":                      sshClient.udpTrafficState.bytesDown,
			"portForwardCountUDP":               sshClient.udpTrafficState.portForwardCount,
			"peakConcurrentPortForwardCountUDP": sshClient.udpTrafficState.peakConcurrentPortForwardCount,
		}).Info("tunnel closed")
	sshClient.Unlock()
}
