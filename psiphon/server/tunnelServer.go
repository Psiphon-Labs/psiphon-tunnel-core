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
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	std_errors "errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/Psiphon-Labs/goarista/monotime"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/accesscontrol"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/crypto/ssh"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/marionette"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/obfuscator"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/osl"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/parameters"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/quic"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/refraction"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/tactics"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/tun"
	"github.com/marusama/semaphore"
	cache "github.com/patrickmn/go-cache"
)

const (
	SSH_AUTH_LOG_PERIOD                   = 30 * time.Minute
	SSH_HANDSHAKE_TIMEOUT                 = 30 * time.Second
	SSH_BEGIN_HANDSHAKE_TIMEOUT           = 1 * time.Second
	SSH_CONNECTION_READ_DEADLINE          = 5 * time.Minute
	SSH_TCP_PORT_FORWARD_COPY_BUFFER_SIZE = 8192
	SSH_TCP_PORT_FORWARD_QUEUE_SIZE       = 1024
	SSH_KEEP_ALIVE_PAYLOAD_MIN_BYTES      = 0
	SSH_KEEP_ALIVE_PAYLOAD_MAX_BYTES      = 256
	SSH_SEND_OSL_INITIAL_RETRY_DELAY      = 30 * time.Second
	SSH_SEND_OSL_RETRY_FACTOR             = 2
	OSL_SESSION_CACHE_TTL                 = 5 * time.Minute
	MAX_AUTHORIZATIONS                    = 16
	PRE_HANDSHAKE_RANDOM_STREAM_MAX_COUNT = 1
	RANDOM_STREAM_MAX_BYTES               = 10485760
	ALERT_REQUEST_QUEUE_BUFFER_SIZE       = 16
)

// TunnelServer is the main server that accepts Psiphon client
// connections, via various obfuscation protocols, and provides
// port forwarding (TCP and UDP) services to the Psiphon client.
// At its core, TunnelServer is an SSH server. SSH is the base
// protocol that provides port forward multiplexing, and transport
// security. Layered on top of SSH, optionally, is Obfuscated SSH
// and meek protocols, which provide further circumvention
// capabilities.
type TunnelServer struct {
	runWaitGroup      *sync.WaitGroup
	listenerError     chan error
	shutdownBroadcast <-chan struct{}
	sshServer         *sshServer
}

type sshListener struct {
	net.Listener
	localAddress   string
	tunnelProtocol string
	port           int
	BPFProgramName string
}

// NewTunnelServer initializes a new tunnel server.
func NewTunnelServer(
	support *SupportServices,
	shutdownBroadcast <-chan struct{}) (*TunnelServer, error) {

	sshServer, err := newSSHServer(support, shutdownBroadcast)
	if err != nil {
		return nil, errors.Trace(err)
	}

	return &TunnelServer{
		runWaitGroup:      new(sync.WaitGroup),
		listenerError:     make(chan error),
		shutdownBroadcast: shutdownBroadcast,
		sshServer:         sshServer,
	}, nil
}

// Run runs the tunnel server; this function blocks while running a selection of
// listeners that handle connection using various obfuscation protocols.
//
// Run listens on each designated tunnel port and spawns new goroutines to handle
// each client connection. It halts when shutdownBroadcast is signaled. A list of active
// clients is maintained, and when halting all clients are cleanly shutdown.
//
// Each client goroutine handles its own obfuscation (optional), SSH handshake, SSH
// authentication, and then looping on client new channel requests. "direct-tcpip"
// channels, dynamic port fowards, are supported. When the UDPInterceptUdpgwServerAddress
// config parameter is configured, UDP port forwards over a TCP stream, following
// the udpgw protocol, are handled.
//
// A new goroutine is spawned to handle each port forward for each client. Each port
// forward tracks its bytes transferred. Overall per-client stats for connection duration,
// GeoIP, number of port forwards, and bytes transferred are tracked and logged when the
// client shuts down.
//
// Note: client handler goroutines may still be shutting down after Run() returns. See
// comment in sshClient.stop(). TODO: fully synchronized shutdown.
func (server *TunnelServer) Run() error {

	// TODO: should TunnelServer hold its own support pointer?
	support := server.sshServer.support

	// First bind all listeners; once all are successful,
	// start accepting connections on each.

	var listeners []*sshListener

	for tunnelProtocol, listenPort := range support.Config.TunnelProtocolPorts {

		localAddress := fmt.Sprintf(
			"%s:%d", support.Config.ServerIPAddress, listenPort)

		var listener net.Listener
		var BPFProgramName string
		var err error

		if protocol.TunnelProtocolUsesFrontedMeekQUIC(tunnelProtocol) {

			// For FRONTED-MEEK-QUIC-OSSH, no listener implemented. The edge-to-server
			// hop uses HTTPS and the client tunnel protocol is distinguished using
			// protocol.MeekCookieData.ClientTunnelProtocol.
			continue

		} else if protocol.TunnelProtocolUsesQUIC(tunnelProtocol) {

			listener, err = quic.Listen(
				CommonLogger(log),
				localAddress,
				support.Config.ObfuscatedSSHKey)

		} else if protocol.TunnelProtocolUsesMarionette(tunnelProtocol) {

			listener, err = marionette.Listen(
				support.Config.ServerIPAddress,
				support.Config.MarionetteFormat)

		} else if protocol.TunnelProtocolUsesRefractionNetworking(tunnelProtocol) {

			listener, err = refraction.Listen(localAddress)

		} else if protocol.TunnelProtocolUsesFrontedMeek(tunnelProtocol) {

			listener, err = net.Listen("tcp", localAddress)

		} else {

			// Only direct, unfronted protocol listeners use TCP BPF circumvention
			// programs.
			listener, BPFProgramName, err = newTCPListenerWithBPF(support, localAddress)
		}

		if err != nil {
			for _, existingListener := range listeners {
				existingListener.Listener.Close()
			}
			return errors.Trace(err)
		}

		tacticsListener := NewTacticsListener(
			support,
			listener,
			tunnelProtocol,
			func(IP string) GeoIPData { return support.GeoIPService.Lookup(IP, false) })

		log.WithTraceFields(
			LogFields{
				"localAddress":   localAddress,
				"tunnelProtocol": tunnelProtocol,
				"BPFProgramName": BPFProgramName,
			}).Info("listening")

		listeners = append(
			listeners,
			&sshListener{
				Listener:       tacticsListener,
				localAddress:   localAddress,
				port:           listenPort,
				tunnelProtocol: tunnelProtocol,
				BPFProgramName: BPFProgramName,
			})
	}

	for _, listener := range listeners {
		server.runWaitGroup.Add(1)
		go func(listener *sshListener) {
			defer server.runWaitGroup.Done()

			log.WithTraceFields(
				LogFields{
					"localAddress":   listener.localAddress,
					"tunnelProtocol": listener.tunnelProtocol,
				}).Info("running")

			server.sshServer.runListener(
				listener,
				server.listenerError)

			log.WithTraceFields(
				LogFields{
					"localAddress":   listener.localAddress,
					"tunnelProtocol": listener.tunnelProtocol,
				}).Info("stopped")

		}(listener)
	}

	var err error
	select {
	case <-server.shutdownBroadcast:
	case err = <-server.listenerError:
	}

	for _, listener := range listeners {
		listener.Close()
	}
	server.sshServer.stopClients()
	server.runWaitGroup.Wait()

	log.WithTrace().Info("stopped")

	return err
}

// GetLoadStats returns load stats for the tunnel server. The stats are
// broken down by protocol ("SSH", "OSSH", etc.) and type. Types of stats
// include current connected client count, total number of current port
// forwards.
func (server *TunnelServer) GetLoadStats() (ProtocolStats, RegionStats) {
	return server.sshServer.getLoadStats()
}

// GetEstablishedClientCount returns the number of currently established
// clients.
func (server *TunnelServer) GetEstablishedClientCount() int {
	return server.sshServer.getEstablishedClientCount()
}

// ResetAllClientTrafficRules resets all established client traffic rules
// to use the latest config and client properties. Any existing traffic
// rule state is lost, including throttling state.
func (server *TunnelServer) ResetAllClientTrafficRules() {
	server.sshServer.resetAllClientTrafficRules()
}

// ResetAllClientOSLConfigs resets all established client OSL state to use
// the latest OSL config. Any existing OSL state is lost, including partial
// progress towards SLOKs.
func (server *TunnelServer) ResetAllClientOSLConfigs() {
	server.sshServer.resetAllClientOSLConfigs()
}

// SetClientHandshakeState sets the handshake state -- that it completed and
// what parameters were passed -- in sshClient. This state is used for allowing
// port forwards and for future traffic rule selection. SetClientHandshakeState
// also triggers an immediate traffic rule re-selection, as the rules selected
// upon tunnel establishment may no longer apply now that handshake values are
// set.
//
// The authorizations received from the client handshake are verified and the
// resulting list of authorized access types are applied to the client's tunnel
// and traffic rules.
//
// A list of active authorization IDs, authorized access types, and traffic
// rate limits are returned for responding to the client and logging.
func (server *TunnelServer) SetClientHandshakeState(
	sessionID string,
	state handshakeState,
	authorizations []string) (*handshakeStateInfo, error) {

	return server.sshServer.setClientHandshakeState(sessionID, state, authorizations)
}

// GetClientHandshaked indicates whether the client has completed a handshake
// and whether its traffic rules are immediately exhausted.
func (server *TunnelServer) GetClientHandshaked(
	sessionID string) (bool, bool, error) {

	return server.sshServer.getClientHandshaked(sessionID)
}

// UpdateClientAPIParameters updates the recorded handshake API parameters for
// the client corresponding to sessionID.
func (server *TunnelServer) UpdateClientAPIParameters(
	sessionID string,
	apiParams common.APIParameters) error {

	return server.sshServer.updateClientAPIParameters(sessionID, apiParams)
}

// ExpectClientDomainBytes indicates whether the client was configured to report
// domain bytes in its handshake response.
func (server *TunnelServer) ExpectClientDomainBytes(
	sessionID string) (bool, error) {

	return server.sshServer.expectClientDomainBytes(sessionID)
}

// SetEstablishTunnels sets whether new tunnels may be established or not.
// When not establishing, incoming connections are immediately closed.
func (server *TunnelServer) SetEstablishTunnels(establish bool) {
	server.sshServer.setEstablishTunnels(establish)
}

// CheckEstablishTunnels returns whether new tunnels may be established or
// not, and increments a metrics counter when establishment is disallowed.
func (server *TunnelServer) CheckEstablishTunnels() bool {
	return server.sshServer.checkEstablishTunnels()
}

// GetEstablishTunnelsMetrics returns whether tunnel establishment is
// currently allowed and the number of tunnels rejected since due to not
// establishing since the last GetEstablishTunnelsMetrics call.
func (server *TunnelServer) GetEstablishTunnelsMetrics() (bool, int64) {
	return server.sshServer.getEstablishTunnelsMetrics()
}

type sshServer struct {
	// Note: 64-bit ints used with atomic operations are placed
	// at the start of struct to ensure 64-bit alignment.
	// (https://golang.org/pkg/sync/atomic/#pkg-note-BUG)
	lastAuthLog                  int64
	authFailedCount              int64
	establishLimitedCount        int64
	support                      *SupportServices
	establishTunnels             int32
	concurrentSSHHandshakes      semaphore.Semaphore
	shutdownBroadcast            <-chan struct{}
	sshHostKey                   ssh.Signer
	clientsMutex                 sync.Mutex
	stoppingClients              bool
	acceptedClientCounts         map[string]map[string]int64
	clients                      map[string]*sshClient
	oslSessionCacheMutex         sync.Mutex
	oslSessionCache              *cache.Cache
	authorizationSessionIDsMutex sync.Mutex
	authorizationSessionIDs      map[string]string
	obfuscatorSeedHistory        *obfuscator.SeedHistory
}

func newSSHServer(
	support *SupportServices,
	shutdownBroadcast <-chan struct{}) (*sshServer, error) {

	privateKey, err := ssh.ParseRawPrivateKey([]byte(support.Config.SSHPrivateKey))
	if err != nil {
		return nil, errors.Trace(err)
	}

	// TODO: use cert (ssh.NewCertSigner) for anti-fingerprint?
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		return nil, errors.Trace(err)
	}

	var concurrentSSHHandshakes semaphore.Semaphore
	if support.Config.MaxConcurrentSSHHandshakes > 0 {
		concurrentSSHHandshakes = semaphore.New(support.Config.MaxConcurrentSSHHandshakes)
	}

	// The OSL session cache temporarily retains OSL seed state
	// progress for disconnected clients. This enables clients
	// that disconnect and immediately reconnect to the same
	// server to resume their OSL progress. Cached progress
	// is referenced by session ID and is retained for
	// OSL_SESSION_CACHE_TTL after disconnect.
	//
	// Note: session IDs are assumed to be unpredictable. If a
	// rogue client could guess the session ID of another client,
	// it could resume its OSL progress and, if the OSL config
	// were known, infer some activity.
	oslSessionCache := cache.New(OSL_SESSION_CACHE_TTL, 1*time.Minute)

	return &sshServer{
		support:                 support,
		establishTunnels:        1,
		concurrentSSHHandshakes: concurrentSSHHandshakes,
		shutdownBroadcast:       shutdownBroadcast,
		sshHostKey:              signer,
		acceptedClientCounts:    make(map[string]map[string]int64),
		clients:                 make(map[string]*sshClient),
		oslSessionCache:         oslSessionCache,
		authorizationSessionIDs: make(map[string]string),
		obfuscatorSeedHistory:   obfuscator.NewSeedHistory(nil),
	}, nil
}

func (sshServer *sshServer) setEstablishTunnels(establish bool) {

	// Do nothing when the setting is already correct. This avoids
	// spurious log messages when setEstablishTunnels is called
	// periodically with the same setting.
	if establish == (atomic.LoadInt32(&sshServer.establishTunnels) == 1) {
		return
	}

	establishFlag := int32(1)
	if !establish {
		establishFlag = 0
	}
	atomic.StoreInt32(&sshServer.establishTunnels, establishFlag)

	log.WithTraceFields(
		LogFields{"establish": establish}).Info("establishing tunnels")
}

func (sshServer *sshServer) checkEstablishTunnels() bool {
	establishTunnels := atomic.LoadInt32(&sshServer.establishTunnels) == 1
	if !establishTunnels {
		atomic.AddInt64(&sshServer.establishLimitedCount, 1)
	}
	return establishTunnels
}

func (sshServer *sshServer) getEstablishTunnelsMetrics() (bool, int64) {
	return atomic.LoadInt32(&sshServer.establishTunnels) == 1,
		atomic.SwapInt64(&sshServer.establishLimitedCount, 0)
}

// runListener is intended to run an a goroutine; it blocks
// running a particular listener. If an unrecoverable error
// occurs, it will send the error to the listenerError channel.
func (sshServer *sshServer) runListener(sshListener *sshListener, listenerError chan<- error) {

	runningProtocols := make([]string, 0)
	for tunnelProtocol := range sshServer.support.Config.TunnelProtocolPorts {
		runningProtocols = append(runningProtocols, tunnelProtocol)
	}

	handleClient := func(clientTunnelProtocol string, clientConn net.Conn) {

		// Note: establish tunnel limiter cannot simply stop TCP
		// listeners in all cases (e.g., meek) since SSH tunnels can
		// span multiple TCP connections.

		if !sshServer.checkEstablishTunnels() {
			log.WithTrace().Debug("not establishing tunnels")
			clientConn.Close()
			return
		}

		// The tunnelProtocol passed to handleClient is used for stats,
		// throttling, etc. When the tunnel protocol can be determined
		// unambiguously from the listening port, use that protocol and
		// don't use any client-declared value. Only use the client's
		// value, if present, in special cases where the listening port
		// cannot distinguish the protocol.
		tunnelProtocol := sshListener.tunnelProtocol
		if clientTunnelProtocol != "" {

			if !common.Contains(runningProtocols, clientTunnelProtocol) {
				log.WithTraceFields(
					LogFields{
						"clientTunnelProtocol": clientTunnelProtocol}).
					Warning("invalid client tunnel protocol")
				clientConn.Close()
				return
			}

			if protocol.UseClientTunnelProtocol(
				clientTunnelProtocol, runningProtocols) {
				tunnelProtocol = clientTunnelProtocol
			}
		}

		// sshListener.tunnelProtocol indictes the tunnel protocol run by the
		// listener. For direct protocols, this is also the client tunnel protocol.
		// For fronted protocols, the client may use a different protocol to connect
		// to the front and then only the front-to-Psiphon server will use the
		// listener protocol.
		//
		// A fronted meek client, for example, reports its first hop protocol in
		// protocol.MeekCookieData.ClientTunnelProtocol. Most metrics record this
		// value as relay_protocol, since the first hop is the one subject to
		// adversarial conditions. In some cases, such as irregular tunnels, there
		// is no ClientTunnelProtocol value available and the listener tunnel
		// protocol will be logged.
		//
		// Similarly, listenerPort indicates the listening port, which is the dialed
		// port number for direct protocols; while, for fronted protocols, the
		// client may dial a different port for its first hop.

		// Process each client connection concurrently.
		go sshServer.handleClient(sshListener, tunnelProtocol, clientConn)
	}

	// Note: when exiting due to a unrecoverable error, be sure
	// to try to send the error to listenerError so that the outer
	// TunnelServer.Run will properly shut down instead of remaining
	// running.

	if protocol.TunnelProtocolUsesMeekHTTP(sshListener.tunnelProtocol) ||
		protocol.TunnelProtocolUsesMeekHTTPS(sshListener.tunnelProtocol) {

		meekServer, err := NewMeekServer(
			sshServer.support,
			sshListener.Listener,
			sshListener.tunnelProtocol,
			sshListener.port,
			protocol.TunnelProtocolUsesMeekHTTPS(sshListener.tunnelProtocol),
			protocol.TunnelProtocolUsesFrontedMeek(sshListener.tunnelProtocol),
			protocol.TunnelProtocolUsesObfuscatedSessionTickets(sshListener.tunnelProtocol),
			handleClient,
			sshServer.shutdownBroadcast)

		if err == nil {
			err = meekServer.Run()
		}

		if err != nil {
			select {
			case listenerError <- errors.Trace(err):
			default:
			}
			return
		}

	} else {

		for {
			conn, err := sshListener.Listener.Accept()

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
					log.WithTraceFields(LogFields{"error": err}).Error("accept failed")
					// Temporary error, keep running
					continue
				}

				select {
				case listenerError <- errors.Trace(err):
				default:
				}
				return
			}

			handleClient("", conn)
		}
	}
}

// An accepted client has completed a direct TCP or meek connection and has a net.Conn. Registration
// is for tracking the number of connections.
func (sshServer *sshServer) registerAcceptedClient(tunnelProtocol, region string) {

	sshServer.clientsMutex.Lock()
	defer sshServer.clientsMutex.Unlock()

	if sshServer.acceptedClientCounts[tunnelProtocol] == nil {
		sshServer.acceptedClientCounts[tunnelProtocol] = make(map[string]int64)
	}

	sshServer.acceptedClientCounts[tunnelProtocol][region] += 1
}

func (sshServer *sshServer) unregisterAcceptedClient(tunnelProtocol, region string) {

	sshServer.clientsMutex.Lock()
	defer sshServer.clientsMutex.Unlock()

	sshServer.acceptedClientCounts[tunnelProtocol][region] -= 1
}

// An established client has completed its SSH handshake and has a ssh.Conn. Registration is
// for tracking the number of fully established clients and for maintaining a list of running
// clients (for stopping at shutdown time).
func (sshServer *sshServer) registerEstablishedClient(client *sshClient) bool {

	sshServer.clientsMutex.Lock()

	if sshServer.stoppingClients {
		sshServer.clientsMutex.Unlock()
		return false
	}

	// In the case of a duplicate client sessionID, the previous client is closed.
	// - Well-behaved clients generate a random sessionID that should be unique (won't
	//   accidentally conflict) and hard to guess (can't be targeted by a malicious
	//   client).
	// - Clients reuse the same sessionID when a tunnel is unexpectedly disconnected
	//   and reestablished. In this case, when the same server is selected, this logic
	//   will be hit; closing the old, dangling client is desirable.
	// - Multi-tunnel clients should not normally use one server for multiple tunnels.

	existingClient := sshServer.clients[client.sessionID]

	sshServer.clientsMutex.Unlock()

	if existingClient != nil {

		// This case is expected to be common, and so logged at the lowest severity
		// level.
		log.WithTrace().Debug(
			"stopping existing client with duplicate session ID")

		existingClient.stop()

		// Block until the existingClient is fully terminated. This is necessary to
		// avoid this scenario:
		// - existingClient is invoking handshakeAPIRequestHandler
		// - sshServer.clients[client.sessionID] is updated to point to new client
		// - existingClient's handshakeAPIRequestHandler invokes
		//   SetClientHandshakeState but sets the handshake parameters for new
		//   client
		// - as a result, the new client handshake will fail (only a single handshake
		//   is permitted) and the new client server_tunnel log will contain an
		//   invalid mix of existing/new client fields
		//
		// Once existingClient.awaitStopped returns, all existingClient port
		// forwards and request handlers have terminated, so no API handler, either
		// tunneled web API or SSH API, will remain and it is safe to point
		// sshServer.clients[client.sessionID] to the new client.
		// Limitation: this scenario remains possible with _untunneled_ web API
		// requests.
		//
		// Blocking also ensures existingClient.releaseAuthorizations is invoked before
		// the new client attempts to submit the same authorizations.
		//
		// Perform blocking awaitStopped operation outside the
		// sshServer.clientsMutex mutex to avoid blocking all other clients for the
		// duration. We still expect and require that the stop process completes
		// rapidly, e.g., does not block on network I/O, allowing the new client
		// connection to proceed without delay.
		//
		// In addition, operations triggered by stop, and which must complete before
		// awaitStopped returns, will attempt to lock sshServer.clientsMutex,
		// including unregisterEstablishedClient.

		existingClient.awaitStopped()
	}

	sshServer.clientsMutex.Lock()
	defer sshServer.clientsMutex.Unlock()

	// existingClient's stop will have removed it from sshServer.clients via
	// unregisterEstablishedClient, so sshServer.clients[client.sessionID] should
	// be nil -- unless yet another client instance using the same sessionID has
	// connected in the meantime while awaiting existingClient stop. In this
	// case, it's not clear which is the most recent connection from the client,
	// so instead of this connection terminating more peers, it aborts.

	if sshServer.clients[client.sessionID] != nil {
		// As this is expected to be rare case, it's logged at a higher severity
		// level.
		log.WithTrace().Warning(
			"aborting new client with duplicate session ID")
		return false
	}

	sshServer.clients[client.sessionID] = client

	return true
}

func (sshServer *sshServer) unregisterEstablishedClient(client *sshClient) {

	sshServer.clientsMutex.Lock()

	registeredClient := sshServer.clients[client.sessionID]

	// registeredClient will differ from client when client is the existingClient
	// terminated in registerEstablishedClient. In that case, registeredClient
	// remains connected, and the sshServer.clients entry should be retained.
	if registeredClient == client {
		delete(sshServer.clients, client.sessionID)
	}

	sshServer.clientsMutex.Unlock()

	client.stop()
}

type ProtocolStats map[string]map[string]interface{}
type RegionStats map[string]map[string]map[string]interface{}

func (sshServer *sshServer) getLoadStats() (ProtocolStats, RegionStats) {

	sshServer.clientsMutex.Lock()
	defer sshServer.clientsMutex.Unlock()

	// Explicitly populate with zeros to ensure 0 counts in log messages.

	zeroStats := func() map[string]interface{} {
		stats := make(map[string]interface{})
		stats["accepted_clients"] = int64(0)
		stats["established_clients"] = int64(0)
		return stats
	}

	// Due to hot reload and changes to the underlying system configuration, the
	// set of resolver IPs may change between getLoadStats calls, so this
	// enumeration for zeroing is a best effort.
	resolverIPs := sshServer.support.DNSResolver.GetAll()

	// Only the non-region "ALL" log has the following fields, which are
	// primarily concerned with upstream/egress performance.
	zeroStatsAll := func() map[string]interface{} {
		stats := zeroStats()
		stats["dialing_tcp_port_forwards"] = int64(0)
		stats["tcp_port_forwards"] = int64(0)
		stats["total_tcp_port_forwards"] = int64(0)
		stats["udp_port_forwards"] = int64(0)
		stats["total_udp_port_forwards"] = int64(0)
		stats["tcp_port_forward_dialed_count"] = int64(0)
		stats["tcp_port_forward_dialed_duration"] = int64(0)
		stats["tcp_port_forward_failed_count"] = int64(0)
		stats["tcp_port_forward_failed_duration"] = int64(0)
		stats["tcp_port_forward_rejected_dialing_limit_count"] = int64(0)
		stats["tcp_port_forward_rejected_disallowed_count"] = int64(0)
		stats["udp_port_forward_rejected_disallowed_count"] = int64(0)
		stats["tcp_ipv4_port_forward_dialed_count"] = int64(0)
		stats["tcp_ipv4_port_forward_dialed_duration"] = int64(0)
		stats["tcp_ipv4_port_forward_failed_count"] = int64(0)
		stats["tcp_ipv4_port_forward_failed_duration"] = int64(0)
		stats["tcp_ipv6_port_forward_dialed_count"] = int64(0)
		stats["tcp_ipv6_port_forward_dialed_duration"] = int64(0)
		stats["tcp_ipv6_port_forward_failed_count"] = int64(0)
		stats["tcp_ipv6_port_forward_failed_duration"] = int64(0)

		zeroDNSStats := func() map[string]int64 {
			m := map[string]int64{"ALL": 0}
			for _, resolverIP := range resolverIPs {
				m[resolverIP.String()] = 0
			}
			return m
		}

		stats["dns_count"] = zeroDNSStats()
		stats["dns_duration"] = zeroDNSStats()
		stats["dns_failed_count"] = zeroDNSStats()
		stats["dns_failed_duration"] = zeroDNSStats()
		return stats
	}

	zeroProtocolStats := func(nonRegion bool) map[string]map[string]interface{} {
		stats := make(map[string]map[string]interface{})
		if nonRegion {
			stats["ALL"] = zeroStatsAll()
		} else {
			stats["ALL"] = zeroStats()
		}
		for tunnelProtocol := range sshServer.support.Config.TunnelProtocolPorts {
			stats[tunnelProtocol] = zeroStats()
		}
		return stats
	}

	addInt64 := func(stats map[string]interface{}, name string, value int64) {
		stats[name] = stats[name].(int64) + value
	}

	// [<protocol or ALL>][<stat name>] -> count
	protocolStats := zeroProtocolStats(true)

	// [<region][<protocol or ALL>][<stat name>] -> count
	regionStats := make(RegionStats)

	// Note: as currently tracked/counted, each established client is also an accepted client

	for tunnelProtocol, regionAcceptedClientCounts := range sshServer.acceptedClientCounts {
		for region, acceptedClientCount := range regionAcceptedClientCounts {

			if acceptedClientCount > 0 {
				if regionStats[region] == nil {
					regionStats[region] = zeroProtocolStats(false)
				}

				addInt64(protocolStats["ALL"], "accepted_clients", acceptedClientCount)
				addInt64(protocolStats[tunnelProtocol], "accepted_clients", acceptedClientCount)

				addInt64(regionStats[region]["ALL"], "accepted_clients", acceptedClientCount)
				addInt64(regionStats[region][tunnelProtocol], "accepted_clients", acceptedClientCount)
			}
		}
	}

	for _, client := range sshServer.clients {

		client.Lock()

		tunnelProtocol := client.tunnelProtocol
		region := client.geoIPData.Country

		if regionStats[region] == nil {
			regionStats[region] = zeroProtocolStats(false)
		}

		for _, stats := range []map[string]interface{}{
			protocolStats["ALL"],
			protocolStats[tunnelProtocol],
			regionStats[region]["ALL"],
			regionStats[region][tunnelProtocol]} {

			addInt64(stats, "established_clients", 1)
		}

		stats := protocolStats["ALL"]

		// Note:
		// - can't sum trafficState.peakConcurrentPortForwardCount to get a global peak
		// - client.udpTrafficState.concurrentDialingPortForwardCount isn't meaningful

		addInt64(stats, "dialing_tcp_port_forwards", client.tcpTrafficState.concurrentDialingPortForwardCount)

		addInt64(stats, "tcp_port_forwards", client.tcpTrafficState.concurrentPortForwardCount)

		addInt64(stats, "total_tcp_port_forwards", client.tcpTrafficState.totalPortForwardCount)

		addInt64(stats, "udp_port_forwards", client.udpTrafficState.concurrentPortForwardCount)

		addInt64(stats, "total_udp_port_forwards", client.udpTrafficState.totalPortForwardCount)

		addInt64(stats, "tcp_port_forward_dialed_count", client.qualityMetrics.TCPPortForwardDialedCount)

		addInt64(stats, "tcp_port_forward_dialed_duration",
			int64(client.qualityMetrics.TCPPortForwardDialedDuration/time.Millisecond))

		addInt64(stats, "tcp_port_forward_failed_count", client.qualityMetrics.TCPPortForwardFailedCount)

		addInt64(stats, "tcp_port_forward_failed_duration",
			int64(client.qualityMetrics.TCPPortForwardFailedDuration/time.Millisecond))

		addInt64(stats, "tcp_port_forward_rejected_dialing_limit_count",
			client.qualityMetrics.TCPPortForwardRejectedDialingLimitCount)

		addInt64(stats, "tcp_port_forward_rejected_disallowed_count",
			client.qualityMetrics.TCPPortForwardRejectedDisallowedCount)

		addInt64(stats, "udp_port_forward_rejected_disallowed_count",
			client.qualityMetrics.UDPPortForwardRejectedDisallowedCount)

		addInt64(stats, "tcp_ipv4_port_forward_dialed_count", client.qualityMetrics.TCPIPv4PortForwardDialedCount)

		addInt64(stats, "tcp_ipv4_port_forward_dialed_duration",
			int64(client.qualityMetrics.TCPIPv4PortForwardDialedDuration/time.Millisecond))

		addInt64(stats, "tcp_ipv4_port_forward_failed_count", client.qualityMetrics.TCPIPv4PortForwardFailedCount)

		addInt64(stats, "tcp_ipv4_port_forward_failed_duration",
			int64(client.qualityMetrics.TCPIPv4PortForwardFailedDuration/time.Millisecond))

		addInt64(stats, "tcp_ipv6_port_forward_dialed_count", client.qualityMetrics.TCPIPv6PortForwardDialedCount)

		addInt64(stats, "tcp_ipv6_port_forward_dialed_duration",
			int64(client.qualityMetrics.TCPIPv6PortForwardDialedDuration/time.Millisecond))

		addInt64(stats, "tcp_ipv6_port_forward_failed_count", client.qualityMetrics.TCPIPv6PortForwardFailedCount)

		addInt64(stats, "tcp_ipv6_port_forward_failed_duration",
			int64(client.qualityMetrics.TCPIPv6PortForwardFailedDuration/time.Millisecond))

		// DNS metrics limitations:
		// - port forwards (sshClient.handleTCPChannel) don't know or log the resolver IP.
		// - udpgw and packet tunnel transparent DNS use a heuristic to classify success/failure.

		// Every client.qualityMetrics DNS map has an "ALL" entry.

		for key, value := range client.qualityMetrics.DNSCount {
			stats["dns_count"].(map[string]int64)[key] += value
		}

		for key, value := range client.qualityMetrics.DNSDuration {
			stats["dns_duration"].(map[string]int64)[key] += int64(value / time.Millisecond)
		}

		for key, value := range client.qualityMetrics.DNSFailedCount {
			stats["dns_failed_count"].(map[string]int64)[key] += value
		}

		for key, value := range client.qualityMetrics.DNSFailedDuration {
			stats["dns_failed_duration"].(map[string]int64)[key] += int64(value / time.Millisecond)
		}

		client.qualityMetrics.reset()

		client.Unlock()
	}

	return protocolStats, regionStats
}

func (sshServer *sshServer) getEstablishedClientCount() int {
	sshServer.clientsMutex.Lock()
	defer sshServer.clientsMutex.Unlock()
	establishedClients := len(sshServer.clients)
	return establishedClients
}

func (sshServer *sshServer) resetAllClientTrafficRules() {

	sshServer.clientsMutex.Lock()
	clients := make(map[string]*sshClient)
	for sessionID, client := range sshServer.clients {
		clients[sessionID] = client
	}
	sshServer.clientsMutex.Unlock()

	for _, client := range clients {
		client.setTrafficRules()
	}
}

func (sshServer *sshServer) resetAllClientOSLConfigs() {

	// Flush cached seed state. This has the same effect
	// and same limitations as calling setOSLConfig for
	// currently connected clients -- all progress is lost.
	sshServer.oslSessionCacheMutex.Lock()
	sshServer.oslSessionCache.Flush()
	sshServer.oslSessionCacheMutex.Unlock()

	sshServer.clientsMutex.Lock()
	clients := make(map[string]*sshClient)
	for sessionID, client := range sshServer.clients {
		clients[sessionID] = client
	}
	sshServer.clientsMutex.Unlock()

	for _, client := range clients {
		client.setOSLConfig()
	}
}

func (sshServer *sshServer) setClientHandshakeState(
	sessionID string,
	state handshakeState,
	authorizations []string) (*handshakeStateInfo, error) {

	sshServer.clientsMutex.Lock()
	client := sshServer.clients[sessionID]
	sshServer.clientsMutex.Unlock()

	if client == nil {
		return nil, errors.TraceNew("unknown session ID")
	}

	handshakeStateInfo, err := client.setHandshakeState(
		state, authorizations)
	if err != nil {
		return nil, errors.Trace(err)
	}

	return handshakeStateInfo, nil
}

func (sshServer *sshServer) getClientHandshaked(
	sessionID string) (bool, bool, error) {

	sshServer.clientsMutex.Lock()
	client := sshServer.clients[sessionID]
	sshServer.clientsMutex.Unlock()

	if client == nil {
		return false, false, errors.TraceNew("unknown session ID")
	}

	completed, exhausted := client.getHandshaked()

	return completed, exhausted, nil
}

func (sshServer *sshServer) updateClientAPIParameters(
	sessionID string,
	apiParams common.APIParameters) error {

	sshServer.clientsMutex.Lock()
	client := sshServer.clients[sessionID]
	sshServer.clientsMutex.Unlock()

	if client == nil {
		return errors.TraceNew("unknown session ID")
	}

	client.updateAPIParameters(apiParams)

	return nil
}

func (sshServer *sshServer) revokeClientAuthorizations(sessionID string) {
	sshServer.clientsMutex.Lock()
	client := sshServer.clients[sessionID]
	sshServer.clientsMutex.Unlock()

	if client == nil {
		return
	}

	// sshClient.handshakeState.authorizedAccessTypes is not cleared. Clearing
	// authorizedAccessTypes may cause sshClient.logTunnel to fail to log
	// access types. As the revocation may be due to legitimate use of an
	// authorization in multiple sessions by a single client, useful metrics
	// would be lost.

	client.Lock()
	client.handshakeState.authorizationsRevoked = true
	client.Unlock()

	// Select and apply new traffic rules, as filtered by the client's new
	// authorization state.

	client.setTrafficRules()
}

func (sshServer *sshServer) expectClientDomainBytes(
	sessionID string) (bool, error) {

	sshServer.clientsMutex.Lock()
	client := sshServer.clients[sessionID]
	sshServer.clientsMutex.Unlock()

	if client == nil {
		return false, errors.TraceNew("unknown session ID")
	}

	return client.expectDomainBytes(), nil
}

func (sshServer *sshServer) stopClients() {

	sshServer.clientsMutex.Lock()
	sshServer.stoppingClients = true
	clients := sshServer.clients
	sshServer.clients = make(map[string]*sshClient)
	sshServer.clientsMutex.Unlock()

	for _, client := range clients {
		client.stop()
	}
}

func (sshServer *sshServer) handleClient(
	sshListener *sshListener, tunnelProtocol string, clientConn net.Conn) {

	// Calling clientConn.RemoteAddr at this point, before any Read calls,
	// satisfies the constraint documented in tapdance.Listen.

	clientAddr := clientConn.RemoteAddr()

	// Check if there were irregularities during the network connection
	// establishment. When present, log and then behave as Obfuscated SSH does
	// when the client fails to provide a valid seed message.
	//
	// One concrete irregular case is failure to send a PROXY protocol header for
	// TAPDANCE-OSSH.

	if indicator, ok := clientConn.(common.IrregularIndicator); ok {

		tunnelErr := indicator.IrregularTunnelError()

		if tunnelErr != nil {

			logIrregularTunnel(
				sshServer.support,
				sshListener.tunnelProtocol,
				sshListener.port,
				common.IPAddressFromAddr(clientAddr),
				errors.Trace(tunnelErr),
				nil)

			var afterFunc *time.Timer
			if sshServer.support.Config.sshHandshakeTimeout > 0 {
				afterFunc = time.AfterFunc(sshServer.support.Config.sshHandshakeTimeout, func() {
					clientConn.Close()
				})
			}
			io.Copy(ioutil.Discard, clientConn)
			clientConn.Close()
			afterFunc.Stop()

			return
		}
	}

	// Get any packet manipulation values from GetAppliedSpecName as soon as
	// possible due to the expiring TTL.

	serverPacketManipulation := ""
	replayedServerPacketManipulation := false

	if sshServer.support.Config.RunPacketManipulator &&
		protocol.TunnelProtocolMayUseServerPacketManipulation(tunnelProtocol) {

		// A meekConn has synthetic address values, including the original client
		// address in cases where the client uses an upstream proxy to connect to
		// Psiphon. For meekConn, and any other conn implementing
		// UnderlyingTCPAddrSource, get the underlying TCP connection addresses.
		//
		// Limitation: a meek tunnel may consist of several TCP connections. The
		// server_packet_manipulation metric will reflect the packet manipulation
		// applied to the _first_ TCP connection only.

		var localAddr, remoteAddr *net.TCPAddr
		var ok bool
		underlying, ok := clientConn.(common.UnderlyingTCPAddrSource)
		if ok {
			localAddr, remoteAddr, ok = underlying.GetUnderlyingTCPAddrs()
		} else {
			localAddr, ok = clientConn.LocalAddr().(*net.TCPAddr)
			if ok {
				remoteAddr, ok = clientConn.RemoteAddr().(*net.TCPAddr)
			}
		}

		if ok {
			specName, extraData, err := sshServer.support.PacketManipulator.
				GetAppliedSpecName(localAddr, remoteAddr)
			if err == nil {
				serverPacketManipulation = specName
				replayedServerPacketManipulation, _ = extraData.(bool)
			}
		}
	}

	geoIPData := sshServer.support.GeoIPService.Lookup(
		common.IPAddressFromAddr(clientAddr), true)

	sshServer.registerAcceptedClient(tunnelProtocol, geoIPData.Country)
	defer sshServer.unregisterAcceptedClient(tunnelProtocol, geoIPData.Country)

	// When configured, enforce a cap on the number of concurrent SSH
	// handshakes. This limits load spikes on busy servers when many clients
	// attempt to connect at once. Wait a short time, SSH_BEGIN_HANDSHAKE_TIMEOUT,
	// to acquire; waiting will avoid immediately creating more load on another
	// server in the network when the client tries a new candidate. Disconnect the
	// client when that wait time is exceeded.
	//
	// This mechanism limits memory allocations and CPU usage associated with the
	// SSH handshake. At this point, new direct TCP connections or new meek
	// connections, with associated resource usage, are already established. Those
	// connections are expected to be rate or load limited using other mechanisms.
	//
	// TODO:
	//
	// - deduct time spent acquiring the semaphore from SSH_HANDSHAKE_TIMEOUT in
	//   sshClient.run, since the client is also applying an SSH handshake timeout
	//   and won't exclude time spent waiting.
	// - each call to sshServer.handleClient (in sshServer.runListener) is invoked
	//   in its own goroutine, but shutdown doesn't synchronously await these
	//   goroutnes. Once this is synchronizes, the following context.WithTimeout
	//   should use an sshServer parent context to ensure blocking acquires
	//   interrupt immediately upon shutdown.

	var onSSHHandshakeFinished func()
	if sshServer.support.Config.MaxConcurrentSSHHandshakes > 0 {

		ctx, cancelFunc := context.WithTimeout(
			context.Background(),
			sshServer.support.Config.sshBeginHandshakeTimeout)
		defer cancelFunc()

		err := sshServer.concurrentSSHHandshakes.Acquire(ctx, 1)
		if err != nil {
			clientConn.Close()
			// This is a debug log as the only possible error is context timeout.
			log.WithTraceFields(LogFields{"error": err}).Debug(
				"acquire SSH handshake semaphore failed")
			return
		}

		onSSHHandshakeFinished = func() {
			sshServer.concurrentSSHHandshakes.Release(1)
		}
	}

	sshClient := newSshClient(
		sshServer,
		sshListener,
		tunnelProtocol,
		serverPacketManipulation,
		replayedServerPacketManipulation,
		clientAddr,
		geoIPData)

	// sshClient.run _must_ call onSSHHandshakeFinished to release the semaphore:
	// in any error case; or, as soon as the SSH handshake phase has successfully
	// completed.

	sshClient.run(clientConn, onSSHHandshakeFinished)
}

func (sshServer *sshServer) monitorPortForwardDialError(err error) {

	// "err" is the error returned from a failed TCP or UDP port
	// forward dial. Certain system error codes indicate low resource
	// conditions: insufficient file descriptors, ephemeral ports, or
	// memory. For these cases, log an alert.

	// TODO: also temporarily suspend new clients

	// Note: don't log net.OpError.Error() as the full error string
	// may contain client destination addresses.

	opErr, ok := err.(*net.OpError)
	if ok {
		if opErr.Err == syscall.EADDRNOTAVAIL ||
			opErr.Err == syscall.EAGAIN ||
			opErr.Err == syscall.ENOMEM ||
			opErr.Err == syscall.EMFILE ||
			opErr.Err == syscall.ENFILE {

			log.WithTraceFields(
				LogFields{"error": opErr.Err}).Error(
				"port forward dial failed due to unavailable resource")
		}
	}
}

type sshClient struct {
	sync.Mutex
	sshServer                            *sshServer
	sshListener                          *sshListener
	tunnelProtocol                       string
	sshConn                              ssh.Conn
	throttledConn                        *common.ThrottledConn
	serverPacketManipulation             string
	replayedServerPacketManipulation     bool
	clientAddr                           net.Addr
	geoIPData                            GeoIPData
	sessionID                            string
	isFirstTunnelInSession               bool
	supportsServerRequests               bool
	handshakeState                       handshakeState
	udpChannel                           ssh.Channel
	packetTunnelChannel                  ssh.Channel
	trafficRules                         TrafficRules
	tcpTrafficState                      trafficState
	udpTrafficState                      trafficState
	qualityMetrics                       *qualityMetrics
	tcpPortForwardLRU                    *common.LRUConns
	oslClientSeedState                   *osl.ClientSeedState
	signalIssueSLOKs                     chan struct{}
	runCtx                               context.Context
	stopRunning                          context.CancelFunc
	stopped                              chan struct{}
	tcpPortForwardDialingAvailableSignal context.CancelFunc
	releaseAuthorizations                func()
	stopTimer                            *time.Timer
	preHandshakeRandomStreamMetrics      randomStreamMetrics
	postHandshakeRandomStreamMetrics     randomStreamMetrics
	sendAlertRequests                    chan protocol.AlertRequest
	sentAlertRequests                    map[string]bool
}

type trafficState struct {
	bytesUp                               int64
	bytesDown                             int64
	concurrentDialingPortForwardCount     int64
	peakConcurrentDialingPortForwardCount int64
	concurrentPortForwardCount            int64
	peakConcurrentPortForwardCount        int64
	totalPortForwardCount                 int64
	availablePortForwardCond              *sync.Cond
}

type randomStreamMetrics struct {
	count                 int
	upstreamBytes         int
	receivedUpstreamBytes int
	downstreamBytes       int
	sentDownstreamBytes   int
}

// qualityMetrics records upstream TCP dial attempts and
// elapsed time. Elapsed time includes the full TCP handshake
// and, in aggregate, is a measure of the quality of the
// upstream link. These stats are recorded by each sshClient
// and then reported and reset in sshServer.getLoadStats().
type qualityMetrics struct {
	TCPPortForwardDialedCount               int64
	TCPPortForwardDialedDuration            time.Duration
	TCPPortForwardFailedCount               int64
	TCPPortForwardFailedDuration            time.Duration
	TCPPortForwardRejectedDialingLimitCount int64
	TCPPortForwardRejectedDisallowedCount   int64
	UDPPortForwardRejectedDisallowedCount   int64
	TCPIPv4PortForwardDialedCount           int64
	TCPIPv4PortForwardDialedDuration        time.Duration
	TCPIPv4PortForwardFailedCount           int64
	TCPIPv4PortForwardFailedDuration        time.Duration
	TCPIPv6PortForwardDialedCount           int64
	TCPIPv6PortForwardDialedDuration        time.Duration
	TCPIPv6PortForwardFailedCount           int64
	TCPIPv6PortForwardFailedDuration        time.Duration
	DNSCount                                map[string]int64
	DNSDuration                             map[string]time.Duration
	DNSFailedCount                          map[string]int64
	DNSFailedDuration                       map[string]time.Duration
}

func newQualityMetrics() *qualityMetrics {
	return &qualityMetrics{
		DNSCount:          make(map[string]int64),
		DNSDuration:       make(map[string]time.Duration),
		DNSFailedCount:    make(map[string]int64),
		DNSFailedDuration: make(map[string]time.Duration),
	}
}

func (q *qualityMetrics) reset() {

	q.TCPPortForwardDialedCount = 0
	q.TCPPortForwardDialedDuration = 0
	q.TCPPortForwardFailedCount = 0
	q.TCPPortForwardFailedDuration = 0
	q.TCPPortForwardRejectedDialingLimitCount = 0
	q.TCPPortForwardRejectedDisallowedCount = 0

	q.UDPPortForwardRejectedDisallowedCount = 0

	q.TCPIPv4PortForwardDialedCount = 0
	q.TCPIPv4PortForwardDialedDuration = 0
	q.TCPIPv4PortForwardFailedCount = 0
	q.TCPIPv4PortForwardFailedDuration = 0

	q.TCPIPv6PortForwardDialedCount = 0
	q.TCPIPv6PortForwardDialedDuration = 0
	q.TCPIPv6PortForwardFailedCount = 0
	q.TCPIPv6PortForwardFailedDuration = 0

	// Retain existing maps to avoid memory churn. The Go compiler optimizes map
	// clearing operations of the following form.

	for k := range q.DNSCount {
		delete(q.DNSCount, k)
	}
	for k := range q.DNSDuration {
		delete(q.DNSDuration, k)
	}
	for k := range q.DNSFailedCount {
		delete(q.DNSFailedCount, k)
	}
	for k := range q.DNSFailedDuration {
		delete(q.DNSFailedDuration, k)
	}
}

type handshakeState struct {
	completed               bool
	apiProtocol             string
	apiParams               common.APIParameters
	activeAuthorizationIDs  []string
	authorizedAccessTypes   []string
	authorizationsRevoked   bool
	expectDomainBytes       bool
	establishedTunnelsCount int
	splitTunnel             bool
}

type handshakeStateInfo struct {
	activeAuthorizationIDs   []string
	authorizedAccessTypes    []string
	upstreamBytesPerSecond   int64
	downstreamBytesPerSecond int64
}

func newSshClient(
	sshServer *sshServer,
	sshListener *sshListener,
	tunnelProtocol string,
	serverPacketManipulation string,
	replayedServerPacketManipulation bool,
	clientAddr net.Addr,
	geoIPData GeoIPData) *sshClient {

	runCtx, stopRunning := context.WithCancel(context.Background())

	// isFirstTunnelInSession is defaulted to true so that the pre-handshake
	// traffic rules won't apply UnthrottleFirstTunnelOnly and negate any
	// unthrottled bytes during the initial protocol negotiation.

	client := &sshClient{
		sshServer:                        sshServer,
		sshListener:                      sshListener,
		tunnelProtocol:                   tunnelProtocol,
		serverPacketManipulation:         serverPacketManipulation,
		replayedServerPacketManipulation: replayedServerPacketManipulation,
		clientAddr:                       clientAddr,
		geoIPData:                        geoIPData,
		isFirstTunnelInSession:           true,
		qualityMetrics:                   newQualityMetrics(),
		tcpPortForwardLRU:                common.NewLRUConns(),
		signalIssueSLOKs:                 make(chan struct{}, 1),
		runCtx:                           runCtx,
		stopRunning:                      stopRunning,
		stopped:                          make(chan struct{}),
		sendAlertRequests:                make(chan protocol.AlertRequest, ALERT_REQUEST_QUEUE_BUFFER_SIZE),
		sentAlertRequests:                make(map[string]bool),
	}

	client.tcpTrafficState.availablePortForwardCond = sync.NewCond(new(sync.Mutex))
	client.udpTrafficState.availablePortForwardCond = sync.NewCond(new(sync.Mutex))

	return client
}

func (sshClient *sshClient) run(
	baseConn net.Conn, onSSHHandshakeFinished func()) {

	// When run returns, the client has fully stopped, with all SSH state torn
	// down and no port forwards or API requests in progress.
	defer close(sshClient.stopped)

	// onSSHHandshakeFinished must be called even if the SSH handshake is aborted.
	defer func() {
		if onSSHHandshakeFinished != nil {
			onSSHHandshakeFinished()
		}
	}()

	// Set initial traffic rules, pre-handshake, based on currently known info.
	sshClient.setTrafficRules()

	conn := baseConn

	// Wrap the base client connection with an ActivityMonitoredConn which will
	// terminate the connection if no data is received before the deadline. This
	// timeout is in effect for the entire duration of the SSH connection. Clients
	// must actively use the connection or send SSH keep alive requests to keep
	// the connection active. Writes are not considered reliable activity indicators
	// due to buffering.

	activityConn, err := common.NewActivityMonitoredConn(
		conn,
		SSH_CONNECTION_READ_DEADLINE,
		false,
		nil,
		nil)
	if err != nil {
		conn.Close()
		if !isExpectedTunnelIOError(err) {
			log.WithTraceFields(LogFields{"error": err}).Error("NewActivityMonitoredConn failed")
		}
		return
	}
	conn = activityConn

	// Further wrap the connection with burst monitoring, when enabled.
	//
	// Limitation: burst parameters are fixed for the duration of the tunnel
	// and do not change after a tactics hot reload.

	var burstConn *common.BurstMonitoredConn

	p, err := sshClient.sshServer.support.ServerTacticsParametersCache.Get(sshClient.geoIPData)
	if err != nil {
		log.WithTraceFields(LogFields{"error": errors.Trace(err)}).Warning(
			"ServerTacticsParametersCache.Get failed")
		return
	}

	if !p.IsNil() {
		upstreamTargetBytes := int64(p.Int(parameters.ServerBurstUpstreamTargetBytes))
		upstreamDeadline := p.Duration(parameters.ServerBurstUpstreamDeadline)
		downstreamTargetBytes := int64(p.Int(parameters.ServerBurstDownstreamTargetBytes))
		downstreamDeadline := p.Duration(parameters.ServerBurstDownstreamDeadline)

		if (upstreamDeadline != 0 && upstreamTargetBytes != 0) ||
			(downstreamDeadline != 0 && downstreamTargetBytes != 0) {

			burstConn = common.NewBurstMonitoredConn(
				conn,
				true,
				upstreamTargetBytes, upstreamDeadline,
				downstreamTargetBytes, downstreamDeadline)
			conn = burstConn
		}
	}

	// Allow garbage collection.
	p.Close()

	// Further wrap the connection in a rate limiting ThrottledConn.

	throttledConn := common.NewThrottledConn(conn, sshClient.rateLimits())
	conn = throttledConn

	// Replay of server-side parameters is set or extended after a new tunnel
	// meets duration and bytes transferred targets. Set a timer now that expires
	// shortly after the target duration. When the timer fires, check the time of
	// last byte read (a read indicating a live connection with the client),
	// along with total bytes transferred and set or extend replay if the targets
	// are met.
	//
	// Both target checks are conservative: the tunnel may be healthy, but a byte
	// may not have been read in the last second when the timer fires. Or bytes
	// may be transferring, but not at the target level. Only clients that meet
	// the strict targets at the single check time will trigger replay; however,
	// this replay will impact all clients with similar GeoIP data.
	//
	// A deferred function cancels the timer and also increments the replay
	// failure counter, which will ultimately clear replay parameters, when the
	// tunnel fails before the API handshake is completed (this includes any
	// liveness test).
	//
	// A tunnel which fails to meet the targets but successfully completes any
	// liveness test and the API handshake is ignored in terms of replay scoring.

	isReplayCandidate, replayWaitDuration, replayTargetDuration :=
		sshClient.sshServer.support.ReplayCache.GetReplayTargetDuration(sshClient.geoIPData)

	if isReplayCandidate {

		getFragmentorSeed := func() *prng.Seed {
			fragmentor, ok := baseConn.(common.FragmentorReplayAccessor)
			if ok {
				fragmentorSeed, _ := fragmentor.GetReplay()
				return fragmentorSeed
			}
			return nil
		}

		setReplayAfterFunc := time.AfterFunc(
			replayWaitDuration,
			func() {
				if activityConn.GetActiveDuration() >= replayTargetDuration {

					sshClient.Lock()
					bytesUp := sshClient.tcpTrafficState.bytesUp + sshClient.udpTrafficState.bytesUp
					bytesDown := sshClient.tcpTrafficState.bytesDown + sshClient.udpTrafficState.bytesDown
					sshClient.Unlock()

					sshClient.sshServer.support.ReplayCache.SetReplayParameters(
						sshClient.tunnelProtocol,
						sshClient.geoIPData,
						sshClient.serverPacketManipulation,
						getFragmentorSeed(),
						bytesUp,
						bytesDown)
				}
			})

		defer func() {
			setReplayAfterFunc.Stop()
			completed, _ := sshClient.getHandshaked()
			if !completed {

				// Count a replay failure case when a tunnel used replay parameters
				// (excluding OSSH fragmentation, which doesn't use the ReplayCache) and
				// failed to complete the API handshake.

				replayedFragmentation := false
				if sshClient.tunnelProtocol != protocol.TUNNEL_PROTOCOL_OBFUSCATED_SSH {
					fragmentor, ok := baseConn.(common.FragmentorReplayAccessor)
					if ok {
						_, replayedFragmentation = fragmentor.GetReplay()
					}
				}
				usedReplay := replayedFragmentation || sshClient.replayedServerPacketManipulation

				if usedReplay {
					sshClient.sshServer.support.ReplayCache.FailedReplayParameters(
						sshClient.tunnelProtocol,
						sshClient.geoIPData,
						sshClient.serverPacketManipulation,
						getFragmentorSeed())
				}
			}
		}()
	}

	// Run the initial [obfuscated] SSH handshake in a goroutine so we can both
	// respect shutdownBroadcast and implement a specific handshake timeout.
	// The timeout is to reclaim network resources in case the handshake takes
	// too long.

	type sshNewServerConnResult struct {
		obfuscatedSSHConn *obfuscator.ObfuscatedSSHConn
		sshConn           *ssh.ServerConn
		channels          <-chan ssh.NewChannel
		requests          <-chan *ssh.Request
		err               error
	}

	resultChannel := make(chan *sshNewServerConnResult, 2)

	var sshHandshakeAfterFunc *time.Timer
	if sshClient.sshServer.support.Config.sshHandshakeTimeout > 0 {
		sshHandshakeAfterFunc = time.AfterFunc(sshClient.sshServer.support.Config.sshHandshakeTimeout, func() {
			resultChannel <- &sshNewServerConnResult{err: std_errors.New("ssh handshake timeout")}
		})
	}

	go func(baseConn, conn net.Conn) {
		sshServerConfig := &ssh.ServerConfig{
			PasswordCallback: sshClient.passwordCallback,
			AuthLogCallback:  sshClient.authLogCallback,
			ServerVersion:    sshClient.sshServer.support.Config.SSHServerVersion,
		}
		sshServerConfig.AddHostKey(sshClient.sshServer.sshHostKey)

		var err error

		if protocol.TunnelProtocolUsesObfuscatedSSH(sshClient.tunnelProtocol) {
			// With Encrypt-then-MAC hash algorithms, packet length is
			// transmitted in plaintext, which aids in traffic analysis;
			// clients may still send Encrypt-then-MAC algorithms in their
			// KEX_INIT message, but do not select these algorithms.
			//
			// The exception is TUNNEL_PROTOCOL_SSH, which is intended to appear
			// like SSH on the wire.
			sshServerConfig.NoEncryptThenMACHash = true

		} else {
			// For TUNNEL_PROTOCOL_SSH only, randomize KEX.
			if sshClient.sshServer.support.Config.ObfuscatedSSHKey != "" {
				sshServerConfig.KEXPRNGSeed, err = protocol.DeriveSSHServerKEXPRNGSeed(
					sshClient.sshServer.support.Config.ObfuscatedSSHKey)
				if err != nil {
					err = errors.Trace(err)
				}
			}
		}

		result := &sshNewServerConnResult{}

		// Wrap the connection in an SSH deobfuscator when required.

		if err == nil && protocol.TunnelProtocolUsesObfuscatedSSH(sshClient.tunnelProtocol) {

			// Note: NewServerObfuscatedSSHConn blocks on network I/O
			// TODO: ensure this won't block shutdown
			result.obfuscatedSSHConn, err = obfuscator.NewServerObfuscatedSSHConn(
				conn,
				sshClient.sshServer.support.Config.ObfuscatedSSHKey,
				sshClient.sshServer.obfuscatorSeedHistory,
				func(clientIP string, err error, logFields common.LogFields) {
					logIrregularTunnel(
						sshClient.sshServer.support,
						sshClient.sshListener.tunnelProtocol,
						sshClient.sshListener.port,
						clientIP,
						errors.Trace(err),
						LogFields(logFields))
				})

			if err != nil {
				err = errors.Trace(err)
			} else {
				conn = result.obfuscatedSSHConn
			}

			// Seed the fragmentor, when present, with seed derived from initial
			// obfuscator message. See tactics.Listener.Accept. This must preceed
			// ssh.NewServerConn to ensure fragmentor is seeded before downstream bytes
			// are written.
			if err == nil && sshClient.tunnelProtocol == protocol.TUNNEL_PROTOCOL_OBFUSCATED_SSH {
				fragmentor, ok := baseConn.(common.FragmentorReplayAccessor)
				if ok {
					var fragmentorPRNG *prng.PRNG
					fragmentorPRNG, err = result.obfuscatedSSHConn.GetDerivedPRNG("server-side-fragmentor")
					if err != nil {
						err = errors.Trace(err)
					} else {
						fragmentor.SetReplay(fragmentorPRNG)
					}
				}
			}
		}

		if err == nil {
			result.sshConn, result.channels, result.requests, err =
				ssh.NewServerConn(conn, sshServerConfig)
			if err != nil {
				err = errors.Trace(err)
			}
		}

		result.err = err

		resultChannel <- result

	}(baseConn, conn)

	var result *sshNewServerConnResult
	select {
	case result = <-resultChannel:
	case <-sshClient.sshServer.shutdownBroadcast:
		// Close() will interrupt an ongoing handshake
		// TODO: wait for SSH handshake goroutines to exit before returning?
		conn.Close()
		return
	}

	if sshHandshakeAfterFunc != nil {
		sshHandshakeAfterFunc.Stop()
	}

	if result.err != nil {
		conn.Close()
		// This is a Debug log due to noise. The handshake often fails due to I/O
		// errors as clients frequently interrupt connections in progress when
		// client-side load balancing completes a connection to a different server.
		log.WithTraceFields(LogFields{"error": result.err}).Debug("SSH handshake failed")
		return
	}

	// The SSH handshake has finished successfully; notify now to allow other
	// blocked SSH handshakes to proceed.
	if onSSHHandshakeFinished != nil {
		onSSHHandshakeFinished()
	}
	onSSHHandshakeFinished = nil

	sshClient.Lock()
	sshClient.sshConn = result.sshConn
	sshClient.throttledConn = throttledConn
	sshClient.Unlock()

	if !sshClient.sshServer.registerEstablishedClient(sshClient) {
		conn.Close()
		log.WithTrace().Warning("register failed")
		return
	}

	sshClient.runTunnel(result.channels, result.requests)

	// Note: sshServer.unregisterEstablishedClient calls sshClient.stop(),
	// which also closes underlying transport Conn.

	sshClient.sshServer.unregisterEstablishedClient(sshClient)

	// Log tunnel metrics.

	var additionalMetrics []LogFields

	// Add activity and burst metrics.
	//
	// The reported duration is based on last confirmed data transfer, which for
	// sshClient.activityConn.GetActiveDuration() is time of last read byte and
	// not conn close time. This is important for protocols such as meek. For
	// meek, the connection remains open until the HTTP session expires, which
	// may be some time after the tunnel has closed. (The meek protocol has no
	// allowance for signalling payload EOF, and even if it did the client may
	// not have the opportunity to send a final request with an EOF flag set.)

	activityMetrics := make(LogFields)
	activityMetrics["start_time"] = activityConn.GetStartTime()
	activityMetrics["duration"] = int64(activityConn.GetActiveDuration() / time.Millisecond)
	additionalMetrics = append(additionalMetrics, activityMetrics)

	if burstConn != nil {
		// Any outstanding burst should be recorded by burstConn.Close which should
		// be called by unregisterEstablishedClient.
		additionalMetrics = append(
			additionalMetrics, LogFields(burstConn.GetMetrics(activityConn.GetStartTime())))
	}

	// Some conns report additional metrics. Meek conns report resiliency
	// metrics and fragmentor.Conns report fragmentor configs.

	if metricsSource, ok := baseConn.(common.MetricsSource); ok {
		additionalMetrics = append(
			additionalMetrics, LogFields(metricsSource.GetMetrics()))
	}
	if result.obfuscatedSSHConn != nil {
		additionalMetrics = append(
			additionalMetrics, LogFields(result.obfuscatedSSHConn.GetMetrics()))
	}

	// Add server-replay metrics.

	replayMetrics := make(LogFields)
	replayedFragmentation := false
	fragmentor, ok := baseConn.(common.FragmentorReplayAccessor)
	if ok {
		_, replayedFragmentation = fragmentor.GetReplay()
	}
	replayMetrics["server_replay_fragmentation"] = replayedFragmentation
	replayMetrics["server_replay_packet_manipulation"] = sshClient.replayedServerPacketManipulation
	additionalMetrics = append(additionalMetrics, replayMetrics)

	sshClient.logTunnel(additionalMetrics)

	// Transfer OSL seed state -- the OSL progress -- from the closing
	// client to the session cache so the client can resume its progress
	// if it reconnects to this same server.
	// Note: following setOSLConfig order of locking.

	sshClient.Lock()
	if sshClient.oslClientSeedState != nil {
		sshClient.sshServer.oslSessionCacheMutex.Lock()
		sshClient.oslClientSeedState.Hibernate()
		sshClient.sshServer.oslSessionCache.Set(
			sshClient.sessionID, sshClient.oslClientSeedState, cache.DefaultExpiration)
		sshClient.sshServer.oslSessionCacheMutex.Unlock()
		sshClient.oslClientSeedState = nil
	}
	sshClient.Unlock()

	// Initiate cleanup of the GeoIP session cache. To allow for post-tunnel
	// final status requests, the lifetime of cached GeoIP records exceeds the
	// lifetime of the sshClient.
	sshClient.sshServer.support.GeoIPService.MarkSessionCacheToExpire(sshClient.sessionID)
}

func (sshClient *sshClient) passwordCallback(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {

	expectedSessionIDLength := 2 * protocol.PSIPHON_API_CLIENT_SESSION_ID_LENGTH
	expectedSSHPasswordLength := 2 * SSH_PASSWORD_BYTE_LENGTH

	var sshPasswordPayload protocol.SSHPasswordPayload
	err := json.Unmarshal(password, &sshPasswordPayload)
	if err != nil {

		// Backwards compatibility case: instead of a JSON payload, older clients
		// send the hex encoded session ID prepended to the SSH password.
		// Note: there's an even older case where clients don't send any session ID,
		// but that's no longer supported.
		if len(password) == expectedSessionIDLength+expectedSSHPasswordLength {
			sshPasswordPayload.SessionId = string(password[0:expectedSessionIDLength])
			sshPasswordPayload.SshPassword = string(password[expectedSessionIDLength:])
		} else {
			return nil, errors.Tracef("invalid password payload for %q", conn.User())
		}
	}

	if !isHexDigits(sshClient.sshServer.support.Config, sshPasswordPayload.SessionId) ||
		len(sshPasswordPayload.SessionId) != expectedSessionIDLength {
		return nil, errors.Tracef("invalid session ID for %q", conn.User())
	}

	userOk := (subtle.ConstantTimeCompare(
		[]byte(conn.User()), []byte(sshClient.sshServer.support.Config.SSHUserName)) == 1)

	passwordOk := (subtle.ConstantTimeCompare(
		[]byte(sshPasswordPayload.SshPassword), []byte(sshClient.sshServer.support.Config.SSHPassword)) == 1)

	if !userOk || !passwordOk {
		return nil, errors.Tracef("invalid password for %q", conn.User())
	}

	sessionID := sshPasswordPayload.SessionId

	// The GeoIP session cache will be populated if there was a previous tunnel
	// with this session ID. This will be true up to GEOIP_SESSION_CACHE_TTL, which
	// is currently much longer than the OSL session cache, another option to use if
	// the GeoIP session cache is retired (the GeoIP session cache currently only
	// supports legacy use cases).
	isFirstTunnelInSession := !sshClient.sshServer.support.GeoIPService.InSessionCache(sessionID)

	supportsServerRequests := common.Contains(
		sshPasswordPayload.ClientCapabilities, protocol.CLIENT_CAPABILITY_SERVER_REQUESTS)

	sshClient.Lock()

	// After this point, these values are read-only as they are read
	// without obtaining sshClient.Lock.
	sshClient.sessionID = sessionID
	sshClient.isFirstTunnelInSession = isFirstTunnelInSession
	sshClient.supportsServerRequests = supportsServerRequests

	geoIPData := sshClient.geoIPData

	sshClient.Unlock()

	// Store the GeoIP data associated with the session ID. This makes
	// the GeoIP data available to the web server for web API requests.
	// A cache that's distinct from the sshClient record is used to allow
	// for or post-tunnel final status requests.
	// If the client is reconnecting with the same session ID, this call
	// will undo the expiry set by MarkSessionCacheToExpire.
	sshClient.sshServer.support.GeoIPService.SetSessionCache(sessionID, geoIPData)

	return nil, nil
}

func (sshClient *sshClient) authLogCallback(conn ssh.ConnMetadata, method string, err error) {

	if err != nil {

		if method == "none" && err.Error() == "ssh: no auth passed yet" {
			// In this case, the callback invocation is noise from auth negotiation
			return
		}

		// Note: here we previously logged messages for fail2ban to act on. This is no longer
		// done as the complexity outweighs the benefits.
		//
		// - The SSH credential is not secret -- it's in the server entry. Attackers targeting
		//   the server likely already have the credential. On the other hand, random scanning and
		//   brute forcing is mitigated with high entropy random passwords, rate limiting
		//   (implemented on the host via iptables), and limited capabilities (the SSH session can
		//   only port forward).
		//
		// - fail2ban coverage was inconsistent; in the case of an unfronted meek protocol through
		//   an upstream proxy, the remote address is the upstream proxy, which should not be blocked.
		//   The X-Forwarded-For header cant be used instead as it may be forged and used to get IPs
		//   deliberately blocked; and in any case fail2ban adds iptables rules which can only block
		//   by direct remote IP, not by original client IP. Fronted meek has the same iptables issue.
		//
		// Random scanning and brute forcing of port 22 will result in log noise. To mitigate this,
		// not every authentication failure is logged. A summary log is emitted periodically to
		// retain some record of this activity in case this is relevant to, e.g., a performance
		// investigation.

		atomic.AddInt64(&sshClient.sshServer.authFailedCount, 1)

		lastAuthLog := monotime.Time(atomic.LoadInt64(&sshClient.sshServer.lastAuthLog))
		if monotime.Since(lastAuthLog) > SSH_AUTH_LOG_PERIOD {
			now := int64(monotime.Now())
			if atomic.CompareAndSwapInt64(&sshClient.sshServer.lastAuthLog, int64(lastAuthLog), now) {
				count := atomic.SwapInt64(&sshClient.sshServer.authFailedCount, 0)
				log.WithTraceFields(
					LogFields{"lastError": err, "failedCount": count}).Warning("authentication failures")
			}
		}

		log.WithTraceFields(LogFields{"error": err, "method": method}).Debug("authentication failed")

	} else {

		log.WithTraceFields(LogFields{"error": err, "method": method}).Debug("authentication success")
	}
}

// stop signals the ssh connection to shutdown. After sshConn.Wait returns,
// the SSH connection has terminated but sshClient.run may still be running and
// in the process of exiting.
//
// The shutdown process must complete rapidly and not, e.g., block on network
// I/O, as newly connecting clients need to await stop completion of any
// existing connection that shares the same session ID.
func (sshClient *sshClient) stop() {
	sshClient.sshConn.Close()
	sshClient.sshConn.Wait()
}

// awaitStopped will block until sshClient.run has exited, at which point all
// worker goroutines associated with the sshClient, including any in-flight
// API handlers, will have exited.
func (sshClient *sshClient) awaitStopped() {
	<-sshClient.stopped
}

// runTunnel handles/dispatches new channels and new requests from the client.
// When the SSH client connection closes, both the channels and requests channels
// will close and runTunnel will exit.
func (sshClient *sshClient) runTunnel(
	channels <-chan ssh.NewChannel,
	requests <-chan *ssh.Request) {

	waitGroup := new(sync.WaitGroup)

	// Start client SSH API request handler

	waitGroup.Add(1)
	go func() {
		defer waitGroup.Done()
		sshClient.handleSSHRequests(requests)
	}()

	// Start request senders

	if sshClient.supportsServerRequests {

		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			sshClient.runOSLSender()
		}()

		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			sshClient.runAlertSender()
		}()
	}

	// Start the TCP port forward manager

	// The queue size is set to the traffic rules (MaxTCPPortForwardCount +
	// MaxTCPDialingPortForwardCount), which is a reasonable indication of resource
	// limits per client; when that value is not set, a default is used.
	// A limitation: this queue size is set once and doesn't change, for this client,
	// when traffic rules are reloaded.
	queueSize := sshClient.getTCPPortForwardQueueSize()
	if queueSize == 0 {
		queueSize = SSH_TCP_PORT_FORWARD_QUEUE_SIZE
	}
	newTCPPortForwards := make(chan *newTCPPortForward, queueSize)

	waitGroup.Add(1)
	go func() {
		defer waitGroup.Done()
		sshClient.handleTCPPortForwards(waitGroup, newTCPPortForwards)
	}()

	// Handle new channel (port forward) requests from the client.

	for newChannel := range channels {
		switch newChannel.ChannelType() {
		case protocol.RANDOM_STREAM_CHANNEL_TYPE:
			sshClient.handleNewRandomStreamChannel(waitGroup, newChannel)
		case protocol.PACKET_TUNNEL_CHANNEL_TYPE:
			sshClient.handleNewPacketTunnelChannel(waitGroup, newChannel)
		case protocol.TCP_PORT_FORWARD_NO_SPLIT_TUNNEL_TYPE:
			// The protocol.TCP_PORT_FORWARD_NO_SPLIT_TUNNEL_TYPE is the same as
			// "direct-tcpip", except split tunnel channel rejections are disallowed
			// even if the client has enabled split tunnel. This channel type allows
			// the client to ensure tunneling for certain cases while split tunnel is
			// enabled.
			sshClient.handleNewTCPPortForwardChannel(waitGroup, newChannel, false, newTCPPortForwards)
		case "direct-tcpip":
			sshClient.handleNewTCPPortForwardChannel(waitGroup, newChannel, true, newTCPPortForwards)
		default:
			sshClient.rejectNewChannel(newChannel,
				fmt.Sprintf("unknown or unsupported channel type: %s", newChannel.ChannelType()))
		}
	}

	// The channel loop is interrupted by a client
	// disconnect or by calling sshClient.stop().

	// Stop the TCP port forward manager
	close(newTCPPortForwards)

	// Stop all other worker goroutines
	sshClient.stopRunning()

	if sshClient.sshServer.support.Config.RunPacketTunnel {
		// PacketTunnelServer.ClientDisconnected stops packet tunnel workers.
		sshClient.sshServer.support.PacketTunnelServer.ClientDisconnected(
			sshClient.sessionID)
	}

	waitGroup.Wait()

	sshClient.cleanupAuthorizations()
}

func (sshClient *sshClient) handleSSHRequests(requests <-chan *ssh.Request) {

	for request := range requests {

		// Requests are processed serially; API responses must be sent in request order.

		var responsePayload []byte
		var err error

		if request.Type == "keepalive@openssh.com" {

			// SSH keep alive round trips are used as speed test samples.
			responsePayload, err = tactics.MakeSpeedTestResponse(
				SSH_KEEP_ALIVE_PAYLOAD_MIN_BYTES, SSH_KEEP_ALIVE_PAYLOAD_MAX_BYTES)

		} else {

			// All other requests are assumed to be API requests.

			sshClient.Lock()
			authorizedAccessTypes := sshClient.handshakeState.authorizedAccessTypes
			sshClient.Unlock()

			// Note: unlock before use is only safe as long as referenced sshClient data,
			// such as slices in handshakeState, is read-only after initially set.

			clientAddr := ""
			if sshClient.clientAddr != nil {
				clientAddr = sshClient.clientAddr.String()
			}

			responsePayload, err = sshAPIRequestHandler(
				sshClient.sshServer.support,
				clientAddr,
				sshClient.geoIPData,
				authorizedAccessTypes,
				request.Type,
				request.Payload)
		}

		if err == nil {
			err = request.Reply(true, responsePayload)
		} else {
			log.WithTraceFields(LogFields{"error": err}).Warning("request failed")
			err = request.Reply(false, nil)
		}
		if err != nil {
			if !isExpectedTunnelIOError(err) {
				log.WithTraceFields(LogFields{"error": err}).Warning("response failed")
			}
		}

	}

}

type newTCPPortForward struct {
	enqueueTime   time.Time
	hostToConnect string
	portToConnect int
	doSplitTunnel bool
	newChannel    ssh.NewChannel
}

func (sshClient *sshClient) handleTCPPortForwards(
	waitGroup *sync.WaitGroup,
	newTCPPortForwards chan *newTCPPortForward) {

	// Lifecycle of a TCP port forward:
	//
	// 1. A "direct-tcpip" SSH request is received from the client.
	//
	//    A new TCP port forward request is enqueued. The queue delivers TCP port
	//    forward requests to the TCP port forward manager, which enforces the TCP
	//    port forward dial limit.
	//
	//    Enqueuing new requests allows for reading further SSH requests from the
	//    client without blocking when the dial limit is hit; this is to permit new
	//    UDP/udpgw port forwards to be restablished without delay. The maximum size
	//    of the queue enforces a hard cap on resources consumed by a client in the
	//    pre-dial phase. When the queue is full, new TCP port forwards are
	//    immediately rejected.
	//
	// 2. The TCP port forward manager dequeues the request.
	//
	//    The manager calls dialingTCPPortForward(), which increments
	//    concurrentDialingPortForwardCount, and calls
	//    isTCPDialingPortForwardLimitExceeded() to check the concurrent dialing
	//    count.
	//
	//    The manager enforces the concurrent TCP dial limit: when at the limit, the
	//    manager blocks waiting for the number of dials to drop below the limit before
	//    dispatching the request to handleTCPPortForward(), which will run in its own
	//    goroutine and will dial and relay the port forward.
	//
	//    The block delays the current request and also halts dequeuing of subsequent
	//    requests and could ultimately cause requests to be immediately rejected if
	//    the queue fills. These actions are intended to apply back pressure when
	//    upstream network resources are impaired.
	//
	//    The time spent in the queue is deducted from the port forward's dial timeout.
	//    The time spent blocking while at the dial limit is similarly deducted from
	//    the dial timeout. If the dial timeout has expired before the dial begins, the
	//    port forward is rejected and a stat is recorded.
	//
	// 3. handleTCPPortForward() performs the port forward dial and relaying.
	//
	//     a. Dial the target, using the dial timeout remaining after queue and blocking
	//        time is deducted.
	//
	//     b. If the dial fails, call abortedTCPPortForward() to decrement
	//        concurrentDialingPortForwardCount, freeing up a dial slot.
	//
	//     c. If the dial succeeds, call establishedPortForward(), which decrements
	//        concurrentDialingPortForwardCount and increments concurrentPortForwardCount,
	//        the "established" port forward count.
	//
	//    d. Check isPortForwardLimitExceeded(), which enforces the configurable limit on
	//       concurrentPortForwardCount, the number of _established_ TCP port forwards.
	//       If the limit is exceeded, the LRU established TCP port forward is closed and
	//       the newly established TCP port forward proceeds. This LRU logic allows some
	//       dangling resource consumption (e.g., TIME_WAIT) while providing a better
	//       experience for clients.
	//
	//    e. Relay data.
	//
	//    f. Call closedPortForward() which decrements concurrentPortForwardCount and
	//       records bytes transferred.

	for newPortForward := range newTCPPortForwards {

		remainingDialTimeout :=
			time.Duration(sshClient.getDialTCPPortForwardTimeoutMilliseconds())*time.Millisecond -
				time.Since(newPortForward.enqueueTime)

		if remainingDialTimeout <= 0 {
			sshClient.updateQualityMetricsWithRejectedDialingLimit()
			sshClient.rejectNewChannel(
				newPortForward.newChannel, "TCP port forward timed out in queue")
			continue
		}

		// Reserve a TCP dialing slot.
		//
		// TOCTOU note: important to increment counts _before_ checking limits; otherwise,
		// the client could potentially consume excess resources by initiating many port
		// forwards concurrently.

		sshClient.dialingTCPPortForward()

		// When max dials are in progress, wait up to remainingDialTimeout for dialing
		// to become available. This blocks all dequeing.

		if sshClient.isTCPDialingPortForwardLimitExceeded() {
			blockStartTime := time.Now()
			ctx, cancelCtx := context.WithTimeout(sshClient.runCtx, remainingDialTimeout)
			sshClient.setTCPPortForwardDialingAvailableSignal(cancelCtx)
			<-ctx.Done()
			sshClient.setTCPPortForwardDialingAvailableSignal(nil)
			cancelCtx() // "must be called or the new context will remain live until its parent context is cancelled"
			remainingDialTimeout -= time.Since(blockStartTime)
		}

		if remainingDialTimeout <= 0 {

			// Release the dialing slot here since handleTCPChannel() won't be called.
			sshClient.abortedTCPPortForward()

			sshClient.updateQualityMetricsWithRejectedDialingLimit()
			sshClient.rejectNewChannel(
				newPortForward.newChannel, "TCP port forward timed out before dialing")
			continue
		}

		// Dial and relay the TCP port forward. handleTCPChannel is run in its own worker goroutine.
		// handleTCPChannel will release the dialing slot reserved by dialingTCPPortForward(); and
		// will deal with remainingDialTimeout <= 0.

		waitGroup.Add(1)
		go func(remainingDialTimeout time.Duration, newPortForward *newTCPPortForward) {
			defer waitGroup.Done()
			sshClient.handleTCPChannel(
				remainingDialTimeout,
				newPortForward.hostToConnect,
				newPortForward.portToConnect,
				newPortForward.doSplitTunnel,
				newPortForward.newChannel)
		}(remainingDialTimeout, newPortForward)
	}
}

func (sshClient *sshClient) handleNewRandomStreamChannel(
	waitGroup *sync.WaitGroup, newChannel ssh.NewChannel) {

	// A random stream channel returns the requested number of bytes -- random
	// bytes -- to the client while also consuming and discarding bytes sent
	// by the client.
	//
	// One use case for the random stream channel is a liveness test that the
	// client performs to confirm that the tunnel is live. As the liveness
	// test is performed in the concurrent establishment phase, before
	// selecting a single candidate for handshake, the random stream channel
	// is available pre-handshake, albeit with additional restrictions.
	//
	// The random stream is subject to throttling in traffic rules; for
	// unthrottled liveness tests, set initial Read/WriteUnthrottledBytes as
	// required. The random stream maximum count and response size cap
	// mitigate clients abusing the facility to waste server resources.
	//
	// Like all other channels, this channel type is handled asynchronously,
	// so it's possible to run at any point in the tunnel lifecycle.
	//
	// Up/downstream byte counts don't include SSH packet and request
	// marshalling overhead.

	var request protocol.RandomStreamRequest
	err := json.Unmarshal(newChannel.ExtraData(), &request)
	if err != nil {
		sshClient.rejectNewChannel(newChannel, fmt.Sprintf("invalid request: %s", err))
		return
	}

	if request.UpstreamBytes > RANDOM_STREAM_MAX_BYTES {
		sshClient.rejectNewChannel(newChannel,
			fmt.Sprintf("invalid upstream bytes: %d", request.UpstreamBytes))
		return
	}

	if request.DownstreamBytes > RANDOM_STREAM_MAX_BYTES {
		sshClient.rejectNewChannel(newChannel,
			fmt.Sprintf("invalid downstream bytes: %d", request.DownstreamBytes))
		return
	}

	var metrics *randomStreamMetrics

	sshClient.Lock()

	if !sshClient.handshakeState.completed {
		metrics = &sshClient.preHandshakeRandomStreamMetrics
	} else {
		metrics = &sshClient.postHandshakeRandomStreamMetrics
	}

	countOk := true
	if !sshClient.handshakeState.completed &&
		metrics.count >= PRE_HANDSHAKE_RANDOM_STREAM_MAX_COUNT {
		countOk = false
	} else {
		metrics.count++
	}

	sshClient.Unlock()

	if !countOk {
		sshClient.rejectNewChannel(newChannel, "max count exceeded")
		return
	}

	channel, requests, err := newChannel.Accept()
	if err != nil {
		if !isExpectedTunnelIOError(err) {
			log.WithTraceFields(LogFields{"error": err}).Warning("accept new channel failed")
		}
		return
	}
	go ssh.DiscardRequests(requests)

	waitGroup.Add(1)
	go func() {
		defer waitGroup.Done()

		upstream := new(sync.WaitGroup)
		received := 0
		sent := 0

		if request.UpstreamBytes > 0 {

			// Process streams concurrently to minimize elapsed time. This also
			// avoids a unidirectional flow burst early in the tunnel lifecycle.

			upstream.Add(1)
			go func() {
				defer upstream.Done()
				n, err := io.CopyN(ioutil.Discard, channel, int64(request.UpstreamBytes))
				received = int(n)
				if err != nil {
					if !isExpectedTunnelIOError(err) {
						log.WithTraceFields(LogFields{"error": err}).Warning("receive failed")
					}
				}
			}()
		}

		if request.DownstreamBytes > 0 {
			n, err := io.CopyN(channel, rand.Reader, int64(request.DownstreamBytes))
			sent = int(n)
			if err != nil {
				if !isExpectedTunnelIOError(err) {
					log.WithTraceFields(LogFields{"error": err}).Warning("send failed")
				}
			}
		}

		upstream.Wait()

		sshClient.Lock()
		metrics.upstreamBytes += request.UpstreamBytes
		metrics.receivedUpstreamBytes += received
		metrics.downstreamBytes += request.DownstreamBytes
		metrics.sentDownstreamBytes += sent
		sshClient.Unlock()

		channel.Close()
	}()
}

func (sshClient *sshClient) handleNewPacketTunnelChannel(
	waitGroup *sync.WaitGroup, newChannel ssh.NewChannel) {

	// packet tunnel channels are handled by the packet tunnel server
	// component. Each client may have at most one packet tunnel channel.

	if !sshClient.sshServer.support.Config.RunPacketTunnel {
		sshClient.rejectNewChannel(newChannel, "unsupported packet tunnel channel type")
		return
	}

	// Accept this channel immediately. This channel will replace any
	// previously existing packet tunnel channel for this client.

	packetTunnelChannel, requests, err := newChannel.Accept()
	if err != nil {
		if !isExpectedTunnelIOError(err) {
			log.WithTraceFields(LogFields{"error": err}).Warning("accept new channel failed")
		}
		return
	}
	go ssh.DiscardRequests(requests)

	sshClient.setPacketTunnelChannel(packetTunnelChannel)

	// PacketTunnelServer will run the client's packet tunnel. If necessary, ClientConnected
	// will stop packet tunnel workers for any previous packet tunnel channel.

	checkAllowedTCPPortFunc := func(upstreamIPAddress net.IP, port int) bool {
		return sshClient.isPortForwardPermitted(portForwardTypeTCP, upstreamIPAddress, port)
	}

	checkAllowedUDPPortFunc := func(upstreamIPAddress net.IP, port int) bool {
		return sshClient.isPortForwardPermitted(portForwardTypeUDP, upstreamIPAddress, port)
	}

	checkAllowedDomainFunc := func(domain string) bool {
		ok, _ := sshClient.isDomainPermitted(domain)
		return ok
	}

	flowActivityUpdaterMaker := func(
		upstreamHostname string, upstreamIPAddress net.IP) []tun.FlowActivityUpdater {

		var updaters []tun.FlowActivityUpdater
		oslUpdater := sshClient.newClientSeedPortForward(upstreamIPAddress)
		if oslUpdater != nil {
			updaters = append(updaters, oslUpdater)
		}
		return updaters
	}

	metricUpdater := func(
		TCPApplicationBytesDown, TCPApplicationBytesUp,
		UDPApplicationBytesDown, UDPApplicationBytesUp int64) {

		sshClient.Lock()
		sshClient.tcpTrafficState.bytesDown += TCPApplicationBytesDown
		sshClient.tcpTrafficState.bytesUp += TCPApplicationBytesUp
		sshClient.udpTrafficState.bytesDown += UDPApplicationBytesDown
		sshClient.udpTrafficState.bytesUp += UDPApplicationBytesUp
		sshClient.Unlock()
	}

	dnsQualityReporter := sshClient.updateQualityMetricsWithDNSResult

	err = sshClient.sshServer.support.PacketTunnelServer.ClientConnected(
		sshClient.sessionID,
		packetTunnelChannel,
		checkAllowedTCPPortFunc,
		checkAllowedUDPPortFunc,
		checkAllowedDomainFunc,
		flowActivityUpdaterMaker,
		metricUpdater,
		dnsQualityReporter)
	if err != nil {
		log.WithTraceFields(LogFields{"error": err}).Warning("start packet tunnel client failed")
		sshClient.setPacketTunnelChannel(nil)
	}
}

func (sshClient *sshClient) handleNewTCPPortForwardChannel(
	waitGroup *sync.WaitGroup,
	newChannel ssh.NewChannel,
	allowSplitTunnel bool,
	newTCPPortForwards chan *newTCPPortForward) {

	// udpgw client connections are dispatched immediately (clients use this for
	// DNS, so it's essential to not block; and only one udpgw connection is
	// retained at a time).
	//
	// All other TCP port forwards are dispatched via the TCP port forward
	// manager queue.

	// http://tools.ietf.org/html/rfc4254#section-7.2
	var directTcpipExtraData struct {
		HostToConnect       string
		PortToConnect       uint32
		OriginatorIPAddress string
		OriginatorPort      uint32
	}

	err := ssh.Unmarshal(newChannel.ExtraData(), &directTcpipExtraData)
	if err != nil {
		sshClient.rejectNewChannel(newChannel, "invalid extra data")
		return
	}

	// Intercept TCP port forwards to a specified udpgw server and handle directly.
	// TODO: also support UDP explicitly, e.g. with a custom "direct-udp" channel type?
	isUDPChannel := sshClient.sshServer.support.Config.UDPInterceptUdpgwServerAddress != "" &&
		sshClient.sshServer.support.Config.UDPInterceptUdpgwServerAddress ==
			net.JoinHostPort(directTcpipExtraData.HostToConnect, strconv.Itoa(int(directTcpipExtraData.PortToConnect)))

	if isUDPChannel {

		// Dispatch immediately. handleUDPChannel runs the udpgw protocol in its
		// own worker goroutine.

		waitGroup.Add(1)
		go func(channel ssh.NewChannel) {
			defer waitGroup.Done()
			sshClient.handleUDPChannel(channel)
		}(newChannel)

	} else {

		// Dispatch via TCP port forward manager. When the queue is full, the channel
		// is immediately rejected.
		//
		// Split tunnel logic is enabled for this TCP port forward when the client
		// has enabled split tunnel mode and the channel type allows it.

		tcpPortForward := &newTCPPortForward{
			enqueueTime:   time.Now(),
			hostToConnect: directTcpipExtraData.HostToConnect,
			portToConnect: int(directTcpipExtraData.PortToConnect),
			doSplitTunnel: sshClient.handshakeState.splitTunnel && allowSplitTunnel,
			newChannel:    newChannel,
		}

		select {
		case newTCPPortForwards <- tcpPortForward:
		default:
			sshClient.updateQualityMetricsWithRejectedDialingLimit()
			sshClient.rejectNewChannel(newChannel, "TCP port forward dial queue full")
		}
	}
}

func (sshClient *sshClient) cleanupAuthorizations() {
	sshClient.Lock()

	if sshClient.releaseAuthorizations != nil {
		sshClient.releaseAuthorizations()
	}

	if sshClient.stopTimer != nil {
		sshClient.stopTimer.Stop()
	}

	sshClient.Unlock()
}

// setPacketTunnelChannel sets the single packet tunnel channel
// for this sshClient. Any existing packet tunnel channel is
// closed.
func (sshClient *sshClient) setPacketTunnelChannel(channel ssh.Channel) {
	sshClient.Lock()
	if sshClient.packetTunnelChannel != nil {
		sshClient.packetTunnelChannel.Close()
	}
	sshClient.packetTunnelChannel = channel
	sshClient.Unlock()
}

// setUDPChannel sets the single UDP channel for this sshClient.
// Each sshClient may have only one concurrent UDP channel. Each
// UDP channel multiplexes many UDP port forwards via the udpgw
// protocol. Any existing UDP channel is closed.
func (sshClient *sshClient) setUDPChannel(channel ssh.Channel) {
	sshClient.Lock()
	if sshClient.udpChannel != nil {
		sshClient.udpChannel.Close()
	}
	sshClient.udpChannel = channel
	sshClient.Unlock()
}

var serverTunnelStatParams = append(
	[]requestParamSpec{
		{"last_connected", isLastConnected, requestParamOptional},
		{"establishment_duration", isIntString, requestParamOptional}},
	baseSessionAndDialParams...)

func (sshClient *sshClient) logTunnel(additionalMetrics []LogFields) {

	sshClient.Lock()

	logFields := getRequestLogFields(
		"server_tunnel",
		sshClient.geoIPData,
		sshClient.handshakeState.authorizedAccessTypes,
		sshClient.handshakeState.apiParams,
		serverTunnelStatParams)

	// "relay_protocol" is sent with handshake API parameters. In pre-
	// handshake logTunnel cases, this value is not yet known. As
	// sshClient.tunnelProtocol is authoritative, set this value
	// unconditionally, overwriting any value from handshake.
	logFields["relay_protocol"] = sshClient.tunnelProtocol

	if sshClient.serverPacketManipulation != "" {
		logFields["server_packet_manipulation"] = sshClient.serverPacketManipulation
	}
	if sshClient.sshListener.BPFProgramName != "" {
		logFields["server_bpf"] = sshClient.sshListener.BPFProgramName
	}
	logFields["session_id"] = sshClient.sessionID
	logFields["is_first_tunnel_in_session"] = sshClient.isFirstTunnelInSession
	logFields["handshake_completed"] = sshClient.handshakeState.completed
	logFields["bytes_up_tcp"] = sshClient.tcpTrafficState.bytesUp
	logFields["bytes_down_tcp"] = sshClient.tcpTrafficState.bytesDown
	logFields["peak_concurrent_dialing_port_forward_count_tcp"] = sshClient.tcpTrafficState.peakConcurrentDialingPortForwardCount
	logFields["peak_concurrent_port_forward_count_tcp"] = sshClient.tcpTrafficState.peakConcurrentPortForwardCount
	logFields["total_port_forward_count_tcp"] = sshClient.tcpTrafficState.totalPortForwardCount
	logFields["bytes_up_udp"] = sshClient.udpTrafficState.bytesUp
	logFields["bytes_down_udp"] = sshClient.udpTrafficState.bytesDown
	// sshClient.udpTrafficState.peakConcurrentDialingPortForwardCount isn't meaningful
	logFields["peak_concurrent_port_forward_count_udp"] = sshClient.udpTrafficState.peakConcurrentPortForwardCount
	logFields["total_port_forward_count_udp"] = sshClient.udpTrafficState.totalPortForwardCount

	logFields["pre_handshake_random_stream_count"] = sshClient.preHandshakeRandomStreamMetrics.count
	logFields["pre_handshake_random_stream_upstream_bytes"] = sshClient.preHandshakeRandomStreamMetrics.upstreamBytes
	logFields["pre_handshake_random_stream_received_upstream_bytes"] = sshClient.preHandshakeRandomStreamMetrics.receivedUpstreamBytes
	logFields["pre_handshake_random_stream_downstream_bytes"] = sshClient.preHandshakeRandomStreamMetrics.downstreamBytes
	logFields["pre_handshake_random_stream_sent_downstream_bytes"] = sshClient.preHandshakeRandomStreamMetrics.sentDownstreamBytes
	logFields["random_stream_count"] = sshClient.postHandshakeRandomStreamMetrics.count
	logFields["random_stream_upstream_bytes"] = sshClient.postHandshakeRandomStreamMetrics.upstreamBytes
	logFields["random_stream_received_upstream_bytes"] = sshClient.postHandshakeRandomStreamMetrics.receivedUpstreamBytes
	logFields["random_stream_downstream_bytes"] = sshClient.postHandshakeRandomStreamMetrics.downstreamBytes
	logFields["random_stream_sent_downstream_bytes"] = sshClient.postHandshakeRandomStreamMetrics.sentDownstreamBytes

	// Pre-calculate a total-tunneled-bytes field. This total is used
	// extensively in analytics and is more performant when pre-calculated.
	logFields["bytes"] = sshClient.tcpTrafficState.bytesUp +
		sshClient.tcpTrafficState.bytesDown +
		sshClient.udpTrafficState.bytesUp +
		sshClient.udpTrafficState.bytesDown

	// Merge in additional metrics from the optional metrics source
	for _, metrics := range additionalMetrics {
		for name, value := range metrics {
			// Don't overwrite any basic fields
			if logFields[name] == nil {
				logFields[name] = value
			}
		}
	}

	sshClient.Unlock()

	// Note: unlock before use is only safe as long as referenced sshClient data,
	// such as slices in handshakeState, is read-only after initially set.

	log.LogRawFieldsWithTimestamp(logFields)
}

var blocklistHitsStatParams = []requestParamSpec{
	{"propagation_channel_id", isHexDigits, 0},
	{"sponsor_id", isHexDigits, 0},
	{"client_version", isIntString, requestParamLogStringAsInt},
	{"client_platform", isClientPlatform, 0},
	{"client_features", isAnyString, requestParamOptional | requestParamArray},
	{"client_build_rev", isHexDigits, requestParamOptional},
	{"device_region", isAnyString, requestParamOptional},
	{"egress_region", isRegionCode, requestParamOptional},
	{"session_id", isHexDigits, 0},
	{"last_connected", isLastConnected, requestParamOptional},
}

func (sshClient *sshClient) logBlocklistHits(IP net.IP, domain string, tags []BlocklistTag) {

	sshClient.Lock()

	logFields := getRequestLogFields(
		"server_blocklist_hit",
		sshClient.geoIPData,
		sshClient.handshakeState.authorizedAccessTypes,
		sshClient.handshakeState.apiParams,
		blocklistHitsStatParams)

	logFields["session_id"] = sshClient.sessionID

	// Note: see comment in logTunnel regarding unlock and concurrent access.

	sshClient.Unlock()

	for _, tag := range tags {
		if IP != nil {
			logFields["blocklist_ip_address"] = IP.String()
		}
		if domain != "" {
			logFields["blocklist_domain"] = domain
		}
		logFields["blocklist_source"] = tag.Source
		logFields["blocklist_subject"] = tag.Subject

		log.LogRawFieldsWithTimestamp(logFields)
	}
}

func (sshClient *sshClient) runOSLSender() {

	for {
		// Await a signal that there are SLOKs to send
		// TODO: use reflect.SelectCase, and optionally await timer here?
		select {
		case <-sshClient.signalIssueSLOKs:
		case <-sshClient.runCtx.Done():
			return
		}

		retryDelay := SSH_SEND_OSL_INITIAL_RETRY_DELAY
		for {
			err := sshClient.sendOSLRequest()
			if err == nil {
				break
			}
			if !isExpectedTunnelIOError(err) {
				log.WithTraceFields(LogFields{"error": err}).Warning("sendOSLRequest failed")
			}

			// If the request failed, retry after a delay (with exponential backoff)
			// or when signaled that there are additional SLOKs to send
			retryTimer := time.NewTimer(retryDelay)
			select {
			case <-retryTimer.C:
			case <-sshClient.signalIssueSLOKs:
			case <-sshClient.runCtx.Done():
				retryTimer.Stop()
				return
			}
			retryTimer.Stop()
			retryDelay *= SSH_SEND_OSL_RETRY_FACTOR
		}
	}
}

// sendOSLRequest will invoke osl.GetSeedPayload to issue SLOKs and
// generate a payload, and send an OSL request to the client when
// there are new SLOKs in the payload.
func (sshClient *sshClient) sendOSLRequest() error {

	seedPayload := sshClient.getOSLSeedPayload()

	// Don't send when no SLOKs. This will happen when signalIssueSLOKs
	// is received but no new SLOKs are issued.
	if len(seedPayload.SLOKs) == 0 {
		return nil
	}

	oslRequest := protocol.OSLRequest{
		SeedPayload: seedPayload,
	}
	requestPayload, err := json.Marshal(oslRequest)
	if err != nil {
		return errors.Trace(err)
	}

	ok, _, err := sshClient.sshConn.SendRequest(
		protocol.PSIPHON_API_OSL_REQUEST_NAME,
		true,
		requestPayload)
	if err != nil {
		return errors.Trace(err)
	}
	if !ok {
		return errors.TraceNew("client rejected request")
	}

	sshClient.clearOSLSeedPayload()

	return nil
}

// runAlertSender dequeues and sends alert requests to the client. As these
// alerts are informational, there is no retry logic and no SSH client
// acknowledgement (wantReply) is requested. This worker scheme allows
// nonconcurrent components including udpgw and packet tunnel to enqueue
// alerts without blocking their traffic processing.
func (sshClient *sshClient) runAlertSender() {
	for {
		select {
		case <-sshClient.runCtx.Done():
			return

		case request := <-sshClient.sendAlertRequests:
			payload, err := json.Marshal(request)
			if err != nil {
				log.WithTraceFields(LogFields{"error": err}).Warning("Marshal failed")
				break
			}
			_, _, err = sshClient.sshConn.SendRequest(
				protocol.PSIPHON_API_ALERT_REQUEST_NAME,
				false,
				payload)
			if err != nil && !isExpectedTunnelIOError(err) {
				log.WithTraceFields(LogFields{"error": err}).Warning("SendRequest failed")
				break
			}
			sshClient.Lock()
			sshClient.sentAlertRequests[fmt.Sprintf("%+v", request)] = true
			sshClient.Unlock()
		}
	}
}

// enqueueAlertRequest enqueues an alert request to be sent to the client.
// Only one request is sent per tunnel per protocol.AlertRequest value;
// subsequent alerts with the same value are dropped. enqueueAlertRequest will
// not block until the queue exceeds ALERT_REQUEST_QUEUE_BUFFER_SIZE.
func (sshClient *sshClient) enqueueAlertRequest(request protocol.AlertRequest) {
	sshClient.Lock()
	if sshClient.sentAlertRequests[fmt.Sprintf("%+v", request)] {
		sshClient.Unlock()
		return
	}
	sshClient.Unlock()
	select {
	case <-sshClient.runCtx.Done():
	case sshClient.sendAlertRequests <- request:
	}
}

func (sshClient *sshClient) enqueueDisallowedTrafficAlertRequest() {

	reason := protocol.PSIPHON_API_ALERT_DISALLOWED_TRAFFIC
	actionURLs := sshClient.getAlertActionURLs(reason)

	sshClient.enqueueAlertRequest(
		protocol.AlertRequest{
			Reason:     protocol.PSIPHON_API_ALERT_DISALLOWED_TRAFFIC,
			ActionURLs: actionURLs,
		})
}

func (sshClient *sshClient) enqueueUnsafeTrafficAlertRequest(tags []BlocklistTag) {

	reason := protocol.PSIPHON_API_ALERT_UNSAFE_TRAFFIC
	actionURLs := sshClient.getAlertActionURLs(reason)

	for _, tag := range tags {
		sshClient.enqueueAlertRequest(
			protocol.AlertRequest{
				Reason:     reason,
				Subject:    tag.Subject,
				ActionURLs: actionURLs,
			})
	}
}

func (sshClient *sshClient) getAlertActionURLs(alertReason string) []string {

	sshClient.Lock()
	sponsorID, _ := getStringRequestParam(
		sshClient.handshakeState.apiParams, "sponsor_id")
	sshClient.Unlock()

	return sshClient.sshServer.support.PsinetDatabase.GetAlertActionURLs(
		alertReason,
		sponsorID,
		sshClient.geoIPData.Country,
		sshClient.geoIPData.ASN)
}

func (sshClient *sshClient) rejectNewChannel(newChannel ssh.NewChannel, logMessage string) {

	// We always return the reject reason "Prohibited":
	// - Traffic rules and connection limits may prohibit the connection.
	// - External firewall rules may prohibit the connection, and this is not currently
	//   distinguishable from other failure modes.
	// - We limit the failure information revealed to the client.
	reason := ssh.Prohibited

	// Note: Debug level, as logMessage may contain user traffic destination address information
	log.WithTraceFields(
		LogFields{
			"channelType":  newChannel.ChannelType(),
			"logMessage":   logMessage,
			"rejectReason": reason.String(),
		}).Debug("reject new channel")

	// Note: logMessage is internal, for logging only; just the reject reason is sent to the client.
	newChannel.Reject(reason, reason.String())
}

// setHandshakeState records that a client has completed a handshake API request.
// Some parameters from the handshake request may be used in future traffic rule
// selection. Port forwards are disallowed until a handshake is complete. The
// handshake parameters are included in the session summary log recorded in
// sshClient.stop().
func (sshClient *sshClient) setHandshakeState(
	state handshakeState,
	authorizations []string) (*handshakeStateInfo, error) {

	sshClient.Lock()
	completed := sshClient.handshakeState.completed
	if !completed {
		sshClient.handshakeState = state
	}
	sshClient.Unlock()

	// Client must only perform one handshake
	if completed {
		return nil, errors.TraceNew("handshake already completed")
	}

	// Verify the authorizations submitted by the client. Verified, active
	// (non-expired) access types will be available for traffic rules
	// filtering.
	//
	// When an authorization is active but expires while the client is
	// connected, the client is disconnected to ensure the access is reset.
	// This is implemented by setting a timer to perform the disconnect at the
	// expiry time of the soonest expiring authorization.
	//
	// sshServer.authorizationSessionIDs tracks the unique mapping of active
	// authorization IDs to client session IDs  and is used to detect and
	// prevent multiple malicious clients from reusing a single authorization
	// (within the scope of this server).

	// authorizationIDs and authorizedAccessTypes are returned to the client
	// and logged, respectively; initialize to empty lists so the
	// protocol/logs don't need to handle 'null' values.
	authorizationIDs := make([]string, 0)
	authorizedAccessTypes := make([]string, 0)
	var stopTime time.Time

	for i, authorization := range authorizations {

		// This sanity check mitigates malicious clients causing excess CPU use.
		if i >= MAX_AUTHORIZATIONS {
			log.WithTrace().Warning("too many authorizations")
			break
		}

		verifiedAuthorization, err := accesscontrol.VerifyAuthorization(
			&sshClient.sshServer.support.Config.AccessControlVerificationKeyRing,
			authorization)

		if err != nil {
			log.WithTraceFields(
				LogFields{"error": err}).Warning("verify authorization failed")
			continue
		}

		authorizationID := base64.StdEncoding.EncodeToString(verifiedAuthorization.ID)

		if common.Contains(authorizedAccessTypes, verifiedAuthorization.AccessType) {
			log.WithTraceFields(
				LogFields{"accessType": verifiedAuthorization.AccessType}).Warning("duplicate authorization access type")
			continue
		}

		authorizationIDs = append(authorizationIDs, authorizationID)
		authorizedAccessTypes = append(authorizedAccessTypes, verifiedAuthorization.AccessType)

		if stopTime.IsZero() || stopTime.After(verifiedAuthorization.Expires) {
			stopTime = verifiedAuthorization.Expires
		}
	}

	// Associate all verified authorizationIDs with this client's session ID.
	// Handle cases where previous associations exist:
	//
	// - Multiple malicious clients reusing a single authorization. In this
	//   case, authorizations are revoked from the previous client.
	//
	// - The client reconnected with a new session ID due to user toggling.
	//   This case is expected due to server affinity. This cannot be
	//   distinguished from the previous case and the same action is taken;
	//   this will have no impact on a legitimate client as the previous
	//   session is dangling.
	//
	// - The client automatically reconnected with the same session ID. This
	//   case is not expected as sshServer.registerEstablishedClient
	//   synchronously calls sshClient.releaseAuthorizations; as a safe guard,
	//   this case is distinguished and no revocation action is taken.

	sshClient.sshServer.authorizationSessionIDsMutex.Lock()
	for _, authorizationID := range authorizationIDs {
		sessionID, ok := sshClient.sshServer.authorizationSessionIDs[authorizationID]
		if ok && sessionID != sshClient.sessionID {

			logFields := LogFields{
				"event_name":                 "irregular_tunnel",
				"tunnel_error":               "duplicate active authorization",
				"duplicate_authorization_id": authorizationID,
			}
			sshClient.geoIPData.SetLogFields(logFields)
			duplicateGeoIPData := sshClient.sshServer.support.GeoIPService.GetSessionCache(sessionID)
			if duplicateGeoIPData != sshClient.geoIPData {
				duplicateGeoIPData.SetLogFieldsWithPrefix("duplicate_authorization_", logFields)
			}
			log.LogRawFieldsWithTimestamp(logFields)

			// Invoke asynchronously to avoid deadlocks.
			// TODO: invoke only once for each distinct sessionID?
			go sshClient.sshServer.revokeClientAuthorizations(sessionID)
		}
		sshClient.sshServer.authorizationSessionIDs[authorizationID] = sshClient.sessionID
	}
	sshClient.sshServer.authorizationSessionIDsMutex.Unlock()

	if len(authorizationIDs) > 0 {

		sshClient.Lock()

		// Make the authorizedAccessTypes available for traffic rules filtering.

		sshClient.handshakeState.activeAuthorizationIDs = authorizationIDs
		sshClient.handshakeState.authorizedAccessTypes = authorizedAccessTypes

		// On exit, sshClient.runTunnel will call releaseAuthorizations, which
		// will release the authorization IDs so the client can reconnect and
		// present the same authorizations again. sshClient.runTunnel will
		// also cancel the stopTimer in case it has not yet fired.
		// Note: termination of the stopTimer goroutine is not synchronized.

		sshClient.releaseAuthorizations = func() {
			sshClient.sshServer.authorizationSessionIDsMutex.Lock()
			for _, authorizationID := range authorizationIDs {
				sessionID, ok := sshClient.sshServer.authorizationSessionIDs[authorizationID]
				if ok && sessionID == sshClient.sessionID {
					delete(sshClient.sshServer.authorizationSessionIDs, authorizationID)
				}
			}
			sshClient.sshServer.authorizationSessionIDsMutex.Unlock()
		}

		sshClient.stopTimer = time.AfterFunc(
			time.Until(stopTime),
			func() {
				sshClient.stop()
			})

		sshClient.Unlock()
	}

	upstreamBytesPerSecond, downstreamBytesPerSecond := sshClient.setTrafficRules()

	sshClient.setOSLConfig()

	return &handshakeStateInfo{
		activeAuthorizationIDs:   authorizationIDs,
		authorizedAccessTypes:    authorizedAccessTypes,
		upstreamBytesPerSecond:   upstreamBytesPerSecond,
		downstreamBytesPerSecond: downstreamBytesPerSecond,
	}, nil
}

// getHandshaked returns whether the client has completed a handshake API
// request and whether the traffic rules that were selected after the
// handshake immediately exhaust the client.
//
// When the client is immediately exhausted it will be closed; but this
// takes effect asynchronously. The "exhausted" return value is used to
// prevent API requests by clients that will close.
func (sshClient *sshClient) getHandshaked() (bool, bool) {
	sshClient.Lock()
	defer sshClient.Unlock()

	completed := sshClient.handshakeState.completed

	exhausted := false

	// Notes:
	// - "Immediately exhausted" is when CloseAfterExhausted is set and
	//   either ReadUnthrottledBytes or WriteUnthrottledBytes starts from
	//   0, so no bytes would be read or written. This check does not
	//   examine whether 0 bytes _remain_ in the ThrottledConn.
	// - This check is made against the current traffic rules, which
	//   could have changed in a hot reload since the handshake.

	if completed &&
		*sshClient.trafficRules.RateLimits.CloseAfterExhausted &&
		(*sshClient.trafficRules.RateLimits.ReadUnthrottledBytes == 0 ||
			*sshClient.trafficRules.RateLimits.WriteUnthrottledBytes == 0) {

		exhausted = true
	}

	return completed, exhausted
}

func (sshClient *sshClient) updateAPIParameters(
	apiParams common.APIParameters) {

	sshClient.Lock()
	defer sshClient.Unlock()

	// Only update after handshake has initialized API params.
	if !sshClient.handshakeState.completed {
		return
	}

	for name, value := range apiParams {
		sshClient.handshakeState.apiParams[name] = value
	}
}

func (sshClient *sshClient) expectDomainBytes() bool {
	sshClient.Lock()
	defer sshClient.Unlock()

	return sshClient.handshakeState.expectDomainBytes
}

// setTrafficRules resets the client's traffic rules based on the latest server config
// and client properties. As sshClient.trafficRules may be reset by a concurrent
// goroutine, trafficRules must only be accessed within the sshClient mutex.
func (sshClient *sshClient) setTrafficRules() (int64, int64) {
	sshClient.Lock()
	defer sshClient.Unlock()

	isFirstTunnelInSession := sshClient.isFirstTunnelInSession &&
		sshClient.handshakeState.establishedTunnelsCount == 0

	sshClient.trafficRules = sshClient.sshServer.support.TrafficRulesSet.GetTrafficRules(
		isFirstTunnelInSession,
		sshClient.tunnelProtocol,
		sshClient.geoIPData,
		sshClient.handshakeState)

	if sshClient.throttledConn != nil {
		// Any existing throttling state is reset.
		sshClient.throttledConn.SetLimits(
			sshClient.trafficRules.RateLimits.CommonRateLimits())
	}

	return *sshClient.trafficRules.RateLimits.ReadBytesPerSecond,
		*sshClient.trafficRules.RateLimits.WriteBytesPerSecond
}

// setOSLConfig resets the client's OSL seed state based on the latest OSL config
// As sshClient.oslClientSeedState may be reset by a concurrent goroutine,
// oslClientSeedState must only be accessed within the sshClient mutex.
func (sshClient *sshClient) setOSLConfig() {
	sshClient.Lock()
	defer sshClient.Unlock()

	propagationChannelID, err := getStringRequestParam(
		sshClient.handshakeState.apiParams, "propagation_channel_id")
	if err != nil {
		// This should not fail as long as client has sent valid handshake
		return
	}

	// Use a cached seed state if one is found for the client's
	// session ID. This enables resuming progress made in a previous
	// tunnel.
	// Note: go-cache is already concurency safe; the additional mutex
	// is necessary to guarantee that Get/Delete is atomic; although in
	// practice no two concurrent clients should ever supply the same
	// session ID.

	sshClient.sshServer.oslSessionCacheMutex.Lock()
	oslClientSeedState, found := sshClient.sshServer.oslSessionCache.Get(sshClient.sessionID)
	if found {
		sshClient.sshServer.oslSessionCache.Delete(sshClient.sessionID)
		sshClient.sshServer.oslSessionCacheMutex.Unlock()
		sshClient.oslClientSeedState = oslClientSeedState.(*osl.ClientSeedState)
		sshClient.oslClientSeedState.Resume(sshClient.signalIssueSLOKs)
		return
	}
	sshClient.sshServer.oslSessionCacheMutex.Unlock()

	// Two limitations when setOSLConfig() is invoked due to an
	// OSL config hot reload:
	//
	// 1. any partial progress towards SLOKs is lost.
	//
	// 2. all existing osl.ClientSeedPortForwards for existing
	//    port forwards will not send progress to the new client
	//    seed state.

	sshClient.oslClientSeedState = sshClient.sshServer.support.OSLConfig.NewClientSeedState(
		sshClient.geoIPData.Country,
		propagationChannelID,
		sshClient.signalIssueSLOKs)
}

// newClientSeedPortForward will return nil when no seeding is
// associated with the specified ipAddress.
func (sshClient *sshClient) newClientSeedPortForward(ipAddress net.IP) *osl.ClientSeedPortForward {
	sshClient.Lock()
	defer sshClient.Unlock()

	// Will not be initialized before handshake.
	if sshClient.oslClientSeedState == nil {
		return nil
	}

	return sshClient.oslClientSeedState.NewClientSeedPortForward(ipAddress)
}

// getOSLSeedPayload returns a payload containing all seeded SLOKs for
// this client's session.
func (sshClient *sshClient) getOSLSeedPayload() *osl.SeedPayload {
	sshClient.Lock()
	defer sshClient.Unlock()

	// Will not be initialized before handshake.
	if sshClient.oslClientSeedState == nil {
		return &osl.SeedPayload{SLOKs: make([]*osl.SLOK, 0)}
	}

	return sshClient.oslClientSeedState.GetSeedPayload()
}

func (sshClient *sshClient) clearOSLSeedPayload() {
	sshClient.Lock()
	defer sshClient.Unlock()

	sshClient.oslClientSeedState.ClearSeedPayload()
}

func (sshClient *sshClient) rateLimits() common.RateLimits {
	sshClient.Lock()
	defer sshClient.Unlock()

	return sshClient.trafficRules.RateLimits.CommonRateLimits()
}

func (sshClient *sshClient) idleTCPPortForwardTimeout() time.Duration {
	sshClient.Lock()
	defer sshClient.Unlock()

	return time.Duration(*sshClient.trafficRules.IdleTCPPortForwardTimeoutMilliseconds) * time.Millisecond
}

func (sshClient *sshClient) idleUDPPortForwardTimeout() time.Duration {
	sshClient.Lock()
	defer sshClient.Unlock()

	return time.Duration(*sshClient.trafficRules.IdleUDPPortForwardTimeoutMilliseconds) * time.Millisecond
}

func (sshClient *sshClient) setTCPPortForwardDialingAvailableSignal(signal context.CancelFunc) {
	sshClient.Lock()
	defer sshClient.Unlock()

	sshClient.tcpPortForwardDialingAvailableSignal = signal
}

const (
	portForwardTypeTCP = iota
	portForwardTypeUDP
)

func (sshClient *sshClient) isPortForwardPermitted(
	portForwardType int,
	remoteIP net.IP,
	port int) bool {

	// Disallow connection to bogons.
	//
	// As a security measure, this is a failsafe. The server should be run on a
	// host with correctly configured firewall rules.
	//
	// This check also avoids spurious disallowed traffic alerts for destinations
	// that are impossible to reach.

	if !sshClient.sshServer.support.Config.AllowBogons && common.IsBogon(remoteIP) {
		return false
	}

	// Blocklist check.
	//
	// Limitation: isPortForwardPermitted is not called in transparent DNS
	// forwarding cases. As the destination IP address is rewritten in these
	// cases, a blocklist entry won't be dialed in any case. However, no logs
	// will be recorded.

	if !sshClient.isIPPermitted(remoteIP) {
		return false
	}

	// Don't lock before calling logBlocklistHits.
	// Unlock before calling enqueueDisallowedTrafficAlertRequest/log.

	sshClient.Lock()

	allowed := true

	// Client must complete handshake before port forwards are permitted.
	if !sshClient.handshakeState.completed {
		allowed = false
	}

	if allowed {
		// Traffic rules checks.
		switch portForwardType {
		case portForwardTypeTCP:
			if !sshClient.trafficRules.AllowTCPPort(remoteIP, port) {
				allowed = false
			}
		case portForwardTypeUDP:
			if !sshClient.trafficRules.AllowUDPPort(remoteIP, port) {
				allowed = false
			}
		}
	}

	sshClient.Unlock()

	if allowed {
		return true
	}

	switch portForwardType {
	case portForwardTypeTCP:
		sshClient.updateQualityMetricsWithTCPRejectedDisallowed()
	case portForwardTypeUDP:
		sshClient.updateQualityMetricsWithUDPRejectedDisallowed()
	}

	sshClient.enqueueDisallowedTrafficAlertRequest()

	log.WithTraceFields(
		LogFields{
			"type": portForwardType,
			"port": port,
		}).Debug("port forward denied by traffic rules")

	return false
}

// isDomainPermitted returns true when the specified domain may be resolved
// and returns false and a reject reason otherwise.
func (sshClient *sshClient) isDomainPermitted(domain string) (bool, string) {

	// We're not doing comprehensive validation, to avoid overhead per port
	// forward. This is a simple sanity check to ensure we don't process
	// blantantly invalid input.
	//
	// TODO: validate with dns.IsDomainName?
	if len(domain) > 255 {
		return false, "invalid domain name"
	}

	tags := sshClient.sshServer.support.Blocklist.LookupDomain(domain)
	if len(tags) > 0 {

		sshClient.logBlocklistHits(nil, domain, tags)

		if sshClient.sshServer.support.Config.BlocklistActive {
			// Actively alert and block
			sshClient.enqueueUnsafeTrafficAlertRequest(tags)
			return false, "port forward not permitted"
		}
	}

	return true, ""
}

func (sshClient *sshClient) isIPPermitted(remoteIP net.IP) bool {

	tags := sshClient.sshServer.support.Blocklist.LookupIP(remoteIP)
	if len(tags) > 0 {

		sshClient.logBlocklistHits(remoteIP, "", tags)

		if sshClient.sshServer.support.Config.BlocklistActive {
			// Actively alert and block
			sshClient.enqueueUnsafeTrafficAlertRequest(tags)
			return false
		}
	}

	return true
}

func (sshClient *sshClient) isTCPDialingPortForwardLimitExceeded() bool {

	sshClient.Lock()
	defer sshClient.Unlock()

	state := &sshClient.tcpTrafficState
	max := *sshClient.trafficRules.MaxTCPDialingPortForwardCount

	if max > 0 && state.concurrentDialingPortForwardCount >= int64(max) {
		return true
	}
	return false
}

func (sshClient *sshClient) getTCPPortForwardQueueSize() int {

	sshClient.Lock()
	defer sshClient.Unlock()

	return *sshClient.trafficRules.MaxTCPPortForwardCount +
		*sshClient.trafficRules.MaxTCPDialingPortForwardCount
}

func (sshClient *sshClient) getDialTCPPortForwardTimeoutMilliseconds() int {

	sshClient.Lock()
	defer sshClient.Unlock()

	return *sshClient.trafficRules.DialTCPPortForwardTimeoutMilliseconds
}

func (sshClient *sshClient) dialingTCPPortForward() {

	sshClient.Lock()
	defer sshClient.Unlock()

	state := &sshClient.tcpTrafficState

	state.concurrentDialingPortForwardCount += 1
	if state.concurrentDialingPortForwardCount > state.peakConcurrentDialingPortForwardCount {
		state.peakConcurrentDialingPortForwardCount = state.concurrentDialingPortForwardCount
	}
}

func (sshClient *sshClient) abortedTCPPortForward() {

	sshClient.Lock()
	defer sshClient.Unlock()

	sshClient.tcpTrafficState.concurrentDialingPortForwardCount -= 1
}

func (sshClient *sshClient) allocatePortForward(portForwardType int) bool {

	sshClient.Lock()
	defer sshClient.Unlock()

	// Check if at port forward limit. The subsequent counter
	// changes must be atomic with the limit check to ensure
	// the counter never exceeds the limit in the case of
	// concurrent allocations.

	var max int
	var state *trafficState
	if portForwardType == portForwardTypeTCP {
		max = *sshClient.trafficRules.MaxTCPPortForwardCount
		state = &sshClient.tcpTrafficState
	} else {
		max = *sshClient.trafficRules.MaxUDPPortForwardCount
		state = &sshClient.udpTrafficState
	}

	if max > 0 && state.concurrentPortForwardCount >= int64(max) {
		return false
	}

	// Update port forward counters.

	if portForwardType == portForwardTypeTCP {

		// Assumes TCP port forwards called dialingTCPPortForward
		state.concurrentDialingPortForwardCount -= 1

		if sshClient.tcpPortForwardDialingAvailableSignal != nil {

			max := *sshClient.trafficRules.MaxTCPDialingPortForwardCount
			if max <= 0 || state.concurrentDialingPortForwardCount < int64(max) {
				sshClient.tcpPortForwardDialingAvailableSignal()
			}
		}
	}

	state.concurrentPortForwardCount += 1
	if state.concurrentPortForwardCount > state.peakConcurrentPortForwardCount {
		state.peakConcurrentPortForwardCount = state.concurrentPortForwardCount
	}
	state.totalPortForwardCount += 1

	return true
}

// establishedPortForward increments the concurrent port
// forward counter. closedPortForward decrements it, so it
// must always be called for each establishedPortForward
// call.
//
// When at the limit of established port forwards, the LRU
// existing port forward is closed to make way for the newly
// established one. There can be a minor delay as, in addition
// to calling Close() on the port forward net.Conn,
// establishedPortForward waits for the LRU's closedPortForward()
// call which will decrement the concurrent counter. This
// ensures all resources associated with the LRU (socket,
// goroutine) are released or will very soon be released before
// proceeding.
func (sshClient *sshClient) establishedPortForward(
	portForwardType int, portForwardLRU *common.LRUConns) {

	// Do not lock sshClient here.

	var state *trafficState
	if portForwardType == portForwardTypeTCP {
		state = &sshClient.tcpTrafficState
	} else {
		state = &sshClient.udpTrafficState
	}

	// When the maximum number of port forwards is already
	// established, close the LRU. CloseOldest will call
	// Close on the port forward net.Conn. Both TCP and
	// UDP port forwards have handler goroutines that may
	// be blocked calling Read on the net.Conn. Close will
	// eventually interrupt the Read and cause the handlers
	// to exit, but not immediately. So the following logic
	// waits for a LRU handler to be interrupted and signal
	// availability.
	//
	// Notes:
	//
	// - the port forward limit can change via a traffic
	//   rules hot reload; the condition variable handles
	//   this case whereas a channel-based semaphore would
	//   not.
	//
	// - if a number of goroutines exceeding the total limit
	//   arrive here all concurrently, some CloseOldest() calls
	//   will have no effect as there can be less existing port
	//   forwards than new ones. In this case, the new port
	//   forward will be delayed. This is highly unlikely in
	//   practise since UDP calls to establishedPortForward are
	//   serialized and TCP calls are limited by the dial
	//   queue/count.

	if !sshClient.allocatePortForward(portForwardType) {

		portForwardLRU.CloseOldest()
		log.WithTrace().Debug("closed LRU port forward")

		state.availablePortForwardCond.L.Lock()
		for !sshClient.allocatePortForward(portForwardType) {
			state.availablePortForwardCond.Wait()
		}
		state.availablePortForwardCond.L.Unlock()
	}
}

func (sshClient *sshClient) closedPortForward(
	portForwardType int, bytesUp, bytesDown int64) {

	sshClient.Lock()

	var state *trafficState
	if portForwardType == portForwardTypeTCP {
		state = &sshClient.tcpTrafficState
	} else {
		state = &sshClient.udpTrafficState
	}

	state.concurrentPortForwardCount -= 1
	state.bytesUp += bytesUp
	state.bytesDown += bytesDown

	sshClient.Unlock()

	// Signal any goroutine waiting in establishedPortForward
	// that an established port forward slot is available.
	state.availablePortForwardCond.Signal()
}

func (sshClient *sshClient) updateQualityMetricsWithDialResult(
	tcpPortForwardDialSuccess bool, dialDuration time.Duration, IP net.IP) {

	sshClient.Lock()
	defer sshClient.Unlock()

	if tcpPortForwardDialSuccess {
		sshClient.qualityMetrics.TCPPortForwardDialedCount += 1
		sshClient.qualityMetrics.TCPPortForwardDialedDuration += dialDuration
		if IP.To4() != nil {
			sshClient.qualityMetrics.TCPIPv4PortForwardDialedCount += 1
			sshClient.qualityMetrics.TCPIPv4PortForwardDialedDuration += dialDuration
		} else if IP != nil {
			sshClient.qualityMetrics.TCPIPv6PortForwardDialedCount += 1
			sshClient.qualityMetrics.TCPIPv6PortForwardDialedDuration += dialDuration
		}
	} else {
		sshClient.qualityMetrics.TCPPortForwardFailedCount += 1
		sshClient.qualityMetrics.TCPPortForwardFailedDuration += dialDuration
		if IP.To4() != nil {
			sshClient.qualityMetrics.TCPIPv4PortForwardFailedCount += 1
			sshClient.qualityMetrics.TCPIPv4PortForwardFailedDuration += dialDuration
		} else if IP != nil {
			sshClient.qualityMetrics.TCPIPv6PortForwardFailedCount += 1
			sshClient.qualityMetrics.TCPIPv6PortForwardFailedDuration += dialDuration
		}
	}
}

func (sshClient *sshClient) updateQualityMetricsWithRejectedDialingLimit() {

	sshClient.Lock()
	defer sshClient.Unlock()

	sshClient.qualityMetrics.TCPPortForwardRejectedDialingLimitCount += 1
}

func (sshClient *sshClient) updateQualityMetricsWithTCPRejectedDisallowed() {

	sshClient.Lock()
	defer sshClient.Unlock()

	sshClient.qualityMetrics.TCPPortForwardRejectedDisallowedCount += 1
}

func (sshClient *sshClient) updateQualityMetricsWithUDPRejectedDisallowed() {

	sshClient.Lock()
	defer sshClient.Unlock()

	sshClient.qualityMetrics.UDPPortForwardRejectedDisallowedCount += 1
}

func (sshClient *sshClient) updateQualityMetricsWithDNSResult(
	success bool, duration time.Duration, resolverIP net.IP) {

	sshClient.Lock()
	defer sshClient.Unlock()

	resolver := ""
	if resolverIP != nil {
		resolver = resolverIP.String()
	}
	if success {
		sshClient.qualityMetrics.DNSCount["ALL"] += 1
		sshClient.qualityMetrics.DNSDuration["ALL"] += duration
		if resolver != "" {
			sshClient.qualityMetrics.DNSCount[resolver] += 1
			sshClient.qualityMetrics.DNSDuration[resolver] += duration
		}
	} else {
		sshClient.qualityMetrics.DNSFailedCount["ALL"] += 1
		sshClient.qualityMetrics.DNSFailedDuration["ALL"] += duration
		if resolver != "" {
			sshClient.qualityMetrics.DNSFailedCount[resolver] += 1
			sshClient.qualityMetrics.DNSFailedDuration[resolver] += duration
		}
	}
}

func (sshClient *sshClient) handleTCPChannel(
	remainingDialTimeout time.Duration,
	hostToConnect string,
	portToConnect int,
	doSplitTunnel bool,
	newChannel ssh.NewChannel) {

	// Assumptions:
	// - sshClient.dialingTCPPortForward() has been called
	// - remainingDialTimeout > 0

	established := false
	defer func() {
		if !established {
			sshClient.abortedTCPPortForward()
		}
	}()

	// Transparently redirect web API request connections.

	isWebServerPortForward := false
	config := sshClient.sshServer.support.Config
	if config.WebServerPortForwardAddress != "" {
		destination := net.JoinHostPort(hostToConnect, strconv.Itoa(portToConnect))
		if destination == config.WebServerPortForwardAddress {
			isWebServerPortForward = true
			if config.WebServerPortForwardRedirectAddress != "" {
				// Note: redirect format is validated when config is loaded
				host, portStr, _ := net.SplitHostPort(config.WebServerPortForwardRedirectAddress)
				port, _ := strconv.Atoi(portStr)
				hostToConnect = host
				portToConnect = port
			}
		}
	}

	// Validate the domain name and check the domain blocklist before dialing.
	//
	// The IP blocklist is checked in isPortForwardPermitted, which also provides
	// IP blocklist checking for the packet tunnel code path. When hostToConnect
	// is an IP address, the following hostname resolution step effectively
	// performs no actions and next immediate step is the isPortForwardPermitted
	// check.
	//
	// Limitation: this case handles port forwards where the client sends the
	// destination domain in the SSH port forward request but does not currently
	// handle DNS-over-TCP; in the DNS-over-TCP case, a client may bypass the
	// block list check.

	if !isWebServerPortForward &&
		net.ParseIP(hostToConnect) == nil {

		ok, rejectMessage := sshClient.isDomainPermitted(hostToConnect)
		if !ok {
			// Note: not recording a port forward failure in this case
			sshClient.rejectNewChannel(newChannel, rejectMessage)
			return
		}
	}

	// Dial the remote address.
	//
	// Hostname resolution is performed explicitly, as a separate step, as the
	// target IP address is used for traffic rules (AllowSubnets), OSL seed
	// progress, and IP address blocklists.
	//
	// Contexts are used for cancellation (via sshClient.runCtx, which is
	// cancelled when the client is stopping) and timeouts.

	dialStartTime := time.Now()

	log.WithTraceFields(LogFields{"hostToConnect": hostToConnect}).Debug("resolving")

	ctx, cancelCtx := context.WithTimeout(sshClient.runCtx, remainingDialTimeout)
	IPs, err := (&net.Resolver{}).LookupIPAddr(ctx, hostToConnect)
	cancelCtx() // "must be called or the new context will remain live until its parent context is cancelled"

	resolveElapsedTime := time.Since(dialStartTime)

	// Record DNS metrics. If LookupIPAddr returns net.DNSError.IsNotFound, this
	// is "no such host" and not a DNS failure. Limitation: the resolver IP is
	// not known.

	dnsErr, ok := err.(*net.DNSError)
	dnsNotFound := ok && dnsErr.IsNotFound
	dnsSuccess := err == nil || dnsNotFound
	sshClient.updateQualityMetricsWithDNSResult(dnsSuccess, resolveElapsedTime, nil)

	// IPv4 is preferred in case the host has limited IPv6 routing. IPv6 is
	// selected and attempted only when there's no IPv4 option.
	// TODO: shuffle list to try other IPs?

	var IP net.IP
	for _, ip := range IPs {
		if ip.IP.To4() != nil {
			IP = ip.IP
			break
		}
	}
	if IP == nil && len(IPs) > 0 {
		// If there are no IPv4 IPs, the first IP is IPv6.
		IP = IPs[0].IP
	}

	if err == nil && IP == nil {
		err = std_errors.New("no IP address")
	}

	if err != nil {

		// Record a port forward failure
		sshClient.updateQualityMetricsWithDialResult(false, resolveElapsedTime, IP)

		sshClient.rejectNewChannel(newChannel, fmt.Sprintf("LookupIP failed: %s", err))
		return
	}

	remainingDialTimeout -= resolveElapsedTime

	if remainingDialTimeout <= 0 {
		sshClient.rejectNewChannel(newChannel, "TCP port forward timed out resolving")
		return
	}

	// When the client has indicated split tunnel mode and when the channel is
	// not of type protocol.TCP_PORT_FORWARD_NO_SPLIT_TUNNEL_TYPE, check if the
	// client and the port forward destination are in the same GeoIP country. If
	// so, reject the port forward with a distinct response code that indicates
	// to the client that this port forward should be performed locally, direct
	// and untunneled.
	//
	// Clients are expected to cache untunneled responses to avoid this round
	// trip in the immediate future and reduce server load.
	//
	// When the countries differ, immediately proceed with the standard port
	// forward. No additional round trip is required.
	//
	// If either GeoIP country is "None", one or both countries are unknown
	// and there is no match.
	//
	// Traffic rules, such as allowed ports, are not enforced for port forward
	// destinations classified as untunneled.
	//
	// Domain and IP blocklists still apply to port forward destinations
	// classified as untunneled.
	//
	// The client's use of split tunnel mode is logged in server_tunnel metrics
	// as the boolean value split_tunnel. As they may indicate some information
	// about browsing activity, no other split tunnel metrics are logged.

	if doSplitTunnel {

		destinationGeoIPData := sshClient.sshServer.support.GeoIPService.LookupIP(IP, false)

		if destinationGeoIPData.Country == sshClient.geoIPData.Country &&
			sshClient.geoIPData.Country != GEOIP_UNKNOWN_VALUE {

			// Since isPortForwardPermitted is not called in this case, explicitly call
			// ipBlocklistCheck. The domain blocklist case is handled above.
			if !sshClient.isIPPermitted(IP) {
				// Note: not recording a port forward failure in this case
				sshClient.rejectNewChannel(newChannel, "port forward not permitted")
			}

			newChannel.Reject(protocol.CHANNEL_REJECT_REASON_SPLIT_TUNNEL, "")
		}
	}

	// Enforce traffic rules, using the resolved IP address.

	if !isWebServerPortForward &&
		!sshClient.isPortForwardPermitted(
			portForwardTypeTCP,
			IP,
			portToConnect) {
		// Note: not recording a port forward failure in this case
		sshClient.rejectNewChannel(newChannel, "port forward not permitted")
		return
	}

	// TCP dial.

	remoteAddr := net.JoinHostPort(IP.String(), strconv.Itoa(portToConnect))

	log.WithTraceFields(LogFields{"remoteAddr": remoteAddr}).Debug("dialing")

	ctx, cancelCtx = context.WithTimeout(sshClient.runCtx, remainingDialTimeout)
	fwdConn, err := (&net.Dialer{}).DialContext(ctx, "tcp", remoteAddr)
	cancelCtx() // "must be called or the new context will remain live until its parent context is cancelled"

	// Record port forward success or failure
	sshClient.updateQualityMetricsWithDialResult(err == nil, time.Since(dialStartTime), IP)

	if err != nil {

		// Monitor for low resource error conditions
		sshClient.sshServer.monitorPortForwardDialError(err)

		sshClient.rejectNewChannel(newChannel, fmt.Sprintf("DialTimeout failed: %s", err))
		return
	}

	// The upstream TCP port forward connection has been established. Schedule
	// some cleanup and notify the SSH client that the channel is accepted.

	defer fwdConn.Close()

	fwdChannel, requests, err := newChannel.Accept()
	if err != nil {
		if !isExpectedTunnelIOError(err) {
			log.WithTraceFields(LogFields{"error": err}).Warning("accept new channel failed")
		}
		return
	}
	go ssh.DiscardRequests(requests)
	defer fwdChannel.Close()

	// Release the dialing slot and acquire an established slot.
	//
	// establishedPortForward increments the concurrent TCP port
	// forward counter and closes the LRU existing TCP port forward
	// when already at the limit.
	//
	// Known limitations:
	//
	// - Closed LRU TCP sockets will enter the TIME_WAIT state,
	//   continuing to consume some resources.

	sshClient.establishedPortForward(portForwardTypeTCP, sshClient.tcpPortForwardLRU)

	// "established = true" cancels the deferred abortedTCPPortForward()
	established = true

	// TODO: 64-bit alignment? https://golang.org/pkg/sync/atomic/#pkg-note-BUG
	var bytesUp, bytesDown int64
	defer func() {
		sshClient.closedPortForward(
			portForwardTypeTCP, atomic.LoadInt64(&bytesUp), atomic.LoadInt64(&bytesDown))
	}()

	lruEntry := sshClient.tcpPortForwardLRU.Add(fwdConn)
	defer lruEntry.Remove()

	// ActivityMonitoredConn monitors the TCP port forward I/O and updates
	// its LRU status. ActivityMonitoredConn also times out I/O on the port
	// forward if both reads and writes have been idle for the specified
	// duration.

	// Ensure nil interface if newClientSeedPortForward returns nil
	var updater common.ActivityUpdater
	seedUpdater := sshClient.newClientSeedPortForward(IP)
	if seedUpdater != nil {
		updater = seedUpdater
	}

	fwdConn, err = common.NewActivityMonitoredConn(
		fwdConn,
		sshClient.idleTCPPortForwardTimeout(),
		true,
		updater,
		lruEntry)
	if err != nil {
		log.WithTraceFields(LogFields{"error": err}).Error("NewActivityMonitoredConn failed")
		return
	}

	// Relay channel to forwarded connection.

	log.WithTraceFields(LogFields{"remoteAddr": remoteAddr}).Debug("relaying")

	// TODO: relay errors to fwdChannel.Stderr()?
	relayWaitGroup := new(sync.WaitGroup)
	relayWaitGroup.Add(1)
	go func() {
		defer relayWaitGroup.Done()
		// io.Copy allocates a 32K temporary buffer, and each port forward relay
		// uses two of these buffers; using common.CopyBuffer with a smaller buffer
		// reduces the overall memory footprint.
		bytes, err := common.CopyBuffer(
			fwdChannel, fwdConn, make([]byte, SSH_TCP_PORT_FORWARD_COPY_BUFFER_SIZE))
		atomic.AddInt64(&bytesDown, bytes)
		if err != nil && err != io.EOF {
			// Debug since errors such as "connection reset by peer" occur during normal operation
			log.WithTraceFields(LogFields{"error": err}).Debug("downstream TCP relay failed")
		}
		// Interrupt upstream io.Copy when downstream is shutting down.
		// TODO: this is done to quickly cleanup the port forward when
		// fwdConn has a read timeout, but is it clean -- upstream may still
		// be flowing?
		fwdChannel.Close()
	}()
	bytes, err := common.CopyBuffer(
		fwdConn, fwdChannel, make([]byte, SSH_TCP_PORT_FORWARD_COPY_BUFFER_SIZE))
	atomic.AddInt64(&bytesUp, bytes)
	if err != nil && err != io.EOF {
		log.WithTraceFields(LogFields{"error": err}).Debug("upstream TCP relay failed")
	}
	// Shutdown special case: fwdChannel will be closed and return EOF when
	// the SSH connection is closed, but we need to explicitly close fwdConn
	// to interrupt the downstream io.Copy, which may be blocked on a
	// fwdConn.Read().
	fwdConn.Close()

	relayWaitGroup.Wait()

	log.WithTraceFields(
		LogFields{
			"remoteAddr": remoteAddr,
			"bytesUp":    atomic.LoadInt64(&bytesUp),
			"bytesDown":  atomic.LoadInt64(&bytesDown)}).Debug("exiting")
}
