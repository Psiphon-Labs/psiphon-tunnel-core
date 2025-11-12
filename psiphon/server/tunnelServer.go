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
	"bytes"
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
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/accesscontrol"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/crypto/ssh"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/inproxy"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/monotime"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/obfuscator"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/osl"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/parameters"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/quic"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/refraction"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/stacktrace"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/tactics"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/transforms"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/tun"
	lrucache "github.com/cognusion/go-cache-lru"
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
	GEOIP_SESSION_CACHE_TTL               = 60 * time.Minute
	OSL_SESSION_CACHE_TTL                 = 5 * time.Minute
	MAX_AUTHORIZATIONS                    = 16
	PRE_HANDSHAKE_RANDOM_STREAM_MAX_COUNT = 1
	RANDOM_STREAM_MAX_BYTES               = 10485760
	ALERT_REQUEST_QUEUE_BUFFER_SIZE       = 16
	SSH_MAX_CLIENT_COUNT                  = 100000
	SSH_CLIENT_MAX_DSL_REQUEST_COUNT      = 32
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
// listeners that handle connections using various obfuscation protocols.
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

	support := server.sshServer.support

	// First bind all listeners; once all are successful,
	// start accepting connections on each.

	var listeners []*sshListener

	defer func() {
		// Ensure listeners are closed on early error returns.
		for _, listener := range listeners {
			listener.Close()
		}
	}()

	for tunnelProtocol, listenPort := range support.Config.TunnelProtocolPorts {

		localAddress := net.JoinHostPort(
			support.Config.ServerIPAddress, strconv.Itoa(listenPort))

		var listener net.Listener
		var BPFProgramName string
		var err error

		if protocol.TunnelProtocolUsesFrontedMeekNonHTTPS(tunnelProtocol) {

			// For FRONTED-MEEK-QUIC, no listener implemented; for
			// FRONTED-MEEK-HTTP, no listener is run. The edge-to-server hop
			// uses HTTPS and the client tunnel protocol is distinguished
			// using protocol.MeekCookieData.ClientTunnelProtocol.
			continue

		} else if protocol.TunnelProtocolUsesQUIC(tunnelProtocol) {

			usesInproxy := protocol.TunnelProtocolUsesInproxy(tunnelProtocol)

			// in-proxy QUIC tunnel protocols don't support gQUIC.
			enableGQUIC := support.Config.EnableGQUIC && !usesInproxy

			disablePathMTUDiscovery := false
			maxPacketSizeAdjustment := 0
			if usesInproxy {

				// In the in-proxy WebRTC media stream mode, QUIC packets sent
				// back to the client, via the proxy, are encapsulated in
				// SRTP packet payloads, and the maximum QUIC packet size
				// must be adjusted to fit. MTU discovery is disabled so the
				// maximum packet size will not grow.
				//
				// Limitation: the WebRTC data channel mode does not have the
				// same QUIC packet size constraint, since data channel
				// messages can be far larger (up to 65536 bytes). However,
				// the server, at this point, does not know whether
				// individual connections are using WebRTC media streams or
				// data channels on the first hop, and will not know until
				// API handshake information is delivered after the QUIC,
				// OSSH, and SSH handshakes are completed. Currently the max
				// packet size adjustment is set unconditionally. For data
				// channels, this will result in suboptimal packet sizes and
				// a corresponding different traffic shape on the 2nd hop.

				maxPacketSizeAdjustment = inproxy.GetQUICMaxPacketSizeAdjustment()
				disablePathMTUDiscovery = true
			}

			logTunnelProtocol := tunnelProtocol
			listener, err = quic.Listen(
				CommonLogger(log),
				func(peerAddress string, err error, logFields common.LogFields) {
					logIrregularTunnel(
						support, logTunnelProtocol, listenPort, peerAddress,
						errors.Trace(err), LogFields(logFields))
				},
				localAddress,
				disablePathMTUDiscovery,
				maxPacketSizeAdjustment,
				support.Config.ObfuscatedSSHKey,
				enableGQUIC)
			if err != nil {
				return errors.Trace(err)
			}

		} else if protocol.TunnelProtocolUsesRefractionNetworking(tunnelProtocol) {

			listener, err = refraction.Listen(localAddress)
			if err != nil {
				return errors.Trace(err)
			}

		} else if protocol.TunnelProtocolUsesFrontedMeek(tunnelProtocol) {

			listener, err = net.Listen("tcp", localAddress)
			if err != nil {
				return errors.Trace(err)
			}

		} else {

			// Only direct, unfronted protocol listeners use TCP BPF circumvention
			// programs.
			listener, BPFProgramName, err = newTCPListenerWithBPF(support, localAddress)
			if err != nil {
				return errors.Trace(err)
			}

			if protocol.TunnelProtocolUsesTLSOSSH(tunnelProtocol) {

				listener, err = ListenTLSTunnel(support, listener, tunnelProtocol, listenPort)
				if err != nil {
					return errors.Trace(err)
				}

			} else if protocol.TunnelProtocolUsesShadowsocks(tunnelProtocol) {

				logTunnelProtocol := tunnelProtocol
				listener, err = ListenShadowsocks(
					support,
					listener,
					support.Config.ShadowsocksKey,
					func(peerAddress string, err error, logFields common.LogFields) {
						logIrregularTunnel(
							support, logTunnelProtocol, listenPort, peerAddress,
							errors.Trace(err), LogFields(logFields))
					},
				)
				if err != nil {
					return errors.Trace(err)
				}
			}
		}

		tacticsListener := NewTacticsListener(
			support,
			listener,
			tunnelProtocol,
			func(IP string) GeoIPData { return support.GeoIPService.Lookup(IP) })

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

	if server.sshServer.inproxyBrokerSessions != nil {

		// When running in-proxy tunnels, start the InproxyBrokerSession
		// background worker, which includes the proxy quality reporter.
		// Start this before any tunnels can be established.
		err := server.sshServer.inproxyBrokerSessions.Start()
		if err != nil {
			return errors.Trace(err)
		}
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

	if server.sshServer.inproxyBrokerSessions != nil {
		server.sshServer.inproxyBrokerSessions.Stop()
	}

	log.WithTrace().Info("stopped")

	return err
}

// GetLoadStats returns load stats for the tunnel server. The stats are
// broken down by protocol ("SSH", "OSSH", etc.) and type. Types of stats
// include current connected client count, total number of current port
// forwards.
func (server *TunnelServer) GetLoadStats() (
	UpstreamStats, ProtocolStats, RegionStats) {

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

// ReloadTactics signals components that use server-side tactics for one-time
// initialization to reload and use potentially changed parameters.
func (server *TunnelServer) ReloadTactics() error {
	return errors.Trace(server.sshServer.reloadTactics())
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

// CheckLoadLimiting returns whether the server is in the load limiting state,
// which is when EstablishTunnels is false. CheckLoadLimiting is intended to
// be checked by non-tunnel components; no metrics are updated by this call.
func (server *TunnelServer) CheckLoadLimiting() bool {
	return server.sshServer.checkLoadLimiting()
}

// GetEstablishTunnelsMetrics returns whether tunnel establishment is
// currently allowed and the number of tunnels rejected since due to not
// establishing since the last GetEstablishTunnelsMetrics call.
func (server *TunnelServer) GetEstablishTunnelsMetrics() (bool, int64) {
	return server.sshServer.getEstablishTunnelsMetrics()
}

type sshServer struct {
	support                 *SupportServices
	establishTunnels        int32
	lastAuthLog             atomic.Int64
	authFailedCount         atomic.Int64
	establishLimitedCount   atomic.Int64
	concurrentSSHHandshakes semaphore.Semaphore
	shutdownBroadcast       <-chan struct{}
	sshHostKey              ssh.Signer
	obfuscatorSeedHistory   *obfuscator.SeedHistory
	inproxyBrokerSessions   *inproxy.ServerBrokerSessions

	clientsMutex         sync.Mutex
	stoppingClients      bool
	acceptedClientCounts map[string]map[string]int64
	clients              map[string]*sshClient

	geoIPSessionCache *cache.Cache

	oslSessionCacheMutex sync.Mutex
	oslSessionCache      *cache.Cache

	authorizationSessionIDsMutex sync.Mutex
	authorizationSessionIDs      map[string]string

	meekServersMutex sync.Mutex
	meekServers      []*MeekServer
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

	// The geoIPSessionCache replaces the legacy cache that used to be in
	// GeoIPServices and was used for the now-retired web API. That cache was
	// also used for, and now geoIPSessionCache provides:
	// - Determining first-tunnel-in-session (from a single server's point of
	//   view)
	// - GeoIP for duplicate authorizations logic.
	//
	// TODO: combine geoIPSessionCache with oslSessionCache; need to deal with
	// OSL flush on hot reload and reconcile differing TTLs.

	geoIPSessionCache := cache.New(GEOIP_SESSION_CACHE_TTL, 1*time.Minute)

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

	// inproxyBrokerSessions are the secure in-proxy broker/server sessions
	// used to relay information from the broker to the server, including the
	// original in-proxy client IP and the in-proxy proxy ID.
	//
	// Only brokers with public keys configured in the
	// InproxyAllBrokerSpecs tactic parameter are allowed to connect to
	// the server, and brokers verify the server's public key via the
	// InproxySessionPublicKey server entry field.
	//
	// Sessions are initialized and run for all psiphond instances running any
	// in-proxy tunnel protocol.
	//
	// inproxyBrokerSessions also run the server proxy quality reporter, which
	// makes requests to brokers configured in InproxyAllBrokerSpecs.

	var inproxyBrokerSessions *inproxy.ServerBrokerSessions

	runningInproxy := false
	for tunnelProtocol := range support.Config.TunnelProtocolPorts {
		if protocol.TunnelProtocolUsesInproxy(tunnelProtocol) {
			runningInproxy = true
			break
		}
	}

	if runningInproxy {

		inproxyPrivateKey, err := inproxy.SessionPrivateKeyFromString(
			support.Config.InproxyServerSessionPrivateKey)
		if err != nil {
			return nil, errors.Trace(err)
		}

		inproxyObfuscationSecret, err := inproxy.ObfuscationSecretFromString(
			support.Config.InproxyServerObfuscationRootSecret)
		if err != nil {
			return nil, errors.Trace(err)
		}

		makeRoundTripper := func(
			brokerPublicKey inproxy.SessionPublicKey) (
			inproxy.RoundTripper, common.APIParameters, error) {

			roundTripper, additionalParams, err := MakeInproxyProxyQualityBrokerRoundTripper(
				support, brokerPublicKey)
			if err != nil {
				return nil, nil, errors.Trace(err)
			}
			return roundTripper, additionalParams, nil
		}

		// The expected broker specd and public keys are set in reloadTactics
		// directly below, so none are set here.
		config := &inproxy.ServerBrokerSessionsConfig{
			Logger:                      CommonLogger(log),
			ServerPrivateKey:            inproxyPrivateKey,
			ServerRootObfuscationSecret: inproxyObfuscationSecret,
			BrokerRoundTripperMaker:     makeRoundTripper,
			ProxyMetricsValidator:       getInproxyBrokerAPIParameterValidator(support.Config),
			ProxyMetricsFormatter:       getInproxyBrokerAPIParameterLogFieldFormatter(),

			// Prefix for proxy metrics log fields in server_tunnel
			ProxyMetricsPrefix: "inproxy_proxy_",
		}

		inproxyBrokerSessions, err = inproxy.NewServerBrokerSessions(config)
		if err != nil {
			return nil, errors.Trace(err)
		}
	}

	// Limitation: rate limiting and resource limiting are handled by external
	// components, and sshServer enforces only a sanity check limit on the
	// number of entries in sshServer.clients; and no limit on the number of
	// entries in sshServer.geoIPSessionCache or sshServer.oslSessionCache.
	//
	// To avoid resource exhaustion, this implementation relies on:
	//
	// - Per-peer IP address and/or overall network connection rate limiting,
	//   provided by iptables as configured by Psiphon automation
	//   (https://github.com/Psiphon-Inc/psiphon-automation/blob/
	//   4d913d13339d7d54c053a01e5a928e343045cde8/Automation/psi_ops_install.py#L1451).
	//
	// - Host CPU/memory/network monitoring and signalling, installed Psiphon
	//   automation
	//   (https://github.com/Psiphon-Inc/psiphon-automation/blob/
	//    4d913d13339d7d54c053a01e5a928e343045cde8/Automation/psi_ops_install.py#L935).
	//   When resource usage meets certain thresholds, the monitoring signals
	//   this process with SIGTSTP or SIGCONT, and handlers call
	//   sshServer.setEstablishTunnels to stop or resume accepting new clients.

	sshServer := &sshServer{
		support:                 support,
		establishTunnels:        1,
		concurrentSSHHandshakes: concurrentSSHHandshakes,
		shutdownBroadcast:       shutdownBroadcast,
		sshHostKey:              signer,
		acceptedClientCounts:    make(map[string]map[string]int64),
		clients:                 make(map[string]*sshClient),
		geoIPSessionCache:       geoIPSessionCache,
		oslSessionCache:         oslSessionCache,
		authorizationSessionIDs: make(map[string]string),
		obfuscatorSeedHistory:   obfuscator.NewSeedHistory(nil),
		inproxyBrokerSessions:   inproxyBrokerSessions,
	}

	// Initialize components that use server-side tactics and which reload on
	// tactics change events.
	err = sshServer.reloadTactics()
	if err != nil {
		return nil, errors.Trace(err)
	}

	return sshServer, nil
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
		sshServer.establishLimitedCount.Add(1)
	}
	return establishTunnels
}

func (sshServer *sshServer) checkLoadLimiting() bool {

	// The server is in a general load limiting state when
	// sshServer.establishTunnels is false (0). This check is intended to be
	// used by non-tunnel components and no metrics are updated by this call.
	return atomic.LoadInt32(&sshServer.establishTunnels) == 0
}

func (sshServer *sshServer) getEstablishTunnelsMetrics() (bool, int64) {
	return atomic.LoadInt32(&sshServer.establishTunnels) == 1,
		sshServer.establishLimitedCount.Swap(0)
}

// additionalTransportData is additional data gathered at transport level,
// such as in MeekServer at the HTTP layer, and relayed to the
// sshServer/sshClient.
type additionalTransportData struct {
	overrideTunnelProtocol string
	steeringIP             string
}

// reportListenerError logs a listener error and sends it the
// TunnelServer.Run. Callers should wrap the input err in an immediate
// errors.Trace.
func reportListenerError(listenerError chan<- error, err error) {

	// Record "caller" just in case the caller fails to wrap err in an
	// errors.Trace.
	log.WithTraceFields(
		LogFields{
			"error":  err,
			"caller": stacktrace.GetParentFunctionName()}).Error("listener error")
	select {
	case listenerError <- err:
	default:
	}
}

// runListener is intended to run an a goroutine; it blocks
// running a particular listener. If an unrecoverable error
// occurs, it will send the error to the listenerError channel.
func (sshServer *sshServer) runListener(sshListener *sshListener, listenerError chan<- error) {

	handleClient := func(conn net.Conn, transportData *additionalTransportData) {

		// Note: establish tunnel limiter cannot simply stop TCP
		// listeners in all cases (e.g., meek) since SSH tunnels can
		// span multiple TCP connections.

		if !sshServer.checkEstablishTunnels() {
			if IsLogLevelDebug() {
				log.WithTrace().Debug("not establishing tunnels")
			}
			conn.Close()
			return
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
		go sshServer.handleClient(sshListener, conn, transportData)
	}

	// Note: when exiting due to a unrecoverable error, be sure
	// to try to send the error to listenerError so that the outer
	// TunnelServer.Run will properly shut down instead of remaining
	// running.

	if protocol.TunnelProtocolUsesMeekHTTP(sshListener.tunnelProtocol) ||
		protocol.TunnelProtocolUsesMeekHTTPS(sshListener.tunnelProtocol) {

		if sshServer.tunnelProtocolUsesTLSDemux(sshListener.tunnelProtocol) {

			sshServer.runMeekTLSOSSHDemuxListener(sshListener, listenerError, handleClient)

		} else {
			meekServer, err := NewMeekServer(
				sshServer.support,
				sshListener.Listener,
				sshListener.tunnelProtocol,
				sshListener.port,
				protocol.TunnelProtocolUsesMeekHTTPS(sshListener.tunnelProtocol),
				protocol.TunnelProtocolUsesFrontedMeek(sshListener.tunnelProtocol),
				protocol.TunnelProtocolUsesObfuscatedSessionTickets(sshListener.tunnelProtocol),
				true,
				handleClient,
				sshServer.shutdownBroadcast)

			if err == nil {
				sshServer.registerMeekServer(meekServer)
				err = meekServer.Run()
			}

			if err != nil {
				reportListenerError(listenerError, errors.Trace(err))
				return
			}
		}

	} else {

		runListener(sshListener.Listener, sshServer.shutdownBroadcast, listenerError, "", handleClient)
	}
}

// runMeekTLSOSSHDemuxListener blocks running a listener which demuxes meek and
// TLS-OSSH connections received on the same port.
func (sshServer *sshServer) runMeekTLSOSSHDemuxListener(
	sshListener *sshListener,
	listenerError chan<- error,
	handleClient func(conn net.Conn, transportData *additionalTransportData)) {

	meekClassifier := protocolClassifier{
		minBytesToMatch: 4,
		maxBytesToMatch: 4,
		match: func(b []byte) bool {

			// NOTE: HTTP transforms are only applied to plain HTTP
			// meek so they are not a concern here.

			return bytes.Contains(b, []byte("POST"))
		},
	}

	tlsClassifier := protocolClassifier{
		// NOTE: technically +1 not needed if detectors are evaluated
		// in order by index in classifier array, which they are.
		minBytesToMatch: meekClassifier.maxBytesToMatch + 1,
		maxBytesToMatch: meekClassifier.maxBytesToMatch + 1,
		match: func(b []byte) bool {
			return len(b) > 4 // if not classified as meek, then tls
		},
	}

	listener, err := ListenTLSTunnel(
		sshServer.support,
		sshListener.Listener,
		sshListener.tunnelProtocol,
		sshListener.port)
	if err != nil {
		reportListenerError(listenerError, errors.Trace(err))
		return
	}

	mux, listeners := newProtocolDemux(
		context.Background(),
		listener,
		[]protocolClassifier{meekClassifier, tlsClassifier},
		sshServer.support.Config.sshHandshakeTimeout)

	var wg sync.WaitGroup

	wg.Add(1)

	go func() {

		// handle shutdown gracefully

		defer wg.Done()

		<-sshServer.shutdownBroadcast
		err := mux.Close()
		if err != nil {
			log.WithTraceFields(LogFields{"error": err}).Error("close failed")
		}
	}()

	wg.Add(1)

	go func() {

		// start demultiplexing TLS-OSSH and meek HTTPS connections

		defer wg.Done()

		err := mux.run()
		if err != nil {
			reportListenerError(listenerError, errors.Trace(err))
			return
		}
	}()

	wg.Add(1)

	go func() {

		// start handling TLS-OSSH connections as they are demultiplexed

		defer wg.Done()

		// Override the listener tunnel protocol to report TLS-OSSH instead.
		runListener(
			listeners[1],
			sshServer.shutdownBroadcast,
			listenerError,
			protocol.TUNNEL_PROTOCOL_TLS_OBFUSCATED_SSH, handleClient)
	}()

	wg.Add(1)

	go func() {

		// start handling meek HTTPS connections as they are
		// demultiplexed

		defer wg.Done()

		meekServer, err := NewMeekServer(
			sshServer.support,
			listeners[0],
			sshListener.tunnelProtocol,
			sshListener.port,
			false,
			protocol.TunnelProtocolUsesFrontedMeek(sshListener.tunnelProtocol),
			protocol.TunnelProtocolUsesObfuscatedSessionTickets(sshListener.tunnelProtocol),
			true,
			handleClient,
			sshServer.shutdownBroadcast)

		if err == nil {
			sshServer.registerMeekServer(meekServer)
			err = meekServer.Run()
		}

		if err != nil {
			reportListenerError(listenerError, errors.Trace(err))
			return
		}
	}()

	wg.Wait()
}

func runListener(
	listener net.Listener,
	shutdownBroadcast <-chan struct{},
	listenerError chan<- error,
	overrideTunnelProtocol string,
	handleClient func(conn net.Conn, transportData *additionalTransportData)) {

	for {
		conn, err := listener.Accept()

		select {
		case <-shutdownBroadcast:
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
			} else if std_errors.Is(err, errRestrictedProvider) {
				log.WithTraceFields(LogFields{"error": err}).Error("accept rejected client")
				// Restricted provider, keep running
				continue
			}

			reportListenerError(listenerError, errors.Trace(err))
			return
		}

		var transportData *additionalTransportData
		if overrideTunnelProtocol != "" {
			transportData = &additionalTransportData{
				overrideTunnelProtocol: overrideTunnelProtocol,
			}
		}

		handleClient(conn, transportData)
	}
}

// registerMeekServer registers a MeekServer instance to receive tactics
// reload signals.
func (sshServer *sshServer) registerMeekServer(meekServer *MeekServer) {
	sshServer.meekServersMutex.Lock()
	defer sshServer.meekServersMutex.Unlock()

	sshServer.meekServers = append(sshServer.meekServers, meekServer)
}

// reloadMeekServerTactics signals each registered MeekServer instance that
// tactics have reloaded and may have changed.
func (sshServer *sshServer) reloadMeekServerTactics() error {
	sshServer.meekServersMutex.Lock()
	defer sshServer.meekServersMutex.Unlock()

	for _, meekServer := range sshServer.meekServers {
		err := meekServer.ReloadTactics()
		if err != nil {
			return errors.Trace(err)
		}
	}
	return nil
}

// An accepted client has completed a direct TCP or meek connection and has a
// net.Conn. Registration is for tracking the number of connections.
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
		//   setHandshakeState but sets the handshake parameters for new
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

	// SSH_MAX_CLIENT_COUNT is a simple sanity check and failsafe. Load
	// limiting tuned to each server's host resources is provided by external
	// components. See comment in newSSHServer for more details.
	if len(sshServer.clients) >= SSH_MAX_CLIENT_COUNT {
		log.WithTrace().Warning("SSH_MAX_CLIENT_COUNT exceeded")
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

type UpstreamStats map[string]interface{}
type ProtocolStats map[string]map[string]interface{}
type RegionStats map[string]map[string]map[string]interface{}

func (sshServer *sshServer) getLoadStats() (
	UpstreamStats, ProtocolStats, RegionStats) {

	sshServer.clientsMutex.Lock()
	defer sshServer.clientsMutex.Unlock()

	// Explicitly populate with zeros to ensure 0 counts in log messages.

	zeroClientStats := func() map[string]interface{} {
		stats := make(map[string]interface{})
		stats["accepted_clients"] = int64(0)
		stats["established_clients"] = int64(0)
		return stats
	}

	// Due to hot reload and changes to the underlying system configuration, the
	// set of resolver IPs may change between getLoadStats calls, so this
	// enumeration for zeroing is a best effort.
	resolverIPs := sshServer.support.DNSResolver.GetAll()

	logDNSServerMetrics := sshServer.support.Config.LogDNSServerLoadMetrics

	// Fields which are primarily concerned with upstream/egress performance.
	zeroUpstreamStats := func() map[string]interface{} {
		stats := make(map[string]interface{})
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
			if logDNSServerMetrics {
				for _, resolverIP := range resolverIPs {
					m[resolverIP.String()] = 0
				}
			}
			return m
		}

		stats["dns_count"] = zeroDNSStats()
		stats["dns_duration"] = zeroDNSStats()
		stats["dns_failed_count"] = zeroDNSStats()
		stats["dns_failed_duration"] = zeroDNSStats()
		return stats
	}

	zeroProtocolStats := func() map[string]map[string]interface{} {
		stats := make(map[string]map[string]interface{})
		stats["ALL"] = zeroClientStats()
		for tunnelProtocol := range sshServer.support.Config.TunnelProtocolPorts {
			stats[tunnelProtocol] = zeroClientStats()

			if sshServer.tunnelProtocolUsesTLSDemux(tunnelProtocol) {
				stats[protocol.TUNNEL_PROTOCOL_TLS_OBFUSCATED_SSH] = zeroClientStats()
			}
		}
		return stats
	}

	addInt64 := func(stats map[string]interface{}, name string, value int64) {
		stats[name] = stats[name].(int64) + value
	}

	upstreamStats := zeroUpstreamStats()

	// [<protocol or ALL>][<stat name>] -> count
	protocolStats := zeroProtocolStats()

	// [<region][<protocol or ALL>][<stat name>] -> count
	regionStats := make(RegionStats)

	// Note: as currently tracked/counted, each established client is also an accepted client

	// Accepted client counts use peer GeoIP data, which in the case of
	// in-proxy tunnel protocols is the proxy, not the client. The original
	// client IP is only obtained after the tunnel handshake has completed.

	for tunnelProtocol, regionAcceptedClientCounts := range sshServer.acceptedClientCounts {
		for region, acceptedClientCount := range regionAcceptedClientCounts {

			if acceptedClientCount > 0 {
				if regionStats[region] == nil {
					regionStats[region] = zeroProtocolStats()
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

		// Limitation: registerEstablishedClient is called before the
		// handshake API completes; as a result, in the case of in-proxy
		// tunnel protocol, clientGeoIPData may not yet be initialized and
		// will count as None.

		tunnelProtocol := client.tunnelProtocol
		region := client.clientGeoIPData.Country

		if regionStats[region] == nil {
			regionStats[region] = zeroProtocolStats()
		}

		for _, stats := range []map[string]interface{}{
			protocolStats["ALL"],
			protocolStats[tunnelProtocol],
			regionStats[region]["ALL"],
			regionStats[region][tunnelProtocol]} {

			addInt64(stats, "established_clients", 1)
		}

		// Note:
		// - can't sum trafficState.peakConcurrentPortForwardCount to get a global peak
		// - client.udpTrafficState.concurrentDialingPortForwardCount isn't meaningful

		addInt64(upstreamStats, "dialing_tcp_port_forwards",
			client.tcpTrafficState.concurrentDialingPortForwardCount)

		addInt64(upstreamStats, "tcp_port_forwards",
			client.tcpTrafficState.concurrentPortForwardCount)

		addInt64(upstreamStats, "total_tcp_port_forwards",
			client.tcpTrafficState.totalPortForwardCount)

		addInt64(upstreamStats, "udp_port_forwards",
			client.udpTrafficState.concurrentPortForwardCount)

		addInt64(upstreamStats, "total_udp_port_forwards",
			client.udpTrafficState.totalPortForwardCount)

		addInt64(upstreamStats, "tcp_port_forward_dialed_count",
			client.qualityMetrics.TCPPortForwardDialedCount)

		addInt64(upstreamStats, "tcp_port_forward_dialed_duration",
			int64(client.qualityMetrics.TCPPortForwardDialedDuration/time.Millisecond))

		addInt64(upstreamStats, "tcp_port_forward_failed_count",
			client.qualityMetrics.TCPPortForwardFailedCount)

		addInt64(upstreamStats, "tcp_port_forward_failed_duration",
			int64(client.qualityMetrics.TCPPortForwardFailedDuration/time.Millisecond))

		addInt64(upstreamStats, "tcp_port_forward_rejected_dialing_limit_count",
			client.qualityMetrics.TCPPortForwardRejectedDialingLimitCount)

		addInt64(upstreamStats, "tcp_port_forward_rejected_disallowed_count",
			client.qualityMetrics.TCPPortForwardRejectedDisallowedCount)

		addInt64(upstreamStats, "udp_port_forward_rejected_disallowed_count",
			client.qualityMetrics.UDPPortForwardRejectedDisallowedCount)

		addInt64(upstreamStats, "tcp_ipv4_port_forward_dialed_count",
			client.qualityMetrics.TCPIPv4PortForwardDialedCount)

		addInt64(upstreamStats, "tcp_ipv4_port_forward_dialed_duration",
			int64(client.qualityMetrics.TCPIPv4PortForwardDialedDuration/time.Millisecond))

		addInt64(upstreamStats, "tcp_ipv4_port_forward_failed_count",
			client.qualityMetrics.TCPIPv4PortForwardFailedCount)

		addInt64(upstreamStats, "tcp_ipv4_port_forward_failed_duration",
			int64(client.qualityMetrics.TCPIPv4PortForwardFailedDuration/time.Millisecond))

		addInt64(upstreamStats, "tcp_ipv6_port_forward_dialed_count",
			client.qualityMetrics.TCPIPv6PortForwardDialedCount)

		addInt64(upstreamStats, "tcp_ipv6_port_forward_dialed_duration",
			int64(client.qualityMetrics.TCPIPv6PortForwardDialedDuration/time.Millisecond))

		addInt64(upstreamStats, "tcp_ipv6_port_forward_failed_count",
			client.qualityMetrics.TCPIPv6PortForwardFailedCount)

		addInt64(upstreamStats, "tcp_ipv6_port_forward_failed_duration",
			int64(client.qualityMetrics.TCPIPv6PortForwardFailedDuration/time.Millisecond))

		// DNS metrics limitations:
		// - port forwards (sshClient.handleTCPChannel) don't know or log the resolver IP.
		// - udpgw and packet tunnel transparent DNS use a heuristic to classify success/failure,
		//   and there may be some delay before these code paths report DNS metrics.

		// Every client.qualityMetrics DNS map has an "ALL" entry.

		totalDNSCount := int64(0)
		totalDNSFailedCount := int64(0)

		for key, value := range client.qualityMetrics.DNSCount {
			all := key == "ALL"
			if all || logDNSServerMetrics {
				upstreamStats["dns_count"].(map[string]int64)[key] += value
			}
			if all {
				totalDNSCount += value
			}
		}

		for key, value := range client.qualityMetrics.DNSDuration {
			if key == "ALL" || logDNSServerMetrics {
				upstreamStats["dns_duration"].(map[string]int64)[key] += int64(value / time.Millisecond)
			}
		}

		for key, value := range client.qualityMetrics.DNSFailedCount {
			all := key == "ALL"
			if all || logDNSServerMetrics {
				upstreamStats["dns_failed_count"].(map[string]int64)[key] += value
			}
			if all {
				totalDNSFailedCount += value
			}
		}

		for key, value := range client.qualityMetrics.DNSFailedDuration {
			if key == "ALL" || logDNSServerMetrics {
				upstreamStats["dns_failed_duration"].(map[string]int64)[key] += int64(value / time.Millisecond)
			}
		}

		// Update client peak failure rate metrics, to be recorded in
		// server_tunnel.
		//
		// Limitations:
		//
		// - This is a simple data sampling that doesn't require additional
		//   timers or tracking logic. Since the rates are calculated on
		//   getLoadStats events and using accumulated counts, these peaks
		//   only represent the highest failure rate within a
		//   Config.LoadMonitorPeriodSeconds non-sliding window. There is no
		//   sample recorded for short tunnels with no overlapping
		//   getLoadStats event.
		//
		// - There is no minimum sample window, as a getLoadStats event may
		//   occur immediately after a client first connects. This may be
		//   compensated for by adjusting
		//   Config.PeakUpstreamFailureRateMinimumSampleSize, so as to only
		//   consider failure rates with a larger number of samples.
		//
		// - Non-UDP "failures" are not currently tracked.

		minimumSampleSize := int64(sshServer.support.Config.peakUpstreamFailureRateMinimumSampleSize)

		sampleSize := client.qualityMetrics.TCPPortForwardDialedCount +
			client.qualityMetrics.TCPPortForwardFailedCount

		if sampleSize >= minimumSampleSize {

			TCPPortForwardFailureRate := float64(client.qualityMetrics.TCPPortForwardFailedCount) /
				float64(sampleSize)

			if client.peakMetrics.TCPPortForwardFailureRate == nil {

				client.peakMetrics.TCPPortForwardFailureRate = new(float64)
				*client.peakMetrics.TCPPortForwardFailureRate = TCPPortForwardFailureRate
				client.peakMetrics.TCPPortForwardFailureRateSampleSize = new(int64)
				*client.peakMetrics.TCPPortForwardFailureRateSampleSize = sampleSize

			} else if *client.peakMetrics.TCPPortForwardFailureRate < TCPPortForwardFailureRate {

				*client.peakMetrics.TCPPortForwardFailureRate = TCPPortForwardFailureRate
				*client.peakMetrics.TCPPortForwardFailureRateSampleSize = sampleSize
			}
		}

		sampleSize = totalDNSCount + totalDNSFailedCount

		if sampleSize >= minimumSampleSize {

			DNSFailureRate := float64(totalDNSFailedCount) / float64(sampleSize)

			if client.peakMetrics.DNSFailureRate == nil {

				client.peakMetrics.DNSFailureRate = new(float64)
				*client.peakMetrics.DNSFailureRate = DNSFailureRate
				client.peakMetrics.DNSFailureRateSampleSize = new(int64)
				*client.peakMetrics.DNSFailureRateSampleSize = sampleSize

			} else if *client.peakMetrics.DNSFailureRate < DNSFailureRate {

				*client.peakMetrics.DNSFailureRate = DNSFailureRate
				*client.peakMetrics.DNSFailureRateSampleSize = sampleSize
			}
		}

		// Reset quality metrics counters

		client.qualityMetrics.reset()

		client.Unlock()
	}

	for _, client := range sshServer.clients {

		client.Lock()

		// Update client peak proximate (same region) concurrently connected
		// (other clients) client metrics, to be recorded in server_tunnel.
		// This operation requires a second loop over sshServer.clients since
		// established_clients is calculated in the first loop.
		//
		// Limitations:
		//
		// - This is an approximation, not a true peak, as it only samples
		//   data every Config.LoadMonitorPeriodSeconds period. There is no
		//   sample recorded for short tunnels with no overlapping
		//   getLoadStats event.
		//
		// - The "-1" calculation counts all but the current client as other
		//   clients; it can be the case that the same client has a dangling
		//   accepted connection that has yet to time-out server side. Due to
		//   NAT, we can't determine if the client is the same based on
		//   network address. For established clients,
		//   registerEstablishedClient ensures that any previous connection
		//   is first terminated, although this is only for the same
		//   session_id. Concurrent proximate clients may be considered an
		//   exact number of other _network connections_, even from the same
		//   client.
		//
		//   Futhermore, since client.Locks aren't held between the previous
		//   loop and this one, it's also possible that the client's
		//   clientGeoIPData was None in the previous loop and is now not
		//   None. In this case, the regionStats may not be populated at all
		//   for the client's current region; if so, the client is skipped.
		//   This scenario can also result in a proximate undercount by one,
		//   when the regionStats _is_ populated: this client was counted
		//   under None, not the current client.peerGeoIPData.Country, so
		//   the -1 subtracts some _other_ client from the populated regionStats.
		//
		// - For in-proxy protocols, the accepted proximate metric uses the
		//   peer GeoIP, which represents the proxy, not the client.

		stats := regionStats[client.peerGeoIPData.Country]["ALL"]

		n := stats["accepted_clients"].(int64) - 1
		if n >= 0 {
			if client.peakMetrics.concurrentProximateAcceptedClients == nil {

				client.peakMetrics.concurrentProximateAcceptedClients = new(int64)
				*client.peakMetrics.concurrentProximateAcceptedClients = n

			} else if *client.peakMetrics.concurrentProximateAcceptedClients < n {

				*client.peakMetrics.concurrentProximateAcceptedClients = n
			}
		}

		// Handle the in-proxy None and None/not-None cases (and any other
		// potential scenario where regionStats[client.clientGeoIPData.Country]
		// may not be populated).
		if client.clientGeoIPData.Country == GEOIP_UNKNOWN_VALUE ||
			regionStats[client.clientGeoIPData.Country] == nil {
			client.Unlock()
			continue
		}

		stats = regionStats[client.clientGeoIPData.Country]["ALL"]

		n = stats["established_clients"].(int64) - 1
		if n >= 0 {
			if client.peakMetrics.concurrentProximateEstablishedClients == nil {

				client.peakMetrics.concurrentProximateEstablishedClients = new(int64)
				*client.peakMetrics.concurrentProximateEstablishedClients = n

			} else if *client.peakMetrics.concurrentProximateEstablishedClients < n {

				*client.peakMetrics.concurrentProximateEstablishedClients = n
			}
		}

		client.Unlock()
	}

	return upstreamStats, protocolStats, regionStats
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

// reloadTactics signals/invokes components that use server-side tactics for
// one-time initialization to reload and use potentially changed parameters.
func (sshServer *sshServer) reloadTactics() error {

	// The following in-proxy components use server-side tactics with a
	// one-time initialization:
	//
	// - For servers running in-proxy tunnel protocols,
	//   sshServer.inproxyBrokerSessions are the broker/server sessions and
	//   the set of expected broker public keys is set from tactics.
	// - For servers running a broker within MeekServer, broker operational
	//   configuration is set from tactics.
	//
	// For these components, one-time initialization is more efficient than
	// constantly fetching tactics. Instead, these components reinitialize
	// when tactics change.

	// sshServer.inproxyBrokerSessions is not nil when the server is running
	// in-proxy tunnel protocols.
	if sshServer.inproxyBrokerSessions != nil {

		// Get InproxyAllBrokerSpecs from tactics.
		//
		// Limitation: assumes no GeoIP targeting for InproxyAllBrokerSpecs.

		p, err := sshServer.support.ServerTacticsParametersCache.Get(NewGeoIPData())
		if err != nil {
			return errors.Trace(err)
		}

		if !p.IsNil() {

			// Fall back to InproxyBrokerSpecs if InproxyAllBrokerSpecs is not
			// configured.
			brokerSpecs := p.InproxyBrokerSpecs(
				parameters.InproxyAllBrokerSpecs, parameters.InproxyBrokerSpecs)

			var brokerPublicKeys []inproxy.SessionPublicKey
			var brokerRootObfuscationSecrets []inproxy.ObfuscationSecret

			for _, brokerSpec := range brokerSpecs {

				brokerPublicKey, err := inproxy.SessionPublicKeyFromString(
					brokerSpec.BrokerPublicKey)
				if err != nil {
					return errors.Trace(err)
				}

				brokerPublicKeys = append(
					brokerPublicKeys, brokerPublicKey)

				brokerRootObfuscationSecret, err := inproxy.ObfuscationSecretFromString(
					brokerSpec.BrokerRootObfuscationSecret)
				if err != nil {
					return errors.Trace(err)
				}

				brokerRootObfuscationSecrets = append(
					brokerRootObfuscationSecrets, brokerRootObfuscationSecret)
			}

			// SetKnownBrokerPublicKeys will terminate any existing sessions
			// for broker public keys no longer in the known/expected list;
			// but will retain any existing sessions for broker public keys
			// that remain in the list.
			err = sshServer.inproxyBrokerSessions.SetKnownBrokers(
				brokerPublicKeys, brokerRootObfuscationSecrets)
			if err != nil {
				return errors.Trace(err)
			}

			sshServer.inproxyBrokerSessions.SetProxyQualityRequestParameters(
				p.Int(parameters.InproxyProxyQualityReporterMaxRequestEntries),
				p.Duration(parameters.InproxyProxyQualityReporterRequestDelay),
				p.Duration(parameters.InproxyProxyQualityReporterRequestTimeout),
				p.Int(parameters.InproxyProxyQualityReporterRequestRetries))
		}
	}

	err := sshServer.reloadMeekServerTactics()
	if err != nil {
		return errors.Trace(err)
	}

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

func (sshServer *sshServer) stopClients() {

	sshServer.clientsMutex.Lock()
	sshServer.stoppingClients = true
	clients := sshServer.clients
	sshServer.clients = make(map[string]*sshClient)
	sshServer.clientsMutex.Unlock()

	// Stop clients concurrently; if any one client stop hangs, due to a bug,
	// this ensures that we still stop and record a server_tunnel for all
	// non-hanging clients.

	waitGroup := new(sync.WaitGroup)
	for _, client := range clients {
		waitGroup.Add(1)
		go func(c *sshClient) {
			defer waitGroup.Done()
			c.stop()
			c.awaitStopped()
		}(client)
	}
	waitGroup.Wait()
}

func (sshServer *sshServer) handleClient(
	sshListener *sshListener,
	conn net.Conn,
	transportData *additionalTransportData) {

	// overrideTunnelProtocol sets the tunnel protocol to a value other than
	// the listener tunnel protocol. This is used in fronted meek
	// configuration, where a single HTTPS listener also handles fronted HTTP
	// and QUIC traffic; and in the protocol demux case.

	tunnelProtocol := sshListener.tunnelProtocol
	if transportData != nil && transportData.overrideTunnelProtocol != "" {
		tunnelProtocol = transportData.overrideTunnelProtocol
	}

	// Calling conn.RemoteAddr at this point, before any Read calls,
	// satisfies the constraint documented in tapdance.Listen.

	peerAddr := conn.RemoteAddr()

	// Check if there were irregularities during the network connection
	// establishment. When present, log and then behave as Obfuscated SSH does
	// when the client fails to provide a valid seed message.
	//
	// One concrete irregular case is failure to send a PROXY protocol header for
	// TAPDANCE-OSSH.

	if indicator, ok := conn.(common.IrregularIndicator); ok {

		tunnelErr := indicator.IrregularTunnelError()

		if tunnelErr != nil {

			logIrregularTunnel(
				sshServer.support,
				sshListener.tunnelProtocol,
				sshListener.port,
				common.IPAddressFromAddr(peerAddr),
				errors.Trace(tunnelErr),
				nil)

			var afterFunc *time.Timer
			if sshServer.support.Config.sshHandshakeTimeout > 0 {
				afterFunc = time.AfterFunc(sshServer.support.Config.sshHandshakeTimeout, func() {
					conn.Close()
				})
			}
			_, _ = io.Copy(ioutil.Discard, conn)
			conn.Close()
			afterFunc.Stop()

			return
		}
	}

	// Get any packet manipulation values from GetAppliedSpecName as soon as
	// possible due to the expiring TTL.
	//
	// In the case of in-proxy tunnel protocols, the remote address will be
	// the proxy, not the client, and GeoIP targeted packet manipulation will
	// apply to the 2nd hop.

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
		underlying, ok := conn.(common.UnderlyingTCPAddrSource)
		if ok {
			localAddr, remoteAddr, ok = underlying.GetUnderlyingTCPAddrs()
		} else {
			localAddr, ok = conn.LocalAddr().(*net.TCPAddr)
			if ok {
				remoteAddr, ok = conn.RemoteAddr().(*net.TCPAddr)
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

	// For in-proxy tunnel protocols, accepted client GeoIP reflects the proxy
	// address, not the client.

	peerGeoIPData := sshServer.support.GeoIPService.Lookup(
		common.IPAddressFromAddr(peerAddr))

	sshServer.registerAcceptedClient(tunnelProtocol, peerGeoIPData.Country)
	defer sshServer.unregisterAcceptedClient(tunnelProtocol, peerGeoIPData.Country)

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
			conn.Close()
			// This is a debug log as the only possible error is context timeout.
			log.WithTraceFields(LogFields{"error": err}).Debug(
				"acquire SSH handshake semaphore failed")
			return
		}

		onSSHHandshakeFinished = func() {
			sshServer.concurrentSSHHandshakes.Release(1)
		}
	}

	sshClient, err := newSshClient(
		sshServer,
		sshListener,
		tunnelProtocol,
		transportData,
		serverPacketManipulation,
		replayedServerPacketManipulation,
		peerAddr,
		peerGeoIPData)
	if err != nil {
		conn.Close()
		log.WithTraceFields(LogFields{"error": err}).Warning(
			"newSshClient failed")
		return
	}

	// sshClient.run _must_ call onSSHHandshakeFinished to release the semaphore:
	// in any error case; or, as soon as the SSH handshake phase has successfully
	// completed.

	sshClient.run(conn, onSSHHandshakeFinished)
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

// tunnelProtocolUsesTLSDemux returns true if the server demultiplexes the given
// protocol and TLS-OSSH over the same port.
func (sshServer *sshServer) tunnelProtocolUsesTLSDemux(tunnelProtocol string) bool {

	// Only use meek/TLS-OSSH demux if unfronted meek HTTPS with non-legacy
	// passthrough, and not in-proxy.
	if protocol.TunnelProtocolUsesMeekHTTPS(tunnelProtocol) &&
		!protocol.TunnelProtocolUsesFrontedMeek(tunnelProtocol) &&
		!protocol.TunnelProtocolUsesInproxy(tunnelProtocol) {
		_, passthroughEnabled := sshServer.support.Config.TunnelProtocolPassthroughAddresses[tunnelProtocol]
		return passthroughEnabled && !sshServer.support.Config.LegacyPassthrough
	}
	return false
}

// setGeoIPSessionCache adds the sessionID/geoIPData pair to the session
// cache. This value will not expire; the caller must call
// markGeoIPSessionCacheToExpire to initiate expiry. Calling
// setGeoIPSessionCache for an existing sessionID will replace the previous
// value and reset any expiry.
func (sshServer *sshServer) setGeoIPSessionCache(sessionID string, geoIPData GeoIPData) {
	sshServer.geoIPSessionCache.Set(sessionID, geoIPData, cache.NoExpiration)
}

// markGeoIPSessionCacheToExpire initiates expiry for an existing session
// cache entry, if the session ID is found in the cache. Concurrency note:
// setGeoIPSessionCache and markGeoIPSessionCacheToExpire should not be
// called concurrently for a single session ID.
func (sshServer *sshServer) markGeoIPSessionCacheToExpire(sessionID string) {
	geoIPData, found := sshServer.geoIPSessionCache.Get(sessionID)
	// Note: potential race condition between Get and Set. In practice,
	// the tunnel server won't clobber a SetSessionCache value by calling
	// MarkSessionCacheToExpire concurrently.
	if found {
		sshServer.geoIPSessionCache.Set(sessionID, geoIPData, cache.DefaultExpiration)
	}
}

// getGeoIPSessionCache returns the cached GeoIPData for the specified session
// ID; a blank GeoIPData is returned if the session ID is not found in the
// cache.
func (sshServer *sshServer) getGeoIPSessionCache(sessionID string) GeoIPData {
	geoIPData, found := sshServer.geoIPSessionCache.Get(sessionID)
	if !found {
		return NewGeoIPData()
	}
	return geoIPData.(GeoIPData)
}

// inGeoIPSessionCache returns whether the session ID is present in the
// session cache.
func (sshServer *sshServer) inGeoIPSessionCache(sessionID string) bool {
	_, found := sshServer.geoIPSessionCache.Get(sessionID)
	return found
}

type sshClient struct {
	sync.Mutex
	sshServer                            *sshServer
	sshListener                          *sshListener
	tunnelProtocol                       string
	isInproxyTunnelProtocol              bool
	additionalTransportData              *additionalTransportData
	sshConn                              ssh.Conn
	throttledConn                        *common.ThrottledConn
	serverPacketManipulation             string
	replayedServerPacketManipulation     bool
	peerAddr                             net.Addr
	peerGeoIPData                        GeoIPData
	clientIP                             string
	clientGeoIPData                      GeoIPData
	sessionID                            string
	isFirstTunnelInSession               bool
	supportsServerRequests               bool
	sponsorID                            string
	handshakeState                       handshakeState
	udpgwChannelHandler                  *udpgwPortForwardMultiplexer
	totalUdpgwChannelCount               int
	packetTunnelChannel                  ssh.Channel
	totalPacketTunnelChannelCount        int
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
	peakMetrics                          peakMetrics
	destinationBytesMetrics              map[string]*protocolDestinationBytesMetrics
	inproxyProxyQualityTracker           *inproxyProxyQualityTracker
	dnsResolver                          *net.Resolver
	dnsCache                             *lrucache.Cache
	requestCheckServerEntryTags          int
	checkedServerEntryTags               int
	invalidServerEntryTags               int
	sshProtocolBytesTracker              *sshProtocolBytesTracker
	dslRequestCount                      int
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
	count                 int64
	upstreamBytes         int64
	receivedUpstreamBytes int64
	downstreamBytes       int64
	sentDownstreamBytes   int64
}

type peakMetrics struct {
	concurrentProximateAcceptedClients    *int64
	concurrentProximateEstablishedClients *int64
	TCPPortForwardFailureRate             *float64
	TCPPortForwardFailureRateSampleSize   *int64
	DNSFailureRate                        *float64
	DNSFailureRateSampleSize              *int64
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

type handshakeStateInfo struct {
	activeAuthorizationIDs   []string
	authorizedAccessTypes    []string
	upstreamBytesPerSecond   int64
	downstreamBytesPerSecond int64
	steeringIP               string
}

type handshakeState struct {
	completed               bool
	apiProtocol             string
	apiParams               common.APIParameters
	activeAuthorizationIDs  []string
	authorizedAccessTypes   []string
	authorizationsRevoked   bool
	domainBytesChecksum     []byte
	establishedTunnelsCount int
	splitTunnelLookup       *splitTunnelLookup
	deviceRegion            string
	newTacticsTag           string
	inproxyClientIP         string
	inproxyClientGeoIPData  GeoIPData
	inproxyProxyID          inproxy.ID
	inproxyMatchedPersonal  bool
	inproxyRelayLogFields   common.LogFields
}

type protocolDestinationBytesMetrics struct {
	tcpMetrics destinationBytesMetrics
	udpMetrics destinationBytesMetrics
}

type destinationBytesMetrics struct {
	bytesUp   int64
	bytesDown int64
}

func (d *destinationBytesMetrics) UpdateProgress(
	downstreamBytes, upstreamBytes, _ int64) {

	// Concurrency: UpdateProgress may be called without holding the sshClient
	// lock; all accesses to bytesUp/bytesDown must use atomic operations.

	atomic.AddInt64(&d.bytesUp, upstreamBytes)
	atomic.AddInt64(&d.bytesDown, downstreamBytes)
}

func (d *destinationBytesMetrics) getBytesUp() int64 {
	return atomic.LoadInt64(&d.bytesUp)
}

func (d *destinationBytesMetrics) getBytesDown() int64 {
	return atomic.LoadInt64(&d.bytesDown)
}

type splitTunnelLookup struct {
	regions       []string
	regionsLookup map[string]bool
}

func newSplitTunnelLookup(
	ownRegion string,
	otherRegions []string) (*splitTunnelLookup, error) {

	length := len(otherRegions)
	if ownRegion != "" {
		length += 1
	}

	// This length check is a sanity check and prevents clients shipping
	// excessively long lists which could impact performance.
	if length > 250 {
		return nil, errors.Tracef("too many regions: %d", length)
	}

	// Create map lookups for lists where the number of values to compare
	// against exceeds a threshold where benchmarks show maps are faster than
	// looping through a slice. Otherwise use a slice for lookups. In both
	// cases, the input slice is no longer referenced.

	if length >= stringLookupThreshold {
		regionsLookup := make(map[string]bool)
		if ownRegion != "" {
			regionsLookup[ownRegion] = true
		}
		for _, region := range otherRegions {
			regionsLookup[region] = true
		}
		return &splitTunnelLookup{
			regionsLookup: regionsLookup,
		}, nil
	} else {
		regions := []string{}
		if ownRegion != "" && !common.Contains(otherRegions, ownRegion) {
			regions = append(regions, ownRegion)
		}
		// TODO: check for other duplicate regions?
		regions = append(regions, otherRegions...)
		return &splitTunnelLookup{
			regions: regions,
		}, nil
	}
}

func (lookup *splitTunnelLookup) lookup(region string) bool {
	if lookup.regionsLookup != nil {
		return lookup.regionsLookup[region]
	} else {
		return common.Contains(lookup.regions, region)
	}
}

type inproxyProxyQualityTracker struct {
	bytesUp         atomic.Int64
	bytesDown       atomic.Int64
	reportTriggered int32

	sshClient       *sshClient
	targetBytesUp   int64
	targetBytesDown int64
	targetDuration  time.Duration
	startTime       time.Time
}

func newInproxyProxyQualityTracker(
	sshClient *sshClient,
	targetBytesUp int64,
	targetBytesDown int64,
	targetDuration time.Duration) *inproxyProxyQualityTracker {

	return &inproxyProxyQualityTracker{
		sshClient:       sshClient,
		targetBytesUp:   targetBytesUp,
		targetBytesDown: targetBytesDown,
		targetDuration:  targetDuration,

		startTime: time.Now(),
	}
}

func (t *inproxyProxyQualityTracker) UpdateProgress(
	downstreamBytes, upstreamBytes, _ int64) {

	// Concurrency: UpdateProgress may be called concurrently; all accesses to
	// mutated fields use atomic operations.

	if atomic.LoadInt32(&t.reportTriggered) != 0 {
		// TODO: performance -- remove the updater once the target met,
		// instead of making this residual, no-op update call per tunnel I/O?
		return
	}

	bytesUp := t.bytesUp.Add(upstreamBytes)
	bytesDown := t.bytesDown.Add(downstreamBytes)

	if (t.targetBytesUp == 0 || bytesUp >= t.targetBytesUp) &&
		(t.targetBytesDown == 0 || bytesDown >= t.targetBytesDown) &&
		(t.targetDuration == 0 || time.Since(t.startTime) >= t.targetDuration) {

		// The tunnel connection is wrapped with the quality tracker just
		// before the SSH handshake. It's possible that the quality targets
		// are met before the Psiphon handshake completes, due to sufficient
		// bytes/duration during the intermediate handshakes, or during the
		// liveness test. Since the proxy ID isn't known until then Psiphon
		// handshake completes, delay any report until at least after the
		// Psiphon handshake is completed.

		handshaked, _ := t.sshClient.getHandshaked()
		if handshaked {

			// Limitation: reporting proxy quality is currently a
			// once-per-tunnel operation. Since in-proxy brokers apply a
			// quality data TTL, InproxyProxyQualityTTL, it's possible that a
			// proxy that continues to relay only one single tunnel for
			// longer than that TTL will eventually lose its priority
			// classification even as the tunnel remains connected and relaying
			// data.
			//
			// As a future enhancement, consider reseting the tracker and
			// triggering a new quality report after the
			// InproxyProxyQualityTTL period.

			if !atomic.CompareAndSwapInt32(&t.reportTriggered, 0, 1) {
				return
			}

			t.sshClient.reportProxyQuality()
		}
	}
}

type sshProtocolBytesTracker struct {
	totalBytesRead    atomic.Int64
	totalBytesWritten atomic.Int64
}

func newSSHProtocolBytesTracker(sshClient *sshClient) *sshProtocolBytesTracker {
	return &sshProtocolBytesTracker{}
}

func (t *sshProtocolBytesTracker) UpdateProgress(
	bytesRead, bytesWritten, _ int64) {

	// Concurrency: UpdateProgress may be called concurrently; all accesses to
	// mutated fields use atomic operations.

	t.totalBytesRead.Add(bytesRead)
	t.totalBytesWritten.Add(bytesWritten)
}

func newSshClient(
	sshServer *sshServer,
	sshListener *sshListener,
	tunnelProtocol string,
	transportData *additionalTransportData,
	serverPacketManipulation string,
	replayedServerPacketManipulation bool,
	peerAddr net.Addr,
	peerGeoIPData GeoIPData) (*sshClient, error) {

	runCtx, stopRunning := context.WithCancel(context.Background())

	// isFirstTunnelInSession is defaulted to true so that the pre-handshake
	// traffic rules won't apply UnthrottleFirstTunnelOnly and negate any
	// unthrottled bytes during the initial protocol negotiation.

	client := &sshClient{
		sshServer:                        sshServer,
		sshListener:                      sshListener,
		tunnelProtocol:                   tunnelProtocol,
		isInproxyTunnelProtocol:          protocol.TunnelProtocolUsesInproxy(tunnelProtocol),
		additionalTransportData:          transportData,
		serverPacketManipulation:         serverPacketManipulation,
		replayedServerPacketManipulation: replayedServerPacketManipulation,
		peerAddr:                         peerAddr,
		peerGeoIPData:                    peerGeoIPData,
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

	if peerAddr == nil {
		return nil, errors.TraceNew("missing peerAddr")
	}
	peerIP, _, err := net.SplitHostPort(peerAddr.String())
	if err != nil {
		return nil, errors.Trace(err)
	}
	if net.ParseIP(peerIP) == nil {
		return nil, errors.TraceNew("invalid peerIP")
	}

	// In the case of in-proxy tunnel protocols, clientIP and clientGeoIPData
	// are not set until the original client IP is relayed from the broker
	// during the handshake. In other cases, clientGeoIPData is the
	// peerGeoIPData (this includes fronted meek).

	if !client.isInproxyTunnelProtocol {
		client.clientIP = peerIP
		client.clientGeoIPData = peerGeoIPData
	}

	return client, nil
}

// getClientP gets sshClient.clientIP. See getClientGeoIPData comment.
func (sshClient *sshClient) getClientIP() string {
	sshClient.Lock()
	defer sshClient.Unlock()
	return sshClient.clientIP
}

// getClientGeoIPData gets sshClient.clientGeoIPData. Use this helper when
// accessing this field without already holding a lock on the sshClient
// mutex. Unlike older code and unlike with client.peerGeoIPData,
// sshClient.clientGeoIPData is not static and may get set during the
// handshake, and it is not safe to access it without a lock.
func (sshClient *sshClient) getClientGeoIPData() GeoIPData {
	sshClient.Lock()
	defer sshClient.Unlock()
	return sshClient.clientGeoIPData
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

	// getTunnelActivityUpdaters wires up updaters that act on tunnel duration
	// and bytes transferred, including the in-proxy proxy quality tracker.
	// The quality tracker will include non-user traffic bytes, so it's not
	// equivalent to server_tunnel bytes.
	//
	// Limitation: wrapping at this point omits some obfuscation layer bytes,
	// including MEEK and QUIC.

	activityConn, err := common.NewActivityMonitoredConn(
		conn,
		SSH_CONNECTION_READ_DEADLINE,
		false,
		nil,
		sshClient.getTunnelActivityUpdaters()...)
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
	// Limitations:
	//
	// - Burst parameters are fixed for the duration of the tunnel and do not
	//   change after a tactics hot reload.
	//
	// - In the case of in-proxy tunnel protocols, the original client IP is
	//   not yet known, and so burst monitoring GeoIP targeting uses the peer
	//   IP, which is the proxy, not the client.

	var burstConn *common.BurstMonitoredConn

	p, err := sshClient.sshServer.support.ServerTacticsParametersCache.Get(sshClient.peerGeoIPData)
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

	// Further wrap the connection in a rate limiting ThrottledConn. The
	// underlying dialConn is always a stream, even when the network conn
	// uses UDP.

	throttledConn := common.NewThrottledConn(conn, true, sshClient.rateLimits())
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
	//
	// In the case of in-proxy tunnel protocols, the peer address will be the
	// proxy, not the client, and GeoIP targeted replay will apply to the 2nd
	// hop.

	isReplayCandidate, replayWaitDuration, replayTargetDuration :=
		sshClient.sshServer.support.ReplayCache.GetReplayTargetDuration(sshClient.peerGeoIPData)

	if isReplayCandidate {

		getFragmentorSeed := func() *prng.Seed {
			fragmentor, ok := baseConn.(common.FragmentorAccessor)
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
						sshClient.peerGeoIPData,
						sshClient.serverPacketManipulation,
						getFragmentorSeed(),
						bytesUp,
						bytesDown)
				}
			})

		defer func() {

			// When panicking, propagate the panic instead of trying to
			// acquire the sshClient lock. Intentional panics may arise from
			// the protobuf code path in logTunnel.
			if r := recover(); r != nil {
				panic(r)
			}

			setReplayAfterFunc.Stop()
			completed, _ := sshClient.getHandshaked()
			if !completed {

				// Count a replay failure case when a tunnel used replay parameters
				// (excluding OSSH fragmentation, which doesn't use the ReplayCache) and
				// failed to complete the API handshake.

				replayedFragmentation := false
				if sshClient.tunnelProtocol != protocol.TUNNEL_PROTOCOL_OBFUSCATED_SSH {
					fragmentor, ok := baseConn.(common.FragmentorAccessor)
					if ok {
						_, replayedFragmentation = fragmentor.GetReplay()
					}
				}
				usedReplay := replayedFragmentation || sshClient.replayedServerPacketManipulation

				if usedReplay {
					sshClient.sshServer.support.ReplayCache.FailedReplayParameters(
						sshClient.tunnelProtocol,
						sshClient.peerGeoIPData,
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

			// In the case of in-proxy tunnel protocols, the peer address will
			// be the proxy, not the client, and GeoIP targeted server-side
			// OSSH tactics, including prefixes, will apply to the 2nd hop.
			//
			// It is recommended to set ServerOSSHPrefixSpecs, etc., in default
			// tactics.

			var p parameters.ParametersAccessor
			p, err = sshClient.sshServer.support.ServerTacticsParametersCache.Get(sshClient.peerGeoIPData)

			// Log error, but continue. A default prefix spec will be used by the server.
			if err != nil {
				log.WithTraceFields(LogFields{"error": errors.Trace(err)}).Warning(
					"ServerTacticsParametersCache.Get failed")
			}

			var osshPrefixEnableFragmentor bool = false
			var serverOsshPrefixSpecs transforms.Specs = nil
			var minDelay, maxDelay time.Duration
			if !p.IsNil() {
				osshPrefixEnableFragmentor = p.Bool(parameters.OSSHPrefixEnableFragmentor)
				serverOsshPrefixSpecs = p.ProtocolTransformSpecs(parameters.ServerOSSHPrefixSpecs)
				minDelay = p.Duration(parameters.OSSHPrefixSplitMinDelay)
				maxDelay = p.Duration(parameters.OSSHPrefixSplitMaxDelay)
				// Allow garbage collection.
				p.Close()
			}

			// Note: NewServerObfuscatedSSHConn blocks on network I/O
			// TODO: ensure this won't block shutdown
			result.obfuscatedSSHConn, err = obfuscator.NewServerObfuscatedSSHConn(
				conn,
				sshClient.sshServer.support.Config.ObfuscatedSSHKey,
				sshClient.sshServer.obfuscatorSeedHistory,
				serverOsshPrefixSpecs,
				func(peerIP string, err error, logFields common.LogFields) {
					logIrregularTunnel(
						sshClient.sshServer.support,
						sshClient.sshListener.tunnelProtocol,
						sshClient.sshListener.port,
						peerIP,
						errors.Trace(err),
						LogFields(logFields))
				})

			if err != nil {
				err = errors.Trace(err)
			} else {
				conn = result.obfuscatedSSHConn
			}

			// Set the OSSH prefix split config.
			if err == nil && result.obfuscatedSSHConn.IsOSSHPrefixStream() {
				err = result.obfuscatedSSHConn.SetOSSHPrefixSplitConfig(minDelay, maxDelay)
				// Log error, but continue.
				if err != nil {
					log.WithTraceFields(LogFields{"error": errors.Trace(err)}).Warning(
						"SetOSSHPrefixSplitConfig failed")
				}
			}

			// Seed the fragmentor, when present, with seed derived from initial
			// obfuscator message. See tactics.Listener.Accept. This must preceed
			// ssh.NewServerConn to ensure fragmentor is seeded before downstream bytes
			// are written.
			if err == nil && protocol.TunnelProtocolIsObfuscatedSSH(sshClient.tunnelProtocol) {
				fragmentor, ok := baseConn.(common.FragmentorAccessor)
				if ok {
					var fragmentorPRNG *prng.PRNG
					fragmentorPRNG, err = result.obfuscatedSSHConn.GetDerivedPRNG("server-side-fragmentor")
					if err != nil {
						err = errors.Trace(err)
					} else {
						fragmentor.SetReplay(fragmentorPRNG)
					}

					// Stops the fragmentor if disabled for prefixed OSSH streams.
					if !osshPrefixEnableFragmentor && result.obfuscatedSSHConn.IsOSSHPrefixStream() {
						fragmentor.StopFragmenting()
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

	// sshClient.stop closes the underlying transport conn, ensuring all
	// network trafic is complete before calling logTunnel.

	sshClient.stop()

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
		// be called via sshClient.stop.
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
	fragmentor, ok := baseConn.(common.FragmentorAccessor)
	if ok {
		_, replayedFragmentation = fragmentor.GetReplay()
	}
	replayMetrics["server_replay_fragmentation"] = replayedFragmentation
	replayMetrics["server_replay_packet_manipulation"] = sshClient.replayedServerPacketManipulation
	additionalMetrics = append(additionalMetrics, replayMetrics)

	// Log the server_tunnel event. This log is only guaranteed to be recorded
	// after the SSH handshake completes successfully. If the tunnel fails or
	// is aborted by the client after that point, there will be a server_tunnel
	// log -- with handshake_completed false, if the failure is during the
	// liveness test or Psiphon API handshake, and handshake_completed true
	// otherwise.
	//
	// Some scenarios where there is no server_tunnel log, despite a client
	// initiating a dial, can include:
	// - Failure during the TCP handshake.
	// - Connecting to a fronting CDN, but not establishing a full meek session.
	// - Failure during QUIC, TLS, or Obfuscated OSSH handshakes and all other
	//   obfuscation layers which come before the SSH handshake.
	// - The server being in the load limiting state, SetEstablishTunnels(false)
	//
	// In the case of the outermost application-level network protocol,
	// including SSH, we do not necessarly want to log any server_tunnel
	// event until the client has passed anti-probing checks; otherwise, the
	// peer may not be a legitimate client.

	// Limitation: there's only one log per tunnel with bytes transferred
	// metrics, so the byte count can't be attributed to a certain day for
	// tunnels that remain connected for well over 24h. In practise, most
	// tunnels are short-lived, especially on mobile devices.

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

	// Set the GeoIP session cache to expire; up to this point, the entry for
	// this session ID has no expiry; retaining entries after the tunnel
	// disconnects supports first-tunnel-in-session and duplicate
	// authorization logic.
	sshClient.sshServer.markGeoIPSessionCacheToExpire(sshClient.sessionID)

	// unregisterEstablishedClient removes the client from sshServer.clients.
	// This call must come after logTunnel to ensure all logTunnel calls
	// complete before a sshServer.stopClients returns, in the case of a
	// server shutdown.

	sshClient.sshServer.unregisterEstablishedClient(sshClient)
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
	// with this session ID. This will be true up to GEOIP_SESSION_CACHE_TTL.
	isFirstTunnelInSession := !sshClient.sshServer.inGeoIPSessionCache(sessionID)

	supportsServerRequests := common.Contains(
		sshPasswordPayload.ClientCapabilities, protocol.CLIENT_CAPABILITY_SERVER_REQUESTS)

	// This optional, early sponsor ID will be logged with server_tunnel if
	// the tunnel doesn't reach handshakeState.completed.
	sponsorID := sshPasswordPayload.SponsorID
	if sponsorID != "" && !isSponsorID(sshClient.sshServer.support.Config, sponsorID) {
		return nil, errors.Tracef("invalid sponsor ID")
	}

	sshClient.Lock()

	// After this point, these values are read-only as they are read
	// without obtaining sshClient.Lock.
	sshClient.sessionID = sessionID
	sshClient.isFirstTunnelInSession = isFirstTunnelInSession
	sshClient.supportsServerRequests = supportsServerRequests
	sshClient.sponsorID = sponsorID

	sshClient.Unlock()

	// Initially, in the case of in-proxy tunnel protocols, the GeoIP session
	// cache entry will be the proxy's GeoIPData. This is updated to be the
	// client's GeoIPData in setHandshakeState.
	sshClient.sshServer.setGeoIPSessionCache(sessionID, sshClient.peerGeoIPData)

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

		sshClient.sshServer.authFailedCount.Add(1)

		lastAuthLog := monotime.Time(sshClient.sshServer.lastAuthLog.Load())
		if monotime.Since(lastAuthLog) > SSH_AUTH_LOG_PERIOD {
			now := int64(monotime.Now())
			if sshClient.sshServer.lastAuthLog.CompareAndSwap(int64(lastAuthLog), now) {
				count := sshClient.sshServer.authFailedCount.Swap(0)
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
	_ = sshClient.sshConn.Close()
	_ = sshClient.sshConn.Wait()
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

	// Close any remaining port forward upstream connections in order to
	// interrupt blocked reads.
	sshClient.Lock()
	udpgwChannelHandler := sshClient.udpgwChannelHandler
	sshClient.Unlock()
	if udpgwChannelHandler != nil {
		udpgwChannelHandler.portForwardLRU.CloseAll()
	}
	sshClient.tcpPortForwardLRU.CloseAll()

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

			responsePayload, err = sshAPIRequestHandler(
				sshClient.sshServer.support,
				sshClient,
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
	//    dispatching the request to handleTCPChannel(), which will run in its own
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
	// 3. handleTCPChannel() performs the port forward dial and relaying.
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
	// unthrottled liveness tests, set EstablishmentRead/WriteBytesPerSecond as
	// required. The random stream maximum count and response size cap mitigate
	// clients abusing the facility to waste server resources.
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
		metrics.upstreamBytes += int64(request.UpstreamBytes)
		metrics.receivedUpstreamBytes += int64(received)
		metrics.downstreamBytes += int64(request.DownstreamBytes)
		metrics.sentDownstreamBytes += int64(sent)
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
		isTCP bool, upstreamHostname string, upstreamIPAddress net.IP) []tun.FlowActivityUpdater {

		trafficType := portForwardTypeTCP
		if !isTCP {
			trafficType = portForwardTypeUDP
		}

		activityUpdaters := sshClient.getPortForwardActivityUpdaters(
			trafficType, upstreamIPAddress)

		flowUpdaters := make([]tun.FlowActivityUpdater, len(activityUpdaters))
		for i, activityUpdater := range activityUpdaters {
			flowUpdaters[i] = activityUpdater
		}

		return flowUpdaters
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
	isUdpgwChannel := sshClient.sshServer.support.Config.UDPInterceptUdpgwServerAddress != "" &&
		sshClient.sshServer.support.Config.UDPInterceptUdpgwServerAddress ==
			net.JoinHostPort(directTcpipExtraData.HostToConnect, strconv.Itoa(int(directTcpipExtraData.PortToConnect)))

	if isUdpgwChannel {

		// Dispatch immediately. handleUDPChannel runs the udpgw protocol in its
		// own worker goroutine.

		waitGroup.Add(1)
		go func(channel ssh.NewChannel) {
			defer waitGroup.Done()
			sshClient.handleUdpgwChannel(channel)
		}(newChannel)

	} else {

		// Dispatch via TCP port forward manager. When the queue is full, the channel
		// is immediately rejected.
		//
		// Split tunnel logic is enabled for this TCP port forward when the client
		// has enabled split tunnel mode and the channel type allows it.

		doSplitTunnel := sshClient.handshakeState.splitTunnelLookup != nil && allowSplitTunnel

		tcpPortForward := &newTCPPortForward{
			enqueueTime:   time.Now(),
			hostToConnect: directTcpipExtraData.HostToConnect,
			portToConnect: int(directTcpipExtraData.PortToConnect),
			doSplitTunnel: doSplitTunnel,
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
	sshClient.totalPacketTunnelChannelCount += 1
	sshClient.Unlock()
}

// setUdpgwChannelHandler sets the single udpgw channel handler for this
// sshClient. Each sshClient may have only one concurrent udpgw
// channel/handler. Each udpgw channel multiplexes many UDP port forwards via
// the udpgw protocol. Any existing udpgw channel/handler is closed.
func (sshClient *sshClient) setUdpgwChannelHandler(udpgwChannelHandler *udpgwPortForwardMultiplexer) bool {
	sshClient.Lock()
	if sshClient.udpgwChannelHandler != nil {
		previousHandler := sshClient.udpgwChannelHandler
		sshClient.udpgwChannelHandler = nil

		// stop must be run without holding the sshClient mutex lock, as the
		// udpgw goroutines may attempt to lock the same mutex. For example,
		// udpgwPortForwardMultiplexer.run calls sshClient.establishedPortForward
		// which calls sshClient.allocatePortForward.
		sshClient.Unlock()
		previousHandler.stop()
		sshClient.Lock()

		// In case some other channel has set the sshClient.udpgwChannelHandler
		// in the meantime, fail. The caller should discard this channel/handler.
		if sshClient.udpgwChannelHandler != nil {
			sshClient.Unlock()
			return false
		}
	}
	sshClient.udpgwChannelHandler = udpgwChannelHandler
	sshClient.totalUdpgwChannelCount += 1
	sshClient.Unlock()
	return true
}

var serverTunnelStatParams = append(
	[]requestParamSpec{
		{"last_connected", isLastConnected, requestParamOptional},
		{"establishment_duration", isIntString, requestParamOptional}},
	baseAndDialParams...)

func (sshClient *sshClient) logTunnel(additionalMetrics []LogFields) {

	sshClient.Lock()

	// For in-proxy tunnel protocols, two sets of GeoIP fields are logged, one
	// for the client and one for the proxy. The client GeoIP fields will
	// be "None" if handshake did not complete.

	logFields := getRequestLogFields(
		"server_tunnel",
		"",
		sshClient.sessionID,
		sshClient.clientGeoIPData,
		sshClient.handshakeState.authorizedAccessTypes,
		sshClient.handshakeState.apiParams,
		serverTunnelStatParams)

	logFields["tunnel_id"] = base64.RawURLEncoding.EncodeToString(prng.Bytes(protocol.PSIPHON_API_TUNNEL_ID_LENGTH))

	if sshClient.isInproxyTunnelProtocol {
		sshClient.peerGeoIPData.SetLogFieldsWithPrefix("", "inproxy_proxy", logFields)
		logFields.Add(
			LogFields(sshClient.handshakeState.inproxyRelayLogFields))
	}

	// new_tactics_tag indicates that the handshake returned new tactics.
	if sshClient.handshakeState.newTacticsTag != "" {
		logFields["new_tactics_tag"] = sshClient.handshakeState.newTacticsTag
	}

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

	logFields["handshake_completed"] = sshClient.handshakeState.completed

	// Use the handshake sponsor ID unless the handshake did not complete; in
	// that case, use the early sponsor ID, if one was provided.
	//
	// TODO: check that the handshake sponsor ID matches the early sponsor ID?
	if !sshClient.handshakeState.completed && sshClient.sponsorID != "" {
		logFields["sponsor_id"] = sshClient.sponsorID
	}

	logFields["is_first_tunnel_in_session"] = sshClient.isFirstTunnelInSession

	if sshClient.preHandshakeRandomStreamMetrics.count > 0 {
		logFields["pre_handshake_random_stream_count"] = sshClient.preHandshakeRandomStreamMetrics.count
		logFields["pre_handshake_random_stream_upstream_bytes"] = sshClient.preHandshakeRandomStreamMetrics.upstreamBytes
		logFields["pre_handshake_random_stream_received_upstream_bytes"] = sshClient.preHandshakeRandomStreamMetrics.receivedUpstreamBytes
		logFields["pre_handshake_random_stream_downstream_bytes"] = sshClient.preHandshakeRandomStreamMetrics.downstreamBytes
		logFields["pre_handshake_random_stream_sent_downstream_bytes"] = sshClient.preHandshakeRandomStreamMetrics.sentDownstreamBytes
	}

	if sshClient.handshakeState.completed {
		// When !handshake_completed, all of these values can be assumed to be zero.
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
		logFields["total_udpgw_channel_count"] = sshClient.totalUdpgwChannelCount
		logFields["total_packet_tunnel_channel_count"] = sshClient.totalPacketTunnelChannelCount
	}

	if sshClient.postHandshakeRandomStreamMetrics.count > 0 {
		logFields["random_stream_count"] = sshClient.postHandshakeRandomStreamMetrics.count
		logFields["random_stream_upstream_bytes"] = sshClient.postHandshakeRandomStreamMetrics.upstreamBytes
		logFields["random_stream_received_upstream_bytes"] = sshClient.postHandshakeRandomStreamMetrics.receivedUpstreamBytes
		logFields["random_stream_downstream_bytes"] = sshClient.postHandshakeRandomStreamMetrics.downstreamBytes
		logFields["random_stream_sent_downstream_bytes"] = sshClient.postHandshakeRandomStreamMetrics.sentDownstreamBytes
	}

	if sshClient.destinationBytesMetrics != nil {

		// Only log destination bytes for ASNs that remain enabled in tactics.
		//
		// Any counts accumulated before DestinationBytesMetricsASN[s] changes
		// are lost. At this time we can't change destination byte counting
		// dynamically, after a tactics hot reload, as there may be
		// destination bytes port forwards that were in place before the
		// change, which will continue to count.

		destinationBytesMetricsASNs := []string{}
		destinationBytesMetricsASN := ""

		// Target this using the client, not peer, GeoIP. In the case of
		// in-proxy tunnel protocols, the client GeoIP fields will be None
		// if the handshake does not complete. In that case, no bytes will
		// have transferred.

		p, err := sshClient.sshServer.support.ServerTacticsParametersCache.Get(sshClient.clientGeoIPData)
		if err == nil && !p.IsNil() {
			destinationBytesMetricsASNs = p.Strings(parameters.DestinationBytesMetricsASNs)
			destinationBytesMetricsASN = p.String(parameters.DestinationBytesMetricsASN)
		}
		p.Close()

		if destinationBytesMetricsASN != "" {

			// Log any parameters.DestinationBytesMetricsASN data in the
			// legacy log field format.

			destinationBytesMetrics, ok :=
				sshClient.destinationBytesMetrics[destinationBytesMetricsASN]

			if ok {
				bytesUpTCP := destinationBytesMetrics.tcpMetrics.getBytesUp()
				bytesDownTCP := destinationBytesMetrics.tcpMetrics.getBytesDown()
				bytesUpUDP := destinationBytesMetrics.udpMetrics.getBytesUp()
				bytesDownUDP := destinationBytesMetrics.udpMetrics.getBytesDown()

				logFields["dest_bytes_asn"] = destinationBytesMetricsASN
				logFields["dest_bytes"] = bytesUpTCP + bytesDownTCP + bytesUpUDP + bytesDownUDP
				logFields["dest_bytes_up_tcp"] = bytesUpTCP
				logFields["dest_bytes_down_tcp"] = bytesDownTCP
				logFields["dest_bytes_up_udp"] = bytesUpUDP
				logFields["dest_bytes_down_udp"] = bytesDownUDP
			}
		}

		if len(destinationBytesMetricsASNs) > 0 {

			destBytes := make(map[string]int64)
			destBytesUpTCP := make(map[string]int64)
			destBytesDownTCP := make(map[string]int64)
			destBytesUpUDP := make(map[string]int64)
			destBytesDownUDP := make(map[string]int64)

			for _, ASN := range destinationBytesMetricsASNs {

				destinationBytesMetrics, ok :=
					sshClient.destinationBytesMetrics[ASN]
				if !ok {
					continue
				}

				bytesUpTCP := destinationBytesMetrics.tcpMetrics.getBytesUp()
				bytesDownTCP := destinationBytesMetrics.tcpMetrics.getBytesDown()
				bytesUpUDP := destinationBytesMetrics.udpMetrics.getBytesUp()
				bytesDownUDP := destinationBytesMetrics.udpMetrics.getBytesDown()

				destBytes[ASN] = bytesUpTCP + bytesDownTCP + bytesUpUDP + bytesDownUDP
				destBytesUpTCP[ASN] = bytesUpTCP
				destBytesDownTCP[ASN] = bytesDownTCP
				destBytesUpUDP[ASN] = bytesUpUDP
				destBytesDownUDP[ASN] = bytesDownUDP
			}

			logFields["asn_dest_bytes"] = destBytes
			logFields["asn_dest_bytes_up_tcp"] = destBytesUpTCP
			logFields["asn_dest_bytes_down_tcp"] = destBytesDownTCP
			logFields["asn_dest_bytes_up_udp"] = destBytesUpUDP
			logFields["asn_dest_bytes_down_udp"] = destBytesDownUDP
		}
	}

	// Only log fields for peakMetrics when there is data recorded, otherwise
	// omit the field.
	if sshClient.peakMetrics.concurrentProximateAcceptedClients != nil {
		logFields["peak_concurrent_proximate_accepted_clients"] = *sshClient.peakMetrics.concurrentProximateAcceptedClients
	}
	if sshClient.peakMetrics.concurrentProximateEstablishedClients != nil {
		logFields["peak_concurrent_proximate_established_clients"] = *sshClient.peakMetrics.concurrentProximateEstablishedClients
	}
	if sshClient.peakMetrics.TCPPortForwardFailureRate != nil && sshClient.peakMetrics.TCPPortForwardFailureRateSampleSize != nil {
		logFields["peak_tcp_port_forward_failure_rate"] = *sshClient.peakMetrics.TCPPortForwardFailureRate
		logFields["peak_tcp_port_forward_failure_rate_sample_size"] = *sshClient.peakMetrics.TCPPortForwardFailureRateSampleSize
	}
	if sshClient.peakMetrics.DNSFailureRate != nil && sshClient.peakMetrics.DNSFailureRateSampleSize != nil {
		logFields["peak_dns_failure_rate"] = *sshClient.peakMetrics.DNSFailureRate
		logFields["peak_dns_failure_rate_sample_size"] = *sshClient.peakMetrics.DNSFailureRateSampleSize
	}

	// Pre-calculate a total-tunneled-bytes field. This total is used
	// extensively in analytics and is more performant when pre-calculated.
	bytes := sshClient.tcpTrafficState.bytesUp +
		sshClient.tcpTrafficState.bytesDown +
		sshClient.udpTrafficState.bytesUp +
		sshClient.udpTrafficState.bytesDown
	logFields["bytes"] = bytes

	// Pre-calculate ssh protocol bytes and overhead.
	sshProtocolBytes := sshClient.sshProtocolBytesTracker.totalBytesWritten.Load() +
		sshClient.sshProtocolBytesTracker.totalBytesRead.Load()
	logFields["ssh_protocol_bytes"] = sshProtocolBytes
	logFields["ssh_protocol_bytes_overhead"] = sshProtocolBytes - bytes

	if sshClient.additionalTransportData != nil &&
		sshClient.additionalTransportData.steeringIP != "" {
		logFields["relayed_steering_ip"] = sshClient.additionalTransportData.steeringIP
	}

	if sshClient.requestCheckServerEntryTags > 0 {
		logFields["request_check_server_entry_tags"] = sshClient.requestCheckServerEntryTags
		logFields["checked_server_entry_tags"] = sshClient.checkedServerEntryTags
		logFields["invalid_server_entry_tags"] = sshClient.invalidServerEntryTags
	}

	// Merge in additional metrics from the optional metrics source
	for _, metrics := range additionalMetrics {
		for name, value := range metrics {
			// Don't overwrite any basic fields
			if logFields[name] == nil {
				logFields[name] = value
			}
		}
	}

	// Retain lock when invoking LogRawFieldsWithTimestamp to block any
	// concurrent writes to variables referenced by logFields.
	log.LogRawFieldsWithTimestamp(logFields)

	sshClient.Unlock()
}

var blocklistHitsStatParams = []requestParamSpec{
	{"propagation_channel_id", isHexDigits, 0},
	{"sponsor_id", isHexDigits, 0},
	{"client_version", isIntString, requestParamLogStringAsInt},
	{"client_platform", isClientPlatform, 0},
	{"client_features", isAnyString, requestParamOptional | requestParamArray},
	{"client_build_rev", isHexDigits, requestParamOptional},
	{"device_region", isAnyString, requestParamOptional},
	{"device_location", isGeoHashString, requestParamOptional},
	{"egress_region", isRegionCode, requestParamOptional},
	{"last_connected", isLastConnected, requestParamOptional},
}

func (sshClient *sshClient) logBlocklistHits(IP net.IP, domain string, tags []BlocklistTag) {

	sshClient.Lock()

	// Log this using the client, not peer, GeoIP. In the case of in-proxy
	// tunnel protocols, the client GeoIP fields will be None if the
	// handshake does not complete. In that case, no port forwarding will
	// occur and there will not be any blocklist hits.

	logFields := getRequestLogFields(
		"server_blocklist_hit",
		"",
		sshClient.sessionID,
		sshClient.clientGeoIPData,
		sshClient.handshakeState.authorizedAccessTypes,
		sshClient.handshakeState.apiParams,
		blocklistHitsStatParams)

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
			Reason:     reason,
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
	clientGeoIPData := sshClient.clientGeoIPData
	deviceRegion := sshClient.handshakeState.deviceRegion
	sshClient.Unlock()

	return sshClient.sshServer.support.PsinetDatabase.GetAlertActionURLs(
		alertReason,
		sponsorID,
		clientGeoIPData.Country,
		clientGeoIPData.ASN,
		deviceRegion)
}

func (sshClient *sshClient) rejectNewChannel(newChannel ssh.NewChannel, logMessage string) {

	// We always return the reject reason "Prohibited":
	// - Traffic rules and connection limits may prohibit the connection.
	// - External firewall rules may prohibit the connection, and this is not currently
	//   distinguishable from other failure modes.
	// - We limit the failure information revealed to the client.
	reason := ssh.Prohibited

	// This log is Debug level, as logMessage can contain user traffic
	// destination address information such as in the "LookupIP failed"
	// and "DialTimeout failed" cases in handleTCPChannel.
	if IsLogLevelDebug() {
		log.WithTraceFields(
			LogFields{
				"sessionID":    sshClient.sessionID,
				"channelType":  newChannel.ChannelType(),
				"logMessage":   logMessage,
				"rejectReason": reason.String(),
			}).Debug("reject new channel")
	}

	// Note: logMessage is internal, for logging only; just the reject reason is sent to the client.
	_ = newChannel.Reject(reason, reason.String())
}

// setHandshakeState sets the handshake state -- that it completed and
// what parameters were passed -- in sshClient. This state is used for allowing
// port forwards and for future traffic rule selection. setHandshakeState
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
//
// All slices in the returnd handshakeStateInfo are read-only, as readers may
// reference slice contents outside of locks.
func (sshClient *sshClient) setHandshakeState(
	state handshakeState,
	authorizations []string) (*handshakeStateInfo, error) {

	sshClient.Lock()
	completed := sshClient.handshakeState.completed
	if !completed {
		sshClient.handshakeState = state

		if sshClient.isInproxyTunnelProtocol {

			// Set the client IP and GeoIP data to the value obtained using
			// the original client IP, from the broker, in the handshake.
			// Also update the GeoIP session hash to use the client GeoIP data.

			sshClient.clientIP = sshClient.handshakeState.inproxyClientIP

			sshClient.clientGeoIPData =
				sshClient.handshakeState.inproxyClientGeoIPData

			sshClient.sshServer.setGeoIPSessionCache(
				sshClient.sessionID, sshClient.clientGeoIPData)
		}
	}
	sshClient.Unlock()

	// Client must only perform one handshake
	if completed {
		return nil, errors.TraceNew("handshake already completed")
	}

	if sshClient.isInproxyTunnelProtocol {

		p, err := sshClient.sshServer.support.ServerTacticsParametersCache.Get(
			sshClient.clientGeoIPData)
		if err != nil {
			return nil, errors.Trace(err)
		}

		// Skip check if no tactics are configured.
		//
		// Disconnect immediately if the tactics for the client restricts usage
		// of the provider ID with inproxy protocols. The probability may be
		// used to influence usage of a given provider with inproxy protocols;
		// but when only that provider works for a given client, and the
		// probability is less than 1.0, the client can retry until it gets a
		// successful coin flip.
		//
		// Clients will also skip inproxy protocol candidates with restricted
		// provider IDs.
		// The client-side probability,
		// RestrictInproxyProviderIDsClientProbability, is applied
		// independently of the server-side coin flip here.
		//
		// At this stage, GeoIP tactics filters are active, but handshake API
		// parameters are not.
		//
		// See the comment in server.LoadConfig regarding provider ID
		// limitations.
		if !p.IsNil() &&
			common.ContainsAny(
				p.KeyStrings(parameters.RestrictInproxyProviderRegions,
					sshClient.sshServer.support.Config.GetProviderID()),
				[]string{"", sshClient.sshServer.support.Config.GetRegion()}) {

			if p.WeightedCoinFlip(
				parameters.RestrictInproxyProviderIDsServerProbability) {
				return nil, errRestrictedProvider
			}
		}
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

		if sshClient.sshServer.support.Config.AccessControlVerificationKeyRing == nil {
			if i == 0 {
				log.WithTrace().Warning("authorization not configured")
			}
			continue
		}

		verifiedAuthorization, err := accesscontrol.VerifyAuthorization(
			sshClient.sshServer.support.Config.AccessControlVerificationKeyRing,
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

			// Log this using client, not peer, GeoIP data. In the case of
			// in-proxy tunnel protocols, the client GeoIP fields will be None
			// if a handshake does not complete. However, presense of a
			// (duplicate) authorization implies that the handshake completed.

			sshClient.getClientGeoIPData().SetClientLogFields(logFields)
			duplicateClientGeoIPData := sshClient.sshServer.getGeoIPSessionCache(sessionID)
			if duplicateClientGeoIPData != sshClient.getClientGeoIPData() {
				duplicateClientGeoIPData.SetClientLogFieldsWithPrefix("duplicate_authorization_", logFields)
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

	// Set destination bytes metrics.
	//
	// Limitation: this is a one-time operation and doesn't get reset when
	// tactics are hot-reloaded. This allows us to simply retain any
	// destination byte counts accumulated and eventually log in
	// server_tunnel, without having to deal with a destination change
	// mid-tunnel. As typical tunnels are short, and destination changes can
	// be applied gradually, handling mid-tunnel changes is not a priority.
	sshClient.setDestinationBytesMetrics()

	info := &handshakeStateInfo{
		activeAuthorizationIDs:   authorizationIDs,
		authorizedAccessTypes:    authorizedAccessTypes,
		upstreamBytesPerSecond:   upstreamBytesPerSecond,
		downstreamBytesPerSecond: downstreamBytesPerSecond,
	}

	// Relay the steering IP to the API handshake handler.
	if sshClient.additionalTransportData != nil {
		info.steeringIP = sshClient.additionalTransportData.steeringIP
	}

	return info, nil
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

func (sshClient *sshClient) getDisableDiscovery() bool {
	sshClient.Lock()
	defer sshClient.Unlock()

	return *sshClient.trafficRules.DisableDiscovery
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

func (sshClient *sshClient) acceptDomainBytes() bool {
	sshClient.Lock()
	defer sshClient.Unlock()

	// When the domain bytes checksum differs from the checksum sent to the
	// client in the handshake response, the psinet regex configuration has
	// changed. In this case, drop the stats so we don't continue to record
	// stats as previously configured.
	//
	// Limitations:
	// - The checksum comparison may result in dropping some stats for a
	//   domain that remains in the new configuration.
	// - We don't push new regexs to the clients, so clients that remain
	//   connected will continue to send stats that will be dropped; and
	//   those clients will not send stats as newly configured until after
	//   reconnecting.
	// - Due to the design of
	//   transferstats.ReportRecentBytesTransferredForServer in the client,
	//   the client may accumulate stats, reconnect before its next status
	//   request, get a new regex configuration, and then send the previously
	//   accumulated stats in its next status request. The checksum scheme
	//   won't prevent the reporting of those stats.

	sponsorID, _ := getStringRequestParam(sshClient.handshakeState.apiParams, "sponsor_id")

	domainBytesChecksum := sshClient.sshServer.support.PsinetDatabase.GetDomainBytesChecksum(sponsorID)

	return bytes.Equal(sshClient.handshakeState.domainBytesChecksum, domainBytesChecksum)
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

	// Use the client, not peer, GeoIP data. In the case of in-proxy tunnel
	// protocols, the client GeoIP fields will be populated using the
	// original client IP already received, from the broker, in the handshake.

	sshClient.oslClientSeedState = sshClient.sshServer.support.OSLConfig.NewClientSeedState(
		sshClient.clientGeoIPData.Country,
		propagationChannelID,
		sshClient.signalIssueSLOKs)
}

// newClientSeedPortForward will return nil when no seeding is
// associated with the specified ipAddress.
func (sshClient *sshClient) newClientSeedPortForward(IPAddress net.IP) *osl.ClientSeedPortForward {
	sshClient.Lock()
	defer sshClient.Unlock()

	// Will not be initialized before handshake.
	if sshClient.oslClientSeedState == nil {
		return nil
	}

	lookupASN := func(IP net.IP) string {
		// TODO: there are potentially multiple identical geo IP lookups per new
		// port forward and flow, cache and use result of first lookup.
		return sshClient.sshServer.support.GeoIPService.LookupISPForIP(IP).ASN
	}

	return sshClient.oslClientSeedState.NewClientSeedPortForward(IPAddress, lookupASN)
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

func (sshClient *sshClient) setDestinationBytesMetrics() {
	sshClient.Lock()
	defer sshClient.Unlock()

	// Limitation: the server-side tactics cache is used to avoid the overhead
	// of an additional tactics filtering per tunnel. As this cache is
	// designed for GeoIP filtering only, handshake API parameters are not
	// applied to tactics filtering in this case.
	//
	// Use the client, not peer, GeoIP data. In the case of in-proxy tunnel
	// protocols, the client GeoIP fields will be populated using the
	// original client IP already received, from the broker, in the handshake.

	p, err := sshClient.sshServer.support.ServerTacticsParametersCache.Get(
		sshClient.clientGeoIPData)
	if err != nil {
		log.WithTraceFields(LogFields{"error": err}).Warning("get tactics failed")
		return
	}
	if p.IsNil() {
		return
	}

	ASNs := p.Strings(parameters.DestinationBytesMetricsASNs)

	// Merge in any legacy parameters.DestinationBytesMetricsASN
	// configuration. Data for this target will be logged using the legacy
	// log field format; see logTunnel. If an ASN is in _both_ configuration
	// parameters, its data will be logged in both log field formats.
	ASN := p.String(parameters.DestinationBytesMetricsASN)

	if len(ASNs) == 0 && ASN == "" {
		return
	}

	sshClient.destinationBytesMetrics = make(map[string]*protocolDestinationBytesMetrics)

	for _, ASN := range ASNs {
		if ASN != "" {
			sshClient.destinationBytesMetrics[ASN] = &protocolDestinationBytesMetrics{}
		}
	}

	if ASN != "" {
		sshClient.destinationBytesMetrics[ASN] = &protocolDestinationBytesMetrics{}
	}
}

func (sshClient *sshClient) newDestinationBytesMetricsUpdater(
	portForwardType int, IPAddress net.IP) *destinationBytesMetrics {

	sshClient.Lock()
	defer sshClient.Unlock()

	if sshClient.destinationBytesMetrics == nil {
		return nil
	}

	destinationASN := sshClient.sshServer.support.GeoIPService.LookupISPForIP(IPAddress).ASN

	// Future enhancement: for 5 or fewer ASNs, iterate over a slice instead
	// of using a map? See, for example, stringLookupThreshold in
	// common/tactics.
	metrics, ok := sshClient.destinationBytesMetrics[destinationASN]
	if !ok {
		return nil
	}

	if portForwardType == portForwardTypeTCP {
		return &metrics.tcpMetrics
	}

	return &metrics.udpMetrics
}

func (sshClient *sshClient) getPortForwardActivityUpdaters(
	portForwardType int, IPAddress net.IP) []common.ActivityUpdater {

	var updaters []common.ActivityUpdater

	clientSeedPortForward := sshClient.newClientSeedPortForward(IPAddress)
	if clientSeedPortForward != nil {
		updaters = append(updaters, clientSeedPortForward)
	}

	destinationBytesMetrics := sshClient.newDestinationBytesMetricsUpdater(portForwardType, IPAddress)
	if destinationBytesMetrics != nil {
		updaters = append(updaters, destinationBytesMetrics)
	}

	return updaters
}

func (sshClient *sshClient) newInproxyProxyQualityTracker() *inproxyProxyQualityTracker {

	sshClient.Lock()
	defer sshClient.Unlock()

	if !protocol.TunnelProtocolUsesInproxy(sshClient.tunnelProtocol) {
		return nil
	}

	// Limitation: assumes no GeoIP targeting for in-proxy quality
	// configuration. The original client GeoIP information is not available
	// until after the Psiphon handshake completes, and we want to include
	// earlier tunnel bytes, including any liveness test.
	//
	// As a future enhancement, quality tracker targets could be _extended_ by
	// GeoIP in reportProxyQuality.
	//
	// Note that the in-proxy broker also enforces InproxyEnableProxyQuality,
	// and also assumes no GeoIP targetting.

	p, err := sshClient.sshServer.support.ServerTacticsParametersCache.Get(NewGeoIPData())
	if err != nil {
		log.WithTraceFields(LogFields{"error": err}).Warning("get tactics failed")
		return nil
	}
	if p.IsNil() {
		return nil
	}

	// InproxyEnableProxyQuality indicates if proxy quality reporting is
	// enabled or not.
	//
	// Note that flipping InproxyEnableProxyQuality to false in tactics does
	// not interrupt any tracker already in progress.
	if !p.Bool(parameters.InproxyEnableProxyQuality) {
		return nil
	}

	tracker := newInproxyProxyQualityTracker(
		sshClient,
		int64(p.Int(parameters.InproxyProxyQualityTargetUpstreamBytes)),
		int64(p.Int(parameters.InproxyProxyQualityTargetDownstreamBytes)),
		p.Duration(parameters.InproxyProxyQualityTargetDuration))

	sshClient.inproxyProxyQualityTracker = tracker

	return tracker
}

func (sshClient *sshClient) reportProxyQuality() {

	sshClient.Lock()
	defer sshClient.Unlock()

	if !protocol.TunnelProtocolUsesInproxy(sshClient.tunnelProtocol) ||
		!sshClient.handshakeState.completed {
		log.Warning("unexpected reportProxyQuality call")
		return
	}

	if sshClient.handshakeState.inproxyMatchedPersonal {
		// Skip quality reporting for personal paired proxies. Brokers don't use
		// quality data for personal matching, and no quality data from personal
		// pairing should not influence common matching prioritization.
		return
	}

	// Enforce InproxyEnableProxyQualityClientRegions. If set, this is a
	// restricted list of client regions for which quality is reported.
	//
	// Note that it's possible to have an soft client GeoIP limit given that
	// in-proxy protocols are default disabled and enabled via
	// LimitTunnelProtocols. However, that parameter is enforced on the
	// client side.
	//
	// Now that that the Psiphon handshake is complete, the original client IP
	// is known. Here, as in newInproxyProxyQualityTracker, the tactics
	// filter remains non-region specific, so
	// InproxyEnableProxyQualityClientRegions should be a global list. This
	// accommodates a simpler configuration vs., for example, using many
	// region-specific filters to override InproxyEnableProxyQuality.
	//
	// Future enhancement: here, we could extend inproxyProxyQualityTracker
	// targets with client GeoIP-specific values.

	p, err := sshClient.sshServer.support.ServerTacticsParametersCache.Get(NewGeoIPData())
	if err != nil || p.IsNil() {
		log.WithTraceFields(LogFields{"error": err}).Warning("get tactics failed")
		return
	}

	enabledRegions := p.Strings(parameters.InproxyEnableProxyQualityClientRegions)
	if len(enabledRegions) > 0 &&
		!common.Contains(enabledRegions, sshClient.clientGeoIPData.Country) {

		// Quality reporting is restricted to specific regions, and this
		// client's region is not included.
		return
	}

	// ReportQuality will enqueue the quality data to be sent to brokers.
	// There's a delay before making broker requests, in an effort to batch
	// up data. Requests may be made to only a subset of brokers in
	// InproxyAllBrokerSpecs, depending on whether the broker is expected to
	// trust this server's session public key; see ReportQuality.

	sshClient.sshServer.inproxyBrokerSessions.ReportQuality(
		sshClient.handshakeState.inproxyProxyID,
		sshClient.peerGeoIPData.ASN,
		sshClient.clientGeoIPData.ASN)
}

func (sshClient *sshClient) newSSHProtocolBytesTracker() *sshProtocolBytesTracker {
	sshClient.Lock()
	defer sshClient.Unlock()

	tracker := newSSHProtocolBytesTracker(sshClient)

	sshClient.sshProtocolBytesTracker = tracker

	return tracker
}

func (sshClient *sshClient) getTunnelActivityUpdaters() []common.ActivityUpdater {

	var updaters []common.ActivityUpdater

	inproxyProxyQualityTracker := sshClient.newInproxyProxyQualityTracker()
	if inproxyProxyQualityTracker != nil {
		updaters = append(updaters, inproxyProxyQualityTracker)
	}

	sshProtocolBytesTracker := sshClient.newSSHProtocolBytesTracker()
	updaters = append(updaters, sshProtocolBytesTracker)

	return updaters
}

// setTrafficRules resets the client's traffic rules based on the latest server config
// and client properties. As sshClient.trafficRules may be reset by a concurrent
// goroutine, trafficRules must only be accessed within the sshClient mutex.
func (sshClient *sshClient) setTrafficRules() (int64, int64) {
	sshClient.Lock()
	defer sshClient.Unlock()

	isFirstTunnelInSession := sshClient.isFirstTunnelInSession &&
		sshClient.handshakeState.establishedTunnelsCount == 0

	// In the case of in-proxy tunnel protocols, the client GeoIP data is None
	// until the handshake completes. Pre-handhake, the rate limit is
	// determined by EstablishmentRead/WriteBytesPerSecond, which default to
	// unthrottled, the recommended setting; in addition, no port forwards
	// are permitted until after the handshake completes, at which time
	// setTrafficRules will be called again with the client GeoIP data
	// populated using the original client IP received from the in-proxy
	// broker.

	sshClient.trafficRules = sshClient.sshServer.support.TrafficRulesSet.GetTrafficRules(
		sshClient.sshServer.support.Config.GetProviderID(),
		isFirstTunnelInSession,
		sshClient.tunnelProtocol,
		sshClient.clientGeoIPData,
		sshClient.handshakeState)

	if sshClient.throttledConn != nil {
		// Any existing throttling state is reset.
		sshClient.throttledConn.SetLimits(
			sshClient.trafficRules.RateLimits.CommonRateLimits(
				sshClient.handshakeState.completed))
	}

	return *sshClient.trafficRules.RateLimits.ReadBytesPerSecond,
		*sshClient.trafficRules.RateLimits.WriteBytesPerSecond
}

func (sshClient *sshClient) rateLimits() common.RateLimits {
	sshClient.Lock()
	defer sshClient.Unlock()

	return sshClient.trafficRules.RateLimits.CommonRateLimits(
		sshClient.handshakeState.completed)
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
			if !sshClient.trafficRules.AllowTCPPort(
				sshClient.sshServer.support.GeoIPService, remoteIP, port) {

				allowed = false
			}
		case portForwardTypeUDP:
			if !sshClient.trafficRules.AllowUDPPort(
				sshClient.sshServer.support.GeoIPService, remoteIP, port) {

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

	if IsLogLevelDebug() {
		log.WithTraceFields(
			LogFields{
				"type": portForwardType,
				"port": port,
			}).Debug("port forward denied by traffic rules")
	}

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

	// Don't even attempt to resolve the default mDNS top-level domain.
	// Non-default cases won't be caught here but should fail to resolve due
	// to the PreferGo setting in net.Resolver.
	if strings.HasSuffix(domain, ".local") {
		return false, "port forward not permitted"
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

		if IsLogLevelDebug() {
			log.WithTrace().Debug("closed LRU port forward")
		}

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

	if net.ParseIP(hostToConnect) == nil {

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

	IP := net.ParseIP(hostToConnect)

	if IP == nil {

		// Resolve the hostname

		if IsLogLevelDebug() {
			log.WithTraceFields(LogFields{"hostToConnect": hostToConnect}).Debug("resolving")
		}

		// See comments in getDNSResolver regarding DNS cache considerations.
		// The cached values may be read by concurrent goroutines and must
		// not be mutated.

		dnsResolver, dnsCache := sshClient.getDNSResolver()

		var IPs []net.IPAddr

		if dnsCache != nil {
			cachedIPs, ok := dnsCache.Get(hostToConnect)
			if ok {
				IPs = cachedIPs.([]net.IPAddr)
			}
		}

		var err error
		var resolveElapsedTime time.Duration

		if len(IPs) == 0 {
			ctx, cancelCtx := context.WithTimeout(sshClient.runCtx, remainingDialTimeout)
			IPs, err = dnsResolver.LookupIPAddr(ctx, hostToConnect)
			cancelCtx() // "must be called or the new context will remain live until its parent context is cancelled"

			resolveElapsedTime = time.Since(dialStartTime)

			if err == nil && len(IPs) > 0 {

				// Add the successful DNS response to the cache. The cache
				// won't be updated in the "no such host"/IsNotFound case,
				// and subsequent resolves will try new requests. The "no IP
				// address" error case in the following IP selection logic
				// should not be reached when len(IPs) > 0.
				if dnsCache != nil {
					dnsCache.Add(hostToConnect, IPs, lrucache.DefaultExpiration)
				}
			}

			// Record DNS request metrics. If LookupIPAddr returns
			// net.DNSError.IsNotFound, this is "no such host" and not a DNS
			// request failure. Limitation: the DNS server IP is not known.

			dnsErr, ok := err.(*net.DNSError)
			dnsNotFound := ok && dnsErr.IsNotFound
			dnsSuccess := err == nil || dnsNotFound
			sshClient.updateQualityMetricsWithDNSResult(dnsSuccess, resolveElapsedTime, nil)
		}

		// IPv4 is preferred in case the host has limited IPv6 routing. IPv6 is
		// selected and attempted only when there's no IPv4 option.
		// TODO: shuffle list to try other IPs?

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
	}

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

		destinationGeoIPData := sshClient.sshServer.support.GeoIPService.LookupIP(IP)

		// Use the client, not peer, GeoIP data. In the case of in-proxy tunnel
		// protocols, the client GeoIP fields will be populated using the
		// original client IP already received, from the broker, in the handshake.

		clientGeoIPData := sshClient.getClientGeoIPData()

		if clientGeoIPData.Country != GEOIP_UNKNOWN_VALUE &&
			sshClient.handshakeState.splitTunnelLookup.lookup(
				destinationGeoIPData.Country) {

			// Since isPortForwardPermitted is not called in this case, explicitly call
			// ipBlocklistCheck. The domain blocklist case is handled above.
			if !sshClient.isIPPermitted(IP) {
				// Note: not recording a port forward failure in this case
				sshClient.rejectNewChannel(newChannel, "port forward not permitted")
				return
			}

			_ = newChannel.Reject(protocol.CHANNEL_REJECT_REASON_SPLIT_TUNNEL, "")
			return
		}
	}

	// Enforce traffic rules, using the resolved IP address.

	if !sshClient.isPortForwardPermitted(
		portForwardTypeTCP, IP, portToConnect) {

		// Note: not recording a port forward failure in this case
		sshClient.rejectNewChannel(newChannel, "port forward not permitted")
		return
	}

	// TCP dial.

	remoteAddr := net.JoinHostPort(IP.String(), strconv.Itoa(portToConnect))

	if IsLogLevelDebug() {
		log.WithTraceFields(LogFields{"remoteAddr": remoteAddr}).Debug("dialing")
	}

	ctx, cancelCtx := context.WithTimeout(sshClient.runCtx, remainingDialTimeout)
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

	fwdConn, err = common.NewActivityMonitoredConn(
		fwdConn,
		sshClient.idleTCPPortForwardTimeout(),
		true,
		lruEntry,
		sshClient.getPortForwardActivityUpdaters(portForwardTypeTCP, IP)...)
	if err != nil {
		log.WithTraceFields(LogFields{"error": err}).Error("NewActivityMonitoredConn failed")
		return
	}

	// Relay channel to forwarded connection.

	if IsLogLevelDebug() {
		log.WithTraceFields(LogFields{"remoteAddr": remoteAddr}).Debug("relaying")
	}

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
			if IsLogLevelDebug() {
				log.WithTraceFields(LogFields{"error": err}).Debug("downstream TCP relay failed")
			}
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
		if IsLogLevelDebug() {
			log.WithTraceFields(LogFields{"error": err}).Debug("upstream TCP relay failed")
		}
	}
	// Shutdown special case: fwdChannel will be closed and return EOF when
	// the SSH connection is closed, but we need to explicitly close fwdConn
	// to interrupt the downstream io.Copy, which may be blocked on a
	// fwdConn.Read().
	fwdConn.Close()

	relayWaitGroup.Wait()

	if IsLogLevelDebug() {
		log.WithTraceFields(
			LogFields{
				"remoteAddr": remoteAddr,
				"bytesUp":    atomic.LoadInt64(&bytesUp),
				"bytesDown":  atomic.LoadInt64(&bytesDown)}).Debug("exiting")
	}
}

func (sshClient *sshClient) getDNSResolver() (*net.Resolver, *lrucache.Cache) {

	// Initialize the DNS resolver and cache used by handleTCPChannel in cases
	// where the client sends unresolved domains through to psiphond. The
	// resolver and cache are allocated on demand, to avoid overhead for
	// clients that don't require this functionality.
	//
	// The standard library net.Resolver is used, with one instance per client
	// to get the advantage of the "singleflight" functionality, where
	// concurrent DNS lookups for the same domain are coalesced into a single
	// in-flight DNS request.
	//
	// net.Resolver reads its configuration from /etc/resolv.conf, including a
	// list of DNS servers, the number or retries to attempt, and whether to
	// rotate the initial DNS server selection.
	//
	// In addition, a cache of successful DNS lookups is maintained to avoid
	// rapid repeats DNS requests for the same domain. Since actual DNS
	// response TTLs are not exposed by net.Resolver, the cache should be
	// configured with a conservative TTL -- 10s of seconds.
	//
	// Each client has its own singleflight resolver and cache, which avoids
	// leaking domain access information between clients. The cache should be
	// configured with a modest max size appropriate for allocating one cache
	// per client.
	//
	// As a potential future enhancement, consider using the custom DNS
	// resolver, psiphon/common/resolver.Resolver, combined with the existing
	// DNS server fetcher, SupportServices.DNSResolver. This resolver
	// includes a cache which will respect the true TTL values in DNS
	// responses; and randomly distributes load over the available DNS
	// servers. Note the current limitations documented in
	// Resolver.ResolveIP, which must be addressed.

	sshClient.Lock()
	defer sshClient.Unlock()

	if sshClient.dnsResolver != nil {
		return sshClient.dnsResolver, sshClient.dnsCache
	}

	// PreferGo, equivalent to GODEBUG=netdns=go, is specified in order to
	// avoid any cases where Go's resolver fails over to the cgo-based
	// resolver (see https://pkg.go.dev/net#hdr-Name_Resolution). Such
	// cases, if they resolve at all, may be expected to resolve to bogon
	// IPs that won't be permitted; but the cgo invocation will consume
	// an OS thread, which is a performance hit we can avoid.

	sshClient.dnsResolver = &net.Resolver{PreferGo: true}

	// Get the server DNS resolver cache parameters from tactics. In the case
	// of an error, no tactics, or zero values no cache is initialized and
	// getDNSResolver initializes only the resolver and returns a nil cache.
	//
	// Limitations:
	// - assumes no GeoIP targeting for server DNS resolver cache parameters
	// - an individual client's cache is not reconfigured on tactics reloads

	p, err := sshClient.sshServer.support.ServerTacticsParametersCache.Get(NewGeoIPData())
	if err != nil {
		log.WithTraceFields(LogFields{"error": err}).Warning("get tactics failed")
		return sshClient.dnsResolver, nil
	}
	if p.IsNil() {
		return sshClient.dnsResolver, nil
	}

	maxSize := p.Int(parameters.ServerDNSResolverCacheMaxSize)
	TTL := p.Duration(parameters.ServerDNSResolverCacheTTL)

	if maxSize == 0 || TTL == 0 {
		return sshClient.dnsResolver, nil
	}

	sshClient.dnsCache = lrucache.NewWithLRU(TTL, 1*time.Minute, maxSize)

	return sshClient.dnsResolver, sshClient.dnsCache
}
