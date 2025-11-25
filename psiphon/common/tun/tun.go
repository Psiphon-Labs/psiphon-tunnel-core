/*
 * Copyright (c) 2017, Psiphon Inc.
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

// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/*
Package tun is an IP packet tunnel server and client. It supports tunneling
both IPv4 and IPv6.

	.........................................................       .-,(  ),-.
	. [server]                                     .-----.  .    .-(          )-.
	.                                              | NIC |<---->(    Internet    )
	. .......................................      '-----'  .    '-(          ).-'
	. . [packet tunnel daemon]              .         ^     .        '-.( ).-'
	. .                                     .         |     .
	. . ...........................         .         |     .
	. . . [session]               .         .        NAT    .
	. . .                         .         .         |     .
	. . .                         .         .         v     .
	. . .                         .         .       .---.   .
	. . .                         .         .       | t |   .
	. . .                         .         .       | u |   .
	. . .                 .---.   .  .---.  .       | n |   .
	. . .                 | q |   .  | d |  .       |   |   .
	. . .                 | u |   .  | e |  .       | d |   .
	. . .          .------| e |<-----| m |<---------| e |   .
	. . .          |      | u |   .  | u |  .       | v |   .
	. . .          |      | e |   .  | x |  .       | i |   .
	. . .       rewrite   '---'   .  '---'  .       | c |   .
	. . .          |              .         .       | e |   .
	. . .          v              .         .       '---'   .
	. . .     .---------.         .         .         ^     .
	. . .     | channel |--rewrite--------------------'     .
	. . .     '---------'         .         .               .
	. . ...........^...............         .               .
	. .............|.........................               .
	...............|.........................................
	               |
	               | (typically via Internet)
	               |
	...............|.................
	. [client]     |                .
	.              |                .
	. .............|............... .
	. .            v              . .
	. .       .---------.         . .
	. .       | channel |         . .
	. .       '---------'         . .
	. .            ^              . .
	. .............|............... .
	.              v                .
	.        .------------.         .
	.        | tun device |         .
	.        '------------'         .
	.................................

The client relays IP packets between a local tun device and a channel, which
is a transport to the server. In Psiphon, the channel will be an SSH channel
within an SSH connection to a Psiphon server.

The server relays packets between each client and its own tun device. The
server tun device is NATed to the Internet via an external network interface.
In this way, client traffic is tunneled and will egress from the server host.

Similar to a typical VPN, IP addresses are assigned to each client. Unlike
a typical VPN, the assignment is not transmitted to the client. Instead, the
server transparently rewrites the source addresses of client packets to
the assigned IP address. The server also rewrites the destination address of
certain DNS packets. The purpose of this is to allow clients to reconnect
to different servers without having to tear down or change their local
network configuration. Clients may configure their local tun device with an
arbitrary IP address and an arbitrary DNS resolver address.

The server uses the 24-bit 10.0.0.0/8 IPv4 private address space to maximize
the number of addresses available, due to Psiphon client churn and minimum
address lease time constraints. For IPv6, a 24-bit unique local space is used.
When a client is allocated addresses, a unique, unused 24-bit "index" is
reserved/leased. This index maps to and from IPv4 and IPv6 private addresses.
The server multiplexes all client packets into a single tun device. When a
packet is read, the destination address is used to map the packet back to the
correct index, which maps back to the client.

The server maintains client "sessions". A session maintains client IP
address state and effectively holds the lease on assigned addresses. If a
client is disconnected and quickly reconnects, it will resume its previous
session, retaining its IP address and network connection states. Idle
sessions with no client connection will eventually expire.

Packet count and bytes transferred metrics are logged for each client session.

The server integrates with and enforces Psiphon traffic rules and logging
facilities. The server parses and validates packets. Client-to-client packets
are not permitted. Only global unicast packets are permitted. Only TCP and UDP
packets are permitted. The client also filters out, before sending, packets
that the server won't route.

Certain aspects of packet tunneling are outside the scope of this package;
e.g, the Psiphon client and server are responsible for establishing an SSH
channel and negotiating the correct MTU and DNS settings. The Psiphon
server will call Server.ClientConnected when a client connects and establishes
a packet tunnel channel; and Server.ClientDisconnected when the client closes
the channel and/or disconnects.
*/
package tun

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/monotime"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
)

const (
	DEFAULT_MTU                          = 1500
	DEFAULT_DOWNSTREAM_PACKET_QUEUE_SIZE = 32768 * 16
	DEFAULT_UPSTREAM_PACKET_QUEUE_SIZE   = 32768
	DEFAULT_IDLE_SESSION_EXPIRY_SECONDS  = 300
	ORPHAN_METRICS_CHECKPOINTER_PERIOD   = 30 * time.Minute
	FLOW_IDLE_EXPIRY                     = 60 * time.Second
)

// ServerConfig specifies the configuration of a packet tunnel server.
type ServerConfig struct {

	// Logger is used for logging events and metrics.
	Logger common.Logger

	// SudoNetworkConfigCommands specifies whether to use "sudo"
	// when executing network configuration commands. This is required
	// when the packet tunnel server is not run as root and when
	// process capabilities are not available (only Linux kernel 4.3+
	// has the required capabilities support). The host sudoers file
	// must be configured to allow the tunnel server process user to
	// execute the commands invoked in configureServerInterface; see
	// the implementation for the appropriate platform.
	SudoNetworkConfigCommands bool

	// AllowNoIPv6NetworkConfiguration indicates that failures while
	// configuring tun interfaces and routing for IPv6 are to be
	// logged as warnings only. This option is intended to support
	// test cases on hosts without IPv6 and is not for production use;
	// the packet tunnel server will still accept IPv6 packets and
	// relay them to the tun device.
	// AllowNoIPv6NetworkConfiguration may not be supported on all
	// platforms.
	AllowNoIPv6NetworkConfiguration bool

	// EgressInterface is the interface to which client traffic is
	// masqueraded/NATed. For example, "eth0". If blank, a platform-
	// appropriate default is used.
	EgressInterface string

	// GetDNSResolverIPv4Addresses is a function which returns the
	// DNS resolvers to use as transparent DNS rewrite targets for
	// IPv4 DNS traffic.
	//
	// GetDNSResolverIPv4Addresses is invoked for each new client
	// session and the list of resolvers is stored with the session.
	// This is a compromise between checking current resolvers for
	// each packet (too expensive) and simply passing in a static
	// list (won't pick up resolver changes). As implemented, only
	// new client sessions will pick up resolver changes.
	//
	// Transparent DNS rewriting occurs when the client uses the
	// specific, target transparent DNS addresses specified by
	// GetTransparentDNSResolverIPv4/6Address.
	//
	// For outbound DNS packets with a target resolver IP address,
	// a random resolver is selected and used for the rewrite.
	// For inbound packets, _any_ resolver in the list is rewritten
	// back to the target resolver IP address. As a side-effect,
	// responses to client DNS packets originally destined for a
	// resolver in GetDNSResolverIPv4Addresses will be lost.
	GetDNSResolverIPv4Addresses func() []net.IP

	// GetDNSResolverIPv6Addresses is a function which returns the
	// DNS resolvers to use as transparent DNS rewrite targets for
	// IPv6 DNS traffic. It functions like GetDNSResolverIPv4Addresses.
	GetDNSResolverIPv6Addresses func() []net.IP

	// EnableDNSFlowTracking specifies whether to apply flow tracking to DNS
	// flows, as required for DNS quality metrics. Typically there are many
	// short-lived DNS flows to track and each tracked flow adds some overhead,
	// so this defaults to off.
	EnableDNSFlowTracking bool

	// DownstreamPacketQueueSize specifies the size of the downstream
	// packet queue. The packet tunnel server multiplexes all client
	// packets through a single tun device, so when a packet is read,
	// it must be queued or dropped if it cannot be immediately routed
	// to the appropriate client. Note that the TCP and SSH windows
	// for the underlying channel transport will impact transfer rate
	// and queuing.
	// When DownstreamPacketQueueSize is 0, a default value tuned for
	// Psiphon is used.
	DownstreamPacketQueueSize int

	// MTU specifies the maximum transmission unit for the packet
	// tunnel. Clients must be configured with the same MTU. The
	// server's tun device will be set to this MTU value and is
	// assumed not to change for the duration of the server.
	// When MTU is 0, a default value is used.
	MTU int

	// SessionIdleExpirySeconds specifies how long to retain client
	// sessions which have no client attached. Sessions are retained
	// across client connections so reconnecting clients can resume
	// a previous session. Resuming avoids leasing new IP addresses
	// for reconnection, and also retains NAT state for active
	// tunneled connections.
	//
	// SessionIdleExpirySeconds is also, effectively, the lease
	// time for assigned IP addresses.
	SessionIdleExpirySeconds int

	// AllowBogons disables bogon checks. This should be used only
	// for testing.
	AllowBogons bool
}

// Server is a packet tunnel server. A packet tunnel server
// maintains client sessions, relays packets through client
// channels, and multiplexes packets through a single tun
// device. The server assigns IP addresses to clients, performs
// IP address and transparent DNS rewriting, and enforces
// traffic rules.
type Server struct {
	config              *ServerConfig
	device              *Device
	indexToSession      sync.Map
	sessionIDToIndex    sync.Map
	connectedInProgress *sync.WaitGroup
	workers             *sync.WaitGroup
	runContext          context.Context
	stopRunning         context.CancelFunc
	orphanMetrics       *packetMetrics
}

// NewServer initializes a server.
func NewServer(config *ServerConfig) (*Server, error) {

	device, err := NewServerDevice(config)
	if err != nil {
		return nil, errors.Trace(err)
	}

	runContext, stopRunning := context.WithCancel(context.Background())

	return &Server{
		config:              config,
		device:              device,
		connectedInProgress: new(sync.WaitGroup),
		workers:             new(sync.WaitGroup),
		runContext:          runContext,
		stopRunning:         stopRunning,
		orphanMetrics:       new(packetMetrics),
	}, nil
}

// Start starts a server and returns with it running.
func (server *Server) Start() {

	server.config.Logger.WithTrace().Info("starting")

	server.workers.Add(1)
	go server.runSessionReaper()

	server.workers.Add(1)
	go server.runOrphanMetricsCheckpointer()

	server.workers.Add(1)
	go server.runDeviceDownstream()
}

// Stop halts a running server.
func (server *Server) Stop() {

	server.config.Logger.WithTrace().Info("stopping")

	server.stopRunning()

	// Interrupt blocked device read/writes.
	server.device.Close()

	// Wait for any in-progress ClientConnected calls to complete.
	server.connectedInProgress.Wait()

	// After this point, no further clients will be added: all
	// in-progress ClientConnected calls have finished; and any
	// later ClientConnected calls won't get past their
	// server.runContext.Done() checks.

	// Close all clients. Client workers will be joined
	// by the following server.workers.Wait().
	server.indexToSession.Range(func(_, value interface{}) bool {
		session := value.(*session)
		server.interruptSession(session)
		return true
	})

	server.workers.Wait()

	server.config.Logger.WithTrace().Info("stopped")
}

// AllowedPortChecker is a function which returns true when it is
// permitted to relay packets to the specified upstream IP address
// and/or port.
type AllowedPortChecker func(upstreamIPAddress net.IP, port int) bool

// AllowedDomainChecker is a function which returns true when it is
// permitted to resolve the specified domain name.
type AllowedDomainChecker func(string) bool

// FlowActivityUpdater defines an interface for receiving updates for
// flow activity. Values passed to UpdateProgress are bytes transferred
// and flow duration since the previous UpdateProgress.
type FlowActivityUpdater interface {
	UpdateProgress(downstreamBytes, upstreamBytes, durationNanoseconds int64)
}

// FlowActivityUpdaterMaker is a function which returns a list of
// appropriate updaters for a new flow to the specified upstream
// hostname (if known -- may be ""), and IP address.
// The flow is TCP when isTCP is true, and UDP otherwise.
type FlowActivityUpdaterMaker func(
	isTCP bool, upstreamHostname string, upstreamIPAddress net.IP) []FlowActivityUpdater

// MetricsUpdater is a function which receives a checkpoint summary
// of application bytes transferred through a packet tunnel.
type MetricsUpdater func(
	TCPApplicationBytesDown, TCPApplicationBytesUp,
	UDPApplicationBytesDown, UDPApplicationBytesUp int64)

// DNSQualityReporter is a function which receives a DNS quality report:
// whether a DNS request received a reponse, the elapsed time, and the
// resolver used.
type DNSQualityReporter func(
	receivedResponse bool, requestDuration time.Duration, resolverIP net.IP)

// ClientConnected handles new client connections, creating or resuming
// a session and returns with client packet handlers running.
//
// sessionID is used to identify sessions for resumption.
//
// transport provides the channel for relaying packets to and from
// the client.
//
// checkAllowedTCPPortFunc/checkAllowedUDPPortFunc/checkAllowedDomainFunc
// are callbacks used to enforce traffic rules. For each TCP/UDP flow, the
// corresponding AllowedPort function is called to check if traffic to the
// packet's port is permitted. For upstream DNS query packets,
// checkAllowedDomainFunc is called to check if domain resolution is
// permitted. These callbacks must be efficient and safe for concurrent
// calls.
//
// flowActivityUpdaterMaker is a callback invoked for each new packet
// flow; it may create updaters to track flow activity.
//
// metricsUpdater is a callback invoked at metrics checkpoints (usually
// when the client disconnects) with a summary of application bytes
// transferred.
//
// It is safe to make concurrent calls to ClientConnected for distinct
// session IDs. The caller is responsible for serializing calls with the
// same session ID. Further, the caller must ensure, in the case of a client
// transport reconnect when an existing transport has not yet disconnected,
// that ClientDisconnected is called first -- so it doesn't undo the new
// ClientConnected. (psiphond meets these constraints by closing any
// existing SSH client with duplicate session ID early in the lifecycle of
// a new SSH client connection.)
func (server *Server) ClientConnected(
	sessionID string,
	transport io.ReadWriteCloser,
	checkAllowedTCPPortFunc, checkAllowedUDPPortFunc AllowedPortChecker,
	checkAllowedDomainFunc AllowedDomainChecker,
	flowActivityUpdaterMaker FlowActivityUpdaterMaker,
	metricsUpdater MetricsUpdater,
	dnsQualityReporter DNSQualityReporter) error {

	// It's unusual to call both sync.WaitGroup.Add() _and_ Done() in the same
	// goroutine. There's no other place to call Add() since ClientConnected is
	// an API entrypoint. And Done() works because the invariant enforced by
	// connectedInProgress.Wait() is not that no ClientConnected calls are in
	// progress, but that no such calls are in progress past the
	// server.runContext.Done() check.

	// TODO: will this violate https://golang.org/pkg/sync/#WaitGroup.Add:
	// "calls with a positive delta that occur when the counter is zero must happen before a Wait"?

	server.connectedInProgress.Add(1)
	defer server.connectedInProgress.Done()

	select {
	case <-server.runContext.Done():
		return errors.TraceNew("server stopping")
	default:
	}

	server.config.Logger.WithTraceFields(
		common.LogFields{"sessionID": sessionID}).Debug("client connected")

	MTU := getMTU(server.config.MTU)

	clientSession := server.getSession(sessionID)

	if clientSession != nil {

		// Call interruptSession to ensure session is in the
		// expected idle state.

		server.interruptSession(clientSession)

		// Note: we don't check the session expiry; whether it has
		// already expired and not yet been reaped; or is about
		// to expire very shortly. It could happen that the reaper
		// will kill this session between now and when the expiry
		// is reset in the following resumeSession call. In this
		// unlikely case, the packet tunnel client should reconnect.

	} else {

		// Store IPv4 resolver addresses in 4-byte representation
		// for use in rewritting.
		resolvers := server.config.GetDNSResolverIPv4Addresses()
		DNSResolverIPv4Addresses := make([]net.IP, len(resolvers))
		for i, resolver := range resolvers {
			// Assumes To4 is non-nil
			DNSResolverIPv4Addresses[i] = resolver.To4()
		}

		clientSession = &session{
			allowBogons:              server.config.AllowBogons,
			sessionID:                sessionID,
			metrics:                  new(packetMetrics),
			enableDNSFlowTracking:    server.config.EnableDNSFlowTracking,
			DNSResolverIPv4Addresses: append([]net.IP(nil), DNSResolverIPv4Addresses...),
			DNSResolverIPv6Addresses: append([]net.IP(nil), server.config.GetDNSResolverIPv6Addresses()...),
			workers:                  new(sync.WaitGroup),
		}
		clientSession.lastActivity.Store(int64(monotime.Now()))

		// One-time, for this session, random resolver selection for TCP transparent
		// DNS forwarding. See comment in processPacket.
		if len(clientSession.DNSResolverIPv4Addresses) > 0 {
			clientSession.TCPDNSResolverIPv4Index = prng.Intn(len(clientSession.DNSResolverIPv4Addresses))
		}
		if len(clientSession.DNSResolverIPv6Addresses) > 0 {
			clientSession.TCPDNSResolverIPv6Index = prng.Intn(len(clientSession.DNSResolverIPv6Addresses))
		}

		// allocateIndex initializes session.index, session.assignedIPv4Address,
		// and session.assignedIPv6Address; and updates server.indexToSession and
		// server.sessionIDToIndex.

		err := server.allocateIndex(clientSession)
		if err != nil {
			return errors.Trace(err)
		}
	}

	// Note: it's possible that a client disconnects (or reconnects before a
	// disconnect is detected) and interruptSession is called between
	// allocateIndex and resumeSession calls here, so interruptSession and
	// related code must not assume resumeSession has been called.

	server.resumeSession(
		clientSession,
		NewChannel(transport, MTU),
		checkAllowedTCPPortFunc,
		checkAllowedUDPPortFunc,
		checkAllowedDomainFunc,
		flowActivityUpdaterMaker,
		metricsUpdater,
		dnsQualityReporter)

	return nil
}

// ClientDisconnected handles clients disconnecting. Packet handlers
// are halted, but the client session is left intact to reserve the
// assigned IP addresses and retain network state in case the client
// soon reconnects.
func (server *Server) ClientDisconnected(sessionID string) {

	session := server.getSession(sessionID)
	if session != nil {

		server.config.Logger.WithTraceFields(
			common.LogFields{"sessionID": sessionID}).Debug("client disconnected")

		server.interruptSession(session)
	}
}

func (server *Server) getSession(sessionID string) *session {

	if index, ok := server.sessionIDToIndex.Load(sessionID); ok {
		s, ok := server.indexToSession.Load(index.(int32))
		if ok {
			return s.(*session)
		}
		server.config.Logger.WithTrace().Warning("unexpected missing session")
	}
	return nil
}

func (server *Server) resumeSession(
	session *session,
	channel *Channel,
	checkAllowedTCPPortFunc, checkAllowedUDPPortFunc AllowedPortChecker,
	checkAllowedDomainFunc AllowedDomainChecker,
	flowActivityUpdaterMaker FlowActivityUpdaterMaker,
	metricsUpdater MetricsUpdater,
	dnsQualityReporter DNSQualityReporter) {

	session.mutex.Lock()
	defer session.mutex.Unlock()

	// Performance/concurrency note: the downstream packet queue
	// and various packet event callbacks may be accessed while
	// the session is idle, via the runDeviceDownstream goroutine,
	// which runs concurrent to resumeSession/interruptSession calls.
	// Consequently, all accesses to these fields must be
	// synchronized.
	//
	// Benchmarking indicates the atomic.LoadPointer mechanism
	// outperforms a mutex; approx. 2 ns/op vs. 20 ns/op in the case
	// of getCheckAllowedTCPPortFunc. Since these accesses occur
	// multiple times per packet, atomic.LoadPointer is used and so
	// each of these fields is an unsafe.Pointer in the session
	// struct.

	// Begin buffering downstream packets.

	downstreamPacketQueueSize := DEFAULT_DOWNSTREAM_PACKET_QUEUE_SIZE
	if server.config.DownstreamPacketQueueSize > 0 {
		downstreamPacketQueueSize = server.config.DownstreamPacketQueueSize
	}
	downstreamPackets := NewPacketQueue(downstreamPacketQueueSize)

	session.setDownstreamPackets(downstreamPackets)

	// Set new access control, flow monitoring, and metrics
	// callbacks; all associated with the new client connection.

	// IMPORTANT: any new callbacks or references to the outer client added
	// here must be cleared in interruptSession to ensure that a paused
	// session does not retain references to old client connection objects
	// after the client disconnects.

	session.setCheckAllowedTCPPortFunc(&checkAllowedTCPPortFunc)

	session.setCheckAllowedUDPPortFunc(&checkAllowedUDPPortFunc)

	session.setCheckAllowedDomainFunc(&checkAllowedDomainFunc)

	session.setFlowActivityUpdaterMaker(&flowActivityUpdaterMaker)

	session.setMetricsUpdater(&metricsUpdater)

	session.setDNSQualityReporter(&dnsQualityReporter)

	session.channel = channel

	// Parent context is not server.runContext so that session workers
	// need only check session.stopRunning to act on shutdown events.
	session.runContext, session.stopRunning = context.WithCancel(context.Background())

	// When a session is interrupted, all goroutines in session.workers
	// are joined. When the server is stopped, all goroutines in
	// server.workers are joined. So, in both cases we synchronously
	// stop all workers associated with this session.

	session.workers.Add(1)
	go server.runClientUpstream(session)

	session.workers.Add(1)
	go server.runClientDownstream(session)

	session.touch()
}

func (server *Server) interruptSession(session *session) {

	session.mutex.Lock()
	defer session.mutex.Unlock()

	wasRunning := (session.channel != nil)

	if session.stopRunning != nil {
		session.stopRunning()
	}

	if session.channel != nil {
		// Interrupt blocked channel read/writes.
		session.channel.Close()
	}

	session.workers.Wait()

	if session.channel != nil {
		// Don't hold a reference to channel, allowing both it and
		// its conn to be garbage collected.
		// Setting channel to nil must happen after workers.Wait()
		// to ensure no goroutine remains which may access
		// session.channel.
		session.channel = nil
	}

	metricsUpdater := session.getMetricsUpdater()

	// interruptSession may be called for idle sessions, to ensure
	// the session is in an expected state: in ClientConnected,
	// and in server.Stop(); don't log in those cases.
	if wasRunning {
		session.metrics.checkpoint(
			server.config.Logger,
			metricsUpdater,
			"server_packet_metrics",
			packetMetricsAll)
	}

	// Release the downstream packet buffer, so the associated
	// memory is not consumed while no client is connected.
	//
	// Since runDeviceDownstream continues to run and will access
	// session.downstreamPackets, an atomic pointer is used to
	// synchronize access.
	session.setDownstreamPackets(nil)

	session.setCheckAllowedTCPPortFunc(nil)

	session.setCheckAllowedUDPPortFunc(nil)

	session.setCheckAllowedDomainFunc(nil)

	session.setFlowActivityUpdaterMaker(nil)

	session.setMetricsUpdater(nil)

	session.setDNSQualityReporter(nil)
}

func (server *Server) runSessionReaper() {

	defer server.workers.Done()

	// Periodically iterate over all sessions and discard expired
	// sessions. This action, removing the index from server.indexToSession,
	// releases the IP addresses assigned  to the session.

	// TODO: As-is, this will discard sessions for live SSH tunnels,
	// as long as the SSH channel for such a session has been idle for
	// a sufficient period. Should the session be retained as long as
	// the SSH tunnel is alive (e.g., expose and call session.touch()
	// on keepalive events)? Or is it better to free up resources held
	// by idle sessions?

	idleExpiry := server.sessionIdleExpiry()

	ticker := time.NewTicker(idleExpiry / 2)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			server.indexToSession.Range(func(_, value interface{}) bool {
				session := value.(*session)
				if session.expired(idleExpiry) {
					server.removeSession(session)
				}
				return true
			})
		case <-server.runContext.Done():
			return
		}
	}
}

func (server *Server) sessionIdleExpiry() time.Duration {
	sessionIdleExpirySeconds := DEFAULT_IDLE_SESSION_EXPIRY_SECONDS
	if server.config.SessionIdleExpirySeconds > 2 {
		sessionIdleExpirySeconds = server.config.SessionIdleExpirySeconds
	}
	return time.Duration(sessionIdleExpirySeconds) * time.Second
}

func (server *Server) removeSession(session *session) {
	server.sessionIDToIndex.Delete(session.sessionID)
	server.indexToSession.Delete(session.index)
	server.interruptSession(session)

	// Delete flows to ensure any pending flow metrics are reported.
	session.deleteFlows()
}

func (server *Server) runOrphanMetricsCheckpointer() {

	defer server.workers.Done()

	// Periodically log orphan packet metrics. Orphan metrics
	// are not associated with any session. This includes
	// packets that are rejected before they can be associated
	// with a session.

	ticker := time.NewTicker(ORPHAN_METRICS_CHECKPOINTER_PERIOD)
	defer ticker.Stop()

	for {
		done := false
		select {
		case <-ticker.C:
		case <-server.runContext.Done():
			done = true
		}

		// TODO: skip log if all zeros?
		server.orphanMetrics.checkpoint(
			server.config.Logger,
			nil,
			"server_orphan_packet_metrics",
			packetMetricsRejected)
		if done {
			return
		}
	}
}

func (server *Server) runDeviceDownstream() {

	defer server.workers.Done()

	// Read incoming packets from the tun device, parse and validate the
	// packets, map them to a session/client, perform rewriting, and relay
	// the packets to the client.

	for {
		readPacket, err := server.device.ReadPacket()

		select {
		case <-server.runContext.Done():
			// No error is logged as shutdown may have interrupted read.
			return
		default:
		}

		if err != nil {
			server.config.Logger.WithTraceFields(
				common.LogFields{"error": err}).Warning("read device packet failed")
			// May be temporary error condition, keep reading.
			continue
		}

		// destinationIPAddress determines which client receives this packet.
		// At this point, only enough of the packet is inspected to determine
		// this routing info; further validation happens in subsequent
		// processPacket in runClientDownstream.

		// Note that masquerading/NAT stands between the Internet and the tun
		// device, so arbitrary packets cannot be sent through to this point.

		// TODO: getPacketDestinationIPAddress and processPacket perform redundant
		// packet parsing; refactor to avoid extra work?

		destinationIPAddress, ok := getPacketDestinationIPAddress(
			server.orphanMetrics, packetDirectionServerDownstream, readPacket)

		if !ok {
			// Packet is dropped. Reason will be counted in orphan metrics.
			continue
		}

		// Map destination IP address to client session.

		index := server.convertIPAddressToIndex(destinationIPAddress)
		s, ok := server.indexToSession.Load(index)

		if !ok {
			server.orphanMetrics.rejectedPacket(
				packetDirectionServerDownstream, packetRejectNoSession)
			continue
		}

		session := s.(*session)

		downstreamPackets := session.getDownstreamPackets()

		// No downstreamPackets buffer is maintained when no client is
		// connected, so the packet is dropped.

		if downstreamPackets == nil {
			server.orphanMetrics.rejectedPacket(
				packetDirectionServerDownstream, packetRejectNoClient)
			continue
		}

		// Simply enqueue the packet for client handling, and move on to
		// read the next packet. The packet tunnel server multiplexes all
		// client packets through a single tun device, so we must not block
		// on client channel I/O here.
		//
		// When the queue is full, the packet is dropped. This is standard
		// behavior for routers, VPN servers, etc.
		//
		// TODO: processPacket is performed here, instead of runClientDownstream,
		// since packets are packed contiguously into the packet queue and if
		// the packet it to be omitted, that should be done before enqueuing.
		// The potential downside is that all packet processing is done in this
		// single thread of execution, blocking the next packet for the next
		// client. Try handing off the packet to another worker which will
		// call processPacket and Enqueue?

		// In downstream mode, processPacket rewrites the destination address
		// to the original client source IP address, and also rewrites DNS
		// packets. As documented in runClientUpstream, the original address
		// should already be populated via an upstream packet; if not, the
		// packet will be rejected.

		if !processPacket(
			session.metrics,
			session,
			nil,
			packetDirectionServerDownstream,
			readPacket) {
			// Packet is rejected and dropped. Reason will be counted in metrics.
			continue
		}

		downstreamPackets.Enqueue(readPacket)
	}
}

func (server *Server) runClientUpstream(session *session) {

	defer session.workers.Done()

	// Read incoming packets from the client channel, validate the packets,
	// perform rewriting, and send them through to the tun device.

	for {
		readPacket, err := session.channel.ReadPacket()

		select {
		case <-session.runContext.Done():
			// No error is logged as shutdown may have interrupted read.
			return
		default:
		}

		if err != nil {

			// Debug since channel I/O errors occur during normal operation.
			server.config.Logger.WithTraceFields(
				common.LogFields{"error": err}).Debug("read channel packet failed")

			// Tear down the session. Must be invoked asynchronously.
			go server.interruptSession(session)

			return
		}

		session.touch()

		// processPacket transparently rewrites the source address to the
		// session's assigned address and rewrites the destination of any
		// DNS packets destined to the transparent DNS resolver.
		//
		// The first time the source address is rewritten, the original
		// value is recorded so inbound packets can have the reverse
		// rewrite applied. This assumes that the client will send a
		// packet before receiving any packet, which is the case since
		// only clients can initiate TCP or UDP connections or flows.

		if !processPacket(
			session.metrics,
			session,
			nil,
			packetDirectionServerUpstream,
			readPacket) {

			// Packet is rejected and dropped. Reason will be counted in metrics.
			continue
		}

		err = server.device.WritePacket(readPacket)

		if err != nil {
			server.config.Logger.WithTraceFields(
				common.LogFields{"error": err}).Warning("write device packet failed")
			// May be temporary error condition, keep working. The packet is
			// most likely dropped.
			continue
		}
	}
}

func (server *Server) runClientDownstream(session *session) {

	defer session.workers.Done()

	// Dequeue, process, and relay packets to be sent to the client channel.

	for {

		downstreamPackets := session.getDownstreamPackets()
		// Note: downstreamPackets will not be nil, since this goroutine only
		// runs while the session has a connected client.

		packetBuffer, ok := downstreamPackets.DequeueFramedPackets(session.runContext)
		if !ok {
			// Dequeue aborted due to session.runContext.Done()
			return
		}

		err := session.channel.WriteFramedPackets(packetBuffer)
		if err != nil {

			// Debug since channel I/O errors occur during normal operation.
			server.config.Logger.WithTraceFields(
				common.LogFields{"error": err}).Debug("write channel packets failed")

			downstreamPackets.Replace(packetBuffer)

			// Tear down the session. Must be invoked asynchronously.
			go server.interruptSession(session)

			return
		}

		session.touch()

		downstreamPackets.Replace(packetBuffer)
	}
}

var (
	serverIPv4AddressCIDR             = "10.0.0.1/8"
	transparentDNSResolverIPv4Address = net.ParseIP("10.0.0.2").To4() // 4-byte for rewriting
	_, privateSubnetIPv4, _           = net.ParseCIDR("10.0.0.0/8")
	assignedIPv4AddressTemplate       = "10.%d.%d.%d"

	serverIPv6AddressCIDR             = "fd19:ca83:e6d5:1c44:0000:0000:0000:0001/64"
	transparentDNSResolverIPv6Address = net.ParseIP("fd19:ca83:e6d5:1c44:0000:0000:0000:0002")
	_, privateSubnetIPv6, _           = net.ParseCIDR("fd19:ca83:e6d5:1c44::/64")
	assignedIPv6AddressTemplate       = "fd19:ca83:e6d5:1c44:8c57:4434:ee%02x:%02x%02x"
)

func (server *Server) allocateIndex(newSession *session) error {

	// Find and assign an available index in the 24-bit index space.
	// The index directly maps to and so determines the assigned
	// IPv4 and IPv6 addresses.

	// Search is a random index selection followed by a linear probe.
	// TODO: is this the most effective (fast on average, simple) algorithm?

	max := 0x00FFFFFF

	randomInt := prng.Intn(max + 1)

	index := int32(randomInt)
	index &= int32(max)

	idleExpiry := server.sessionIdleExpiry()

	for tries := 0; tries < 100000; index++ {

		tries++

		// The index/address space isn't exactly 24-bits:
		// - 0 and 0x00FFFFFF are reserved since they map to
		//   the network identifier (10.0.0.0) and broadcast
		//   address (10.255.255.255) respectively
		// - 1 is reserved as the server tun device address,
		//   (10.0.0.1, and IPv6 equivalent)
		// - 2 is reserved as the transparent DNS target
		//   address (10.0.0.2, and IPv6 equivalent)

		if index <= 2 {
			continue
		}
		if index == 0x00FFFFFF {
			index = 0
			continue
		}

		IPv4Address := server.convertIndexToIPv4Address(index).To4()
		IPv6Address := server.convertIndexToIPv6Address(index)

		// Ensure that the index converts to valid IPs. This is not expected
		// to fail, but continuing with nil IPs will silently misroute
		// packets with rewritten source IPs.
		if IPv4Address == nil || IPv6Address == nil {
			server.config.Logger.WithTraceFields(
				common.LogFields{"index": index}).Warning("convert index to IP address failed")
			continue
		}

		if s, ok := server.indexToSession.LoadOrStore(index, newSession); ok {
			// Index is already in use or acquired concurrently.
			// If the existing session is expired, reap it and try again
			// to acquire it.
			existingSession := s.(*session)
			if existingSession.expired(idleExpiry) {
				server.removeSession(existingSession)
				// Try to acquire this index again. We can't fall through and
				// use this index as removeSession has cleared indexToSession.
				index--
			}
			continue
		}

		// Note: the To4() for assignedIPv4Address is essential since
		// that address value is assumed to be 4 bytes when rewriting.

		newSession.index = index
		newSession.assignedIPv4Address = IPv4Address
		newSession.assignedIPv6Address = IPv6Address
		server.sessionIDToIndex.Store(newSession.sessionID, index)

		server.resetRouting(newSession.assignedIPv4Address, newSession.assignedIPv6Address)

		return nil
	}

	return errors.TraceNew("unallocated index not found")
}

func (server *Server) resetRouting(IPv4Address, IPv6Address net.IP) {

	// Attempt to clear the NAT table of any existing connection
	// states. This will prevent the (already unlikely) delivery
	// of packets to the wrong client when an assigned IP address is
	// recycled. Silently has no effect on some platforms, see
	// resetNATTables implementations.

	err := resetNATTables(server.config, IPv4Address)
	if err != nil {
		server.config.Logger.WithTraceFields(
			common.LogFields{"error": err}).Warning("reset IPv4 routing failed")

	}

	err = resetNATTables(server.config, IPv6Address)
	if err != nil {
		server.config.Logger.WithTraceFields(
			common.LogFields{"error": err}).Warning("reset IPv6 routing failed")

	}
}

func (server *Server) convertIPAddressToIndex(IP net.IP) int32 {
	// Assumes IP is at least 3 bytes.
	size := len(IP)
	return int32(IP[size-3])<<16 | int32(IP[size-2])<<8 | int32(IP[size-1])
}

func (server *Server) convertIndexToIPv4Address(index int32) net.IP {
	return net.ParseIP(
		fmt.Sprintf(
			assignedIPv4AddressTemplate,
			(index>>16)&0xFF,
			(index>>8)&0xFF,
			index&0xFF))
}

func (server *Server) convertIndexToIPv6Address(index int32) net.IP {
	return net.ParseIP(
		fmt.Sprintf(
			assignedIPv6AddressTemplate,
			(index>>16)&0xFF,
			(index>>8)&0xFF,
			index&0xFF))
}

type session struct {
	lastActivity             atomic.Int64
	lastFlowReapIndex        atomic.Int64
	downstreamPackets        unsafe.Pointer
	checkAllowedTCPPortFunc  unsafe.Pointer
	checkAllowedUDPPortFunc  unsafe.Pointer
	checkAllowedDomainFunc   unsafe.Pointer
	flowActivityUpdaterMaker unsafe.Pointer
	metricsUpdater           unsafe.Pointer
	dnsQualityReporter       unsafe.Pointer

	allowBogons              bool
	metrics                  *packetMetrics
	sessionID                string
	index                    int32
	enableDNSFlowTracking    bool
	DNSResolverIPv4Addresses []net.IP
	TCPDNSResolverIPv4Index  int
	assignedIPv4Address      net.IP
	setOriginalIPv4Address   int32
	originalIPv4Address      net.IP
	DNSResolverIPv6Addresses []net.IP
	TCPDNSResolverIPv6Index  int
	assignedIPv6Address      net.IP
	setOriginalIPv6Address   int32
	originalIPv6Address      net.IP
	flows                    sync.Map
	workers                  *sync.WaitGroup
	mutex                    sync.Mutex
	channel                  *Channel
	runContext               context.Context
	stopRunning              context.CancelFunc
}

func (session *session) touch() {
	session.lastActivity.Store(int64(monotime.Now()))
}

func (session *session) expired(idleExpiry time.Duration) bool {
	lastActivity := monotime.Time(session.lastActivity.Load())
	return monotime.Since(lastActivity) > idleExpiry
}

func (session *session) setOriginalIPv4AddressIfNotSet(IPAddress net.IP) {
	if !atomic.CompareAndSwapInt32(&session.setOriginalIPv4Address, 0, 1) {
		return
	}
	// Make a copy of IPAddress; don't reference a slice of a reusable
	// packet buffer, which will be overwritten.
	session.originalIPv4Address = net.IP(append([]byte(nil), []byte(IPAddress)...))
}

func (session *session) getOriginalIPv4Address() net.IP {
	if atomic.LoadInt32(&session.setOriginalIPv4Address) == 0 {
		return nil
	}
	return session.originalIPv4Address
}

func (session *session) setOriginalIPv6AddressIfNotSet(IPAddress net.IP) {
	if !atomic.CompareAndSwapInt32(&session.setOriginalIPv6Address, 0, 1) {
		return
	}
	// Make a copy of IPAddress.
	session.originalIPv6Address = net.IP(append([]byte(nil), []byte(IPAddress)...))
}

func (session *session) getOriginalIPv6Address() net.IP {
	if atomic.LoadInt32(&session.setOriginalIPv6Address) == 0 {
		return nil
	}
	return session.originalIPv6Address
}

func (session *session) setDownstreamPackets(p *PacketQueue) {
	atomic.StorePointer(&session.downstreamPackets, unsafe.Pointer(p))
}

func (session *session) getDownstreamPackets() *PacketQueue {
	return (*PacketQueue)(atomic.LoadPointer(&session.downstreamPackets))
}

func (session *session) setCheckAllowedTCPPortFunc(p *AllowedPortChecker) {
	atomic.StorePointer(&session.checkAllowedTCPPortFunc, unsafe.Pointer(p))
}

func (session *session) getCheckAllowedTCPPortFunc() AllowedPortChecker {
	p := (*AllowedPortChecker)(atomic.LoadPointer(&session.checkAllowedTCPPortFunc))
	if p == nil {
		return nil
	}
	return *p
}

func (session *session) setCheckAllowedUDPPortFunc(p *AllowedPortChecker) {
	atomic.StorePointer(&session.checkAllowedUDPPortFunc, unsafe.Pointer(p))
}

func (session *session) getCheckAllowedUDPPortFunc() AllowedPortChecker {
	p := (*AllowedPortChecker)(atomic.LoadPointer(&session.checkAllowedUDPPortFunc))
	if p == nil {
		return nil
	}
	return *p
}

func (session *session) setCheckAllowedDomainFunc(p *AllowedDomainChecker) {
	atomic.StorePointer(&session.checkAllowedDomainFunc, unsafe.Pointer(p))
}

func (session *session) getCheckAllowedDomainFunc() AllowedDomainChecker {
	p := (*AllowedDomainChecker)(atomic.LoadPointer(&session.checkAllowedDomainFunc))
	if p == nil {
		return nil
	}
	return *p
}

func (session *session) setFlowActivityUpdaterMaker(p *FlowActivityUpdaterMaker) {
	atomic.StorePointer(&session.flowActivityUpdaterMaker, unsafe.Pointer(p))
}

func (session *session) getFlowActivityUpdaterMaker() FlowActivityUpdaterMaker {
	p := (*FlowActivityUpdaterMaker)(atomic.LoadPointer(&session.flowActivityUpdaterMaker))
	if p == nil {
		return nil
	}
	return *p
}

func (session *session) setMetricsUpdater(p *MetricsUpdater) {
	atomic.StorePointer(&session.metricsUpdater, unsafe.Pointer(p))
}

func (session *session) getMetricsUpdater() MetricsUpdater {
	p := (*MetricsUpdater)(atomic.LoadPointer(&session.metricsUpdater))
	if p == nil {
		return nil
	}
	return *p
}

func (session *session) setDNSQualityReporter(p *DNSQualityReporter) {
	atomic.StorePointer(&session.dnsQualityReporter, unsafe.Pointer(p))
}

func (session *session) getDNSQualityReporter() DNSQualityReporter {
	p := (*DNSQualityReporter)(atomic.LoadPointer(&session.dnsQualityReporter))
	if p == nil {
		return nil
	}
	return *p
}

// flowID identifies an IP traffic flow using the conventional
// network 5-tuple. flowIDs track bidirectional flows.
type flowID struct {
	downstreamIPAddress [net.IPv6len]byte
	downstreamPort      uint16
	upstreamIPAddress   [net.IPv6len]byte
	upstreamPort        uint16
	protocol            internetProtocol
}

// From: https://github.com/golang/go/blob/b88efc7e7ac15f9e0b5d8d9c82f870294f6a3839/src/net/ip.go#L55
var v4InV6Prefix = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff}

func (f *flowID) set(
	downstreamIPAddress net.IP,
	downstreamPort uint16,
	upstreamIPAddress net.IP,
	upstreamPort uint16,
	protocol internetProtocol) {

	if len(downstreamIPAddress) == net.IPv4len {
		copy(f.downstreamIPAddress[:], v4InV6Prefix)
		copy(f.downstreamIPAddress[len(v4InV6Prefix):], downstreamIPAddress)
	} else { // net.IPv6len
		copy(f.downstreamIPAddress[:], downstreamIPAddress)
	}
	f.downstreamPort = downstreamPort

	if len(upstreamIPAddress) == net.IPv4len {
		copy(f.upstreamIPAddress[:], v4InV6Prefix)
		copy(f.upstreamIPAddress[len(v4InV6Prefix):], upstreamIPAddress)
	} else { // net.IPv6len
		copy(f.upstreamIPAddress[:], upstreamIPAddress)
	}
	f.upstreamPort = upstreamPort

	f.protocol = protocol
}

type flowState struct {
	firstUpstreamPacketTime   atomic.Int64
	lastUpstreamPacketTime    atomic.Int64
	firstDownstreamPacketTime atomic.Int64
	lastDownstreamPacketTime  atomic.Int64
	isDNS                     bool
	dnsQualityReporter        DNSQualityReporter
	activityUpdaters          []FlowActivityUpdater
}

func (flowState *flowState) expired(idleExpiry time.Duration) bool {
	now := monotime.Now()

	// Traffic in either direction keeps the flow alive. Initially, only one of
	// lastUpstreamPacketTime or lastDownstreamPacketTime will be set by
	// startTrackingFlow, and the other value will be 0 and evaluate as expired.

	return (now.Sub(monotime.Time(flowState.lastUpstreamPacketTime.Load())) > idleExpiry) &&
		(now.Sub(monotime.Time(flowState.lastDownstreamPacketTime.Load())) > idleExpiry)
}

// isTrackingFlow checks if a flow is being tracked.
func (session *session) isTrackingFlow(ID flowID) bool {

	f, ok := session.flows.Load(ID)
	if !ok {
		return false
	}
	flowState := f.(*flowState)

	// Check if flow is expired but not yet reaped.
	if flowState.expired(FLOW_IDLE_EXPIRY) {
		session.deleteFlow(ID, flowState)
		return false
	}

	return true
}

// startTrackingFlow starts flow tracking for the flow identified
// by ID.
//
// Flow tracking is used to implement:
// - one-time permissions checks for a flow
// - OSLs
// - domain bytes transferred [TODO]
// - DNS quality metrics
//
// The applicationData from the first packet in the flow is
// inspected to determine any associated hostname, using HTTP or
// TLS payload. The session's FlowActivityUpdaterMaker is invoked
// to determine a list of updaters to track flow activity.
//
// Updaters receive reports with the number of application data
// bytes in each flow packet. This number, totalled for all packets
// in a flow, may exceed the total bytes transferred at the
// application level due to TCP retransmission. Currently, the flow
// tracking logic doesn't exclude retransmitted packets from update
// reporting.
//
// Flows are untracked after an idle expiry period. Transport
// protocol indicators of end of flow, such as FIN or RST for TCP,
// which may or may not appear in a flow, are not currently used.
//
// startTrackingFlow may be called from concurrent goroutines; if
// the flow is already tracked, it is simply updated.
func (session *session) startTrackingFlow(
	ID flowID,
	direction packetDirection,
	applicationData []byte,
	isDNS bool) {

	now := int64(monotime.Now())

	// Once every period, iterate over flows and reap expired entries.
	reapIndex := now / int64(monotime.Time(FLOW_IDLE_EXPIRY/2))
	previousReapIndex := session.lastFlowReapIndex.Load()
	if reapIndex != previousReapIndex &&
		session.lastFlowReapIndex.CompareAndSwap(previousReapIndex, reapIndex) {
		session.reapFlows()
	}

	var isTCP bool
	var hostname string
	if ID.protocol == internetProtocolTCP {
		// TODO: implement
		// hostname = common.ExtractHostnameFromTCPFlow(applicationData)
		isTCP = true
	}

	var activityUpdaters []FlowActivityUpdater

	// Don't incur activity monitor overhead for DNS requests
	if !isDNS {
		flowActivityUpdaterMaker := session.getFlowActivityUpdaterMaker()
		if flowActivityUpdaterMaker != nil {
			activityUpdaters = flowActivityUpdaterMaker(
				isTCP,
				hostname,
				net.IP(ID.upstreamIPAddress[:]))
		}
	}

	flowState := &flowState{
		isDNS:              isDNS,
		activityUpdaters:   activityUpdaters,
		dnsQualityReporter: session.getDNSQualityReporter(),
	}

	if direction == packetDirectionServerUpstream {
		flowState.firstUpstreamPacketTime.Store(now)
		flowState.lastUpstreamPacketTime.Store(now)
	} else {
		flowState.firstDownstreamPacketTime.Store(now)
		flowState.lastDownstreamPacketTime.Store(now)
	}

	// LoadOrStore will retain any existing entry
	session.flows.LoadOrStore(ID, flowState)

	session.updateFlow(ID, direction, applicationData)
}

func (session *session) updateFlow(
	ID flowID,
	direction packetDirection,
	applicationData []byte) {

	f, ok := session.flows.Load(ID)
	if !ok {
		return
	}
	flowState := f.(*flowState)

	// Note: no expired check here, since caller is assumed to
	// have just called isTrackingFlow.

	now := int64(monotime.Now())
	var upstreamBytes, downstreamBytes, durationNanoseconds int64

	if direction == packetDirectionServerUpstream {
		upstreamBytes = int64(len(applicationData))

		flowState.firstUpstreamPacketTime.CompareAndSwap(0, now)

		flowState.lastUpstreamPacketTime.Store(now)

	} else {
		downstreamBytes = int64(len(applicationData))

		flowState.firstDownstreamPacketTime.CompareAndSwap(0, now)

		// Follows common.ActivityMonitoredConn semantics, where
		// duration is updated only for downstream activity. This
		// is intened to produce equivalent behaviour for port
		// forward clients (tracked with ActivityUpdaters) and
		// packet tunnel clients (tracked with FlowActivityUpdaters).

		durationNanoseconds = now - flowState.lastDownstreamPacketTime.Swap(now)
	}

	for _, updater := range flowState.activityUpdaters {
		updater.UpdateProgress(downstreamBytes, upstreamBytes, durationNanoseconds)
	}
}

// deleteFlow stops tracking a flow and logs any outstanding metrics.
// flowState is passed in to avoid duplicating the lookup that all callers
// have already performed.
func (session *session) deleteFlow(ID flowID, flowState *flowState) {

	if flowState.isDNS {

		dnsStartTime := monotime.Time(
			flowState.firstUpstreamPacketTime.Load())

		if dnsStartTime > 0 {

			// Record DNS quality metrics using a heuristic: if a packet was sent and
			// then a packet was received, assume the DNS request successfully received
			// a valid response; failure occurs when the resolver fails to provide a
			// response; a "no such host" response is still a success. Limitations: we
			// assume a resolver will not respond when, e.g., rate limiting; we ignore
			// subsequent requests made via the same UDP/TCP flow; deleteFlow may be
			// called only after the flow has expired, which adds some delay to the
			// recording of the DNS metric.

			dnsEndTime := monotime.Time(
				flowState.firstDownstreamPacketTime.Load())

			dnsSuccess := true
			if dnsEndTime == 0 {
				dnsSuccess = false
				dnsEndTime = monotime.Now()
			}

			resolveElapsedTime := dnsEndTime.Sub(dnsStartTime)

			if flowState.dnsQualityReporter != nil {
				flowState.dnsQualityReporter(
					dnsSuccess,
					resolveElapsedTime,
					net.IP(ID.upstreamIPAddress[:]))
			}
		}
	}

	session.flows.Delete(ID)
}

// reapFlows removes expired idle flows.
func (session *session) reapFlows() {
	session.flows.Range(func(key, value interface{}) bool {
		flowState := value.(*flowState)
		if flowState.expired(FLOW_IDLE_EXPIRY) {
			session.deleteFlow(key.(flowID), flowState)
		}
		return true
	})
}

// deleteFlows deletes all flows.
func (session *session) deleteFlows() {
	session.flows.Range(func(key, value interface{}) bool {
		session.deleteFlow(key.(flowID), value.(*flowState))
		return true
	})
}

type packetMetrics struct {
	upstreamRejectReasons   [packetRejectReasonCount]atomic.Int64
	downstreamRejectReasons [packetRejectReasonCount]atomic.Int64
	TCPIPv4                 relayedPacketMetrics
	TCPIPv6                 relayedPacketMetrics
	UDPIPv4                 relayedPacketMetrics
	UDPIPv6                 relayedPacketMetrics
}

type relayedPacketMetrics struct {
	packetsUp            atomic.Int64
	packetsDown          atomic.Int64
	bytesUp              atomic.Int64
	bytesDown            atomic.Int64
	applicationBytesUp   atomic.Int64
	applicationBytesDown atomic.Int64
}

func (metrics *packetMetrics) rejectedPacket(
	direction packetDirection,
	reason packetRejectReason) {

	if direction == packetDirectionServerUpstream ||
		direction == packetDirectionClientUpstream {

		metrics.upstreamRejectReasons[reason].Add(1)

	} else { // packetDirectionDownstream

		metrics.downstreamRejectReasons[reason].Add(1)

	}
}

func (metrics *packetMetrics) relayedPacket(
	direction packetDirection,
	version int,
	protocol internetProtocol,
	packetLength, applicationDataLength int) {

	var packetsMetric, bytesMetric, applicationBytesMetric *atomic.Int64

	if direction == packetDirectionServerUpstream ||
		direction == packetDirectionClientUpstream {

		if version == 4 {

			if protocol == internetProtocolTCP {
				packetsMetric = &metrics.TCPIPv4.packetsUp
				bytesMetric = &metrics.TCPIPv4.bytesUp
				applicationBytesMetric = &metrics.TCPIPv4.applicationBytesUp
			} else { // UDP
				packetsMetric = &metrics.UDPIPv4.packetsUp
				bytesMetric = &metrics.UDPIPv4.bytesUp
				applicationBytesMetric = &metrics.UDPIPv4.applicationBytesUp
			}

		} else { // IPv6

			if protocol == internetProtocolTCP {
				packetsMetric = &metrics.TCPIPv6.packetsUp
				bytesMetric = &metrics.TCPIPv6.bytesUp
				applicationBytesMetric = &metrics.TCPIPv6.applicationBytesUp
			} else { // UDP
				packetsMetric = &metrics.UDPIPv6.packetsUp
				bytesMetric = &metrics.UDPIPv6.bytesUp
				applicationBytesMetric = &metrics.UDPIPv6.applicationBytesUp
			}
		}

	} else { // packetDirectionDownstream

		if version == 4 {

			if protocol == internetProtocolTCP {
				packetsMetric = &metrics.TCPIPv4.packetsDown
				bytesMetric = &metrics.TCPIPv4.bytesDown
				applicationBytesMetric = &metrics.TCPIPv4.applicationBytesDown
			} else { // UDP
				packetsMetric = &metrics.UDPIPv4.packetsDown
				bytesMetric = &metrics.UDPIPv4.bytesDown
				applicationBytesMetric = &metrics.UDPIPv4.applicationBytesDown
			}

		} else { // IPv6

			if protocol == internetProtocolTCP {
				packetsMetric = &metrics.TCPIPv6.packetsDown
				bytesMetric = &metrics.TCPIPv6.bytesDown
				applicationBytesMetric = &metrics.TCPIPv6.applicationBytesDown
			} else { // UDP
				packetsMetric = &metrics.UDPIPv6.packetsDown
				bytesMetric = &metrics.UDPIPv6.bytesDown
				applicationBytesMetric = &metrics.UDPIPv6.applicationBytesDown
			}
		}
	}

	packetsMetric.Add(1)
	bytesMetric.Add(int64(packetLength))
	applicationBytesMetric.Add(int64(applicationDataLength))
}

const (
	packetMetricsRejected = 1
	packetMetricsRelayed  = 2
	packetMetricsAll      = packetMetricsRejected | packetMetricsRelayed
)

func (metrics *packetMetrics) checkpoint(
	logger common.Logger, updater MetricsUpdater, logName string, whichMetrics int) {

	// Report all metric counters in a single log message. Each
	// counter is reset to 0 when added to the log.

	logFields := make(common.LogFields)

	if whichMetrics&packetMetricsRejected != 0 {

		for i := 0; i < packetRejectReasonCount; i++ {
			logFields["upstream_packet_rejected_"+packetRejectReasonDescription(packetRejectReason(i))] =
				metrics.upstreamRejectReasons[i].Swap(0)
			logFields["downstream_packet_rejected_"+packetRejectReasonDescription(packetRejectReason(i))] =
				metrics.downstreamRejectReasons[i].Swap(0)
		}
	}

	if whichMetrics&packetMetricsRelayed != 0 {

		var TCPApplicationBytesUp, TCPApplicationBytesDown,
			UDPApplicationBytesUp, UDPApplicationBytesDown int64

		relayedMetrics := []struct {
			prefix           string
			metrics          *relayedPacketMetrics
			updaterBytesUp   *int64
			updaterBytesDown *int64
		}{
			{"tcp_ipv4_", &metrics.TCPIPv4, &TCPApplicationBytesUp, &TCPApplicationBytesDown},
			{"tcp_ipv6_", &metrics.TCPIPv6, &TCPApplicationBytesUp, &TCPApplicationBytesDown},
			{"udp_ipv4_", &metrics.UDPIPv4, &UDPApplicationBytesUp, &UDPApplicationBytesDown},
			{"udp_ipv6_", &metrics.UDPIPv6, &UDPApplicationBytesUp, &UDPApplicationBytesDown},
		}

		for _, r := range relayedMetrics {

			applicationBytesUp := r.metrics.applicationBytesUp.Swap(0)
			applicationBytesDown := r.metrics.applicationBytesDown.Swap(0)

			*r.updaterBytesUp += applicationBytesUp
			*r.updaterBytesDown += applicationBytesDown

			logFields[r.prefix+"packets_up"] = r.metrics.packetsUp.Swap(0)
			logFields[r.prefix+"packets_down"] = r.metrics.packetsDown.Swap(0)
			logFields[r.prefix+"bytes_up"] = r.metrics.bytesUp.Swap(0)
			logFields[r.prefix+"bytes_down"] = r.metrics.bytesDown.Swap(0)
			logFields[r.prefix+"application_bytes_up"] = applicationBytesUp
			logFields[r.prefix+"application_bytes_down"] = applicationBytesDown
		}

		if updater != nil {
			updater(
				TCPApplicationBytesDown, TCPApplicationBytesUp,
				UDPApplicationBytesDown, UDPApplicationBytesUp)
		}
	}

	// Not currently a shipped LogMetric.
	logger.WithTraceFields(logFields).Info(logName)
}

// PacketQueue is a fixed-size, preallocated queue of packets.
// Enqueued packets are packed into a contiguous buffer with channel
// framing, allowing the entire queue to be written to a channel
// in a single call.
// Reuse of the queue buffers avoids GC churn. To avoid memory use
// spikes when many clients connect and may disconnect before relaying
// packets, the packet queue buffers start small and grow when required,
// up to the maximum size, and then remain static.
type PacketQueue struct {
	maxSize      int
	emptyBuffers chan []byte
	activeBuffer chan []byte
}

// NewPacketQueue creates a new PacketQueue.
// The caller must ensure that maxSize exceeds the
// packet MTU, or packets will will never enqueue.
func NewPacketQueue(maxSize int) *PacketQueue {

	// Two buffers of size up to maxSize are allocated, to
	// allow packets to continue to enqueue while one buffer
	// is borrowed by the DequeueFramedPackets caller.
	//
	// TODO: is there a way to implement this without
	// allocating up to 2x maxSize bytes? A circular queue
	// won't work because we want DequeueFramedPackets
	// to return a contiguous buffer. Perhaps a Bip
	// Buffer would work here:
	// https://www.codeproject.com/Articles/3479/The-Bip-Buffer-The-Circular-Buffer-with-a-Twist

	queue := &PacketQueue{
		maxSize:      maxSize,
		emptyBuffers: make(chan []byte, 2),
		activeBuffer: make(chan []byte, 1),
	}

	queue.emptyBuffers <- make([]byte, 0)
	queue.emptyBuffers <- make([]byte, 0)

	return queue
}

// Enqueue adds a packet to the queue.
// If the queue is full, the packet is dropped.
// Enqueue is _not_ safe for concurrent calls.
func (queue *PacketQueue) Enqueue(packet []byte) {

	var buffer []byte

	select {
	case buffer = <-queue.activeBuffer:
	default:
		buffer = <-queue.emptyBuffers
	}

	packetSize := len(packet)

	if queue.maxSize-len(buffer) >= channelHeaderSize+packetSize {
		// Assumes len(packet)/MTU <= 64K
		var channelHeader [channelHeaderSize]byte
		binary.BigEndian.PutUint16(channelHeader[:], uint16(packetSize))

		// Once the buffer has reached maxSize capacity
		// and been replaced (buffer = buffer[0:0]), these
		// appends should no longer allocate new memory and
		// should just copy to preallocated memory.

		buffer = append(buffer, channelHeader[:]...)
		buffer = append(buffer, packet...)
	}
	// Else, queue is full, so drop packet.

	queue.activeBuffer <- buffer
}

// DequeueFramedPackets waits until at least one packet is
// enqueued, and then returns a packet buffer containing one
// or more framed packets. The returned buffer remains part
// of the PacketQueue structure and the caller _must_ replace
// the buffer by calling Replace.
// DequeueFramedPackets unblocks and returns false if it receives
// runContext.Done().
// DequeueFramedPackets is _not_ safe for concurrent calls.
func (queue *PacketQueue) DequeueFramedPackets(
	runContext context.Context) ([]byte, bool) {

	var buffer []byte

	select {
	case buffer = <-queue.activeBuffer:
	case <-runContext.Done():
		return nil, false
	}

	return buffer, true
}

// Replace returns the buffer to the PacketQueue to be
// reused.
// The input must be a return value from DequeueFramedPackets.
func (queue *PacketQueue) Replace(buffer []byte) {

	buffer = buffer[0:0]

	// This won't block (as long as it is a DequeueFramedPackets return value).
	queue.emptyBuffers <- buffer
}

// ClientConfig specifies the configuration of a packet tunnel client.
type ClientConfig struct {

	// Logger is used for logging events and metrics.
	Logger common.Logger

	// SudoNetworkConfigCommands specifies whether to use "sudo"
	// when executing network configuration commands. See description
	// for ServerConfig.SudoNetworkConfigCommands.
	SudoNetworkConfigCommands bool

	// AllowNoIPv6NetworkConfiguration indicates that failures while
	// configuring tun interfaces and routing for IPv6 are to be
	// logged as warnings only. See description for
	// ServerConfig.AllowNoIPv6NetworkConfiguration.
	AllowNoIPv6NetworkConfiguration bool

	// MTU is the packet MTU value to use; this value
	// should be obtained from the packet tunnel server.
	// When MTU is 0, a default value is used.
	MTU int

	// UpstreamPacketQueueSize specifies the size of the upstream
	// packet queue.
	// When UpstreamPacketQueueSize is 0, a default value tuned for
	// Psiphon is used.
	UpstreamPacketQueueSize int

	// Transport is an established transport channel that
	// will be used to relay packets to and from a packet
	// tunnel server.
	Transport io.ReadWriteCloser

	// TunFileDescriptor specifies a file descriptor to use to
	// read and write packets to be relayed to the client. When
	// TunFileDescriptor is specified, the Client will use this
	// existing tun device and not create its own; in this case,
	// network address and routing configuration is not performed
	// by the Client. As the packet tunnel server performs
	// transparent source IP address and DNS rewriting, the tun
	// device may have any assigned IP address, but should be
	// configured with the given MTU; and DNS should be configured
	// to use the specified transparent DNS resolver addresses.
	// Set TunFileDescriptor to <= 0 to ignore this parameter
	// and create and configure a tun device.
	TunFileDescriptor int

	// IPv4AddressCIDR is the IPv4 address and netmask to
	// assign to a newly created tun device.
	IPv4AddressCIDR string

	// IPv6AddressCIDR is the IPv6 address and prefix to
	// assign to a newly created tun device.
	IPv6AddressCIDR string

	// TransparentDNSIPv4Address is the IPv4 address of the DNS server
	// configured by a VPN using a packet tunnel. All DNS packets
	// destined to this DNS server are transparently redirected to
	// the Psiphon server DNS.
	TransparentDNSIPv4Address string

	// TransparentDNSIPv4Address is the IPv6 address of the DNS server
	// configured by a VPN using a packet tunnel. All DNS packets
	// destined to this DNS server are transparently redirected to
	// the Psiphon server DNS.
	TransparentDNSIPv6Address string

	// RouteDestinations are hosts (IPs) or networks (CIDRs)
	// to be configured to be routed through a newly
	// created tun device.
	RouteDestinations []string
}

// Client is a packet tunnel client. A packet tunnel client
// relays packets between a local tun device and a packet
// tunnel server via a transport channel.
type Client struct {
	config          *ClientConfig
	transparentDNS  *clientTransparentDNS
	device          *Device
	channel         *Channel
	upstreamPackets *PacketQueue
	metrics         *packetMetrics
	runContext      context.Context
	stopRunning     context.CancelFunc
	workers         *sync.WaitGroup
}

// clientTransparentDNS caches the parsed representions of
// TransparentDNSIPv4/6Address for fast packet processing and rewriting.
type clientTransparentDNS struct {
	IPv4Address net.IP
	IPv6Address net.IP
}

func newClientTransparentDNS(
	IPv4Address, IPv6Address string) (*clientTransparentDNS, error) {

	var IPv4, IPv6 net.IP

	if IPv4Address != "" {
		IPv4 = net.ParseIP(IPv4Address)
		if IPv4 != nil {
			IPv4 = IPv4.To4()
		}
		if IPv4 == nil {
			return nil, errors.TraceNew("invalid IPv4 address")
		}
	}

	if IPv6Address != "" {
		IPv6 = net.ParseIP(IPv6Address)
		if IPv6 == nil || IPv6.To4() != nil {
			return nil, errors.TraceNew("invalid IPv6 address")
		}
	}

	return &clientTransparentDNS{
		IPv4Address: IPv4,
		IPv6Address: IPv6,
	}, nil
}

// NewClient initializes a new Client. Unless using the
// TunFileDescriptor configuration parameter, a new tun
// device is created for the client.
func NewClient(config *ClientConfig) (*Client, error) {

	var device *Device
	var err error

	if config.TunFileDescriptor > 0 {
		device, err = NewClientDeviceFromFD(config)
	} else {
		device, err = NewClientDevice(config)
	}

	if err != nil {
		return nil, errors.Trace(err)
	}

	upstreamPacketQueueSize := DEFAULT_UPSTREAM_PACKET_QUEUE_SIZE
	if config.UpstreamPacketQueueSize > 0 {
		upstreamPacketQueueSize = config.UpstreamPacketQueueSize
	}

	transparentDNS, err := newClientTransparentDNS(
		config.TransparentDNSIPv4Address,
		config.TransparentDNSIPv6Address)
	if err != nil {
		return nil, errors.Trace(err)
	}

	runContext, stopRunning := context.WithCancel(context.Background())

	return &Client{
		config:          config,
		transparentDNS:  transparentDNS,
		device:          device,
		channel:         NewChannel(config.Transport, getMTU(config.MTU)),
		upstreamPackets: NewPacketQueue(upstreamPacketQueueSize),
		metrics:         new(packetMetrics),
		runContext:      runContext,
		stopRunning:     stopRunning,
		workers:         new(sync.WaitGroup),
	}, nil
}

// Start starts a client and returns with it running.
func (client *Client) Start() {

	client.config.Logger.WithTrace().Info("starting")

	client.workers.Add(1)
	go func() {
		defer client.workers.Done()
		for {
			readPacket, err := client.device.ReadPacket()

			select {
			case <-client.runContext.Done():
				// No error is logged as shutdown may have interrupted read.
				return
			default:
			}

			if err != nil {
				client.config.Logger.WithTraceFields(
					common.LogFields{"error": err}).Info("read device packet failed")
				// May be temporary error condition, keep working.
				continue
			}

			// processPacket will check for packets the server will reject
			// and drop those without sending.

			// Limitation: packet metrics, including successful relay count,
			// are incremented _before_ the packet is written to the channel.

			if !processPacket(
				client.metrics,
				nil,
				client.transparentDNS,
				packetDirectionClientUpstream,
				readPacket) {
				continue
			}

			// Instead of immediately writing to the channel, the
			// packet is enqueued, which has the effect of batching
			// up IP packets into a single channel packet (for Psiphon,
			// an SSH packet) to minimize overhead and, as benchmarked,
			// improve throughput.
			// Packet will be dropped if queue is full.

			client.upstreamPackets.Enqueue(readPacket)
		}
	}()

	client.workers.Add(1)
	go func() {
		defer client.workers.Done()
		for {
			packetBuffer, ok := client.upstreamPackets.DequeueFramedPackets(client.runContext)
			if !ok {
				// Dequeue aborted due to session.runContext.Done()
				return
			}

			err := client.channel.WriteFramedPackets(packetBuffer)

			client.upstreamPackets.Replace(packetBuffer)

			if err != nil {
				client.config.Logger.WithTraceFields(
					common.LogFields{"error": err}).Info("write channel packets failed")
				// May be temporary error condition, such as reconnecting the tunnel;
				// keep working. The packets are most likely dropped.
				continue
			}
		}
	}()

	client.workers.Add(1)
	go func() {
		defer client.workers.Done()
		for {
			readPacket, err := client.channel.ReadPacket()

			select {
			case <-client.runContext.Done():
				// No error is logged as shutdown may have interrupted read.
				return
			default:
			}

			if err != nil {
				client.config.Logger.WithTraceFields(
					common.LogFields{"error": err}).Info("read channel packet failed")
				// May be temporary error condition, such as reconnecting the tunnel;
				// keep working.
				continue
			}

			if !processPacket(
				client.metrics,
				nil,
				client.transparentDNS,
				packetDirectionClientDownstream,
				readPacket) {
				continue
			}

			err = client.device.WritePacket(readPacket)

			if err != nil {
				client.config.Logger.WithTraceFields(
					common.LogFields{"error": err}).Info("write device packet failed")
				// May be temporary error condition, keep working. The packet is
				// most likely dropped.
				continue
			}
		}
	}()
}

// Stop halts a running client.
func (client *Client) Stop() {

	client.config.Logger.WithTrace().Info("stopping")

	client.stopRunning()
	client.device.Close()
	client.channel.Close()

	client.workers.Wait()

	client.metrics.checkpoint(
		client.config.Logger, nil, "packet_metrics", packetMetricsAll)

	client.config.Logger.WithTrace().Info("stopped")
}

/*
   Packet offset constants in getPacketDestinationIPAddress and
   processPacket are from the following RFC definitions.


   IPv4 header: https://tools.ietf.org/html/rfc791

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Version|  IHL  |Type of Service|          Total Length         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Identification        |Flags|      Fragment Offset    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Time to Live |    Protocol   |         Header Checksum       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Source Address                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Destination Address                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Options                    |    Padding    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   IPv6 header: https://tools.ietf.org/html/rfc2460

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Version| Traffic Class |           Flow Label                  |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Payload Length        |  Next Header  |   Hop Limit   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   +                                                               +
   |                                                               |
   +                         Source Address                        +
   |                                                               |
   +                                                               +
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   +                                                               +
   |                                                               |
   +                      Destination Address                      +
   |                                                               |
   +                                                               +
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   TCP header: https://tools.ietf.org/html/rfc793

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          Source Port          |       Destination Port        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        Sequence Number                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Acknowledgment Number                      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Data |           |U|A|P|R|S|F|                               |
   | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
   |       |           |G|K|H|T|N|N|                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Checksum            |         Urgent Pointer        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Options                    |    Padding    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                             data                              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   UDP header: https://tools.ietf.org/html/rfc768

                  0      7 8     15 16    23 24    31
                 +--------+--------+--------+--------+
                 |     Source      |   Destination   |
                 |      Port       |      Port       |
                 +--------+--------+--------+--------+
                 |                 |                 |
                 |     Length      |    Checksum     |
                 +--------+--------+--------+--------+
                 |
                 |          data octets ...
                 +---------------- ...
*/

const (
	packetDirectionServerUpstream   = 0
	packetDirectionServerDownstream = 1
	packetDirectionClientUpstream   = 2
	packetDirectionClientDownstream = 3

	internetProtocolTCP = 6
	internetProtocolUDP = 17

	portNumberDNS = 53

	packetRejectNoSession          = 0
	packetRejectDestinationAddress = 1
	packetRejectLength             = 2
	packetRejectVersion            = 3
	packetRejectOptions            = 4
	packetRejectProtocol           = 5
	packetRejectTCPProtocolLength  = 6
	packetRejectUDPProtocolLength  = 7
	packetRejectTCPPort            = 8
	packetRejectUDPPort            = 9
	packetRejectNoOriginalAddress  = 10
	packetRejectNoDNSResolvers     = 11
	packetRejectInvalidDNSMessage  = 12
	packetRejectDisallowedDomain   = 13
	packetRejectNoClient           = 14
	packetRejectReasonCount        = 15
	packetOk                       = 15
)

type packetDirection int
type internetProtocol int
type packetRejectReason int

func packetRejectReasonDescription(reason packetRejectReason) string {

	// Description strings follow the metrics naming
	// convention: all lowercase; underscore seperators.

	switch reason {
	case packetRejectNoSession:
		return "no_session"
	case packetRejectDestinationAddress:
		return "invalid_destination_address"
	case packetRejectLength:
		return "invalid_ip_packet_length"
	case packetRejectVersion:
		return "invalid_ip_header_version"
	case packetRejectOptions:
		return "invalid_ip_header_options"
	case packetRejectProtocol:
		return "invalid_ip_header_protocol"
	case packetRejectTCPProtocolLength:
		return "invalid_tcp_packet_length"
	case packetRejectUDPProtocolLength:
		return "invalid_tcp_packet_length"
	case packetRejectTCPPort:
		return "disallowed_tcp_destination_port"
	case packetRejectUDPPort:
		return "disallowed_udp_destination_port"
	case packetRejectNoOriginalAddress:
		return "no_original_address"
	case packetRejectNoDNSResolvers:
		return "no_dns_resolvers"
	case packetRejectInvalidDNSMessage:
		return "invalid_dns_message"
	case packetRejectDisallowedDomain:
		return "disallowed_domain"
	case packetRejectNoClient:
		return "no_client"
	}

	return "unknown_reason"
}

// Caller: the destination IP address return value is
// a slice of the packet input value and only valid while
// the packet buffer remains valid.
func getPacketDestinationIPAddress(
	metrics *packetMetrics,
	direction packetDirection,
	packet []byte) (net.IP, bool) {

	// TODO: this function duplicates a subset of the packet
	// parsing code in processPacket. Refactor to reuse code;
	// also, both getPacketDestinationIPAddress and processPacket
	// are called for some packets; refactor to only parse once.

	if len(packet) < 1 {
		metrics.rejectedPacket(direction, packetRejectLength)
		return nil, false
	}

	version := packet[0] >> 4

	if version != 4 && version != 6 {
		metrics.rejectedPacket(direction, packetRejectVersion)
		return nil, false
	}

	if version == 4 {
		if len(packet) < 20 {
			metrics.rejectedPacket(direction, packetRejectLength)
			return nil, false
		}

		return packet[16:20], true

	} else { // IPv6
		if len(packet) < 40 {
			metrics.rejectedPacket(direction, packetRejectLength)
			return nil, false
		}

		return packet[24:40], true
	}
}

// processPacket parses IP packets, applies relaying rules,
// and rewrites packet elements as required. processPacket
// returns true if a packet parses correctly, is accepted
// by the relay rules, and is successfully rewritten.
//
// When a packet is rejected, processPacket returns false
// and updates a reason in the supplied metrics.
//
// Rejection may result in partially rewritten packets.
func processPacket(
	metrics *packetMetrics,
	session *session,
	clientTransparentDNS *clientTransparentDNS,
	direction packetDirection,
	packet []byte) bool {

	// Parse and validate IP packet structure

	// Must have an IP version field.
	if len(packet) < 1 {
		metrics.rejectedPacket(direction, packetRejectLength)
		return false
	}

	version := packet[0] >> 4

	// Must be IPv4 or IPv6.
	if version != 4 && version != 6 {
		metrics.rejectedPacket(direction, packetRejectVersion)
		return false
	}

	var protocol internetProtocol
	var sourceIPAddress, destinationIPAddress net.IP
	var sourcePort, destinationPort uint16
	var IPChecksum, TCPChecksum, UDPChecksum []byte
	var applicationData []byte

	if version == 4 {

		// IHL must be 5: options are not supported; a fixed
		// 20 byte header is expected.

		headerLength := packet[0] & 0x0F

		if headerLength != 5 {
			metrics.rejectedPacket(direction, packetRejectOptions)
			return false
		}

		if len(packet) < 20 {
			metrics.rejectedPacket(direction, packetRejectLength)
			return false
		}

		// Protocol must be TCP or UDP.

		protocol = internetProtocol(packet[9])
		dataOffset := 0

		if protocol == internetProtocolTCP {
			if len(packet) < 38 {
				metrics.rejectedPacket(direction, packetRejectTCPProtocolLength)
				return false
			}
			dataOffset = 20 + 4*int(packet[32]>>4)
			if len(packet) < dataOffset {
				metrics.rejectedPacket(direction, packetRejectTCPProtocolLength)
				return false
			}
		} else if protocol == internetProtocolUDP {
			dataOffset = 28
			if len(packet) < dataOffset {
				metrics.rejectedPacket(direction, packetRejectUDPProtocolLength)
				return false
			}
		} else {
			metrics.rejectedPacket(direction, packetRejectProtocol)
			return false
		}

		applicationData = packet[dataOffset:]

		// Slices reference packet bytes to be rewritten.

		sourceIPAddress = packet[12:16]
		destinationIPAddress = packet[16:20]
		IPChecksum = packet[10:12]

		// Port numbers have the same offset in TCP and UDP.

		sourcePort = binary.BigEndian.Uint16(packet[20:22])
		destinationPort = binary.BigEndian.Uint16(packet[22:24])

		if protocol == internetProtocolTCP {
			TCPChecksum = packet[36:38]
		} else { // UDP
			UDPChecksum = packet[26:28]
		}

	} else { // IPv6

		if len(packet) < 40 {
			metrics.rejectedPacket(direction, packetRejectLength)
			return false
		}

		// Next Header must be TCP or UDP.

		nextHeader := packet[6]

		protocol = internetProtocol(nextHeader)
		dataOffset := 0

		if protocol == internetProtocolTCP {
			if len(packet) < 58 {
				metrics.rejectedPacket(direction, packetRejectTCPProtocolLength)
				return false
			}
			dataOffset = 40 + 4*int(packet[52]>>4)
			if len(packet) < dataOffset {
				metrics.rejectedPacket(direction, packetRejectTCPProtocolLength)
				return false
			}
		} else if protocol == internetProtocolUDP {
			dataOffset = 48
			if len(packet) < dataOffset {
				metrics.rejectedPacket(direction, packetRejectUDPProtocolLength)
				return false
			}
		} else {
			metrics.rejectedPacket(direction, packetRejectProtocol)
			return false
		}

		applicationData = packet[dataOffset:]

		// Slices reference packet bytes to be rewritten.

		sourceIPAddress = packet[8:24]
		destinationIPAddress = packet[24:40]

		// Port numbers have the same offset in TCP and UDP.

		sourcePort = binary.BigEndian.Uint16(packet[40:42])
		destinationPort = binary.BigEndian.Uint16(packet[42:44])

		if protocol == internetProtocolTCP {
			TCPChecksum = packet[56:58]
		} else { // UDP
			UDPChecksum = packet[46:48]
		}
	}

	// Apply rules
	//
	// Most of this logic is only applied on the server, as only
	// the server knows the traffic rules configuration, and is
	// tracking flows.

	isServer := (direction == packetDirectionServerUpstream ||
		direction == packetDirectionServerDownstream)

	// Check if the packet qualifies for transparent DNS rewriting
	//
	// - Both TCP and UDP DNS packets may qualify
	// - Unless configured, transparent DNS flows are not tracked,
	//   as most DNS resolutions are very-short lived exchanges
	// - The traffic rules checks are bypassed, since transparent
	//   DNS is essential

	// Transparent DNS is a two-step translation. On the client, the VPN
	// can be configured with any private address range, so as to not
	// conflict with other local networks, such as WiFi. For example, the
	// client may select from 192.168.0.0/16, when an existing interface
	// uses a subnet in 10.0.0.0/8, and specify the VPN DNS server as 192.168.0.1.
	//
	// The first translation, on the client side, rewrites packets
	// destined to 192.168.0.1:53, the DNS server, to the destination
	// transparentDNSResolverIPv4Address:53. This packet is sent to the
	// server.
	//
	// The second translation, on the server side, rewrites packets
	// destined to transparentDNSResolverIPv4Address:53 to an actual DNS
	// server destination.
	//
	// Then, reverse rewrites are applied to DNS response packets: the
	// server rewrites the source address actual-DNS-server:53 to
	// transparentDNSResolverIPv4Address:53, and then the client rewrites
	// the source address transparentDNSResolverIPv4Address:53 to
	// 192.168.0.1:53, and that packet is written to the tun device.

	doTransparentDNS := false

	if isServer {
		if direction == packetDirectionServerUpstream {

			// DNS packets destinated for the transparent DNS target addresses
			// will be rewritten to go to one of the server's resolvers.

			if destinationPort == portNumberDNS {
				if version == 4 &&
					destinationIPAddress.Equal(transparentDNSResolverIPv4Address) {

					numResolvers := len(session.DNSResolverIPv4Addresses)
					if numResolvers > 0 {
						doTransparentDNS = true
					} else {
						metrics.rejectedPacket(direction, packetRejectNoDNSResolvers)
						return false
					}

				} else if version == 6 &&
					destinationIPAddress.Equal(transparentDNSResolverIPv6Address) {

					numResolvers := len(session.DNSResolverIPv6Addresses)
					if numResolvers > 0 {
						doTransparentDNS = true
					} else {
						metrics.rejectedPacket(direction, packetRejectNoDNSResolvers)
						return false
					}
				}

				// Limitation: checkAllowedDomainFunc is applied only to DNS queries in
				// UDP; currently DNS-over-TCP will bypass the domain block list check.

				if doTransparentDNS && protocol == internetProtocolUDP {

					domain, err := common.ParseDNSQuestion(applicationData)
					if err != nil {
						metrics.rejectedPacket(direction, packetRejectInvalidDNSMessage)
						return false
					}
					if domain != "" {
						checkAllowedDomainFunc := session.getCheckAllowedDomainFunc()
						if !checkAllowedDomainFunc(domain) {
							metrics.rejectedPacket(direction, packetRejectDisallowedDomain)
							return false
						}
					}
				}
			}

		} else { // packetDirectionServerDownstream

			// DNS packets with a source address of any of the server's
			// resolvers will be rewritten back to the transparent DNS target
			// address.

			// Limitation: responses to client DNS packets _originally
			// destined_ for a resolver in GetDNSResolverIPv4Addresses will
			// be lost. This would happen if some process on the client
			// ignores the system set DNS values; and forces use of the same
			// resolvers as the server.

			if sourcePort == portNumberDNS {
				if version == 4 {
					for _, IPAddress := range session.DNSResolverIPv4Addresses {
						if sourceIPAddress.Equal(IPAddress) {
							doTransparentDNS = true
							break
						}
					}
				} else if version == 6 {
					for _, IPAddress := range session.DNSResolverIPv6Addresses {
						if sourceIPAddress.Equal(IPAddress) {
							doTransparentDNS = true
							break
						}
					}
				}
			}
		}

	} else { // isClient

		if direction == packetDirectionClientUpstream {

			// DNS packets destined to the configured VPN DNS servers,
			// specified in clientTransparentDNS, are rewritten to go to
			// transparentDNSResolverIPv4/6Address.

			if destinationPort == portNumberDNS {
				if (version == 4 && destinationIPAddress.Equal(clientTransparentDNS.IPv4Address)) ||
					(version == 6 && destinationIPAddress.Equal(clientTransparentDNS.IPv6Address)) {
					doTransparentDNS = true
				}
			}

		} else { // packetDirectionClientDownstream

			// DNS packets with a transparentDNSResolverIPv4/6Address source
			// address are rewritten to come from the configured VPN DNS servers.

			if sourcePort == portNumberDNS {
				if (version == 4 && sourceIPAddress.Equal(transparentDNSResolverIPv4Address)) ||
					(version == 6 && sourceIPAddress.Equal(transparentDNSResolverIPv6Address)) {
					doTransparentDNS = true
				}
			}
		}
	}

	// Apply rewrites before determining flow ID to ensure that corresponding up-
	// and downstream flows yield the same flow ID.

	var rewriteSourceIPAddress, rewriteDestinationIPAddress net.IP

	if direction == packetDirectionServerUpstream {

		// Store original source IP address to be replaced in
		// downstream rewriting.

		if version == 4 {
			session.setOriginalIPv4AddressIfNotSet(sourceIPAddress)
			rewriteSourceIPAddress = session.assignedIPv4Address
		} else { // version == 6
			session.setOriginalIPv6AddressIfNotSet(sourceIPAddress)
			rewriteSourceIPAddress = session.assignedIPv6Address
		}

		// Rewrite DNS packets destinated for the transparent DNS target addresses
		// to go to one of the server's resolvers. This random selection uses
		// math/rand to minimize overhead.
		//
		// Limitation: TCP packets are always assigned to the same resolver, as
		// currently there is no method for tracking the assigned resolver per TCP
		// flow.

		if doTransparentDNS {
			if version == 4 {

				index := session.TCPDNSResolverIPv4Index
				if protocol == internetProtocolUDP {
					index = rand.Intn(len(session.DNSResolverIPv4Addresses))
				}
				rewriteDestinationIPAddress = session.DNSResolverIPv4Addresses[index]

			} else { // version == 6

				index := session.TCPDNSResolverIPv6Index
				if protocol == internetProtocolUDP {
					index = rand.Intn(len(session.DNSResolverIPv6Addresses))
				}
				rewriteDestinationIPAddress = session.DNSResolverIPv6Addresses[index]
			}
		}

	} else if direction == packetDirectionServerDownstream {

		// Destination address will be original source address.

		if version == 4 {
			rewriteDestinationIPAddress = session.getOriginalIPv4Address()
		} else if version == 6 {
			rewriteDestinationIPAddress = session.getOriginalIPv6Address()
		}

		if rewriteDestinationIPAddress == nil {
			metrics.rejectedPacket(direction, packetRejectNoOriginalAddress)
			return false
		}

		// Rewrite source address of packets from servers' resolvers
		// to transparent DNS target address.

		if doTransparentDNS {

			if version == 4 {
				rewriteSourceIPAddress = transparentDNSResolverIPv4Address
			} else if version == 6 {
				rewriteSourceIPAddress = transparentDNSResolverIPv6Address
			}
		}

	} else if direction == packetDirectionClientUpstream {

		// Rewrite the destination address to be
		// transparentDNSResolverIPv4/6Address, which the server will
		// subsequently send on to actual DNS servers.

		if doTransparentDNS {

			if version == 4 {
				rewriteDestinationIPAddress = transparentDNSResolverIPv4Address
			} else if version == 6 {
				rewriteDestinationIPAddress = transparentDNSResolverIPv6Address
			}
		}
	} else if direction == packetDirectionClientDownstream {

		// Rewrite the source address so the DNS response appears to come from
		// the configured VPN DNS server.

		if doTransparentDNS {

			if version == 4 {
				rewriteSourceIPAddress = clientTransparentDNS.IPv4Address
			} else if version == 6 {
				rewriteSourceIPAddress = clientTransparentDNS.IPv6Address
			}
		}
	}

	// Check if flow is tracked before checking traffic permission

	doFlowTracking := isServer && (!doTransparentDNS || session.enableDNSFlowTracking)

	// TODO: verify this struct is stack allocated
	var ID flowID

	isTrackingFlow := false

	if doFlowTracking {

		if direction == packetDirectionServerUpstream {

			// Reflect rewrites in the upstream case and don't reflect rewrites in the
			// following downstream case: all flow IDs are in the upstream space, with
			// the assigned private IP for the client and, in the case of DNS, the
			// actual resolver IP.

			srcIP := sourceIPAddress
			if rewriteSourceIPAddress != nil {
				srcIP = rewriteSourceIPAddress
			}

			destIP := destinationIPAddress
			if rewriteDestinationIPAddress != nil {
				destIP = rewriteDestinationIPAddress
			}

			ID.set(srcIP, sourcePort, destIP, destinationPort, protocol)

		} else if direction == packetDirectionServerDownstream {

			ID.set(
				destinationIPAddress,
				destinationPort,
				sourceIPAddress,
				sourcePort,
				protocol)
		}

		isTrackingFlow = session.isTrackingFlow(ID)
	}

	// Check packet source/destination is permitted; except for:
	// - existing flows, which have already been checked
	// - transparent DNS, which is always allowed

	if !doTransparentDNS && !isTrackingFlow {

		// Enforce traffic rules (allowed TCP/UDP ports).

		checkPort := 0
		if direction == packetDirectionServerUpstream ||
			direction == packetDirectionClientUpstream {

			checkPort = int(destinationPort)

		} else if direction == packetDirectionServerDownstream ||
			direction == packetDirectionClientDownstream {

			checkPort = int(sourcePort)
		}

		if protocol == internetProtocolTCP {

			invalidPort := (checkPort == 0)

			if !invalidPort && isServer {
				checkAllowedTCPPortFunc := session.getCheckAllowedTCPPortFunc()
				if checkAllowedTCPPortFunc == nil ||
					!checkAllowedTCPPortFunc(net.IP(ID.upstreamIPAddress[:]), checkPort) {
					invalidPort = true
				}
			}

			if invalidPort {
				metrics.rejectedPacket(direction, packetRejectTCPPort)
				return false
			}

		} else if protocol == internetProtocolUDP {

			invalidPort := (checkPort == 0)

			if !invalidPort && isServer {
				checkAllowedUDPPortFunc := session.getCheckAllowedUDPPortFunc()
				if checkAllowedUDPPortFunc == nil ||
					!checkAllowedUDPPortFunc(net.IP(ID.upstreamIPAddress[:]), checkPort) {
					invalidPort = true
				}
			}

			if invalidPort {
				metrics.rejectedPacket(direction, packetRejectUDPPort)
				return false
			}
		}

		// Enforce no localhost, multicast or broadcast packets; and no
		// client-to-client packets.
		//
		// TODO: a client-side check could check that destination IP
		// is strictly a tun device IP address.

		if !destinationIPAddress.IsGlobalUnicast() ||

			(direction == packetDirectionServerUpstream &&
				!session.allowBogons &&
				common.IsBogon(destinationIPAddress)) ||

			// Client-to-client packets are disallowed even when other bogons are
			// allowed.
			(direction == packetDirectionServerUpstream &&
				((version == 4 &&
					!destinationIPAddress.Equal(transparentDNSResolverIPv4Address) &&
					privateSubnetIPv4.Contains(destinationIPAddress)) ||
					(version == 6 &&
						!destinationIPAddress.Equal(transparentDNSResolverIPv6Address) &&
						privateSubnetIPv6.Contains(destinationIPAddress)))) {

			metrics.rejectedPacket(direction, packetRejectDestinationAddress)
			return false
		}
	}

	// Apply packet rewrites. IP (v4 only) and TCP/UDP all have packet
	// checksums which are updated to relect the rewritten headers.

	var checksumAccumulator int32

	if rewriteSourceIPAddress != nil {
		checksumAccumulate(sourceIPAddress, false, &checksumAccumulator)
		copy(sourceIPAddress, rewriteSourceIPAddress)
		checksumAccumulate(sourceIPAddress, true, &checksumAccumulator)
	}

	if rewriteDestinationIPAddress != nil {
		checksumAccumulate(destinationIPAddress, false, &checksumAccumulator)
		copy(destinationIPAddress, rewriteDestinationIPAddress)
		checksumAccumulate(destinationIPAddress, true, &checksumAccumulator)
	}

	if rewriteSourceIPAddress != nil || rewriteDestinationIPAddress != nil {

		// IPv6 doesn't have an IP header checksum.
		if version == 4 {
			checksumAdjust(IPChecksum, checksumAccumulator)
		}

		if protocol == internetProtocolTCP {
			checksumAdjust(TCPChecksum, checksumAccumulator)
		} else { // UDP
			checksumAdjust(UDPChecksum, checksumAccumulator)
		}
	}

	// Start/update flow tracking, only once past all possible packet rejects

	if doFlowTracking {
		if !isTrackingFlow {
			session.startTrackingFlow(ID, direction, applicationData, doTransparentDNS)
		} else {
			session.updateFlow(ID, direction, applicationData)
		}
	}

	metrics.relayedPacket(direction, int(version), protocol, len(packet), len(applicationData))

	return true
}

// Checksum code based on https://github.com/OpenVPN/openvpn:
/*
OpenVPN (TM) -- An Open Source VPN daemon

Copyright (C) 2002-2017 OpenVPN Technologies, Inc. <sales@openvpn.net>

OpenVPN license:
----------------

OpenVPN is distributed under the GPL license version 2 (see COPYRIGHT.GPL).
*/

func checksumAccumulate(data []byte, newData bool, accumulator *int32) {

	// Based on ADD_CHECKSUM_32 and SUB_CHECKSUM_32 macros from OpenVPN:
	// https://github.com/OpenVPN/openvpn/blob/58716979640b5d8850b39820f91da616964398cc/src/openvpn/proto.h#L177

	// Assumes length of data is factor of 4.

	for i := 0; i < len(data); i += 4 {
		word := uint32(data[i+0])<<24 | uint32(data[i+1])<<16 | uint32(data[i+2])<<8 | uint32(data[i+3])
		if newData {
			*accumulator -= int32(word & 0xFFFF)
			*accumulator -= int32(word >> 16)
		} else {
			*accumulator += int32(word & 0xFFFF)
			*accumulator += int32(word >> 16)
		}
	}
}

func checksumAdjust(checksumData []byte, accumulator int32) {

	// Based on ADJUST_CHECKSUM macro from OpenVPN:
	// https://github.com/OpenVPN/openvpn/blob/58716979640b5d8850b39820f91da616964398cc/src/openvpn/proto.h#L177

	// Assumes checksumData is 2 byte slice.

	checksum := uint16(checksumData[0])<<8 | uint16(checksumData[1])

	accumulator += int32(checksum)
	if accumulator < 0 {
		accumulator = -accumulator
		accumulator = (accumulator >> 16) + (accumulator & 0xFFFF)
		accumulator += accumulator >> 16
		checksum = uint16(^accumulator)
	} else {
		accumulator = (accumulator >> 16) + (accumulator & 0xFFFF)
		accumulator += accumulator >> 16
		checksum = uint16(accumulator)
	}

	checksumData[0] = byte(checksum >> 8)
	checksumData[1] = byte(checksum & 0xFF)
}

/*

packet debugging snippet:

	import (
        "github.com/google/gopacket"
        "github.com/google/gopacket/layers"
	)


	func tracePacket(where string, packet []byte) {
		var p gopacket.Packet
		if len(packet) > 0 && packet[0]>>4 == 4 {
			p = gopacket.NewPacket(packet, layers.LayerTypeIPv4, gopacket.Default)
		} else {
			p = gopacket.NewPacket(packet, layers.LayerTypeIPv6, gopacket.Default)
		}
		fmt.Printf("[%s packet]:\n%s\n\n", where, p)
	}
*/

// Device manages a tun device. It handles packet I/O using static,
// preallocated buffers to avoid GC churn.
type Device struct {
	name           string
	writeMutex     sync.Mutex
	deviceIO       io.ReadWriteCloser
	inboundBuffer  []byte
	outboundBuffer []byte
}

// NewServerDevice creates and configures a new server tun device.
// Since the server uses fixed address spaces, only one server
// device may exist per host.
func NewServerDevice(config *ServerConfig) (*Device, error) {

	file, deviceName, err := OpenTunDevice("")
	if err != nil {
		return nil, errors.Trace(err)
	}

	err = configureServerInterface(config, deviceName)
	if err != nil {
		_ = file.Close()
		return nil, errors.Trace(err)
	}

	return newDevice(
		deviceName,
		file,
		getMTU(config.MTU)), nil
}

// NewClientDevice creates and configures a new client tun device.
// Multiple client tun devices may exist per host.
func NewClientDevice(config *ClientConfig) (*Device, error) {

	file, deviceName, err := OpenTunDevice("")
	if err != nil {
		return nil, errors.Trace(err)
	}

	err = configureClientInterface(
		config, deviceName)
	if err != nil {
		_ = file.Close()
		return nil, errors.Trace(err)
	}

	return newDevice(
		deviceName,
		file,
		getMTU(config.MTU)), nil
}

func newDevice(
	name string,
	deviceIO io.ReadWriteCloser,
	MTU int) *Device {

	return &Device{
		name:           name,
		deviceIO:       deviceIO,
		inboundBuffer:  makeDeviceInboundBuffer(MTU),
		outboundBuffer: makeDeviceOutboundBuffer(MTU),
	}
}

// NewClientDeviceFromFD wraps an existing tun device.
func NewClientDeviceFromFD(config *ClientConfig) (*Device, error) {

	file, err := fileFromFD(config.TunFileDescriptor, "")
	if err != nil {
		return nil, errors.Trace(err)
	}

	MTU := getMTU(config.MTU)

	return &Device{
		name:           "",
		deviceIO:       file,
		inboundBuffer:  makeDeviceInboundBuffer(MTU),
		outboundBuffer: makeDeviceOutboundBuffer(MTU),
	}, nil
}

// Name returns the interface name for a created tun device,
// or returns "" for a device created by NewClientDeviceFromFD.
// The interface name may be used for additional network and
// routing configuration.
func (device *Device) Name() string {
	return device.name
}

// ReadPacket reads one full packet from the tun device. The
// return value is a slice of a static, reused buffer, so the
// value is only valid until the next ReadPacket call.
// Concurrent calls to ReadPacket are _not_ supported.
func (device *Device) ReadPacket() ([]byte, error) {

	// readTunPacket performs the platform dependent
	// packet read operation.
	offset, size, err := device.readTunPacket()
	if err != nil {
		return nil, errors.Trace(err)
	}

	return device.inboundBuffer[offset : offset+size], nil
}

// WritePacket writes one full packet to the tun device.
// Concurrent calls to WritePacket are supported.
func (device *Device) WritePacket(packet []byte) error {

	// This mutex ensures that only one concurrent goroutine
	// can use outboundBuffer when writing.
	device.writeMutex.Lock()
	defer device.writeMutex.Unlock()

	// writeTunPacket performs the platform dependent
	// packet write operation.
	err := device.writeTunPacket(packet)
	if err != nil {
		return errors.Trace(err)
	}

	return nil
}

// Close interrupts any blocking Read/Write calls and
// tears down the tun device.
func (device *Device) Close() error {
	return device.deviceIO.Close()
}

// Channel manages packet transport over a communications channel.
// Any io.ReadWriteCloser can provide transport. In psiphond, the
// io.ReadWriteCloser will be an SSH channel. Channel I/O frames
// packets with a length header and uses static, preallocated
// buffers to avoid GC churn.
type Channel struct {
	transport      io.ReadWriteCloser
	inboundBuffer  []byte
	outboundBuffer []byte
}

// IP packets cannot be larger that 64K, so a 16-bit length
// header is sufficient.
const (
	channelHeaderSize = 2
)

// NewChannel initializes a new Channel.
func NewChannel(transport io.ReadWriteCloser, MTU int) *Channel {
	return &Channel{
		transport:      transport,
		inboundBuffer:  make([]byte, channelHeaderSize+MTU),
		outboundBuffer: make([]byte, channelHeaderSize+MTU),
	}
}

// ReadPacket reads one full packet from the channel. The
// return value is a slice of a static, reused buffer, so the
// value is only valid until the next ReadPacket call.
// Concurrent calls to ReadPacket are not supported.
func (channel *Channel) ReadPacket() ([]byte, error) {

	header := channel.inboundBuffer[0:channelHeaderSize]
	_, err := io.ReadFull(channel.transport, header)
	if err != nil {
		return nil, errors.Trace(err)
	}

	size := int(binary.BigEndian.Uint16(header))
	if size > len(channel.inboundBuffer[channelHeaderSize:]) {
		return nil, errors.Tracef("packet size exceeds MTU: %d", size)
	}

	packet := channel.inboundBuffer[channelHeaderSize : channelHeaderSize+size]
	_, err = io.ReadFull(channel.transport, packet)
	if err != nil {
		return nil, errors.Trace(err)
	}

	return packet, nil
}

// WritePacket writes one full packet to the channel.
// Concurrent calls to WritePacket are not supported.
func (channel *Channel) WritePacket(packet []byte) error {

	// Flow control assumed to be provided by the transport. In the case
	// of SSH, the channel window size will determine whether the packet
	// data is transmitted immediately or whether the transport.Write will
	// block. When the channel window is full and transport.Write blocks,
	// the sender's tun device will not be read (client case) or the send
	// queue will fill (server case) and packets will be dropped. In this
	// way, the channel window size will influence the TCP window size for
	// tunneled traffic.

	// When the transport is an SSH channel, the overhead per packet message
	// includes:
	//
	// - SSH_MSG_CHANNEL_DATA: 5 bytes (https://tools.ietf.org/html/rfc4254#section-5.2)
	// - SSH packet: ~28 bytes (https://tools.ietf.org/html/rfc4253#section-5.3), with MAC
	// - TCP/IP transport for SSH: 40 bytes for IPv4

	// Assumes MTU <= 64K and len(packet) <= MTU

	size := len(packet)
	binary.BigEndian.PutUint16(channel.outboundBuffer, uint16(size))
	copy(channel.outboundBuffer[channelHeaderSize:], packet)
	_, err := channel.transport.Write(channel.outboundBuffer[0 : channelHeaderSize+size])
	if err != nil {
		return errors.Trace(err)
	}

	return nil
}

// WriteFramedPackets writes a buffer of pre-framed packets to
// the channel.
// Concurrent calls to WriteFramedPackets are not supported.
func (channel *Channel) WriteFramedPackets(packetBuffer []byte) error {
	_, err := channel.transport.Write(packetBuffer)
	if err != nil {
		return errors.Trace(err)
	}
	return nil
}

// Close interrupts any blocking Read/Write calls and
// closes the channel transport.
func (channel *Channel) Close() error {
	return channel.transport.Close()
}
