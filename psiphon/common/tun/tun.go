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
within an SSH connection to a Psiphom server.

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
arbitrary IP address and a static DNS resolver address.

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
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	// TODO: use stdlib in Go 1.9
	"golang.org/x/sync/syncmap"

	"github.com/Psiphon-Inc/goarista/monotime"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
)

const (
	DEFAULT_MTU                          = 1500
	DEFAULT_DOWNSTREAM_PACKET_QUEUE_SIZE = 64
	DEFAULT_IDLE_SESSION_EXPIRY_SECONDS  = 300
	ORPHAN_METRICS_CHECKPOINTER_PERIOD   = 30 * time.Minute
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

	// DownStreamPacketQueueSize specifies the size of the downstream
	// packet queue. The packet tunnel server multiplexes all client
	// packets through a single tun device, so when a packet is read,
	// it must be queued or dropped if it cannot be immediately routed
	// to the appropriate client. Note that the TCP and SSH windows
	// for the underlying channel transport will impact transfer rate
	// and queuing.
	// When DownStreamPacketQueueSize is 0, a default value is used.
	DownStreamPacketQueueSize int

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
	indexToSession      syncmap.Map
	sessionIDToIndex    syncmap.Map
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
		return nil, common.ContextError(err)
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

	server.config.Logger.WithContext().Info("starting")

	server.workers.Add(1)
	go server.runSessionReaper()

	server.workers.Add(1)
	go server.runOrphanMetricsCheckpointer()

	server.workers.Add(1)
	go server.runDeviceDownstream()
}

// Stop halts a running server.
func (server *Server) Stop() {

	server.config.Logger.WithContext().Info("stopping")

	server.stopRunning()

	// Interrupt blocked device read/writes.
	server.device.Close()

	// Wait for any in-progress ClientConnected calls to complete.
	server.connectedInProgress.Wait()

	// After this point, no futher clients will be added: all
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

	server.config.Logger.WithContext().Info("stopped")
}

type AllowedPortChecker func(upstreamIPAddress net.IP, port int) bool

// ClientConnected handles new client connections, creating or resuming
// a session and returns with client packet handlers running.
//
// sessionID is used to identify sessions for resumption.
//
// transport provides the channel for relaying packets to and from
// the client.
//
// checkAllowedTCPPortFunc/checkAllowedUDPPortFunc are callbacks used
// to enforce traffic rules. For each TCP/UDP packet, the corresponding
// function is called to check if traffic to the packet's port is
// permitted. These callbacks must be efficient and safe for concurrent
// calls.
//
// It is safe to make concurrent calls to ClientConnected for distinct
// session IDs. The caller is responsible for serializing calls with the
// same session ID. Futher, the caller must ensure, in the case of a client
// transport reconnect when an existing transport has not yet disconnected,
// that ClientDisconnected is called first -- so it doesn't undo the new
// ClientConnected. (psiphond meets these constraints by closing any
// existing SSH client with duplicate session ID early in the lifecycle of
// a new SSH client connection.)
func (server *Server) ClientConnected(
	sessionID string,
	transport io.ReadWriteCloser,
	checkAllowedTCPPortFunc, checkAllowedUDPPortFunc AllowedPortChecker) error {

	// It's unusual to call both sync.WaitGroup.Add() _and_ Done() in the same
	// goroutine. There's no other place to call Add() since ClientConnected is
	// an API entrypoint. And Done() works because the invariant enforced by
	// connectedInProgress.Wait() is not that no ClientConnected calls are in
	// progress, but that no such calls are in progress past the
	// server.runContext.Done() check.

	server.connectedInProgress.Add(1)
	defer server.connectedInProgress.Done()

	select {
	case <-server.runContext.Done():
		return common.ContextError(errors.New("server stopping"))
	default:
	}

	server.config.Logger.WithContextFields(
		common.LogFields{"sessionID": sessionID}).Info("client connected")

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

		downStreamPacketQueueSize := DEFAULT_DOWNSTREAM_PACKET_QUEUE_SIZE
		if server.config.DownStreamPacketQueueSize > 0 {
			downStreamPacketQueueSize = server.config.DownStreamPacketQueueSize
		}

		// Store IPv4 resolver addresses in 4-byte representation
		// for use in rewritting.
		resolvers := server.config.GetDNSResolverIPv4Addresses()
		DNSResolverIPv4Addresses := make([]net.IP, len(resolvers))
		for i, resolver := range resolvers {
			// Assumes To4 is non-nil
			DNSResolverIPv4Addresses[i] = resolver.To4()
		}

		clientSession = &session{
			lastActivity:             int64(monotime.Now()),
			sessionID:                sessionID,
			metrics:                  new(packetMetrics),
			DNSResolverIPv4Addresses: append([]net.IP(nil), DNSResolverIPv4Addresses...),
			DNSResolverIPv6Addresses: append([]net.IP(nil), server.config.GetDNSResolverIPv6Addresses()...),
			checkAllowedTCPPortFunc:  checkAllowedTCPPortFunc,
			checkAllowedUDPPortFunc:  checkAllowedUDPPortFunc,
			downstreamPackets:        make(chan []byte, downStreamPacketQueueSize),
			freePackets:              make(chan []byte, downStreamPacketQueueSize),
			workers:                  new(sync.WaitGroup),
		}

		// To avoid GC churn, downstream packet buffers are allocated
		// once and reused. Available buffers are sent to the freePackets
		// channel. When a packet is enqueued, a buffer is obtained from
		// freePackets and sent to downstreamPackets.
		// TODO: allocate on first use? if the full queue size is not
		// often used, preallocating all buffers is unnecessary.

		for i := 0; i < downStreamPacketQueueSize; i++ {
			clientSession.freePackets <- make([]byte, MTU)
		}

		// allocateIndex initializes session.index, session.assignedIPv4Address,
		// and session.assignedIPv6Address; and updates server.indexToSession and
		// server.sessionIDToIndex.

		err := server.allocateIndex(clientSession)
		if err != nil {
			return common.ContextError(err)
		}
	}

	server.resumeSession(clientSession, NewChannel(transport, MTU))

	return nil
}

// ClientDisconnected handles clients disconnecting. Packet handlers
// are halted, but the client session is left intact to reserve the
// assigned IP addresses and retain network state in case the client
// soon reconnects.
func (server *Server) ClientDisconnected(sessionID string) {

	session := server.getSession(sessionID)
	if session != nil {

		server.config.Logger.WithContextFields(
			common.LogFields{"sessionID": sessionID}).Info("client disconnected")

		server.interruptSession(session)
	}
}

func (server *Server) getSession(sessionID string) *session {

	if index, ok := server.sessionIDToIndex.Load(sessionID); ok {
		s, ok := server.indexToSession.Load(index.(int32))
		if ok {
			return s.(*session)
		}
		server.config.Logger.WithContext().Warning("unexpected missing session")
	}
	return nil
}

func (server *Server) resumeSession(session *session, channel *Channel) {

	session.mutex.Lock()
	session.mutex.Unlock()

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

	session.stopRunning()
	if session.channel != nil {
		// Interrupt blocked channel read/writes.
		session.channel.Close()
	}
	session.workers.Wait()
	if session.channel != nil {
		// Don't hold a reference to channel, allowing both it and
		// its conn to be garbage collected.
		// Setting channel to nil must happen after workers.Wait()
		// to ensure no goroutines remains which may access
		// session.channel.
		session.channel = nil
	}

	// interruptSession may be called for idle sessions, to ensure
	// the session is in an expected state: in ClientConnected,
	// and in server.Stop(); don't log in those cases.
	if wasRunning {
		session.metrics.checkpoint(
			server.config.Logger, "packet_metrics", packetMetricsAll)
	}

}

func (server *Server) runSessionReaper() {

	defer server.workers.Done()

	// Periodically iterate over all sessions and discard expired
	// sessions. This action, removing the index from server.indexToSession,
	// releases the IP addresses assigned  to the session.

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
			server.config.Logger, "orphan_packet_metrics", packetMetricsRejected)
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
			server.config.Logger.WithContextFields(
				common.LogFields{"error": err}).Warning("read device packet failed")
			// May be temporary error condition, keep reading.
			continue
		}

		// destinationIPAddress determines which client recieves this packet.
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

		// Simply enqueue the packet for client handling, and move on to
		// read the next packet. The packet tunnel server multiplexes all
		// client packets through a single tun device, so we must not block
		// on client channel I/O here.
		//
		// When the queue is full, the packet is dropped. This is standard
		// behavior for routers, VPN servers, etc.
		//
		// We allow packets to enqueue in an idle session in case a client
		// is in the process of reconnecting.

		var packet []byte
		select {
		case packet = <-session.freePackets:
		case <-server.runContext.Done():
			return
		default:
			// Queue is full, so drop packet.
			continue
		}

		// Reuse the preallocated packet buffer. This slice indexing
		// assumes the size of the packet <= MTU and the preallocated
		// capacity == MTU.
		packet = packet[0:len(readPacket)]
		copy(packet, readPacket)

		// This won't block: both freePackets/downstreamPackets have
		// queue-size capacity, and only queue-size packet buffers
		// exist.
		session.downstreamPackets <- packet
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
			server.config.Logger.WithContextFields(
				common.LogFields{"error": err}).Warning("read channel packet failed")
			// Tear down the session. Must be invoked asynchronously.
			go server.interruptSession(session)
			return
		}

		session.touch()

		// processPacket transparently rewrites the source address to the
		// session's assigned address and rewrites the destination of any
		// DNS packets destined to the target DNS resolver.
		//
		// The first time the source address is rewritten, the original
		// value is recorded so inbound packets can have the reverse
		// rewrite applied. This assumes that the client will send a
		// packet before receiving any packet, which is the case since
		// only clients can initiate TCP or UDP connections or flows.

		if !processPacket(
			session.metrics,
			session,
			packetDirectionServerUpstream,
			readPacket) {

			// Packet is rejected and dropped. Reason will be counted in metrics.
			continue
		}

		err = server.device.WritePacket(readPacket)

		if err != nil {
			server.config.Logger.WithContextFields(
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
		var packet []byte
		select {
		case packet = <-session.downstreamPackets:
		case <-session.runContext.Done():
			return
		}

		// In downstream mode, processPacket rewrites the destination address
		// to the original client source IP address, and also rewrites DNS
		// packets. As documented in runClientUpstream, the original address
		// should already be populated via an upstream packet; if not, the
		// packet will be rejected.

		if !processPacket(
			session.metrics,
			session,
			packetDirectionServerDownstream,
			packet) {

			// Packet is rejected and dropped. Reason will be counted in metrics.
			continue
		}

		err := session.channel.WritePacket(packet)
		if err != nil {
			server.config.Logger.WithContextFields(
				common.LogFields{"error": err}).Warning("write channel packet failed")
			// Tear down the session. Must be invoked asynchronously.
			go server.interruptSession(session)
			return
		}

		session.touch()

		// This won't block.
		session.freePackets <- packet
	}
}

var (
	serverIPv4AddressCIDR             = "10.0.0.1/8"
	transparentDNSResolverIPv4Address = net.ParseIP("10.0.0.2").To4() // 4-byte for rewriting
	_, privateSubnetIPv4, _           = net.ParseCIDR("10.0.0.0/8")
	assignedIPv4AddressTemplate       = "10.%02d.%02d.%02d"

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

	randomInt, err := common.MakeSecureRandomInt(max + 1)
	if err != nil {
		return common.ContextError(err)
	}

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
		//   (10.0.0.1, and IPv6 equivilent)
		// - 2 is reserver as the transparent DNS target
		//   address (10.0.0.2, and IPv6 equivilent)

		if index <= 2 {
			continue
		}
		if index == 0x00FFFFFF {
			index = 0
			continue
		}
		if s, ok := server.indexToSession.LoadOrStore(index, newSession); ok {
			// Index is already in use or aquired concurrently.
			// If the existing session is expired, reap it and use index.
			existingSession := s.(*session)
			if existingSession.expired(idleExpiry) {
				server.removeSession(existingSession)
			} else {
				continue
			}
		}

		// Note: the To4() for assignedIPv4Address is essential since
		// that address value is assumed to be 4 bytes when rewriting.

		newSession.index = index
		newSession.assignedIPv4Address = server.convertIndexToIPv4Address(index).To4()
		newSession.assignedIPv6Address = server.convertIndexToIPv6Address(index)
		server.sessionIDToIndex.Store(newSession.sessionID, index)

		server.resetRouting(newSession.assignedIPv4Address, newSession.assignedIPv6Address)

		return nil
	}

	return common.ContextError(errors.New("unallocated index not found"))
}

func (server *Server) resetRouting(IPv4Address, IPv6Address net.IP) {

	// Attempt to clear the NAT table of any existing connection
	// states. This will prevent the (already unlikely) delivery
	// of packets to the wrong client when an assigned IP address is
	// recycled. Silently has no effect on some platforms, see
	// resetNATTables implementations.

	err := resetNATTables(server.config, IPv4Address)
	if err != nil {
		server.config.Logger.WithContextFields(
			common.LogFields{"error": err}).Warning("reset IPv4 routing failed")

	}

	err = resetNATTables(server.config, IPv6Address)
	if err != nil {
		server.config.Logger.WithContextFields(
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

// GetTransparentDNSResolverIPv4Address returns the static IPv4 address
// to use as a DNS resolver when transparent DNS rewriting is desired.
func GetTransparentDNSResolverIPv4Address() net.IP {
	return transparentDNSResolverIPv4Address
}

// GetTransparentDNSResolverIPv4Address returns the static IPv6 address
// to use as a DNS resolver when transparent DNS rewriting is desired.
func GeTransparentDNSResolverIPv6Address() net.IP {
	return transparentDNSResolverIPv6Address
}

type session struct {
	// Note: 64-bit ints used with atomic operations are placed
	// at the start of struct to ensure 64-bit alignment.
	// (https://golang.org/pkg/sync/atomic/#pkg-note-BUG)
	lastActivity             int64
	metrics                  *packetMetrics
	sessionID                string
	index                    int32
	DNSResolverIPv4Addresses []net.IP
	assignedIPv4Address      net.IP
	setOriginalIPv4Address   int32
	originalIPv4Address      net.IP
	DNSResolverIPv6Addresses []net.IP
	assignedIPv6Address      net.IP
	setOriginalIPv6Address   int32
	originalIPv6Address      net.IP
	checkAllowedTCPPortFunc  AllowedPortChecker
	checkAllowedUDPPortFunc  AllowedPortChecker
	downstreamPackets        chan []byte
	freePackets              chan []byte
	workers                  *sync.WaitGroup
	mutex                    sync.Mutex
	channel                  *Channel
	runContext               context.Context
	stopRunning              context.CancelFunc
}

func (session *session) touch() {
	atomic.StoreInt64(&session.lastActivity, int64(monotime.Now()))
}

func (session *session) expired(idleExpiry time.Duration) bool {
	lastActivity := monotime.Time(atomic.LoadInt64(&session.lastActivity))
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

type packetMetrics struct {
	upstreamRejectReasons   [packetRejectReasonCount]int64
	downstreamRejectReasons [packetRejectReasonCount]int64
	TCPIPv4                 relayedPacketMetrics
	TCPIPv6                 relayedPacketMetrics
	UDPIPv4                 relayedPacketMetrics
	UDPIPv6                 relayedPacketMetrics
}

type relayedPacketMetrics struct {
	packetsUp   int64
	packetsDown int64
	bytesUp     int64
	bytesDown   int64
}

func (metrics *packetMetrics) rejectedPacket(
	direction packetDirection,
	reason packetRejectReason) {

	if direction == packetDirectionServerUpstream ||
		direction == packetDirectionClientUpstream {

		atomic.AddInt64(&metrics.upstreamRejectReasons[reason], 1)

	} else { // packetDirectionDownstream

		atomic.AddInt64(&metrics.downstreamRejectReasons[reason], 1)

	}
}

func (metrics *packetMetrics) relayedPacket(
	direction packetDirection,
	version int,
	protocol internetProtocol,
	upstreamIPAddress net.IP,
	packetLength int) {

	// TODO: OSL integration
	// - Update OSL up/down progress for upstreamIPAddress.
	// - For port forwards, OSL progress tracking involves one SeedSpecs subnets
	//   lookup per port forward; this may be too much overhead per packet; OSL
	//   progress tracking also uses port forward duration as an input.
	// - Can we do simple flow tracking to achive the same (a) lookup rate,
	//   (b) duration measurement? E.g., track flow via 4-tuple of source/dest
	//   IP/port?

	var packetsMetric, bytesMetric *int64

	if direction == packetDirectionServerUpstream ||
		direction == packetDirectionClientUpstream {

		if version == 4 {

			if protocol == internetProtocolTCP {
				packetsMetric = &metrics.TCPIPv4.packetsUp
				bytesMetric = &metrics.TCPIPv4.bytesUp
			} else { // UDP
				packetsMetric = &metrics.UDPIPv4.packetsUp
				bytesMetric = &metrics.UDPIPv4.bytesUp
			}

		} else { // IPv6

			if protocol == internetProtocolTCP {
				packetsMetric = &metrics.TCPIPv6.packetsUp
				bytesMetric = &metrics.TCPIPv6.bytesUp
			} else { // UDP
				packetsMetric = &metrics.UDPIPv6.packetsUp
				bytesMetric = &metrics.UDPIPv6.bytesUp
			}
		}

	} else { // packetDirectionDownstream

		if version == 4 {

			if protocol == internetProtocolTCP {
				packetsMetric = &metrics.TCPIPv4.packetsDown
				bytesMetric = &metrics.TCPIPv4.bytesDown
			} else { // UDP
				packetsMetric = &metrics.UDPIPv4.packetsDown
				bytesMetric = &metrics.UDPIPv4.bytesDown
			}

		} else { // IPv6

			if protocol == internetProtocolTCP {
				packetsMetric = &metrics.TCPIPv6.packetsDown
				bytesMetric = &metrics.TCPIPv6.bytesDown
			} else { // UDP
				packetsMetric = &metrics.UDPIPv6.packetsDown
				bytesMetric = &metrics.UDPIPv6.bytesDown
			}
		}
	}

	// Note: packet length, and so bytes transferred, includes IP and TCP/UDP
	// headers, not just payload data, as is counted in port forwarding. It
	// makes sense to include this packet overhead, since we have to tunnel it.

	atomic.AddInt64(packetsMetric, 1)
	atomic.AddInt64(bytesMetric, int64(packetLength))
}

const (
	packetMetricsRejected = 1
	packetMetricsRelayed  = 2
	packetMetricsAll      = packetMetricsRejected | packetMetricsRelayed
)

func (metrics *packetMetrics) checkpoint(
	logger common.Logger, logName string, whichMetrics int) {

	// Report all metric counters in a single log message. Each
	// counter is reset to 0 when added to the log.

	logFields := make(common.LogFields)

	if whichMetrics&packetMetricsRejected != 0 {

		for i := 0; i < packetRejectReasonCount; i++ {
			logFields["upstream_packet_rejected_"+packetRejectReasonDescription(packetRejectReason(i))] =
				atomic.SwapInt64(&metrics.upstreamRejectReasons[i], 0)
			logFields["downstream_packet_rejected_"+packetRejectReasonDescription(packetRejectReason(i))] =
				atomic.SwapInt64(&metrics.downstreamRejectReasons[i], 0)
		}
	}

	if whichMetrics&packetMetricsRelayed != 0 {

		relayedMetrics := []struct {
			prefix  string
			metrics *relayedPacketMetrics
		}{
			{"tcp_ipv4_", &metrics.TCPIPv4},
			{"tcp_ipv6_", &metrics.TCPIPv6},
			{"udp_ipv4_", &metrics.UDPIPv4},
			{"udp_ipv6_", &metrics.UDPIPv6},
		}

		for _, r := range relayedMetrics {
			logFields[r.prefix+"packets_up"] = atomic.SwapInt64(&r.metrics.packetsUp, 0)
			logFields[r.prefix+"packets_down"] = atomic.SwapInt64(&r.metrics.packetsDown, 0)
			logFields[r.prefix+"bytes_up"] = atomic.SwapInt64(&r.metrics.bytesUp, 0)
			logFields[r.prefix+"bytes_down"] = atomic.SwapInt64(&r.metrics.bytesDown, 0)
		}
	}

	logger.LogMetric(logName, logFields)
}

// ClientConfig specifies the configuration of a packet tunnel client.
type ClientConfig struct {

	// Logger is used for logging events and metrics.
	Logger common.Logger

	// SudoNetworkConfigCommands specifies whether to use "sudo"
	// when executing network configuration commands. See description
	// for ServerConfig.SudoNetworkConfigCommands.
	SudoNetworkConfigCommands bool

	// MTU is the packet MTU value to use; this value
	// should be obtained from the packet tunnel server.
	// When MTU is 0, a default value is used.
	MTU int

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
	// to use the transparent DNS target resolver addresses.
	// Set TunFileDescriptor to <= 0 to ignore this parameter
	// and create and configure a tun device.
	TunFileDescriptor int

	// IPv4AddressCIDR is the IPv4 address and netmask to
	// assign to a newly created tun device.
	IPv4AddressCIDR string

	// IPv6AddressCIDR is the IPv6 address and prefix to
	// assign to a newly created tun device.
	IPv6AddressCIDR string

	// RouteDestinations are hosts (IPs) or networks (CIDRs)
	// to be configured to be routed through a newly
	// created tun device.
	RouteDestinations []string
}

// Client is a packet tunnel client. A packet tunnel client
// relays packets between a local tun device and a packet
// tunnel server via a transport channel.
type Client struct {
	config      *ClientConfig
	device      *Device
	channel     *Channel
	metrics     *packetMetrics
	runContext  context.Context
	stopRunning context.CancelFunc
	workers     *sync.WaitGroup
}

// NewClient initializes a new Client. Unless using the
// TunFileDescriptor configuration parameter, a new tun
// device is created for the client.
func NewClient(config *ClientConfig) (*Client, error) {

	var device *Device
	var err error

	if config.TunFileDescriptor <= 0 {
		device, err = NewClientDevice(config)
	} else {
		device, err = NewClientDeviceFromFD(config)
	}
	if err != nil {
		return nil, common.ContextError(err)
	}

	runContext, stopRunning := context.WithCancel(context.Background())

	return &Client{
		config:      config,
		device:      device,
		channel:     NewChannel(config.Transport, getMTU(config.MTU)),
		metrics:     new(packetMetrics),
		runContext:  runContext,
		stopRunning: stopRunning,
		workers:     new(sync.WaitGroup),
	}, nil
}

// Start starts a client and returns with it running.
func (client *Client) Start() {

	client.config.Logger.WithContext().Info("starting")

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
				client.config.Logger.WithContextFields(
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
				packetDirectionClientUpstream,
				readPacket) {
				continue
			}

			err = client.channel.WritePacket(readPacket)

			if err != nil {
				client.config.Logger.WithContextFields(
					common.LogFields{"error": err}).Info("write channel packet failed")
				// Only this goroutine exits and no alarm is raised. It's assumed
				// that if the channel fails, the outer client will know about it.
				return
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
				client.config.Logger.WithContextFields(
					common.LogFields{"error": err}).Info("read channel packet failed")
				// Only this goroutine exits and no alarm is raised. It's assumed
				// that if the channel fails, the outer client will know about it.
				return
			}

			if !processPacket(
				client.metrics,
				nil,
				packetDirectionClientDownstream,
				readPacket) {
				continue
			}

			err = client.device.WritePacket(readPacket)

			if err != nil {
				client.config.Logger.WithContextFields(
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

	client.config.Logger.WithContext().Info("stopping")

	client.stopRunning()
	client.device.Close()
	client.channel.Close()

	client.workers.Wait()

	client.metrics.checkpoint(
		client.config.Logger, "packet_metrics", packetMetricsAll)

	client.config.Logger.WithContext().Info("stopped")
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
	packetRejectReasonCount        = 12
	packetOk                       = 12
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

	return nil, false
}

func processPacket(
	metrics *packetMetrics,
	session *session,
	direction packetDirection,
	packet []byte) bool {

	// Parse and validate packets and perform either upstream
	// or downstream rewriting.
	// Failures may result in partially rewritten packets.

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

		if protocol == internetProtocolTCP {
			if len(packet) < 40 {
				metrics.rejectedPacket(direction, packetRejectTCPProtocolLength)
				return false
			}
		} else if protocol == internetProtocolUDP {
			if len(packet) < 28 {
				metrics.rejectedPacket(direction, packetRejectUDPProtocolLength)
				return false
			}
		} else {
			metrics.rejectedPacket(direction, packetRejectProtocol)
			return false
		}

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

		if protocol == internetProtocolTCP {
			if len(packet) < 60 {
				metrics.rejectedPacket(direction, packetRejectTCPProtocolLength)
				return false
			}
		} else if protocol == internetProtocolUDP {
			if len(packet) < 48 {
				metrics.rejectedPacket(direction, packetRejectUDPProtocolLength)
				return false
			}
		} else {
			metrics.rejectedPacket(direction, packetRejectProtocol)
			return false
		}

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

	var upstreamIPAddress net.IP
	if direction == packetDirectionServerUpstream {

		upstreamIPAddress = destinationIPAddress

	} else if direction == packetDirectionServerDownstream {

		upstreamIPAddress = sourceIPAddress
	}

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

		if checkPort == 0 ||
			(session != nil &&
				!session.checkAllowedTCPPortFunc(upstreamIPAddress, checkPort)) {

			metrics.rejectedPacket(direction, packetRejectTCPPort)
			return false
		}

	} else if protocol == internetProtocolUDP {

		if checkPort == 0 ||
			(session != nil &&
				!session.checkAllowedUDPPortFunc(upstreamIPAddress, checkPort)) {

			metrics.rejectedPacket(direction, packetRejectUDPPort)
			return false
		}
	}

	// Enforce no localhost, multicast or broadcast packets; and
	// no client-to-client packets.

	if !destinationIPAddress.IsGlobalUnicast() ||

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

	// Configure rewriting.

	var checksumAccumulator int32
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

		// Rewrite DNS packets destinated for the transparent DNS target
		// addresses to go to one of the server's resolvers.

		if destinationPort == portNumberDNS {
			if version == 4 && destinationIPAddress.Equal(transparentDNSResolverIPv4Address) {
				numResolvers := len(session.DNSResolverIPv4Addresses)
				if numResolvers > 0 {
					rewriteDestinationIPAddress = session.DNSResolverIPv4Addresses[rand.Intn(numResolvers)]
				} else {
					metrics.rejectedPacket(direction, packetRejectNoDNSResolvers)
					return false
				}

			} else if version == 6 && destinationIPAddress.Equal(transparentDNSResolverIPv6Address) {
				numResolvers := len(session.DNSResolverIPv6Addresses)
				if numResolvers > 0 {
					rewriteDestinationIPAddress = session.DNSResolverIPv6Addresses[rand.Intn(numResolvers)]
				} else {
					metrics.rejectedPacket(direction, packetRejectNoDNSResolvers)
					return false
				}
			}
		}

	} else if direction == packetDirectionServerDownstream {

		// Destination address will be original source address.

		if version == 4 {
			rewriteDestinationIPAddress = session.getOriginalIPv4Address()
		} else { // version == 6
			rewriteDestinationIPAddress = session.getOriginalIPv6Address()
		}

		if rewriteDestinationIPAddress == nil {
			metrics.rejectedPacket(direction, packetRejectNoOriginalAddress)
			return false
		}

		// Source address for DNS packets from the server's resolvers
		// will be changed to transparent DNS target address.

		// Limitation: responses to client DNS packets _originally
		// destined_ for a resolver in GetDNSResolverIPv4Addresses will
		// be lost. This would happen if some process on the client
		// ignores the system set DNS values; and forces use of the same
		// resolvers as the server.

		if sourcePort == portNumberDNS {
			if version == 4 {
				for _, IPAddress := range session.DNSResolverIPv4Addresses {
					if sourceIPAddress.Equal(IPAddress) {
						rewriteSourceIPAddress = transparentDNSResolverIPv4Address
						break
					}
				}
			} else if version == 6 {
				for _, IPAddress := range session.DNSResolverIPv6Addresses {
					if sourceIPAddress.Equal(IPAddress) {
						rewriteSourceIPAddress = transparentDNSResolverIPv6Address
						break
					}
				}
			}
		}
	}

	// Apply rewrites. IP (v4 only) and TCP/UDP all have packet
	// checksums which are updated to relect the rewritten headers.

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

	metrics.relayedPacket(direction, int(version), protocol, upstreamIPAddress, len(packet))

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
		var word uint32
		word = uint32(data[i+0])<<24 | uint32(data[i+1])<<16 | uint32(data[i+2])<<8 | uint32(data[i+3])
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
	deviceIO       io.ReadWriteCloser
	inboundBuffer  []byte
	outboundBuffer []byte
}

// NewServerDevice creates and configures a new server tun device.
// Since the server uses fixed address spaces, only one server
// device may exist per host.
func NewServerDevice(config *ServerConfig) (*Device, error) {

	deviceIO, deviceName, err := createTunDevice()
	if err != nil {
		return nil, common.ContextError(err)
	}

	err = configureServerInterface(config, deviceName)
	if err != nil {
		return nil, common.ContextError(err)
	}

	return newDevice(deviceName, deviceIO, getMTU(config.MTU)), nil
}

// NewClientDevice creates and configures a new client tun device.
// Multiple client tun devices may exist per host.
func NewClientDevice(config *ClientConfig) (*Device, error) {

	deviceIO, deviceName, err := createTunDevice()
	if err != nil {
		return nil, common.ContextError(err)
	}

	err = configureClientInterface(
		config, deviceName)
	if err != nil {
		return nil, common.ContextError(err)
	}

	return newDevice(deviceName, deviceIO, getMTU(config.MTU)), nil
}

func newDevice(
	name string, deviceIO io.ReadWriteCloser, MTU int) *Device {

	return &Device{
		name:           name,
		deviceIO:       deviceIO,
		inboundBuffer:  makeDeviceInboundBuffer(MTU),
		outboundBuffer: makeDeviceOutboundBuffer(MTU),
	}
}

// NewClientDeviceFromFD wraps an existing tun device.
func NewClientDeviceFromFD(config *ClientConfig) (*Device, error) {

	dupFD, err := dupCloseOnExec(config.TunFileDescriptor)
	if err != nil {
		return nil, common.ContextError(err)
	}

	file := os.NewFile(uintptr(dupFD), "")

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
// Concurrent calls to ReadPacket are not supported.
func (device *Device) ReadPacket() ([]byte, error) {

	// readTunPacket performs the platform dependent
	// packet read operation.
	offset, size, err := device.readTunPacket()
	if err != nil {
		return nil, common.ContextError(err)
	}

	return device.inboundBuffer[offset : offset+size], nil
}

// WritePacket writes one full packet to the tun device.
// Concurrent calls to WritePacket are not supported.
func (device *Device) WritePacket(packet []byte) error {

	// writeTunPacket performs the platform dependent
	// packet write operation.
	err := device.writeTunPacket(packet)
	if err != nil {
		return common.ContextError(err)
	}

	return nil
}

// Close interrupts any blocking Read/Write calls and
// tears down the tun device.
func (device *Device) Close() error {

	// TODO: dangerous data race exists until Go 1.9
	//
	// https://github.com/golang/go/issues/7970
	//
	// Unlike net.Conns, os.File doesn't use the poller and
	// it's not correct to use Close() cannot to interrupt
	// blocking reads and writes. This changes in Go 1.9,
	// which changes os.File to use the poller.
	//
	// Severity may be high since there's a remote possibility
	// that a Write could send a packet to wrong fd, including
	// sending as plaintext to a network socket.
	//
	// As of this writing, we do not expect to put this
	// code into production before Go 1.9 is released. Since
	// interrupting blocking Read/Writes is necessary, the
	// race condition is left as-is.
	//
	// This appears running tun_test with the race detector
	// enabled:
	//
	// ==================
	// WARNING: DATA RACE
	// Write at 0x00c4200ce220 by goroutine 16:
	//   os.(*file).close()
	//       /usr/local/go/src/os/file_unix.go:143 +0x10a
	//   os.(*File).Close()
	//       /usr/local/go/src/os/file_unix.go:132 +0x55
	//   _/root/psiphon-tunnel-core/psiphon/common/tun.(*Device).Close()
	//       /root/psiphon-tunnel-core/psiphon/common/tun/tun.go:1999 +0x53
	//   _/root/psiphon-tunnel-core/psiphon/common/tun.(*Client).Stop()
	//       /root/psiphon-tunnel-core/psiphon/common/tun/tun.go:1314 +0x1a8
	//   _/root/psiphon-tunnel-core/psiphon/common/tun.(*testClient).stop()
	//       /root/psiphon-tunnel-core/psiphon/common/tun/tun_test.go:426 +0x77
	//   _/root/psiphon-tunnel-core/psiphon/common/tun.testTunneledTCP.func1()
	//       /root/psiphon-tunnel-core/psiphon/common/tun/tun_test.go:172 +0x550
	//
	// Previous read at 0x00c4200ce220 by goroutine 100:
	//   os.(*File).Read()
	//       /usr/local/go/src/os/file.go:98 +0x70
	//   _/root/psiphon-tunnel-core/psiphon/common/tun.(*Device).readTunPacket()
	//       /root/psiphon-tunnel-core/psiphon/common/tun/tun_linux.go:109 +0x84
	//   _/root/psiphon-tunnel-core/psiphon/common/tun.(*Device).ReadPacket()
	//       /root/psiphon-tunnel-core/psiphon/common/tun/tun.go:1974 +0x3c
	//   _/root/psiphon-tunnel-core/psiphon/common/tun.(*Client).Start.func1()
	//       /root/psiphon-tunnel-core/psiphon/common/tun/tun.go:1224 +0xaf
	// ==================

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
		return nil, common.ContextError(err)
	}

	size := int(binary.BigEndian.Uint16(header))
	if size > len(channel.inboundBuffer[channelHeaderSize:]) {
		return nil, common.ContextError(fmt.Errorf("packet size exceeds MTU: %d", size))
	}

	packet := channel.inboundBuffer[channelHeaderSize : channelHeaderSize+size]
	_, err = io.ReadFull(channel.transport, packet)
	if err != nil {
		return nil, common.ContextError(err)
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

	// Writes are not batched up but dispatched immediately. When the
	// transport is an SSH channel, the overhead per tunneled packet includes:
	//
	// - SSH_MSG_CHANNEL_DATA: 5 bytes (https://tools.ietf.org/html/rfc4254#section-5.2)
	// - SSH packet: ~28 bytes (https://tools.ietf.org/html/rfc4253#section-5.3), with MAC
	// - TCP/IP transport for SSH: 40 bytes for IPv4
	//
	// Also, when the transport in an SSH channel, batching of packets will
	// naturally occur when the SSH channel window is full.

	// Assumes MTU <= 64K and len(packet) <= MTU

	size := len(packet)
	binary.BigEndian.PutUint16(channel.outboundBuffer, uint16(size))
	copy(channel.outboundBuffer[channelHeaderSize:], packet)
	_, err := channel.transport.Write(channel.outboundBuffer[0 : channelHeaderSize+size])
	if err != nil {
		return common.ContextError(err)
	}

	return nil
}

// Close interrupts any blocking Read/Write calls and
// closes the channel transport.
func (channel *Channel) Close() error {
	return channel.transport.Close()
}
