//go:build !PSIPHON_DISABLE_QUIC
// +build !PSIPHON_DISABLE_QUIC

/*
 * Copyright (c) 2018, Psiphon Inc.
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

package quic

import (
	"context"
	"crypto/sha256"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/crypto/Yawning/chacha20"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/transforms"
	ietf_quic "github.com/Psiphon-Labs/quic-go"
	"github.com/Psiphon-Labs/quic-go/logging"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/net/ipv4"
)

const (

	// MAX_PACKET_SIZE is the largest packet size quic-go will produce,
	// including post MTU discovery. This value is quic-go
	// internal/protocol.MaxPacketBufferSize, which is the Ethernet MTU of
	// 1500 less IPv6 and UDP header sizes.
	//
	// Legacy gQUIC quic-go will produce packets no larger than
	// MAX_PRE_DISCOVERY_PACKET_SIZE_IPV4/IPV6.

	MAX_PACKET_SIZE = 1452

	// MAX_PRE_DISCOVERY_PACKET_SIZE is the largest packet size quic-go will
	// produce before MTU discovery.

	MAX_PRE_DISCOVERY_PACKET_SIZE = 1280

	// OBFUSCATED_MAX_PACKET_SIZE_ADJUSTMENT is the minimum amount of bytes
	// required for obfuscation overhead, the nonce and the padding length.
	// In IETF quic-go, this adjustment value is passed into quic-go and
	// applied to packet construction so that quic-go produces max packet
	// sizes reduced by this adjustment value.

	OBFUSCATED_MAX_PACKET_SIZE_ADJUSTMENT = NONCE_SIZE + 1

	// MIN_FIRST_PACKET_SIZE is checked before any peer state is allocated,
	// ensuring small packets can't result in allocation. Currently the
	// smallest legitimate first packet is a 1024 byte gQUIC CHLO. IETF
	// Initial packets are larger, at least 1171 bytes with the in-proxy
	// media stream adjustment, and quic-go enforces their minimum size, but
	// only after peer state allocation. The MIN_FIRST_PACKET_SIZE check
	// assumes a flow's first packet from an address is an Initial;
	// connection migration would break that assumption.

	MIN_FIRST_PACKET_SIZE = 1024

	MAX_PADDING_SIZE       = 255
	MAX_GQUIC_PADDING_SIZE = 64

	MIN_DECOY_PACKETS = 0
	MAX_DECOY_PACKETS = 10

	NONCE_SIZE = 12

	RANDOM_STREAM_LIMIT = 1<<38 - 64

	CONCURRENT_WRITER_LIMIT = 5000

	MAX_PEERS            = 1000000
	MAX_REAP_PEERS       = 100000
	PENDING_PEER_TIMEOUT = 10 * time.Second

	// UNESTABLISHED_PEER_TIMEOUT exceeds quic-go's absolute handshake
	// timeout, 2x HandshakeIdleTimeout, so a peer state entry doesn't become
	// stale before its QUIC handshake completes or times out; see
	// the "unknown peer" comment in writePacket.

	UNESTABLISHED_PEER_TIMEOUT = 2*SERVER_HANDSHAKE_TIMEOUT + 10*time.Second

	SOURCE_ADDRESS_VALIDATION_TRIGGER_CONCURRENT_HANDSHAKES = 1000

	// MAX_CONCURRENT_HANDSHAKES bounds quic-go connection allocations,
	// roughly 100 KB each.

	MAX_CONCURRENT_HANDSHAKES = 10000

	// MAX_CONCURRENT_HANDSHAKES_PER_IP accommodate many clients behind one
	// NAT or proxy. Enforced only for address validated handshakes; see
	// handshakeStarted.

	MAX_CONCURRENT_HANDSHAKES_PER_IP = 100
)

// quic_test overrides the peer mode limits.
var (
	maxPeers                                           = MAX_PEERS
	pendingPeerTimeout                                 = PENDING_PEER_TIMEOUT
	unestablishedPeerTimeout                           = UNESTABLISHED_PEER_TIMEOUT
	sourceAddressValidationTriggerConcurrentHandshakes = SOURCE_ADDRESS_VALIDATION_TRIGGER_CONCURRENT_HANDSHAKES
	maxConcurrentHandshakes                            = MAX_CONCURRENT_HANDSHAKES
	maxConcurrentHandshakesPerIP                       = MAX_CONCURRENT_HANDSHAKES_PER_IP
)

// ObfuscatedPacketConn wraps a QUIC net.PacketConn with an obfuscation layer
// that obscures QUIC packets, adding random padding and producing uniformly
// random payload.
//
// The crypto performed by ObfuscatedPacketConn is purely for obfuscation to
// frustrate wire-speed DPI and does not add privacy/security. The small
// nonce space and single key per server is not cryptographically secure.
//
// A server-side ObfuscatedPacketConn performs simple QUIC DPI to distinguish
// between obfuscated and non-obfsucated peer flows and responds accordingly.
//
// The header and padding added by ObfuscatedPacketConn on top of the QUIC
// payload will increase UDP packets beyond the QUIC max of 1280 bytes,
// introducing some risk of fragmentation and/or dropped packets.
type ObfuscatedPacketConn struct {
	net.PacketConn
	remoteAddr                 *net.UDPAddr
	isServer                   bool
	isIETFClient               bool
	isDecoyClient              bool
	enableGQUIC                bool
	isClosed                   int32
	runWaitGroup               *sync.WaitGroup
	stopBroadcast              chan struct{}
	obfuscationKey             [32]byte
	noncePRNG                  *prng.PRNG
	paddingPRNG                *prng.PRNG
	nonceTransformerParameters *transforms.ObfuscatorSeedTransformerParameters
	decoyPacketCount           int32
	decoyBuffer                []byte
	concurrentWriters          int32

	peerModesMutex           sync.Mutex
	peers                    [peerStateCount]map[netip.AddrPort]*peerMode
	concurrentHandshakesByIP map[netip.Addr]int

	concurrentHandshakeCount     atomic.Int32
	sourceAddressValidationCount atomic.Int64
	droppedFlowCount             atomic.Int64
	evictedFlowCount             atomic.Int64
	limitedFlowCount             atomic.Int64
}

// peerMode records the obfuscation mode of a peer flow, keyed by peer
// address. Each peer is in exactly one of the peerState maps.
//
//   - A new flow starts in the pending state. It moves to unestablished when
//     quic-go allows a connection for it, which follows anti-probing, and
//     moves to established when its handshake completes; see
//     handshakeStarted. It returns to pending when its last connection
//     closes, so closed peers are evictable; see updatePeerState.
//
//   - An IETF peer that remains pending has no quic-go connection
//     allocated: it sent an invalid packet, failed anti-probing, or received
//     only a stateless reply such as a Retry. A connection, when there is
//     one, is allocated almost immediately, so PENDING_PEER_TIMEOUT is very
//     conservative, and reaping a pending peer loses nothing, as its next
//     packet is an Initial.
//
//   - Each state has its own map and expiry, so the frequent reaping of
//     short-lived states never scans the large established map. A reap
//     examines at most MAX_REAP_PEERS live entries, to limit how long a
//     flooded pending map holds peerModesMutex.
//
//   - Peers are capped at MAX_PEERS in total across all maps. At capacity, a
//     new flow evicts a random pending peer, or is dropped if there isn't
//     any.
//
//   - New peers must validate their source address via QUIC Retry when there
//     are excessive concurrent QUIC handshakes in flight; see
//     verifySourceAddress.
//
//   - Limitations: legacy gQUIC has no equivalent to
//     GetConfigForClient/handshakeStarted. A gQUIC peer remains pending,
//     with the larger unestablished timeout, until its connection is
//     accepted, so its handshake is evictable at capacity; see peerAccepted.
//     With no close callback, an accepted gQUIC peer stays established until
//     its idle timeout, so closed gQUIC peers are not evictable, and gQUIC
//     handshakes bypass the handshake limits.
type peerMode struct {
	isObfuscated         bool
	isIETF               bool
	lastPacketTime       time.Time
	concurrentHandshakes int
	connections          int
}

type peerState int

const (
	peerPending peerState = iota
	peerUnestablished
	peerEstablished
	peerStateCount
)

func (p *peerMode) isStale(now time.Time, state peerState) bool {
	var timeout time.Duration
	switch {
	case state == peerEstablished:
		timeout = serverIdleTimeout
	case state == peerUnestablished || !p.isIETF:
		timeout = unestablishedPeerTimeout
	default:
		timeout = pendingPeerTimeout
	}
	return now.Sub(p.lastPacketTime) >= timeout
}

func NewClientObfuscatedPacketConn(
	packetConn net.PacketConn,
	remoteAddr *net.UDPAddr,
	isIETFClient bool,
	isDecoyClient bool,
	obfuscationKey string,
	paddingSeed *prng.Seed,
	obfuscationNonceTransformerParameters *transforms.ObfuscatorSeedTransformerParameters,
) (*ObfuscatedPacketConn, error) {

	return newObfuscatedPacketConn(
		packetConn,
		remoteAddr,
		false,
		isIETFClient,
		isDecoyClient,
		false,
		obfuscationKey,
		paddingSeed,
		obfuscationNonceTransformerParameters)

}

func NewServerObfuscatedPacketConn(
	packetConn net.PacketConn,
	isIETFClient bool,
	isDecoyClient bool,
	enableGQUIC bool,
	obfuscationKey string,
	paddingSeed *prng.Seed) (*ObfuscatedPacketConn, error) {

	return newObfuscatedPacketConn(
		packetConn,
		nil,
		true,
		isIETFClient,
		isDecoyClient,
		enableGQUIC,
		obfuscationKey,
		paddingSeed,
		nil)

}

// newObfuscatedPacketConn creates a new ObfuscatedPacketConn.
func newObfuscatedPacketConn(
	packetConn net.PacketConn,
	remoteAddr *net.UDPAddr,
	isServer bool,
	isIETFClient bool,
	isDecoyClient bool,
	enableGQUIC bool,
	obfuscationKey string,
	paddingSeed *prng.Seed,
	obfuscationNonceTransformerParameters *transforms.ObfuscatorSeedTransformerParameters,
) (*ObfuscatedPacketConn, error) {

	// Store the specified remoteAddr, which is used to implement
	// net.Conn.RemoteAddr, as the input packetConn may return a nil remote
	// addr from ReadFrom. This must be set and is only set for clients.
	if isServer != (remoteAddr == nil) {
		return nil, errors.TraceNew("invalid remoteAddr")
	}

	// There is no replay of obfuscation "encryption", just padding.
	nonceSeed, err := prng.NewSeed()
	if err != nil {
		return nil, errors.Trace(err)
	}

	conn := &ObfuscatedPacketConn{
		PacketConn:                 packetConn,
		remoteAddr:                 remoteAddr,
		isServer:                   isServer,
		isIETFClient:               isIETFClient,
		isDecoyClient:              isDecoyClient,
		enableGQUIC:                enableGQUIC,
		noncePRNG:                  prng.NewPRNGWithSeed(nonceSeed),
		paddingPRNG:                prng.NewPRNGWithSeed(paddingSeed),
		nonceTransformerParameters: obfuscationNonceTransformerParameters,
	}

	secret := []byte(obfuscationKey)
	salt := []byte("quic-obfuscation-key")
	_, err = io.ReadFull(
		hkdf.New(sha256.New, secret, salt, nil), conn.obfuscationKey[:])
	if err != nil {
		return nil, errors.Trace(err)
	}

	if isDecoyClient {
		conn.decoyPacketCount = int32(conn.paddingPRNG.Range(
			MIN_DECOY_PACKETS, MAX_DECOY_PACKETS))
		conn.decoyBuffer = make([]byte, MAX_PACKET_SIZE)
	}

	if isServer {

		for state := range conn.peers {
			conn.peers[state] = make(map[netip.AddrPort]*peerMode)
		}
		conn.concurrentHandshakesByIP = make(map[netip.Addr]int)
		conn.runWaitGroup = new(sync.WaitGroup)
		conn.stopBroadcast = make(chan struct{})

		// Reap stale peer mode information to reclaim memory.

		conn.runWaitGroup.Add(1)
		go func() {
			defer conn.runWaitGroup.Done()

			pendingTicker := time.NewTicker(pendingPeerTimeout / 2)
			defer pendingTicker.Stop()
			unestablishedTicker := time.NewTicker(unestablishedPeerTimeout / 2)
			defer unestablishedTicker.Stop()
			establishedTicker := time.NewTicker(serverIdleTimeout / 2)
			defer establishedTicker.Stop()
			for {
				select {
				case <-pendingTicker.C:
					conn.reapPeers(peerPending)
				case <-unestablishedTicker.C:
					conn.reapPeers(peerUnestablished)
				case <-establishedTicker.C:
					conn.reapPeers(peerEstablished)
				case <-conn.stopBroadcast:
					return
				}
			}
		}()
	}

	return conn, nil
}

func (conn *ObfuscatedPacketConn) Close() error {

	// Ensure close channel only called once.
	if !atomic.CompareAndSwapInt32(&conn.isClosed, 0, 1) {
		return nil
	}

	if conn.isServer {

		// Interrupt any blocked writes.
		_ = conn.PacketConn.SetWriteDeadline(time.Now())

		close(conn.stopBroadcast)
		conn.runWaitGroup.Wait()
	}

	return conn.PacketConn.Close()
}

type temporaryNetError struct {
	err error
}

func newTemporaryNetError(err error) *temporaryNetError {
	return &temporaryNetError{err: err}
}

func (e *temporaryNetError) Timeout() bool {
	return false
}

func (e *temporaryNetError) Temporary() bool {
	return true
}

func (e *temporaryNetError) Error() string {
	return e.err.Error()
}

func (conn *ObfuscatedPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, _, _, addr, _, err := conn.readPacketWithType(p, nil)
	// Do not wrap any I/O err returned by conn.PacketConn
	return n, addr, err
}

func (conn *ObfuscatedPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		return 0, errors.TraceNew("unexpected addr type")
	}
	n, _, err := conn.writePacket(p, nil, udpAddr)
	// Do not wrap any I/O err returned by conn.PacketConn
	return n, err
}

// ReadBatch implements ietf_quic.batchConn. Providing this implementation
// effectively disables the quic-go batch packet reading optimization, which
// would otherwise bypass deobfuscation. Note that ipv4.Message is an alias
// for x/net/internal/socket.Message and quic-go uses this one type for both
// IPv4 and IPv6 packets.
func (conn *ObfuscatedPacketConn) ReadBatch(ms []ipv4.Message, _ int) (int, error) {

	// Read a "batch" of 1 message, with any necessary deobfuscation performed
	// by readPacketWithType.
	//
	// TODO: implement proper batch packet reading here, along with batch
	// deobfuscation.

	if len(ms) < 1 || len(ms[0].Buffers[0]) < 1 {
		return 0, errors.TraceNew("unexpected message buffer size")
	}
	for {
		var err error
		ms[0].N, ms[0].NN, ms[0].Flags, ms[0].Addr, _, err =
			conn.readPacketWithType(ms[0].Buffers[0], ms[0].OOB)
		if err == nil {
			return 1, nil
		}
		// Skip over dropped packets here: quic-go's oobConn.ReadPacket does
		// not reset its batch state on error, so returning 0 would serve
		// stale messages on subsequent reads.
		if _, ok := err.(*temporaryNetError); ok {
			continue
		}
		// Do not wrap any I/O err returned by conn.PacketConn
		return 0, err
	}
}

// SetReadBuffer and SetWriteBuffer are used by quic-go to optimize socket
// buffer sizes.
//
// Unlike SyscallConn, quic-go will not fail on a SetReadBuffer/SetWriteBuffer
// error, so it's safe to expose these functions even when the underlying
// functionality is not always supported.
//
// When ObfuscatedPacketConn is wrapped in ObfuscatedPacketConnOOB,
// SyscallConn is provided and quic-go's setReceiveBuffer will check that
// buffer is set to expected size.
func (conn *ObfuscatedPacketConn) SetReadBuffer(n int) error {
	bufferConn, ok := conn.PacketConn.(interface{ SetReadBuffer(int) error })
	if !ok {
		return errors.Trace(errNotSupported)
	}

	// TODO: log errors in diagnostics. In quic-go, wrapConn logs errors from
	// SetReadBuffer (via setReceiveBuffer) and proceeds; those quic-go logs
	// are not captured.

	return errors.Trace(bufferConn.SetReadBuffer(n))
}

func (conn *ObfuscatedPacketConn) SetWriteBuffer(n int) error {
	bufferConn, ok := conn.PacketConn.(interface{ SetWriteBuffer(int) error })
	if !ok {
		return errors.Trace(errNotSupported)
	}
	return errors.Trace(bufferConn.SetWriteBuffer(n))
}

// Read and Write are present to satisfy the net.Conn interface, to which
// ObfuscatedPacketConn is converted internally, via quic-go, in x/net/ipv
// [4|6] for OOB manipulation. These functions do not need to be
// implemented.
func (conn *ObfuscatedPacketConn) Read(_ []byte) (int, error) {
	return 0, errors.Trace(errNotSupported)
}

func (conn *ObfuscatedPacketConn) Write(_ []byte) (int, error) {
	return 0, errors.Trace(errNotSupported)
}

func (conn *ObfuscatedPacketConn) RemoteAddr() net.Addr {
	return conn.remoteAddr
}

// GetMetrics implements the common.MetricsSource interface.
func (conn *ObfuscatedPacketConn) GetMetrics() common.LogFields {

	logFields := make(common.LogFields)

	// Include metrics, such as inproxy and fragmentor metrics, from the
	// underlying dial conn.
	underlyingMetrics, ok := conn.PacketConn.(common.MetricsSource)
	if ok {
		logFields.Add(underlyingMetrics.GetMetrics())
	}

	return logFields
}

func peerAddress(addr *net.UDPAddr) netip.AddrPort {
	addrPort := addr.AddrPort()
	return netip.AddrPortFrom(addrPort.Addr().Unmap(), addrPort.Port())
}

// lookupPeer returns the peer mode, its state, and whether it was found.
// The caller must hold peerModesMutex.
func (conn *ObfuscatedPacketConn) lookupPeer(
	address netip.AddrPort) (*peerMode, peerState, bool) {

	// The most common case is a lookup for an established peer flow, so
	// check in reverse state order.
	for state := peerStateCount - 1; state >= peerPending; state-- {
		if mode, ok := conn.peers[state][address]; ok {
			return mode, state, true
		}
	}
	return nil, 0, false
}

// evictPeer evicts a random pending peer, returning false when there is
// none. The caller must hold peerModesMutex.
func (conn *ObfuscatedPacketConn) evictPeer() bool {
	// Random eviction, via map iteration order, is reasonable for pending
	// peers: a legitimate peer gets a response, and so promoted, within
	// milliseconds.
	for address := range conn.peers[peerPending] {
		delete(conn.peers[peerPending], address)
		conn.evictedFlowCount.Add(1)
		return true
	}
	return false
}

func (conn *ObfuscatedPacketConn) reapPeers(state peerState) {

	// TODO: Go maps retain their allocated memory after entries are deleted,
	// so a flood leaves each map at its peak memory footprint, about 100 MB
	// at current MAX_PEERS. To reclaim memory, periodically replace a map
	// with a fresh one, copying over unexpired entries, instead of deleting
	// in place.

	now := time.Now()
	conn.peerModesMutex.Lock()
	scanned := 0
	for address, mode := range conn.peers[state] {
		if mode.isStale(now, state) {
			delete(conn.peers[state], address)
		}
		// Map iteration starts at a random entry; subsequent calls won't start
		// over from the same spot.
		scanned++
		if scanned >= MAX_REAP_PEERS {
			break
		}
	}
	conn.peerModesMutex.Unlock()
}

// handshakeStarted implements quic-go Config.GetConfigForClient. quic-go
// invokes it once per new connection, after anti-probing, token validation,
// and any Retry, and before allocating the connection; returning an error
// fails the connection. handshakeStarted counts total QUIC handshakes in
// flight, and, for address validated Initials, per source IP; and promotes
// the peer.
//
// Limitation: any quic-go path that drops the connection after this call
// without running its close path would permanently leak a count. Known
// paths, none expected in practice:
//   - A server-selected connection ID collision in quic-go's AddWithConnID.
//     The quic-go fork then blocks waiting on a connection goroutine that
//     never started, and no close is signaled. The collision window is a
//     single synchronous call on the server goroutine.
//   - A connection ID generation error. The random source it uses does not
//     fail in current Go.
//   - The connection's run loop failing to start its TLS handshake. On the
//     server, starting the handshake can't fail before any client data is
//     processed.
func (conn *ObfuscatedPacketConn) handshakeStarted(
	config *ietf_quic.Config,
	info *ietf_quic.ClientHelloInfo) (*ietf_quic.Config, error) {

	udpAddr, ok := info.RemoteAddr.(*net.UDPAddr)
	if !ok {
		return nil, errors.TraceNew("unexpected remote address type")
	}
	address := peerAddress(udpAddr)
	ip := common.GetRateLimitAddr(address.Addr())

	// TODO: avoid allocating errors etc. when in a limited state.

	conn.peerModesMutex.Lock()
	defer conn.peerModesMutex.Unlock()

	// The pending peer entry may have been evicted or reaped after the Initial
	// was read. With no entry to promote, the connection would fail on its
	// first write, so fail it before incrementing any counts.
	mode, state, ok := conn.lookupPeer(address)
	if !ok {
		return nil, errors.TraceNew("unknown peer")
	}

	if int(conn.concurrentHandshakeCount.Load()) >= maxConcurrentHandshakes {
		conn.limitedFlowCount.Add(1)
		return nil, errors.TraceNew("too many concurrent handshakes")
	}

	// The per-IP limit applies only to source address verified Initials: a
	// spoofed source IP must not consume another IP's limit. The source
	// address validation trigger itself bounds concurrent handshakes in
	// general.
	if info.AddrVerified {
		if conn.concurrentHandshakesByIP[ip] >= maxConcurrentHandshakesPerIP {
			conn.limitedFlowCount.Add(1)
			return nil, errors.TraceNew("handshake limit exceeded")
		}
		conn.concurrentHandshakesByIP[ip]++
	}
	conn.concurrentHandshakeCount.Add(1)
	mode.concurrentHandshakes++
	conn.updatePeerState(address, mode, state)

	connConfig := *config
	connConfig.Tracer = func(
		context.Context, logging.Perspective, ietf_quic.ConnectionID) *logging.ConnectionTracer {
		return conn.newConnectionTracer(address, mode, info.AddrVerified)
	}
	return &connConfig, nil
}

// newConnectionTracer signals handshake completion and connection close.
// All callbacks run on the connection's goroutine.
func (conn *ObfuscatedPacketConn) newConnectionTracer(
	address netip.AddrPort, mode *peerMode, validated bool) *logging.ConnectionTracer {

	// A reference to the peer state entry at newConnectionTracer time is
	// retained and peer state is modified only while that entry is current,
	// as a reaped, evicted, or reset peer entry may be replaced.

	// quic-go calls ChoseALPN on handshake completion, and ClosedConnection
	// on close; a close before completion is a failed handshake.
	completed := false
	return &logging.ConnectionTracer{
		ChoseALPN: func(string) {
			completed = true
			conn.handshakeFinished(address, mode, validated, true)
		},
		ClosedConnection: func(error) {
			if completed {
				conn.connectionClosed(address, mode)
			} else {
				conn.handshakeFinished(address, mode, validated, false)
			}
		},
	}
}

// peerAccepted establishes a gQUIC peer on accept; see peerMode.
func (conn *ObfuscatedPacketConn) peerAccepted(addr net.Addr) {
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		return
	}
	address := peerAddress(udpAddr)
	conn.peerModesMutex.Lock()
	defer conn.peerModesMutex.Unlock()
	mode, state, ok := conn.lookupPeer(address)
	if ok && !mode.isIETF {
		mode.connections++
		conn.updatePeerState(address, mode, state)
	}
}

func (conn *ObfuscatedPacketConn) handshakeFinished(
	address netip.AddrPort, mode *peerMode, validated, completed bool) {

	conn.concurrentHandshakeCount.Add(-1)
	ip := common.GetRateLimitAddr(address.Addr())
	conn.peerModesMutex.Lock()
	defer conn.peerModesMutex.Unlock()
	if validated {
		conn.concurrentHandshakesByIP[ip]--
		if conn.concurrentHandshakesByIP[ip] <= 0 {
			delete(conn.concurrentHandshakesByIP, ip)
		}
	}

	current, state, ok := conn.lookupPeer(address)
	if !ok || current != mode {
		return
	}
	mode.concurrentHandshakes--
	if completed {
		mode.connections++
	}
	conn.updatePeerState(address, mode, state)
}

func (conn *ObfuscatedPacketConn) connectionClosed(
	address netip.AddrPort, mode *peerMode) {

	conn.peerModesMutex.Lock()
	defer conn.peerModesMutex.Unlock()
	current, state, ok := conn.lookupPeer(address)
	if !ok || current != mode {
		return
	}
	mode.connections--
	conn.updatePeerState(address, mode, state)
}

// updatePeerState moves the peer to appropriate state: established while a
// handshaked connection is live, unestablished while a handshake is in
// flight, and otherwise pending, where it is evictable. The caller must hold
// peerModesMutex.
func (conn *ObfuscatedPacketConn) updatePeerState(
	address netip.AddrPort, mode *peerMode, currentState peerState) {

	targetState := peerPending
	if mode.connections > 0 {
		targetState = peerEstablished
	} else if mode.concurrentHandshakes > 0 {
		targetState = peerUnestablished
	}
	if targetState != currentState {
		delete(conn.peers[currentState], address)
		conn.peers[targetState][address] = mode
	}
}

// verifySourceAddress implements quic-go Transport.VerifySourceAddress, and
// indicates if a new peer is required to perform source address validation
// via a Retry packet.
//
// verifySourceAddress returns true when there is an excessive number of
// concurrent handshakes and is intended to limit internal quic-go connection
// allocations, particularly due to Initial packets from spoofed source
// addresses, which are not subject to MAX_CONCURRENT_HANDSHAKES_PER_IP.
//
// quic-go invokes this callback only after the anti-probing check, so a
// prober without the obfuscation key cannot trigger source address
// validation.
//
// sourceAddressValidationCount counts validations required, not Retry
// packets sent; quic-go drops the Retry when its send queue is full.
func (conn *ObfuscatedPacketConn) verifySourceAddress(_ net.Addr) bool {
	if int(conn.concurrentHandshakeCount.Load()) < sourceAddressValidationTriggerConcurrentHandshakes {
		return false
	}
	conn.sourceAddressValidationCount.Add(1)
	return true
}

// counterMetrics resets the counters it returns. Limited flows are those
// refused at MAX_CONCURRENT_HANDSHAKES or MAX_CONCURRENT_HANDSHAKES_PER_IP.
func (conn *ObfuscatedPacketConn) counterMetrics() common.LogFields {
	return common.LogFields{
		"quic_dropped_flow_count":              conn.droppedFlowCount.Swap(0),
		"quic_evicted_flow_count":              conn.evictedFlowCount.Swap(0),
		"quic_source_address_validation_count": conn.sourceAddressValidationCount.Swap(0),
		"quic_limited_flow_count":              conn.limitedFlowCount.Swap(0),
	}
}

func (conn *ObfuscatedPacketConn) readPacketWithType(
	p, oob []byte) (int, int, int, *net.UDPAddr, bool, error) {

	for {
		n, oobn, flags, addr, isIETF, err := conn.readPacket(p, oob)

		// Use the remoteAddr specified in NewClientObfuscatedPacketConn when
		// the underlying ReadFrom does not return a remote addr. This is the
		// case with inproxy.ClientConn.
		if addr == nil {
			addr = conn.remoteAddr
		}

		// When enabled, and when a packet is received, sometimes immediately
		// respond with a decoy packet, which is entirely random. Sending a
		// small number of these packets early in the connection is intended
		// to frustrate simple traffic fingerprinting which looks for a
		// certain number of packets client->server, followed by a certain
		// number of packets server->client, and so on.
		//
		// TODO: use a more sophisticated distribution; configure via tactics
		// parameters; add server-side decoy packet injection.
		//
		// See also:
		//
		// Tor Project's Sharknado concept:
		// https://gitlab.torproject.org/legacy/trac/-/issues/30716#note_2326086
		//
		// Lantern's OQUIC specification:
		// https://github.com/getlantern/quicwrapper/blob/master/OQUIC.md
		if err == nil && conn.isIETFClient && conn.isDecoyClient {
			count := atomic.LoadInt32(&conn.decoyPacketCount)
			if count > 0 && conn.paddingPRNG.FlipCoin() {

				if atomic.CompareAndSwapInt32(&conn.decoyPacketCount, count, count-1) {

					// The decoy packet is obfuscated in WriteTo, which adds
					// OBFUSCATED_MAX_PACKET_SIZE_ADJUSTMENT bytes; limit the
					// size so the obfuscated decoy packet doesn't exceed
					// MAX_PRE_DISCOVERY_PACKET_SIZE.

					packetSize := conn.paddingPRNG.Range(
						1,
						MAX_PRE_DISCOVERY_PACKET_SIZE-
							OBFUSCATED_MAX_PACKET_SIZE_ADJUSTMENT)

					// decoyBuffer is all zeros, so the QUIC Fixed Bit is zero.
					// Ignore any errors when writing decoy packets.
					_, _ = conn.WriteTo(conn.decoyBuffer[:packetSize], addr)
				}
			}
		}

		// Ignore/drop packets with an invalid QUIC Fixed Bit (see RFC 9000,
		// Packet Formats).
		if err == nil && (isIETF || conn.isIETFClient) && n > 0 && (p[0]&0x40) == 0 {
			continue
		}

		// Do not wrap any I/O err returned by conn.PacketConn
		return n, oobn, flags, addr, isIETF, err
	}
}

func (conn *ObfuscatedPacketConn) readPacket(
	p, oob []byte) (int, int, int, *net.UDPAddr, bool, error) {

	var n, oobn, flags int
	var addr *net.UDPAddr
	var err error

	oobCapablePacketConn, ok := conn.PacketConn.(ietf_quic.OOBCapablePacketConn)
	if ok {
		// Read OOB ECN bits when supported by the packet conn.
		n, oobn, flags, addr, err = oobCapablePacketConn.ReadMsgUDP(p, oob)
	} else {
		// Fall back to a generic ReadFrom, supported by any packet conn.
		var netAddr net.Addr
		n, netAddr, err = conn.PacketConn.ReadFrom(p)
		if netAddr != nil {
			// Directly convert from net.Addr to *net.UDPAddr, if possible.
			addr, ok = netAddr.(*net.UDPAddr)
			if !ok {
				addr, err = net.ResolveUDPAddr("udp", netAddr.String())
			}
		}
	}

	// Data is processed even when err != nil, as ReadFrom may return both
	// a packet and an error, such as io.EOF.
	// See: https://golang.org/pkg/net/#PacketConn.

	// In client mode, obfuscation is always performed as the client knows it is
	// using obfuscation. In server mode, DPI is performed to distinguish whether
	// the QUIC packet for a new flow is obfuscated or not, and whether it's IETF
	// or gQUIC. The isIETF return value is set only in server mode and is set
	// only when the function returns no error.

	isObfuscated := true
	isIETF := true
	var address netip.AddrPort
	var firstFlowPacket bool
	var now time.Time

	if n > 0 {

		if conn.isServer {

			// The server handles both plain and obfuscated QUIC packets.
			// isQUIC performs DPI to determine whether the packet appears to
			// be QUIC, in which case deobfuscation is not performed. Not all
			// plain QUIC packets will pass the DPI test, but the initial
			// packet(s) in a flow are expected to match; so the server
			// records a peer "mode", referenced by peer address to know when
			// to skip deobfuscation for later packets.
			//
			// It's possible for clients to redial QUIC connections,
			// transitioning from obfuscated to plain, using the same source
			// address (IP and port). This is more likely when many clients
			// are behind NAT. If a packet appears to be QUIC, this can reset
			// an existing peer "mode" to plain. The obfuscator checks that
			// its obfuscated packets don't pass the QUIC DPI test.

			now = time.Now()

			// isIETF is not meaningful if not the first packet in a flow and is not
			// meaningful when first packet is obfuscated. To correctly indicate isIETF
			// when obfuscated, the isIETFQUICClientHello test is repeated after
			// deobfuscating the packet.
			var isQUIC bool
			isQUIC, isIETF = isQUICClientHello(p[:n])

			// When gQUIC is not enabled, force IETF processing; valid gQUIC
			// packets do not get legacy gQUIC peer state tracking treatment.
			if isQUIC && !conn.enableGQUIC {
				isIETF = true
			}

			isObfuscated = !isQUIC

			if isObfuscated && isIETF {
				return n, oobn, flags, addr, false, newTemporaryNetError(
					errors.Tracef("unexpected isQUIC result"))
			}

			// Without addr, the mode cannot be determined.
			if addr == nil {
				return n, oobn, flags, addr, true, newTemporaryNetError(
					errors.Tracef("missing addr"))
			}

			conn.peerModesMutex.Lock()
			address = peerAddress(addr)
			mode, state, ok := conn.lookupPeer(address)
			stale := ok && mode.isStale(now, state)
			if ok && (stale ||
				(isQUIC && n >= MIN_FIRST_PACKET_SIZE &&
					(mode.isObfuscated || (mode.isIETF != isIETF)))) {
				// Only protect established peers. Spoofed packets can populate earlier
				// states and would otherwise pin the mode before a client connects.
				// Redials using the same source IP:port and a different mode
				// must wait for close or expiry. gQUIC has no close callback.
				if !stale && state == peerEstablished {
					conn.peerModesMutex.Unlock()
					return 0, 0, 0, nil, true, newTemporaryNetError(
						errors.TraceNew("unexpected peer mode change"))
				}
				// The address for this flow has been seen before, but either (1) it's
				// stale and not yet reaped; or (2) the client has redialed and switched
				// from obfuscated to non-obfuscated; or (3) the client has redialed and
				// switched non-obfuscated gQUIC<-->IETF. These cases are treated like a
				// new flow.
				//
				// Limitation: since the DPI doesn't detect QUIC in post-Hello
				// non-obfuscated packets, some client redial cases are not identified as
				// and handled like new flows and the QUIC session will fail. These cases
				// include the client immediately redialing and switching from
				// non-obfuscated to obfuscated or switching obfuscated gQUIC<-->IETF.
				//
				// The new flow is unproven, so the peer state returns to pending
				// with a new entry; callbacks of any earlier handshake will no
				// longer match it.
				delete(conn.peers[state], address)
				ok = false
			}
			if !ok {
				// This is a new flow.

				if n < MIN_FIRST_PACKET_SIZE {
					conn.peerModesMutex.Unlock()
					return 0, 0, 0, nil, true, newTemporaryNetError(errors.TraceNew("short first packet"))
				}

				// See concurrent writer limit comment in writePacket.
				concurrentWriters := atomic.LoadInt32(&conn.concurrentWriters)
				if concurrentWriters > CONCURRENT_WRITER_LIMIT {
					conn.peerModesMutex.Unlock()
					return 0, 0, 0, nil, true, newTemporaryNetError(errors.TraceNew("too many concurrent writers"))
				}

				peerCount := 0
				for _, peers := range conn.peers {
					peerCount += len(peers)
				}
				if peerCount >= maxPeers && !conn.evictPeer() {
					conn.peerModesMutex.Unlock()
					conn.droppedFlowCount.Add(1)
					return 0, 0, 0, nil, true, newTemporaryNetError(errors.TraceNew("too many peers"))
				}

				mode = &peerMode{isObfuscated: isObfuscated, isIETF: isIETF}
				conn.peers[peerPending][address] = mode
				firstFlowPacket = true
			} else {
				isObfuscated = mode.isObfuscated
			}
			mode.lastPacketTime = now

			isIETF = mode.isIETF
			conn.peerModesMutex.Unlock()

		} else {

			isIETF = conn.isIETFClient
		}

		if isObfuscated {

			// We can use p as a scratch buffer for deobfuscation, and this
			// avoids allocting a buffer.

			if n < (NONCE_SIZE + 1) {
				return n, oobn, flags, addr, true, newTemporaryNetError(
					errors.Tracef("unexpected obfuscated QUIC packet length: %d", n))
			}

			cipher, err := chacha20.NewCipher(conn.obfuscationKey[:], p[0:NONCE_SIZE])
			if err != nil {
				return n, oobn, flags, addr, true, errors.Trace(err)
			}
			cipher.XORKeyStream(p[NONCE_SIZE:], p[NONCE_SIZE:])

			// The padding length check allows legacy gQUIC padding to exceed
			// its 64 byte maximum, as we don't yet know if this is gQUIC or
			// IETF QUIC.

			paddingLen := int(p[NONCE_SIZE])
			if paddingLen > MAX_PADDING_SIZE || paddingLen > n-(NONCE_SIZE+1) {
				return n, oobn, flags, addr, true, newTemporaryNetError(
					errors.Tracef("unexpected padding length: %d, %d", paddingLen, n))
			}

			n -= (NONCE_SIZE + 1) + paddingLen
			copy(p[0:n], p[(NONCE_SIZE+1)+paddingLen:n+(NONCE_SIZE+1)+paddingLen])

			if conn.isServer && firstFlowPacket {
				isIETF = isIETFQUICClientHello(p[0:n])

				// When an obfuscated packet looks like neither IETF nor
				// gQUIC, force it through the IETF code path which will
				// perform anti-probing check before sending any response
				// packet. The gQUIC stack may respond with a version
				// negotiation packet.
				//
				// Ensure that mode.isIETF is set to true before returning,
				// so subsequent packets in the same flow are also forced
				// through the same anti-probing code path.
				//
				// Limitation: the following race condition check is not
				// consistent with this constraint. This will be resolved by
				// disabling gQUIC or once gQUIC is ultimatel retired.

				if !conn.enableGQUIC || (!isIETF && !isGQUICClientHello(p[0:n])) {
					isIETF = true
				}

				conn.peerModesMutex.Lock()
				mode, _, ok := conn.lookupPeer(address)

				// There's a possible race condition between the two instances of locking
				// peerModesMutex: the client might redial in the meantime. Check that the
				// mode state is unchanged from when the lock was last held.
				if !ok || !mode.isObfuscated || mode.isIETF ||
					mode.lastPacketTime != now {
					conn.peerModesMutex.Unlock()
					return n, oobn, flags, addr, true, newTemporaryNetError(
						errors.Tracef("unexpected peer mode"))
				}

				mode.isIETF = isIETF

				conn.peerModesMutex.Unlock()
			}
		}
	}

	// Do not wrap any I/O err returned by conn.PacketConn
	return n, oobn, flags, addr, isIETF, err
}

type obfuscatorBuffer struct {
	buffer [MAX_PACKET_SIZE]byte
}

var obfuscatorBufferPool = &sync.Pool{
	New: func() interface{} {
		return new(obfuscatorBuffer)
	},
}

func (conn *ObfuscatedPacketConn) writePacket(
	p, oob []byte, addr *net.UDPAddr) (int, int, error) {

	n := len(p)

	isObfuscated := true
	isIETF := true

	if conn.isServer {

		// Drop packets when there are too many concurrent writers.
		//
		// Typically, a UDP socket write will complete in microseconds, and
		// the socket write buffer should rarely fill up. However, Go's
		// runtime will loop indefinitely on EAGAIN, the error returned when
		// a UDP socket write buffer is full. Additionally, Go's runtime
		// serializes socket writes, so once a write blocks, all concurrent
		// writes also block.
		//
		// The EAGAIN condition may arise due to problems with the host's
		// driver or NIC, among other network issues on the host. We have
		// observed that, on such problematic hosts, quic-go ends up with an
		// unbounded number of goroutines blocking on UDP socket writes,
		// almost all trying to send a final packet when closing a
		// connection, due to handshake timeout. This condition leads to
		// excess memory usage on the host and triggers load limiting with
		// few connected clients.
		//
		// To avoid this condition, drop write packets, without calling the
		// socket write, once there is an excess number of concurrent
		// writers, presumably all blocked due to EAGAIN. Use a high enough
		// limit to avoid dropping packets on a busy, healthy host -- there
		// will always be some number of concurrent writers, since the QUIC
		// server uses a single socket for all writes.
		//
		// The concurrent writer limit is also checked in readPacket and used
		// to drop packets from new flows, to avoid starting new QUIC
		// connection handshakes while writes are blocked.
		//
		// The WriteTimeoutUDPConn is not used in the server case. While it is
		// effective at interrupting EAGAIN blocking on the client, its use
		// of SetWriteDeadline will extend the deadline for all blocked
		// writers, which fails to clear the server-side backlog.
		concurrentWriters := atomic.AddInt32(&conn.concurrentWriters, 1)
		defer atomic.AddInt32(&conn.concurrentWriters, -1)
		if concurrentWriters > CONCURRENT_WRITER_LIMIT {
			return 0, 0, newTemporaryNetError(errors.TraceNew("too many concurrent writers"))
		}

		conn.peerModesMutex.Lock()
		address := peerAddress(addr)
		mode, _, ok := conn.lookupPeer(address)
		if ok {
			isObfuscated = mode.isObfuscated
			isIETF = mode.isIETF
		}
		conn.peerModesMutex.Unlock()

		if !ok {

			// Every server write follows a read that created or refreshed the
			// peerMode entry, so in this missing peer entry case an entry was
			// reaped or evicted.
			//
			// Guessing the peer mode risks sending obfuscated packets to a
			// plain QUIC peer; the error closes the quic-go connection instead.
			//
			// One case here is a handshake retransmit or keep alive sent just
			// before quic-go's absolute handshake timeout, after the reaper
			// removed the peer entry. UNESTABLISHED_PEER_TIMEOUT exceeds that
			// timeout to avoid this. An established peer entry may be reaped up to
			// a keep alive period before quic-go's idle timeout; a PTO probe
			// in that window fails, which is accepted: both close silently.

			return 0, 0, newTemporaryNetError(errors.TraceNew("unknown peer"))
		}

	} else {

		isIETF = conn.isIETFClient
	}

	if isObfuscated {

		// Check that the input packet length doesn't exceed MAX_PACKET_SIZE,
		// the expected standard max quic-go packet size, adjusted down by
		// OBFUSCATED_MAX_PACKET_SIZE_ADJUSTMENT to leave room for the
		// obfuscation nonce and padding. This adjustment is configured in
		// Dial and makeServerIETFConfig and should be applied within
		// Psiphon-Labs/quic-go before it calls through to writePacket.
		//
		// There's no special case for legacy gQUIC, even though it lacks
		// packet size adjustments, since gQUIC has a hard max packet size of
		// 1280 bytes, less than the limit checked here.

		// Limitation: on Linux, with GSO enabled, standard quic-go can call
		// WriteTo with oversized packets which are then split in the kernel.
		// These oversized writes would exceed the MAX_PACKET_SIZE length
		// check. Furthermore, writePacket doesn't handle obfuscating GSO
		// writes. Psiphon-Labs/quic-go currently disables GSO.

		if n > MAX_PACKET_SIZE-OBFUSCATED_MAX_PACKET_SIZE_ADJUSTMENT {
			return 0, 0, newTemporaryNetError(errors.Tracef(
				"unexpected QUIC packet length: %d", n))
		}

		// Note: escape analysis showed a local array escaping to the heap,
		// so use a buffer pool instead to avoid heap allocation per packet.

		b := obfuscatorBufferPool.Get().(*obfuscatorBuffer)
		buffer := b.buffer[:]
		defer obfuscatorBufferPool.Put(b)

		for {

			// Note: this zero-memory pattern is compiler optimized:
			// https://golang.org/cl/137880043
			for i := range buffer {
				buffer[i] = 0
			}

			nonce := buffer[0:NONCE_SIZE]
			_, _ = conn.noncePRNG.Read(nonce)

			// This transform may reduce the entropy of the nonce, which increases
			// the chance of nonce reuse. However, this chacha20 encryption is for
			// obfuscation purposes only.
			if conn.nonceTransformerParameters != nil {
				err := conn.nonceTransformerParameters.Apply(nonce)
				if err != nil {
					return 0, 0, errors.Trace(err)
				}
			}

			maxPadding := getMaxPaddingSize(isIETF, n)

			paddingLen := conn.paddingPRNG.Intn(maxPadding + 1)
			buffer[NONCE_SIZE] = uint8(paddingLen)

			padding := buffer[(NONCE_SIZE + 1) : (NONCE_SIZE+1)+paddingLen]
			_, _ = conn.paddingPRNG.Read(padding)

			copy(buffer[(NONCE_SIZE+1)+paddingLen:], p)
			dataLen := (NONCE_SIZE + 1) + paddingLen + n

			// Sanity check that the addition of the nonce and padding didn't
			// grow the packet beyond MAX_PACKET_SIZE, the buffer size.
			if dataLen > MAX_PACKET_SIZE {
				return 0, 0, newTemporaryNetError(errors.Tracef(
					"unexpected obfuscated packet length: %d", dataLen))
			}

			cipher, err := chacha20.NewCipher(conn.obfuscationKey[:], nonce)
			if err != nil {
				return 0, 0, errors.Trace(err)
			}
			packet := buffer[NONCE_SIZE:dataLen]
			cipher.XORKeyStream(packet, packet)

			p = buffer[:dataLen]

			// Don't use obfuscation that looks like QUIC, or the
			// peer will not treat this packet as obfuscated.
			isQUIC, _ := isQUICClientHello(p)
			if !isQUIC {
				break
			}
		}
	}

	var oobn int
	var err error

	oobCapablePacketConn, ok := conn.PacketConn.(ietf_quic.OOBCapablePacketConn)
	if ok {

		// Write OOB bits if supported by the packet conn.
		//
		// At this time, quic-go reads but does not write ECN OOB bits. On the
		// client-side, the Dial function arranges for conn.PacketConn to not
		// implement OOBCapablePacketConn when using obfuscated QUIC, and so
		// quic-go is not expected to write ECN bits -- a potential
		// obfuscation fingerprint -- in the future, on the client-side.
		//
		// Limitation: on the server-side, the single UDP server socket is
		// wrapped with ObfuscatedPacketConn and supports both obfuscated and
		// regular QUIC; as it stands, this logic will support writing ECN
		// bits for both obfuscated and regular QUIC.

		_, oobn, err = oobCapablePacketConn.WriteMsgUDP(p, oob, addr)

	} else {

		// Fall back to WriteTo, supported by any packet conn. If there are
		// OOB bits to be written, fail.

		if oob != nil {
			return 0, 0, errors.TraceNew("unexpected OOB payload for non-OOBCapablePacketConn")
		}
		_, err = conn.PacketConn.WriteTo(p, addr)
	}

	// Return n = len(input p) bytes written even when p is an obfuscated
	// buffer and longer than the input p.

	// Do not wrap any I/O err returned by conn.PacketConn
	return n, oobn, err
}

func getMaxPaddingSize(isIETF bool, packetSize int) int {

	maxPacketSize := MAX_PRE_DISCOVERY_PACKET_SIZE

	maxPadding := 0

	if isIETF {

		// quic-go starts with a maximum packet size of 1280, which is the
		// IPv6 minimum MTU as well as very commonly supported for IPv4
		// (quic-go may increase the maximum packet size via MTU discovery).
		// Do not pad beyond that initial maximum size. As a result, padding
		// is only added for smaller packets.
		//
		// The obfuscated packet size is the input packet size plus the
		// padding plus OBFUSCATED_MAX_PACKET_SIZE_ADJUSTMENT, for the nonce
		// and padding length. Client/ServerMaxPacketSizeAdjustment reduces
		// the size of the packets produced by quic-go by that amount, but
		// that only makes room for the nonce and padding length; the
		// adjustment must also be deducted here or else the obfuscated
		// packet could exceed the initial maximum size by up to
		// OBFUSCATED_MAX_PACKET_SIZE_ADJUSTMENT bytes.
		//
		// As a result, quic-go packets at the adjusted pre-MTU discovery
		// maximum size are not padded and produce obfuscated packets of
		// exactly the initial maximum size.

		maxPadding = maxPacketSize - OBFUSCATED_MAX_PACKET_SIZE_ADJUSTMENT - packetSize
		if maxPadding < 0 {
			maxPadding = 0
		}
		if maxPadding > MAX_PADDING_SIZE {
			maxPadding = MAX_PADDING_SIZE
		}

	} else {

		// Legacy gQUIC has a strict maximum packet size of 1280, and legacy
		// obfuscation adds padding on top of that.

		maxPadding = (maxPacketSize + NONCE_SIZE + 1 + MAX_GQUIC_PADDING_SIZE) - packetSize
		if maxPadding < 0 {
			maxPadding = 0
		}
		if maxPadding > MAX_GQUIC_PADDING_SIZE {
			maxPadding = MAX_GQUIC_PADDING_SIZE
		}
	}

	return maxPadding
}

func (conn *ObfuscatedPacketConn) serverMaxPacketSizeAdjustment(
	addr net.Addr) int {

	udpAddr, ok := addr.(*net.UDPAddr)
	if !conn.isServer || !ok {
		return 0
	}

	conn.peerModesMutex.Lock()
	mode, _, ok := conn.lookupPeer(peerAddress(udpAddr))
	isObfuscated := ok && mode.isObfuscated
	conn.peerModesMutex.Unlock()

	if isObfuscated {
		return OBFUSCATED_MAX_PACKET_SIZE_ADJUSTMENT
	}

	return 0
}

func isQUICClientHello(buffer []byte) (bool, bool) {

	// As this function is called for every packet, it needs to be fast.
	//
	// As QUIC header parsing is complex, with many cases, we are not
	// presently doing that, although this might improve accuracy as we should
	// be able to identify the precise offset of indicators based on header
	// values.

	if isIETFQUICClientHello(buffer) {
		return true, true
	} else if isGQUICClientHello(buffer) {
		return true, false
	}

	return false, false
}

func isGQUICClientHello(buffer []byte) bool {

	// In all currently supported versions, the first client packet contains
	// the "CHLO" tag at one of the following offsets. The offset can vary for
	// a single version.
	//
	// Note that v44 does not include the "QUIC version" header field in its
	// first client packet.

	if (len(buffer) >= 33 &&
		buffer[29] == 'C' &&
		buffer[30] == 'H' &&
		buffer[31] == 'L' &&
		buffer[32] == 'O') ||
		(len(buffer) >= 35 &&
			buffer[31] == 'C' &&
			buffer[32] == 'H' &&
			buffer[33] == 'L' &&
			buffer[34] == 'O') ||
		(len(buffer) >= 38 &&
			buffer[34] == 'C' &&
			buffer[35] == 'H' &&
			buffer[36] == 'L' &&
			buffer[37] == 'O') {

		return true
	}

	return false
}

func isIETFQUICClientHello(buffer []byte) bool {

	// https://tools.ietf.org/html/draft-ietf-quic-transport-23#section-17.2:
	//
	// Check 1st nibble of byte 0:
	// 1... .... = Header Form: Long Header (1)
	// .1.. .... = Fixed Bit: True
	// ..00 .... = Packet Type: Initial (0)
	//
	// Then check bytes 1..4 for expected version number.

	if len(buffer) < 5 {
		return false
	}

	if buffer[0]>>4 != 0x0c {
		return false
	}

	// IETF QUIC version 1, RFC 9000

	return buffer[1] == 0 &&
		buffer[2] == 0 &&
		buffer[3] == 0 &&
		buffer[4] == 0x1
}

// ObfuscatedOOBCapablePacketConn implements quic-go's OOBCapablePacketConn
// interface by exposing the necessary functionality in the underlying
// ObfuscatedPacketConn.PacketConn. The packet conn should be a *net.UDPConn
// and must implement SyscallConn/ReadMsgUDP/WriteMsgUDP.
//
// SyscallConn is used to set the DF bit for path MTU discovery, and is
// required for MTU discovery to function. SyscallConn is also used to verify
// the buffers set by SetReadBuffer and SetWriteBuffer.
//
// ReadMsgUDP and WriteMsgUDP are used to operate on the ECN bit.
//
// quic-go's wrapConn assumes SyscallConn works when provided, or else the
// dial fails, so providing SyscallConn and then returning errNotSupported is
// fatal.
type ObfuscatedOOBCapablePacketConn struct {
	*ObfuscatedPacketConn
}

func NewObfuscatedOOBCapablePacketConn(
	conn *ObfuscatedPacketConn) *ObfuscatedOOBCapablePacketConn {

	return &ObfuscatedOOBCapablePacketConn{ObfuscatedPacketConn: conn}
}

func (conn *ObfuscatedOOBCapablePacketConn) SyscallConn() (syscall.RawConn, error) {

	// quic-go uses SyscallConn to set DF bit for path MTU discovery.

	syscallConn, ok := conn.ObfuscatedPacketConn.PacketConn.(ietf_quic.OOBCapablePacketConn)
	if !ok {
		return nil, errors.Trace(errNotSupported)
	}
	rawConn, err := syscallConn.SyscallConn()
	if err != nil {
		return nil, errors.Trace(err)
	}
	return rawConn, nil
}

func (conn *ObfuscatedOOBCapablePacketConn) ReadMsgUDP(
	p, oob []byte) (int, int, int, *net.UDPAddr, error) {

	// quic-go uses ReadMsgUDP to read ECN bits.
	//
	// The underlying readPacketWithType performs its own type assertion and
	// reads OOB bits when ObfuscatedPacketConn.PacketConn is capable.

	n, oobn, flags, addr, _, err := conn.readPacketWithType(p, nil)
	// Do not wrap any I/O err returned by conn.PacketConn
	return n, oobn, flags, addr, err
}

func (conn *ObfuscatedOOBCapablePacketConn) WriteMsgUDP(
	p, oob []byte, addr *net.UDPAddr) (int, int, error) {

	// quic-go uses WriteMsgUDP to write ECN bits.
	//
	// The underlying readPacketWithType performs its own type assertion and
	// writes OOB bits when ObfuscatedPacketConn.PacketConn is capable. If
	// oob is not nil and the type assertion fails, writePacket fails.

	n, oobn, err := conn.writePacket(p, oob, addr)
	// Do not wrap any I/O err returned by conn.PacketConn
	return n, oobn, err
}

var _ ietf_quic.OOBCapablePacketConn = &ObfuscatedOOBCapablePacketConn{}

var _ ietf_quic.OOBCapablePacketConn = &common.WriteTimeoutUDPConn{}
