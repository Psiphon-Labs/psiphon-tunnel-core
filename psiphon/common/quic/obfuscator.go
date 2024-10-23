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
	"crypto/sha256"
	std_errors "errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/crypto/Yawning/chacha20"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/transforms"
	ietf_quic "github.com/Psiphon-Labs/quic-go"
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

	// MAX_PRE_DISCOVERY_PACKET_SIZE_IPV4/IPV6 are the largest packet sizes
	// quic-go will produce before MTU discovery, 1280 less IP and UDP header
	// sizes. These values, which match quic-go
	// internal/protocol.InitialPacketSizeIPv4/IPv6, are used to calculate
	// maximum padding sizes.

	MAX_PRE_DISCOVERY_PACKET_SIZE_IPV4 = 1252
	MAX_PRE_DISCOVERY_PACKET_SIZE_IPV6 = 1232

	// OBFUSCATED_MAX_PACKET_SIZE_ADJUSTMENT is the minimum amount of bytes
	// required for obfuscation overhead, the nonce and the padding length.
	// In IETF quic-go, this adjustment value is passed into quic-go and
	// applied to packet construction so that quic-go produces max packet
	// sizes reduced by this adjustment value.

	OBFUSCATED_MAX_PACKET_SIZE_ADJUSTMENT = NONCE_SIZE + 1

	// MIN_INITIAL_PACKET_SIZE is the minimum UDP packet payload size for
	// Initial packets, an anti-amplification measure (see RFC 9000, section
	// 14.1). To accomodate obfuscation prefix messages within the same
	// Initial UDP packet, quic-go's enforcement of this size requirement is
	// disabled and the enforcment is done by ObfuscatedPacketConn.

	MIN_INITIAL_PACKET_SIZE = 1200

	MAX_PADDING_SIZE       = 255
	MAX_GQUIC_PADDING_SIZE = 64

	MIN_DECOY_PACKETS = 0
	MAX_DECOY_PACKETS = 10

	NONCE_SIZE = 12

	RANDOM_STREAM_LIMIT = 1<<38 - 64

	CONCURRENT_WRITER_LIMIT = 5000
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
	isClosed                   int32
	runWaitGroup               *sync.WaitGroup
	stopBroadcast              chan struct{}
	obfuscationKey             [32]byte
	peerModesMutex             sync.Mutex
	peerModes                  map[string]*peerMode
	noncePRNG                  *prng.PRNG
	paddingPRNG                *prng.PRNG
	nonceTransformerParameters *transforms.ObfuscatorSeedTransformerParameters
	decoyPacketCount           int32
	decoyBuffer                []byte
	concurrentWriters          int32
}

type peerMode struct {
	isObfuscated   bool
	isIETF         bool
	lastPacketTime time.Time
}

func (p *peerMode) isStale() bool {
	return time.Since(p.lastPacketTime) >= SERVER_IDLE_TIMEOUT
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
		obfuscationKey,
		paddingSeed,
		obfuscationNonceTransformerParameters)

}

func NewServerObfuscatedPacketConn(
	packetConn net.PacketConn,
	isIETFClient bool,
	isDecoyClient bool,
	obfuscationKey string,
	paddingSeed *prng.Seed) (*ObfuscatedPacketConn, error) {

	return newObfuscatedPacketConn(
		packetConn,
		nil,
		true,
		isIETFClient,
		isDecoyClient,
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
		peerModes:                  make(map[string]*peerMode),
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

		conn.runWaitGroup = new(sync.WaitGroup)
		conn.stopBroadcast = make(chan struct{})

		// Reap stale peer mode information to reclaim memory.

		conn.runWaitGroup.Add(1)
		go func() {
			defer conn.runWaitGroup.Done()

			ticker := time.NewTicker(SERVER_IDLE_TIMEOUT / 2)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					conn.peerModesMutex.Lock()
					for address, mode := range conn.peerModes {
						if mode.isStale() {
							delete(conn.peerModes, address)
						}
					}
					conn.peerModesMutex.Unlock()
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

// ReadMsgUDP, and WriteMsgUDP satisfy the ietf_quic.OOBCapablePacketConn
// interface. In non-muxListener mode, quic-go will access the
// ObfuscatedPacketConn directly and use these functions to set ECN bits.
//
// ReadBatch implements ietf_quic.batchConn. Providing this implementation
// effectively disables the quic-go batch packet reading optimization, which
// would otherwise bypass deobfuscation. Note that ipv4.Message is an alias
// for x/net/internal/socket.Message and quic-go uses this one type for both
// IPv4 and IPv6 packets.
//
// Read and Write are present to satisfy the net.Conn interface, to which
// ObfuscatedPacketConn is converted internally, via quic-go, in x/net/ipv
// [4|6] for OOB manipulation. These functions do not need to be
// implemented.

func (conn *ObfuscatedPacketConn) ReadMsgUDP(p, oob []byte) (int, int, int, *net.UDPAddr, error) {
	n, oobn, flags, addr, _, err := conn.readPacketWithType(p, nil)
	// Do not wrap any I/O err returned by conn.PacketConn
	return n, oobn, flags, addr, err
}

func (conn *ObfuscatedPacketConn) WriteMsgUDP(p, oob []byte, addr *net.UDPAddr) (int, int, error) {
	n, oobn, err := conn.writePacket(p, oob, addr)
	// Do not wrap any I/O err returned by conn.PacketConn
	return n, oobn, err
}

func (conn *ObfuscatedPacketConn) ReadBatch(ms []ipv4.Message, _ int) (int, error) {

	// Read a "batch" of 1 message, with any necessary deobfuscation performed
	// by readPacketWithType.
	//
	// TODO: implement proper batch packet reading here, along with batch
	// deobfuscation.

	if len(ms) < 1 || len(ms[0].Buffers[0]) < 1 {
		return 0, errors.TraceNew("unexpected message buffer size")
	}
	var err error
	ms[0].N, ms[0].NN, ms[0].Flags, ms[0].Addr, _, err =
		conn.readPacketWithType(ms[0].Buffers[0], ms[0].OOB)
	if err != nil {
		// Do not wrap any I/O err returned by conn.PacketConn
		return 0, err
	}
	return 1, nil
}

var notSupported = std_errors.New("not supported")

func (conn *ObfuscatedPacketConn) Read(_ []byte) (int, error) {
	return 0, errors.Trace(notSupported)
}

func (conn *ObfuscatedPacketConn) Write(_ []byte) (int, error) {
	return 0, errors.Trace(notSupported)
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

					packetSize := conn.paddingPRNG.Range(
						1, getMaxPreDiscoveryPacketSize(addr))

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
	var address string
	var firstFlowPacket bool
	var lastPacketTime time.Time

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
			// are behind NAT. If a packet appears to be QUIC, this will reset
			// any existing peer "mode" to plain. The obfuscator checks that
			// its obfuscated packets don't pass the QUIC DPI test.
			//
			// TODO: delete peerMode when a packet is a client connection
			// termination QUIC packet? Will reclaim peerMode memory faster
			// than relying on reaper.

			lastPacketTime = time.Now()

			// isIETF is not meaningful if not the first packet in a flow and is not
			// meaningful when first packet is obfuscated. To correctly indicate isIETF
			// when obfuscated, the isIETFQUICClientHello test is repeated after
			// deobfuscating the packet.
			var isQUIC bool
			isQUIC, isIETF = isQUICClientHello(p[:n])

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
			address = addr.String()
			mode, ok := conn.peerModes[address]
			if !ok {
				// This is a new flow.

				// See concurrent writer limit comment in writePacket.
				concurrentWriters := atomic.LoadInt32(&conn.concurrentWriters)
				if concurrentWriters > CONCURRENT_WRITER_LIMIT {
					conn.peerModesMutex.Unlock()
					return 0, 0, 0, nil, true, newTemporaryNetError(errors.TraceNew("too many concurrent writers"))
				}

				mode = &peerMode{isObfuscated: isObfuscated, isIETF: isIETF}
				conn.peerModes[address] = mode
				firstFlowPacket = true
			} else if mode.isStale() ||
				(isQUIC && (mode.isObfuscated || (mode.isIETF != isIETF))) {
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
				mode.isObfuscated = isObfuscated
				mode.isIETF = isIETF
				firstFlowPacket = true
			} else {
				isObfuscated = mode.isObfuscated
			}
			mode.lastPacketTime = lastPacketTime

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

				if !isIETF && !isGQUICClientHello(p[0:n]) {
					isIETF = true
				}

				conn.peerModesMutex.Lock()
				mode, ok := conn.peerModes[address]

				// There's a possible race condition between the two instances of locking
				// peerModesMutex: the client might redial in the meantime. Check that the
				// mode state is unchanged from when the lock was last held.
				if !ok || !mode.isObfuscated || mode.isIETF ||
					mode.lastPacketTime != lastPacketTime {
					conn.peerModesMutex.Unlock()
					return n, oobn, flags, addr, true, newTemporaryNetError(
						errors.Tracef("unexpected peer mode"))
				}

				mode.isIETF = isIETF

				conn.peerModesMutex.Unlock()

				// Enforce the MIN_INITIAL_PACKET_SIZE size requirement for new flows.
				//
				// Limitations:
				//
				// - The Initial packet may be sent more than once, but we
				//   only check the very first packet.
				// - For session resumption, the first packet may be a
				//   Handshake packet, not an Initial packet, and can be smaller.

				if isIETF && n < MIN_INITIAL_PACKET_SIZE {
					return n, oobn, flags, addr, true, newTemporaryNetError(errors.Tracef(
						"unexpected first QUIC packet length: %d", n))
				}
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
		address := addr.String()
		mode, ok := conn.peerModes[address]
		if ok {
			isObfuscated = mode.isObfuscated
			isIETF = mode.isIETF
		}
		conn.peerModesMutex.Unlock()

	} else {

		isIETF = conn.isIETFClient
	}

	if isObfuscated {

		if n > MAX_PACKET_SIZE {
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

			maxPadding := getMaxPaddingSize(isIETF, addr, n)

			paddingLen := conn.paddingPRNG.Intn(maxPadding + 1)
			buffer[NONCE_SIZE] = uint8(paddingLen)

			padding := buffer[(NONCE_SIZE + 1) : (NONCE_SIZE+1)+paddingLen]
			_, _ = conn.paddingPRNG.Read(padding)

			copy(buffer[(NONCE_SIZE+1)+paddingLen:], p)
			dataLen := (NONCE_SIZE + 1) + paddingLen + n

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

func getMaxPreDiscoveryPacketSize(addr net.Addr) int {
	maxPacketSize := MAX_PRE_DISCOVERY_PACKET_SIZE_IPV4
	if udpAddr, ok := addr.(*net.UDPAddr); ok &&
		udpAddr != nil && udpAddr.IP != nil && udpAddr.IP.To4() == nil {

		maxPacketSize = MAX_PRE_DISCOVERY_PACKET_SIZE_IPV6
	}
	return maxPacketSize
}

func getMaxPaddingSize(isIETF bool, addr net.Addr, packetSize int) int {

	maxPacketSize := getMaxPreDiscoveryPacketSize(addr)

	maxPadding := 0

	if isIETF {

		// quic-go starts with a maximum packet size of 1280, which is the
		// IPv6 minimum MTU as well as very commonly supported for IPv4
		// (quic-go may increase the maximum packet size via MTU discovery).
		// Do not pad beyond that initial maximum size. As a result, padding
		// is only added for smaller packets.
		// OBFUSCATED_PACKET_SIZE_ADJUSTMENT is already factored in via
		// Client/ServerInitalPacketPaddingAdjustment.

		maxPadding = maxPacketSize - packetSize
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

	if !conn.isServer {
		return 0
	}

	conn.peerModesMutex.Lock()
	address := addr.String()
	mode, ok := conn.peerModes[address]
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
