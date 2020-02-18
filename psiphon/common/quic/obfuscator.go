// +build !DISABLE_QUIC

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
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/crypto/Yawning/chacha20"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"golang.org/x/crypto/hkdf"
)

const (
	MAX_QUIC_IPV4_PACKET_SIZE            = 1252
	MAX_QUIC_IPV6_PACKET_SIZE            = 1232
	MAX_OBFUSCATED_QUIC_IPV4_PACKET_SIZE = 1372
	MAX_OBFUSCATED_QUIC_IPV6_PACKET_SIZE = 1352
	MAX_PADDING                          = 64
	NONCE_SIZE                           = 12
	RANDOM_STREAM_LIMIT                  = 1<<38 - 64
)

// ObfuscatedPacketConn wraps a QUIC net.PacketConn with an obfuscation layer
// that obscures QUIC packets, adding random padding and producing uniformly
// random payload.
//
// The crypto performed by ObfuscatedPacketConn is purely for obfuscation to
// frusctrate wire-speed DPI and does not add privacy/security. The small
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
	isServer       bool
	isClosed       int32
	runWaitGroup   *sync.WaitGroup
	stopBroadcast  chan struct{}
	obfuscationKey [32]byte
	peerModesMutex sync.Mutex
	peerModes      map[string]*peerMode
	noncePRNG      *prng.PRNG
	paddingPRNG    *prng.PRNG
}

type peerMode struct {
	isObfuscated   bool
	isIETF         bool
	lastPacketTime time.Time
}

func (p *peerMode) isStale() bool {
	return time.Since(p.lastPacketTime) >= SERVER_IDLE_TIMEOUT
}

// NewObfuscatedPacketConn creates a new ObfuscatedPacketConn.
func NewObfuscatedPacketConn(
	conn net.PacketConn,
	isServer bool,
	obfuscationKey string,
	paddingSeed *prng.Seed) (*ObfuscatedPacketConn, error) {

	// There is no replay of obfuscation "encryption", just padding.
	nonceSeed, err := prng.NewSeed()
	if err != nil {
		return nil, errors.Trace(err)
	}

	packetConn := &ObfuscatedPacketConn{
		PacketConn:  conn,
		isServer:    isServer,
		peerModes:   make(map[string]*peerMode),
		noncePRNG:   prng.NewPRNGWithSeed(nonceSeed),
		paddingPRNG: prng.NewPRNGWithSeed(paddingSeed),
	}

	secret := []byte(obfuscationKey)
	salt := []byte("quic-obfuscation-key")
	_, err = io.ReadFull(
		hkdf.New(sha256.New, secret, salt, nil), packetConn.obfuscationKey[:])
	if err != nil {
		return nil, errors.Trace(err)
	}

	if isServer {

		packetConn.runWaitGroup = new(sync.WaitGroup)
		packetConn.stopBroadcast = make(chan struct{})

		// Reap stale peer mode information to reclaim memory.

		packetConn.runWaitGroup.Add(1)
		go func() {
			defer packetConn.runWaitGroup.Done()

			ticker := time.NewTicker(SERVER_IDLE_TIMEOUT / 2)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					packetConn.peerModesMutex.Lock()
					for address, mode := range packetConn.peerModes {
						if mode.isStale() {
							delete(packetConn.peerModes, address)
						}
					}
					packetConn.peerModesMutex.Unlock()
				case <-packetConn.stopBroadcast:
					return
				}
			}
		}()
	}

	return packetConn, nil
}

func (conn *ObfuscatedPacketConn) Close() error {

	// Ensure close channel only called once.
	if !atomic.CompareAndSwapInt32(&conn.isClosed, 0, 1) {
		return nil
	}

	if conn.isServer {
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
	n, addr, _, err := conn.readFromWithType(p)
	return n, addr, err
}

func (conn *ObfuscatedPacketConn) readFromWithType(p []byte) (int, net.Addr, bool, error) {

	n, addr, err := conn.PacketConn.ReadFrom(p)

	// Data is processed even when err != nil, as ReadFrom may return both
	// a packet and an error, such as io.EOF.
	// See: https://golang.org/pkg/net/#PacketConn.

	// In client mode, obfuscation is always performed as the client knows it is
	// using obfuscation. In server mode, DPI is performed to distinguish whether
	// the QUIC packet for a new flow is obfuscated or not, and whether it's IETF
	// or gQUIC. The isIETF return value is set only in server mode and is set
	// only when the function returns no error.

	isObfuscated := true
	var isIETF bool
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
				return n, addr, false, newTemporaryNetError(
					errors.Tracef("unexpected isQUIC result"))
			}

			// Without addr, the mode cannot be determined.
			if addr == nil {
				return n, addr, false, newTemporaryNetError(errors.Tracef("missing addr"))
			}

			conn.peerModesMutex.Lock()
			address = addr.String()
			mode, ok := conn.peerModes[address]
			if !ok {
				// This is a new flow.
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
				isIETF = mode.isIETF
			}
			mode.lastPacketTime = lastPacketTime

			isIETF = mode.isIETF
			conn.peerModesMutex.Unlock()
		}

		if isObfuscated {

			// We can use p as a scratch buffer for deobfuscation, and this
			// avoids allocting a buffer.

			if n < (NONCE_SIZE + 1) {
				return n, addr, false, newTemporaryNetError(errors.Tracef(
					"unexpected obfuscated QUIC packet length: %d", n))
			}

			cipher, err := chacha20.NewCipher(conn.obfuscationKey[:], p[0:NONCE_SIZE])
			if err != nil {
				return n, addr, false, errors.Trace(err)
			}
			cipher.XORKeyStream(p[NONCE_SIZE:], p[NONCE_SIZE:])

			paddingLen := int(p[NONCE_SIZE])
			if paddingLen > MAX_PADDING || paddingLen > n-(NONCE_SIZE+1) {
				return n, addr, false, newTemporaryNetError(errors.Tracef(
					"unexpected padding length: %d, %d", paddingLen, n))
			}

			n -= (NONCE_SIZE + 1) + paddingLen
			copy(p[0:n], p[(NONCE_SIZE+1)+paddingLen:n+(NONCE_SIZE+1)+paddingLen])

			if conn.isServer && firstFlowPacket {
				isIETF = isIETFQUICClientHello(p[0:n])
				conn.peerModesMutex.Lock()
				mode, ok := conn.peerModes[address]

				// There's a possible race condition between the two instances of locking
				// peerModesMutex: the client might redial in the meantime. Check that the
				// mode state is unchanged from when the lock was last held.
				if !ok || mode.isObfuscated != true || mode.isIETF != false ||
					mode.lastPacketTime != lastPacketTime {
					conn.peerModesMutex.Unlock()
					return n, addr, false, newTemporaryNetError(
						errors.Tracef("unexpected peer mode"))
				}

				mode.isIETF = isIETF
				conn.peerModesMutex.Unlock()
			}
		}
	}

	// Do not wrap any err returned by conn.PacketConn.ReadFrom.
	return n, addr, isIETF, err
}

type obfuscatorBuffer struct {
	buffer [MAX_OBFUSCATED_QUIC_IPV4_PACKET_SIZE]byte
}

var obfuscatorBufferPool = &sync.Pool{
	New: func() interface{} {
		return new(obfuscatorBuffer)
	},
}

func getMaxPacketSizes(addr net.Addr) (int, int) {
	if udpAddr, ok := addr.(*net.UDPAddr); ok && udpAddr.IP.To4() == nil {
		return MAX_QUIC_IPV6_PACKET_SIZE, MAX_OBFUSCATED_QUIC_IPV6_PACKET_SIZE
	}
	return MAX_QUIC_IPV4_PACKET_SIZE, MAX_OBFUSCATED_QUIC_IPV4_PACKET_SIZE
}

func (conn *ObfuscatedPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {

	n := len(p)

	isObfuscated := true

	if conn.isServer {

		conn.peerModesMutex.Lock()
		address := addr.String()
		mode, ok := conn.peerModes[address]
		isObfuscated = ok && mode.isObfuscated
		conn.peerModesMutex.Unlock()
	}

	if isObfuscated {

		maxQUICPacketSize, maxObfuscatedPacketSize := getMaxPacketSizes(addr)

		if n > maxQUICPacketSize {
			return 0, newTemporaryNetError(errors.Tracef(
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
			conn.noncePRNG.Read(nonce)

			// Obfuscated QUIC padding results in packets that exceed the
			// QUIC max packet size of 1280.

			maxPaddingLen := maxObfuscatedPacketSize - (n + (NONCE_SIZE + 1))
			if maxPaddingLen < 0 {
				maxPaddingLen = 0
			}
			if maxPaddingLen > MAX_PADDING {
				maxPaddingLen = MAX_PADDING
			}

			paddingLen := conn.paddingPRNG.Intn(maxPaddingLen + 1)
			buffer[NONCE_SIZE] = uint8(paddingLen)

			padding := buffer[(NONCE_SIZE + 1) : (NONCE_SIZE+1)+paddingLen]
			conn.paddingPRNG.Read(padding)

			copy(buffer[(NONCE_SIZE+1)+paddingLen:], p)
			dataLen := (NONCE_SIZE + 1) + paddingLen + n

			cipher, err := chacha20.NewCipher(conn.obfuscationKey[:], nonce)
			if err != nil {
				return 0, errors.Trace(err)
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

	_, err := conn.PacketConn.WriteTo(p, addr)

	// Do not wrap any err returned by conn.PacketConn.WriteTo.
	return n, err
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
	} else if isgQUICClientHello(buffer) {
		return true, false
	}

	return false, false
}

func isgQUICClientHello(buffer []byte) bool {

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

	// IETF QUIC draft-24

	return buffer[1] == 0xff &&
		buffer[2] == 0 &&
		buffer[3] == 0 &&
		buffer[4] == 0x18
}
