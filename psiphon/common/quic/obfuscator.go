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
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Psiphon-Labs/goarista/monotime"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/crypto/hkdf"
	"github.com/Yawning/chacha20"
)

const (
	MAX_QUIC_IPV4_PACKET_SIZE            = 1252
	MAX_QUIC_IPV6_PACKET_SIZE            = 1232
	MAX_OBFUSCATED_QUIC_IPV4_PACKET_SIZE = 1372
	MAX_OBFUSCATED_QUIC_IPV6_PACKET_SIZE = 1352
	MAX_PADDING_SIZE                     = 64
	NONCE_SIZE                           = 12
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
}

type peerMode struct {
	isObfuscated   bool
	lastPacketTime monotime.Time
}

func (p *peerMode) isStale() bool {
	return monotime.Since(p.lastPacketTime) >= SERVER_IDLE_TIMEOUT
}

// NewObfuscatedPacketConnPacketConn creates a new ObfuscatedPacketConn.
func NewObfuscatedPacketConnPacketConn(
	conn net.PacketConn,
	isServer bool,
	obfuscationKey string) (*ObfuscatedPacketConn, error) {

	packetConn := &ObfuscatedPacketConn{
		PacketConn: conn,
		isServer:   isServer,
		peerModes:  make(map[string]*peerMode),
	}

	secret := []byte(obfuscationKey)
	salt := []byte("quic-obfuscation-key")
	_, err := io.ReadFull(
		hkdf.New(sha256.New, secret, salt, nil), packetConn.obfuscationKey[:])
	if err != nil {
		return nil, common.ContextError(err)
	}

	if isServer {

		packetConn.runWaitGroup = new(sync.WaitGroup)
		packetConn.stopBroadcast = make(chan struct{}, 1)

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

func (conn *ObfuscatedPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {

	n, addr, err := conn.PacketConn.ReadFrom(p)

	if n > 0 {

		isObfuscated := true

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

			isQUIC := isQUIC(p[:n])

			conn.peerModesMutex.Lock()
			address := addr.String()
			mode, ok := conn.peerModes[address]
			if !ok {
				mode = &peerMode{isObfuscated: !isQUIC}
				conn.peerModes[address] = mode
			} else if mode.isStale() {
				mode.isObfuscated = !isQUIC
			} else if mode.isObfuscated && isQUIC {
				mode.isObfuscated = false
			}
			isObfuscated = mode.isObfuscated
			mode.lastPacketTime = monotime.Now()
			conn.peerModesMutex.Unlock()

		}

		if isObfuscated {

			// We can use p as a scratch buffer for deobfuscation, and this
			// avoids allocting a buffer.

			if n < (NONCE_SIZE + 1) {
				return n, addr, common.ContextError(
					fmt.Errorf("unexpected obfuscated QUIC packet length: %d", n))
			}

			cipher, err := chacha20.NewCipher(conn.obfuscationKey[:], p[0:NONCE_SIZE])
			if err != nil {
				return n, addr, common.ContextError(err)
			}
			cipher.XORKeyStream(p[NONCE_SIZE:], p[NONCE_SIZE:])

			paddingLen := int(p[NONCE_SIZE])
			if paddingLen > MAX_PADDING_SIZE || paddingLen > n-(NONCE_SIZE+1) {
				return n, addr, common.ContextError(
					fmt.Errorf("unexpected padding length: %d, %d", paddingLen, n))
			}

			n -= (NONCE_SIZE + 1) + paddingLen
			copy(p[0:n], p[(NONCE_SIZE+1)+paddingLen:n+(NONCE_SIZE+1)+paddingLen])
		}
	}

	return n, addr, err
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
			return 0, common.ContextError(
				fmt.Errorf("unexpected QUIC packet length: %d", n))
		}

		// Note: escape analysis showed a local array escaping to the heap,
		// so use a buffer pool instead to avoid heap allocation per packet.

		b := obfuscatorBufferPool.Get().(*obfuscatorBuffer)
		buffer := b.buffer[:]
		defer obfuscatorBufferPool.Put(b)

		for {
			_, err := rand.Read(buffer[0:NONCE_SIZE])
			if err != nil {
				return 0, common.ContextError(err)
			}

			// Don't use a random nonce that looks like QUIC, or the
			// peer will not treat this packet as obfuscated.
			if !isQUIC(buffer[:]) {
				break
			}
		}

		// Obfuscated QUIC padding results in packets that exceed the
		// QUIC max packet size of 1280.

		maxPaddingSize := maxObfuscatedPacketSize - (n + (NONCE_SIZE + 1))
		if maxPaddingSize < 0 {
			maxPaddingSize = 0
		}
		if maxPaddingSize > MAX_PADDING_SIZE {
			maxPaddingSize = MAX_PADDING_SIZE
		}

		paddingLen, err := common.MakeSecureRandomRange(0, maxPaddingSize)
		if err != nil {
			return 0, common.ContextError(err)
		}

		buffer[NONCE_SIZE] = uint8(paddingLen)
		_, err = rand.Read(buffer[(NONCE_SIZE + 1) : (NONCE_SIZE+1)+paddingLen])
		if err != nil {
			return 0, common.ContextError(err)
		}

		copy(buffer[(NONCE_SIZE+1)+paddingLen:], p)
		dataLen := (NONCE_SIZE + 1) + paddingLen + n

		cipher, err := chacha20.NewCipher(conn.obfuscationKey[:], buffer[0:NONCE_SIZE])
		if err != nil {
			return 0, common.ContextError(err)
		}
		cipher.XORKeyStream(buffer[NONCE_SIZE:dataLen], buffer[NONCE_SIZE:dataLen])

		p = buffer[:dataLen]
	}

	_, err := conn.PacketConn.WriteTo(p, addr)

	return n, err
}

func isQUIC(buffer []byte) bool {

	// As this function is called for every packet, it needs to be fast.
	//
	// In all currently supported versions, the first client packet contains
	// the "CHLO" tag at one of the following offsets. The offset can vary for
	// a single version.
	//
	// Note that v44 does not include the "QUIC version" header field in its
	// first client packet.
	//
	// As QUIC header parsing is complex, with many cases, we are not
	// presently doing that, although this might improve accuracy as we should
	// be able to identify the precise offset of "CHLO" based on header
	// values.

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
