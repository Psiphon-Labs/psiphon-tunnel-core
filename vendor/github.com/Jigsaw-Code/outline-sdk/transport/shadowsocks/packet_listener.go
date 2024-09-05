// Copyright 2023 Jigsaw Operations LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package shadowsocks

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/Jigsaw-Code/outline-sdk/internal/slicepool"
	"github.com/Jigsaw-Code/outline-sdk/transport"
	"github.com/shadowsocks/go-shadowsocks2/socks"
)

// clientUDPBufferSize is the maximum supported UDP packet size in bytes.
const clientUDPBufferSize = 16 * 1024

// udpPool stores the byte slices used for storing encrypted packets.
var udpPool = slicepool.MakePool(clientUDPBufferSize)

type packetListener struct {
	endpoint transport.PacketEndpoint
	key      *EncryptionKey
}

var _ transport.PacketListener = (*packetListener)(nil)

func NewPacketListener(endpoint transport.PacketEndpoint, key *EncryptionKey) (transport.PacketListener, error) {
	if endpoint == nil {
		return nil, errors.New("argument endpoint must not be nil")
	}
	if key == nil {
		return nil, errors.New("argument key must not be nil")
	}
	return &packetListener{endpoint: endpoint, key: key}, nil
}

func (c *packetListener) ListenPacket(ctx context.Context) (net.PacketConn, error) {
	proxyConn, err := c.endpoint.ConnectPacket(ctx)
	if err != nil {
		return nil, fmt.Errorf("could not connect to endpoint: %w", err)
	}
	conn := packetConn{Conn: proxyConn, key: c.key}
	return &conn, nil
}

type packetConn struct {
	net.Conn
	key *EncryptionKey
}

var _ net.PacketConn = (*packetConn)(nil)

// WriteTo encrypts `b` and writes to `addr` through the proxy.
func (c *packetConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	socksTargetAddr := socks.ParseAddr(addr.String())
	if socksTargetAddr == nil {
		return 0, errors.New("failed to parse target address")
	}
	lazySlice := udpPool.LazySlice()
	cipherBuf := lazySlice.Acquire()
	defer lazySlice.Release()
	saltSize := c.key.SaltSize()
	// Copy the SOCKS target address and payload, reserving space for the generated salt to avoid
	// partially overlapping the plaintext and cipher slices since `Pack` skips the salt when calling
	// `AEAD.Seal` (see https://golang.org/pkg/crypto/cipher/#AEAD).
	plaintextBuf := append(append(cipherBuf[saltSize:saltSize], socksTargetAddr...), b...)
	buf, err := Pack(cipherBuf, plaintextBuf, c.key)
	if err != nil {
		return 0, err
	}
	_, err = c.Conn.Write(buf)
	return len(b), err
}

// ReadFrom reads from the embedded PacketConn and decrypts into `b`.
func (c *packetConn) ReadFrom(b []byte) (int, net.Addr, error) {
	lazySlice := udpPool.LazySlice()
	cipherBuf := lazySlice.Acquire()
	defer lazySlice.Release()
	n, err := c.Conn.Read(cipherBuf)
	if err != nil {
		return 0, nil, err
	}
	// Decrypt in-place.
	buf, err := Unpack(nil, cipherBuf[:n], c.key)
	if err != nil {
		return 0, nil, err
	}
	socksSrcAddr := socks.SplitAddr(buf)
	if socksSrcAddr == nil {
		return 0, nil, errors.New("failed to read source address")
	}
	srcAddr, err := transport.MakeNetAddr("udp", socksSrcAddr.String())
	if err != nil {
		return 0, nil, fmt.Errorf("failed to convert incoming address: %w", err)
	}
	n = copy(b, buf[len(socksSrcAddr):]) // Strip the SOCKS source address
	if len(b) < len(buf)-len(socksSrcAddr) {
		return n, srcAddr, io.ErrShortBuffer
	}
	return n, srcAddr, nil
}
