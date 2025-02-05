// Copyright 2019 Jigsaw Operations LLC
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

package transport

import (
	"context"
	"fmt"
	"net"
)

// PacketEndpoint represents an endpoint that can be used to establish packet connections (like UDP) to a fixed destination.
type PacketEndpoint interface {
	// ConnectPacket creates a connection bound to an endpoint, returning the connection.
	ConnectPacket(ctx context.Context) (net.Conn, error)
}

// UDPEndpoint is a [PacketEndpoint] that connects to the specified address using UDP.
type UDPEndpoint struct {
	// The Dialer used to create the net.Conn on Connect().
	Dialer net.Dialer
	// The endpoint address ("host:port") to pass to Dial.
	// If the host is a domain name, consider pre-resolving it to avoid resolution calls.
	Address string
}

var _ PacketEndpoint = (*UDPEndpoint)(nil)

// ConnectPacket implements [PacketEndpoint].ConnectPacket.
func (e UDPEndpoint) ConnectPacket(ctx context.Context) (net.Conn, error) {
	return e.Dialer.DialContext(ctx, "udp", e.Address)
}

// FuncPacketEndpoint is a [PacketEndpoint] that uses the given function to connect.
type FuncPacketEndpoint func(ctx context.Context) (net.Conn, error)

var _ PacketEndpoint = (*FuncPacketEndpoint)(nil)

// ConnectPacket implements the [PacketEndpoint] interface.
func (f FuncPacketEndpoint) ConnectPacket(ctx context.Context) (net.Conn, error) {
	return f(ctx)
}

// PacketDialerEndpoint is a [PacketEndpoint] that connects to the given address using the specified [PacketDialer].
type PacketDialerEndpoint struct {
	Dialer  PacketDialer
	Address string
}

var _ PacketEndpoint = (*PacketDialerEndpoint)(nil)

// ConnectPacket implements [PacketEndpoint].ConnectPacket.
func (e *PacketDialerEndpoint) ConnectPacket(ctx context.Context) (net.Conn, error) {
	return e.Dialer.DialPacket(ctx, e.Address)
}

// PacketDialer provides a way to dial a destination and establish datagram connections.
type PacketDialer interface {
	// DialPacket connects to `addr`.
	// `addr` has the form "host:port", where "host" can be a domain name or IP address.
	DialPacket(ctx context.Context, addr string) (net.Conn, error)
}

// UDPDialer is a [PacketDialer] that uses the standard [net.Dialer] to dial.
// It provides a convenient way to use a [net.Dialer] when you need a [PacketDialer].
type UDPDialer struct {
	Dialer net.Dialer
}

var _ PacketDialer = (*UDPDialer)(nil)

// DialPacket implements [PacketDialer].DialPacket.
func (d *UDPDialer) DialPacket(ctx context.Context, addr string) (net.Conn, error) {
	return d.Dialer.DialContext(ctx, "udp", addr)
}

// PacketListenerDialer is a [PacketDialer] that connects to the destination using the specified [PacketListener].
type PacketListenerDialer struct {
	// The PacketListener that is used to create the net.PacketConn to bind on Dial. Must be non nil.
	Listener PacketListener
}

var _ PacketDialer = (*PacketListenerDialer)(nil)

type boundPacketConn struct {
	net.PacketConn
	remoteAddr net.Addr
}

var _ net.Conn = (*boundPacketConn)(nil)

// DialPacket implements [PacketDialer].DialPacket.
// The address is in "host:port" format and the host must be either a full IP address (not "[::]") or a domain.
// The address must be supported by the WriteTo call of the [net.PacketConn] returned by the [PacketListener].
// For example, a [net.UDPConn] only supports IP addresses, not domain names.
// If the host is a domain name, consider pre-resolving it to avoid resolution calls.
func (e PacketListenerDialer) DialPacket(ctx context.Context, address string) (net.Conn, error) {
	netAddr, err := MakeNetAddr("udp", address)
	if err != nil {
		return nil, err
	}
	packetConn, err := e.Listener.ListenPacket(ctx)
	if err != nil {
		return nil, fmt.Errorf("could not create PacketConn: %w", err)
	}
	return &boundPacketConn{
		PacketConn: packetConn,
		remoteAddr: netAddr,
	}, nil
}

// Read implements [net.Conn].Read.
func (c *boundPacketConn) Read(packet []byte) (int, error) {
	for {
		n, remoteAddr, err := c.PacketConn.ReadFrom(packet)
		if err != nil {
			return n, err
		}
		if remoteAddr.String() != c.remoteAddr.String() {
			continue
		}
		return n, nil
	}
}

// Write implements [net.Conn].Write.
func (c *boundPacketConn) Write(packet []byte) (int, error) {
	// This may return syscall.EINVAL if remoteAddr is a name like localhost or [::].
	n, err := c.PacketConn.WriteTo(packet, c.remoteAddr)
	return n, err
}

// RemoteAddr implements [net.Conn].RemoteAddr.
func (c *boundPacketConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

// PacketListener provides a way to create a local unbound packet connection to send packets to different destinations.
type PacketListener interface {
	// ListenPacket creates a PacketConn that can be used to relay packets (such as UDP) through a proxy.
	ListenPacket(ctx context.Context) (net.PacketConn, error)
}

// UDPListener is a [PacketListener] that uses the standard [net.ListenConfig].ListenPacket to listen.
type UDPListener struct {
	net.ListenConfig
	// The local address to bind to, as specified in net.ListenPacket.
	Address string
}

var _ PacketListener = (*UDPListener)(nil)

// ListenPacket implements [PacketListener].ListenPacket
func (l UDPListener) ListenPacket(ctx context.Context) (net.PacketConn, error) {
	return l.ListenConfig.ListenPacket(ctx, "udp", l.Address)
}

// FuncPacketDialer is a [PacketDialer] that uses the given function to dial.
type FuncPacketDialer func(ctx context.Context, addr string) (net.Conn, error)

var _ PacketDialer = (*FuncPacketDialer)(nil)

// DialPacket implements the [PacketDialer] interface.
func (f FuncPacketDialer) DialPacket(ctx context.Context, addr string) (net.Conn, error) {
	return f(ctx, addr)
}
