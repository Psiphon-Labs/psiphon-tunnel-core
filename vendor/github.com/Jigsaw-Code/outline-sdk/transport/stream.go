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
	"io"
	"net"
)

// StreamConn is a [net.Conn] that allows for closing only the reader or writer end of it, supporting half-open state.
type StreamConn interface {
	net.Conn
	// Closes the Read end of the connection, allowing for the release of resources.
	// No more reads should happen.
	CloseRead() error
	// Closes the Write end of the connection. An EOF or FIN signal can be
	// sent to the connection target.
	CloseWrite() error
}

type duplexConnAdaptor struct {
	StreamConn
	r io.Reader
	w io.Writer
}

var _ StreamConn = (*duplexConnAdaptor)(nil)

func (dc *duplexConnAdaptor) Read(b []byte) (int, error) {
	return dc.r.Read(b)
}
func (dc *duplexConnAdaptor) WriteTo(w io.Writer) (int64, error) {
	return io.Copy(w, dc.r)
}
func (dc *duplexConnAdaptor) CloseRead() error {
	return dc.StreamConn.CloseRead()
}
func (dc *duplexConnAdaptor) Write(b []byte) (int, error) {
	return dc.w.Write(b)
}
func (dc *duplexConnAdaptor) ReadFrom(r io.Reader) (int64, error) {
	// Make sure we prefer ReadFrom. Otherwise io.Copy will try WriteTo first.
	if rf, ok := dc.w.(io.ReaderFrom); ok {
		return rf.ReadFrom(r)
	}
	return io.Copy(dc.w, r)
}
func (dc *duplexConnAdaptor) CloseWrite() error {
	return dc.StreamConn.CloseWrite()
}

// WrapConn wraps an existing [StreamConn] with a new [io.Reader] and [io.Writer], but preserves the original
// [StreamConn].CloseRead and [StreamConn].CloseWrite.
func WrapConn(c StreamConn, r io.Reader, w io.Writer) StreamConn {
	conn := c
	// We special-case duplexConnAdaptor to avoid multiple levels of nesting.
	if a, ok := c.(*duplexConnAdaptor); ok {
		conn = a.StreamConn
	}
	return &duplexConnAdaptor{StreamConn: conn, r: r, w: w}
}

// StreamEndpoint represents an endpoint that can be used to establish stream connections (like TCP) to a fixed
// destination.
type StreamEndpoint interface {
	// ConnectStream establishes a connection with the endpoint, returning the connection.
	ConnectStream(ctx context.Context) (StreamConn, error)
}

// TCPEndpoint is a [StreamEndpoint] that connects to the specified address using the specified [StreamDialer].
type TCPEndpoint struct {
	// The Dialer used to create the net.Conn on Connect().
	Dialer net.Dialer
	// The endpoint address (host:port) to pass to Dial.
	// If the host is a domain name, consider pre-resolving it to avoid resolution calls.
	Address string
}

var _ StreamEndpoint = (*TCPEndpoint)(nil)

// ConnectStream implements [StreamEndpoint].ConnectStream.
func (e *TCPEndpoint) ConnectStream(ctx context.Context) (StreamConn, error) {
	conn, err := e.Dialer.DialContext(ctx, "tcp", e.Address)
	if err != nil {
		return nil, err
	}
	return conn.(*net.TCPConn), nil
}

// FuncStreamEndpoint is a [StreamEndpoint] that uses the given function to connect.
type FuncStreamEndpoint func(ctx context.Context) (StreamConn, error)

var _ StreamEndpoint = (*FuncStreamEndpoint)(nil)

// ConnectStream implements the [StreamEndpoint] interface.
func (f FuncStreamEndpoint) ConnectStream(ctx context.Context) (StreamConn, error) {
	return f(ctx)
}

// StreamDialerEndpoint is a [StreamEndpoint] that connects to the specified address using the specified
// [StreamDialer].
type StreamDialerEndpoint struct {
	Dialer  StreamDialer
	Address string
}

var _ StreamEndpoint = (*StreamDialerEndpoint)(nil)

// ConnectStream implements [StreamEndpoint].ConnectStream.
func (e *StreamDialerEndpoint) ConnectStream(ctx context.Context) (StreamConn, error) {
	return e.Dialer.DialStream(ctx, e.Address)
}

// StreamDialer provides a way to dial a destination and establish stream connections.
type StreamDialer interface {
	// DialStream connects to `raddr`.
	// `raddr` has the form "host:port", where "host" can be a domain name or IP address.
	DialStream(ctx context.Context, raddr string) (StreamConn, error)
}

// TCPDialer is a [StreamDialer] that uses the standard [net.Dialer] to dial.
// It provides a convenient way to use a [net.Dialer] when you need a [StreamDialer].
type TCPDialer struct {
	Dialer net.Dialer
}

var _ StreamDialer = (*TCPDialer)(nil)

func (d *TCPDialer) DialStream(ctx context.Context, addr string) (StreamConn, error) {
	conn, err := d.Dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	return conn.(*net.TCPConn), nil
}

// FuncStreamDialer is a [StreamDialer] that uses the given function to dial.
type FuncStreamDialer func(ctx context.Context, addr string) (StreamConn, error)

var _ StreamDialer = (*FuncStreamDialer)(nil)

// DialStream implements the [StreamDialer] interface.
func (f FuncStreamDialer) DialStream(ctx context.Context, addr string) (StreamConn, error) {
	return f(ctx, addr)
}
