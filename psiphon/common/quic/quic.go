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

/*

Package quic wraps github.com/lucas-clemente/quic-go with net.Listener and
net.Conn types that provide a drop-in replacement for net.TCPConn.

Each QUIC session has exactly one stream, which is the equivilent of a TCP
stream.

Conns returned from Accept will have an established QUIC session and are
configured to perform a deferred AcceptStream on the first Read or Write.

Conns returned from Dial have an established QUIC session and stream. Dial
accepts a Context input which may be used to cancel the dial.

Conns mask or translate qerr.PeerGoingAway to io.EOF as appropriate.

*/
package quic

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	quic_go "github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/qerr"
)

const (
	SERVER_HANDSHAKE_TIMEOUT = 30 * time.Second
	SERVER_IDLE_TIMEOUT      = 5 * time.Minute
)

// Listener is a net.Listener.
type Listener struct {
	quic_go.Listener
}

// NewListener creates a new Listener. The inputs certificate/privateKey
// specify the TLS key pair to be used by QUIC.
func NewListener(
	addr string,
	certificate, privateKey string) (*Listener, error) {

	tlsCertificate, err := tls.X509KeyPair(
		[]byte(certificate), []byte(privateKey))
	if err != nil {
		return nil, common.ContextError(err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCertificate},
	}

	quicConfig := &quic_go.Config{
		HandshakeTimeout:      SERVER_HANDSHAKE_TIMEOUT,
		IdleTimeout:           SERVER_IDLE_TIMEOUT,
		MaxIncomingStreams:    1,
		MaxIncomingUniStreams: -1,
		KeepAlive:             false,
	}

	quicListener, err := quic_go.ListenAddr(
		addr, tlsConfig, quicConfig)
	if err != nil {
		return nil, common.ContextError(err)
	}

	return &Listener{
		Listener: quicListener,
	}, nil
}

// Accept returns a net.Conn that wraps a single QUIC session and stream. The
// stream establishment is deferred until the first Read or Write, allowing
// Accept to be called in a fast loop while goroutines spawned to handle each
// net.Conn will perform the blocking AcceptStream.
func (listener *Listener) Accept() (net.Conn, error) {

	session, err := listener.Listener.Accept()
	if err != nil {
		return nil, common.ContextError(err)
	}

	return &Conn{
		session:              session,
		deferredAcceptStream: true,
	}, nil
}

// Dial establishes a new QUIC session and stream to the server specified by
// remoteAddr. packetConn is used as the underlying packet connection for
// QUIC. hostname specifies the SNI value to use in TLS. The dial may be
// cancelled by ctx; packetConn will be closed if the dial is cancelled.
func Dial(
	ctx context.Context,
	packetConn net.PacketConn,
	remoteAddr net.Addr,
	hostname string) (net.Conn, error) {

	type dialResult struct {
		conn *Conn
		err  error
	}

	resultChannel := make(chan dialResult)

	go func() {

		quicConfig := &quic_go.Config{
			KeepAlive: false,
		}

		deadline, ok := ctx.Deadline()
		if ok {
			quicConfig.HandshakeTimeout = deadline.Sub(time.Now())
		}

		session, err := quic_go.Dial(
			packetConn,
			remoteAddr,
			hostname,
			&tls.Config{InsecureSkipVerify: true},
			quicConfig)
		if err != nil {
			resultChannel <- dialResult{err: err}
			return
		}

		stream, err := session.OpenStream()
		if err != nil {
			resultChannel <- dialResult{err: err}
			return
		}

		resultChannel <- dialResult{
			conn: &Conn{
				session: session,
				stream:  stream,
			},
		}
	}()

	var conn *Conn
	var err error

	select {
	case result := <-resultChannel:
		conn, err = result.conn, result.err
	case <-ctx.Done():
		err = ctx.Err()
		// Interrupt the goroutine
		packetConn.Close()
		<-resultChannel
	}

	if err != nil {
		return nil, common.ContextError(err)
	}

	return conn, nil
}

// Conn is a net.Conn and psiphon/common.Closer.
type Conn struct {
	session quic_go.Session

	deferredAcceptStream bool

	acceptMutex sync.Mutex
	acceptErr   error
	stream      quic_go.Stream

	readMutex  sync.Mutex
	writeMutex sync.Mutex

	isClosed int32
}

func (conn *Conn) doDeferredAcceptStream() error {
	conn.acceptMutex.Lock()
	defer conn.acceptMutex.Unlock()

	if conn.stream != nil {
		return nil
	}

	if conn.acceptErr != nil {
		return conn.acceptErr
	}

	stream, err := conn.session.AcceptStream()
	if err != nil {
		conn.session.Close(nil)
		conn.acceptErr = common.ContextError(err)
		return conn.acceptErr
	}

	conn.stream = stream

	return nil
}

func (conn *Conn) Read(b []byte) (int, error) {

	if conn.deferredAcceptStream {
		err := conn.doDeferredAcceptStream()
		if err != nil {
			return 0, common.ContextError(err)
		}
	}

	// Add mutex to provide full net.Conn concurrency semantics.
	// https://github.com/lucas-clemente/quic-go/blob/9cc23135d0477baf83aa4715de39ae7070039cb2/stream.go#L64
	// "Read() and Write() may be called concurrently, but multiple calls to Read() or Write() individually must be synchronized manually."
	conn.readMutex.Lock()
	defer conn.readMutex.Unlock()

	n, err := conn.stream.Read(b)
	if isPeerGoingAway(err) {
		err = io.EOF
	}
	return n, err
}

func (conn *Conn) Write(b []byte) (int, error) {

	if conn.deferredAcceptStream {
		err := conn.doDeferredAcceptStream()
		if err != nil {
			return 0, common.ContextError(err)
		}
	}

	conn.writeMutex.Lock()
	defer conn.writeMutex.Unlock()

	n, err := conn.stream.Write(b)
	if isPeerGoingAway(err) && n == len(b) {
		err = nil
	}
	return n, err
}

func (conn *Conn) Close() error {
	err := conn.session.Close(nil)
	atomic.StoreInt32(&conn.isClosed, 1)
	return err
}

func (conn *Conn) IsClosed() bool {
	return atomic.LoadInt32(&conn.isClosed) == 1
}

func (conn *Conn) LocalAddr() net.Addr {
	return conn.session.LocalAddr()
}

func (conn *Conn) RemoteAddr() net.Addr {
	return conn.session.RemoteAddr()
}

func (conn *Conn) SetDeadline(t time.Time) error {

	if conn.deferredAcceptStream {
		err := conn.doDeferredAcceptStream()
		if err != nil {
			return common.ContextError(err)
		}
	}

	return conn.stream.SetDeadline(t)
}

func (conn *Conn) SetReadDeadline(t time.Time) error {

	if conn.deferredAcceptStream {
		err := conn.doDeferredAcceptStream()
		if err != nil {
			return common.ContextError(err)
		}
	}

	return conn.stream.SetReadDeadline(t)
}

func (conn *Conn) SetWriteDeadline(t time.Time) error {

	if conn.deferredAcceptStream {
		err := conn.doDeferredAcceptStream()
		if err != nil {
			return common.ContextError(err)
		}
	}

	return conn.stream.SetWriteDeadline(t)
}

func isPeerGoingAway(err error) bool {
	if err != nil {
		if quicErr, ok := err.(*qerr.QuicError); ok && quicErr.ErrorCode == qerr.PeerGoingAway {
			return true
		}
	}
	return false
}
