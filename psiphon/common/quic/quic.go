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

QUIC idle timeouts and keep alives are tuned to mitigate aggressive UDP NAT
timeouts on mobile data networks while accounting for the fact that mobile
devices in standby/sleep may not be able to initiate the keep alive.

*/
package quic

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	quic_go "github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/qerr"
)

const (
	SERVER_HANDSHAKE_TIMEOUT = 30 * time.Second
	SERVER_IDLE_TIMEOUT      = 5 * time.Minute
	CLIENT_IDLE_TIMEOUT      = 30 * time.Second
)

// quic_test overrides the server idle timeout.
var serverIdleTimeout = SERVER_IDLE_TIMEOUT

// Listener is a net.Listener.
type Listener struct {
	quic_go.Listener
	logger common.Logger
}

// Listen creates a new Listener.
func Listen(
	logger common.Logger,
	address string,
	obfuscationKey string) (*Listener, error) {

	certificate, privateKey, err := common.GenerateWebServerCertificate(
		common.GenerateHostName())
	if err != nil {
		return nil, common.ContextError(err)
	}

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
		IdleTimeout:           serverIdleTimeout,
		MaxIncomingStreams:    1,
		MaxIncomingUniStreams: -1,
		KeepAlive:             true,
	}

	addr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return nil, common.ContextError(err)
	}

	udpConn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, common.ContextError(err)
	}

	var packetConn net.PacketConn
	packetConn, err = NewObfuscatedPacketConnPacketConn(
		udpConn, true, obfuscationKey)
	if err != nil {
		return nil, common.ContextError(err)
	}

	// This wrapping must be outermost to ensure that all
	// ReadFrom errors are intercepted and logged.
	packetConn = newLoggingPacketConn(logger, packetConn)

	quicListener, err := quic_go.Listen(
		packetConn, tlsConfig, quicConfig)
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

var supportedVersionNumbers = map[string]quic_go.VersionNumber{
	protocol.QUIC_VERSION_GQUIC39:    quic_go.VersionGQUIC39,
	protocol.QUIC_VERSION_GQUIC43:    quic_go.VersionGQUIC43,
	protocol.QUIC_VERSION_GQUIC44:    quic_go.VersionGQUIC44,
	protocol.QUIC_VERSION_OBFUSCATED: quic_go.VersionGQUIC43,
}

// Dial establishes a new QUIC session and stream to the server specified by
// address.
//
// packetConn is used as the underlying packet connection for QUIC. The dial
// may be cancelled by ctx; packetConn will be closed if the dial is
// cancelled or fails.
//
// Keep alive and idle timeout functionality in QUIC is disabled as these
// aspects are expected to be handled at a higher level.
func Dial(
	ctx context.Context,
	packetConn net.PacketConn,
	remoteAddr *net.UDPAddr,
	quicSNIAddress string,
	negotiateQUICVersion string,
	obfuscationKey string) (net.Conn, error) {

	var versions []quic_go.VersionNumber

	if negotiateQUICVersion != "" {
		versionNumber, ok := supportedVersionNumbers[negotiateQUICVersion]
		if !ok {
			return nil, common.ContextError(fmt.Errorf("unsupported version: %s", negotiateQUICVersion))
		}
		versions = []quic_go.VersionNumber{versionNumber}
	}

	quicConfig := &quic_go.Config{
		HandshakeTimeout: time.Duration(1<<63 - 1),
		IdleTimeout:      CLIENT_IDLE_TIMEOUT,
		KeepAlive:        true,
		Versions:         versions,
	}

	deadline, ok := ctx.Deadline()
	if ok {
		quicConfig.HandshakeTimeout = deadline.Sub(time.Now())
	}

	if negotiateQUICVersion == protocol.QUIC_VERSION_OBFUSCATED {
		var err error
		packetConn, err = NewObfuscatedPacketConnPacketConn(
			packetConn, false, obfuscationKey)
		if err != nil {
			return nil, common.ContextError(err)
		}
	}

	session, err := quic_go.DialContext(
		ctx,
		packetConn,
		remoteAddr,
		quicSNIAddress,
		&tls.Config{InsecureSkipVerify: true},
		quicConfig)
	if err != nil {
		packetConn.Close()
		return nil, common.ContextError(err)
	}

	type dialResult struct {
		conn *Conn
		err  error
	}

	resultChannel := make(chan dialResult)

	go func() {

		stream, err := session.OpenStream()
		if err != nil {
			session.Close()
			resultChannel <- dialResult{err: err}
			return
		}

		resultChannel <- dialResult{
			conn: &Conn{
				packetConn: packetConn,
				session:    session,
				stream:     stream,
			},
		}
	}()

	var conn *Conn

	select {
	case result := <-resultChannel:
		conn, err = result.conn, result.err
	case <-ctx.Done():
		err = ctx.Err()
		// Interrupt the goroutine
		session.Close()
		<-resultChannel
	}

	if err != nil {
		packetConn.Close()
		return nil, common.ContextError(err)
	}

	return conn, nil
}

// Conn is a net.Conn and psiphon/common.Closer.
type Conn struct {
	packetConn net.PacketConn
	session    quic_go.Session

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
		conn.session.Close()
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
	if isErrorIndicatingClosed(err) {
		_ = conn.Close()
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
	if isErrorIndicatingClosed(err) {
		_ = conn.Close()
		if n == len(b) {
			err = nil
		}
	}
	return n, err
}

func (conn *Conn) Close() error {
	err := conn.session.Close()
	if conn.packetConn != nil {
		err1 := conn.packetConn.Close()
		if err == nil {
			err = err1
		}
	}
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

func isErrorIndicatingClosed(err error) bool {
	if err != nil {
		if quicErr, ok := err.(*qerr.QuicError); ok {
			switch quicErr.ErrorCode {
			case qerr.PeerGoingAway, qerr.NetworkIdleTimeout:
				return true
			}
		}
	}
	return false
}

// loggingPacketConn is a workaround for issues in the quic-go server (as of
// revision ffdfa1).
//
// 1. quic-go will shutdown the QUIC server on any error returned from
//    ReadFrom, even net.Error.Temporary() errors.
//
// 2. The server shutdown hangs due to a mutex deadlock:
//
//    sync.(*RWMutex).Lock+0x2c                                          /usr/local/go/src/sync/rwmutex.go:93
//    [...]/lucas-clemente/quic-go.(*packetHandlerMap).CloseServer+0x41  [...]/lucas-clemente/quic-go/packet_handler_map.go:77
//    [...]/lucas-clemente/quic-go.(*server).closeWithMutex+0x37         [...]/lucas-clemente/quic-go/server.go:314
//    [...]/lucas-clemente/quic-go.(*server).closeWithError+0xa2         [...]/lucas-clemente/quic-go/server.go:336
//    [...]/lucas-clemente/quic-go.(*packetHandlerMap).close+0x1da       [...]/lucas-clemente/quic-go/packet_handler_map.go:115
//    [...]/lucas-clemente/quic-go.(*packetHandlerMap).listen+0x230      [...]/lucas-clemente/quic-go/packet_handler_map.go:130
//
//    packetHandlerMap.CloseServer is attempting to lock the same mutex that
//    is already locked in packetHandlerMap.close, which deadlocks. As
//    packetHandlerMap and its mutex are used by all client sessions, this
//    effectively hangs the entire server.
//
// loggingPacketConn PacketConn ReadFrom errors and returns any usable values
// or loops and calls ReadFrom again. In practise, due to the nature of UDP
// sockets, ReadFrom errors are exceptional as they will mosyt likely not
// occur due to network transmission failures. ObfuscatedPacketConn returns
// errors that could be due to network transmission failures that corrupt
// packets; these are marked as net.Error.Temporary() and loggingPacketConn
// logs these at debug level.
//
// loggingPacketConn assumes quic-go revision ffdfa1 behavior and will break
// other behavior, such as setting deadlines and expecting net.Error.Timeout()
// errors from ReadFrom.
type loggingPacketConn struct {
	net.PacketConn
	logger common.Logger
}

func newLoggingPacketConn(
	logger common.Logger,
	packetConn net.PacketConn) *loggingPacketConn {

	return &loggingPacketConn{
		PacketConn: packetConn,
		logger:     logger,
	}
}

func (conn *loggingPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {

	for {
		n, addr, err := conn.PacketConn.ReadFrom(p)

		if err != nil && conn.logger != nil {
			message := "ReadFrom failed"
			if e, ok := err.(net.Error); ok && e.Temporary() {
				conn.logger.WithContextFields(
					common.LogFields{"error": err}).Debug(message)
			} else {
				conn.logger.WithContextFields(
					common.LogFields{"error": err}).Warning(message)
			}
		}
		err = nil

		if n > 0 || addr != nil {
			return n, addr, nil
		}
	}
}
