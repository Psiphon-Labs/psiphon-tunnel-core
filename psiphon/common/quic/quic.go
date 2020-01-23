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
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/quic/gquic-go"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/quic/gquic-go/h2quic"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/quic/gquic-go/qerr"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/values"
	ietf_quic "github.com/Psiphon-Labs/quic-go"
	"github.com/Psiphon-Labs/quic-go/http3"
)

const (
	SERVER_HANDSHAKE_TIMEOUT = 30 * time.Second
	SERVER_IDLE_TIMEOUT      = 5 * time.Minute
	CLIENT_IDLE_TIMEOUT      = 30 * time.Second
)

// Enabled indicates if QUIC functionality is enabled.
func Enabled() bool {
	return true
}

const ietfQUICDraft24VersionNumber = 0xff000018

var supportedVersionNumbers = map[string]uint32{
	protocol.QUIC_VERSION_GQUIC39:      uint32(gquic.VersionGQUIC39),
	protocol.QUIC_VERSION_GQUIC43:      uint32(gquic.VersionGQUIC43),
	protocol.QUIC_VERSION_GQUIC44:      uint32(gquic.VersionGQUIC44),
	protocol.QUIC_VERSION_OBFUSCATED:   uint32(gquic.VersionGQUIC43),
	protocol.QUIC_VERSION_IETF_DRAFT24: ietfQUICDraft24VersionNumber,
}

func isObfuscated(quicVersion string) bool {
	return quicVersion == protocol.QUIC_VERSION_OBFUSCATED
}

func isIETFVersion(versionNumber uint32) bool {
	return versionNumber == ietfQUICDraft24VersionNumber
}

func getALPN(versionNumber uint32) string {
	return "h3-24"
}

// quic_test overrides the server idle timeout.
var serverIdleTimeout = SERVER_IDLE_TIMEOUT

// Listener is a net.Listener.
type Listener struct {
	*muxListener
}

// Listen creates a new Listener.
func Listen(
	logger common.Logger,
	address string,
	obfuscationKey string) (net.Listener, error) {

	certificate, privateKey, err := common.GenerateWebServerCertificate(
		values.GetHostName())
	if err != nil {
		return nil, errors.Trace(err)
	}

	tlsCertificate, err := tls.X509KeyPair(
		[]byte(certificate), []byte(privateKey))
	if err != nil {
		return nil, errors.Trace(err)
	}

	addr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return nil, errors.Trace(err)
	}

	udpConn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, errors.Trace(err)
	}

	seed, err := prng.NewSeed()
	if err != nil {
		udpConn.Close()
		return nil, errors.Trace(err)
	}

	obfuscatedPacketConn, err := NewObfuscatedPacketConn(udpConn, true, obfuscationKey, seed)
	if err != nil {
		udpConn.Close()
		return nil, errors.Trace(err)
	}

	// Note that, due to nature of muxListener, full accepts may happen before
	// return and caller calls Accept.

	listener, err := newMuxListener(logger, obfuscatedPacketConn, tlsCertificate)
	if err != nil {
		obfuscatedPacketConn.Close()
		return nil, errors.Trace(err)
	}

	return &Listener{muxListener: listener}, nil
}

// Accept returns a net.Conn that wraps a single QUIC session and stream. The
// stream establishment is deferred until the first Read or Write, allowing
// Accept to be called in a fast loop while goroutines spawned to handle each
// net.Conn will perform the blocking AcceptStream.
func (listener *Listener) Accept() (net.Conn, error) {

	session, err := listener.muxListener.Accept()
	if err != nil {
		return nil, errors.Trace(err)
	}

	return &Conn{
		session:              session,
		deferredAcceptStream: true,
	}, nil
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
	obfuscationKey string,
	obfuscationPaddingSeed *prng.Seed) (net.Conn, error) {

	if negotiateQUICVersion == "" {
		return nil, errors.TraceNew("missing version")
	}

	versionNumber, ok := supportedVersionNumbers[negotiateQUICVersion]
	if !ok {
		return nil, errors.Tracef("unsupported version: %s", negotiateQUICVersion)
	}

	if isObfuscated(negotiateQUICVersion) {
		var err error
		packetConn, err = NewObfuscatedPacketConn(
			packetConn, false, obfuscationKey, obfuscationPaddingSeed)
		if err != nil {
			return nil, errors.Trace(err)
		}
	}

	session, err := dialQUIC(
		ctx,
		packetConn,
		remoteAddr,
		quicSNIAddress,
		versionNumber)
	if err != nil {
		packetConn.Close()
		return nil, errors.Trace(err)
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
		return nil, errors.Trace(err)
	}

	return conn, nil
}

// Conn is a net.Conn and psiphon/common.Closer.
type Conn struct {
	packetConn net.PacketConn
	session    quicSession

	deferredAcceptStream bool

	acceptMutex sync.Mutex
	acceptErr   error
	stream      quicStream

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
		conn.acceptErr = errors.Trace(err)
		return conn.acceptErr
	}

	conn.stream = stream

	return nil
}

func (conn *Conn) Read(b []byte) (int, error) {

	if conn.deferredAcceptStream {
		err := conn.doDeferredAcceptStream()
		if err != nil {
			return 0, errors.Trace(err)
		}
	}

	// Add mutex to provide full net.Conn concurrency semantics.
	// https://github.com/lucas-clemente/quic-go/blob/9cc23135d0477baf83aa4715de39ae7070039cb2/stream.go#L64
	// "Read() and Write() may be called concurrently, but multiple calls to
	// "Read() or Write() individually must be synchronized manually."
	conn.readMutex.Lock()
	defer conn.readMutex.Unlock()

	n, err := conn.stream.Read(b)
	if conn.session.isErrorIndicatingClosed(err) {
		_ = conn.Close()
		err = io.EOF
	}
	return n, err
}

func (conn *Conn) Write(b []byte) (int, error) {

	if conn.deferredAcceptStream {
		err := conn.doDeferredAcceptStream()
		if err != nil {
			return 0, errors.Trace(err)
		}
	}

	conn.writeMutex.Lock()
	defer conn.writeMutex.Unlock()

	n, err := conn.stream.Write(b)
	if conn.session.isErrorIndicatingClosed(err) {
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
			return errors.Trace(err)
		}
	}

	return conn.stream.SetDeadline(t)
}

func (conn *Conn) SetReadDeadline(t time.Time) error {

	if conn.deferredAcceptStream {
		err := conn.doDeferredAcceptStream()
		if err != nil {
			return errors.Trace(err)
		}
	}

	return conn.stream.SetReadDeadline(t)
}

func (conn *Conn) SetWriteDeadline(t time.Time) error {

	if conn.deferredAcceptStream {
		err := conn.doDeferredAcceptStream()
		if err != nil {
			return errors.Trace(err)
		}
	}

	return conn.stream.SetWriteDeadline(t)
}

// QUICTransporter implements the psiphon.transporter interface, used in
// psiphon.MeekConn for HTTP requests, which requires a RoundTripper and
// CloseIdleConnections.
type QUICTransporter struct {
	quicRoundTripper
	noticeEmitter        func(string)
	udpDialer            func(ctx context.Context) (net.PacketConn, *net.UDPAddr, error)
	quicSNIAddress       string
	negotiateQUICVersion string
	packetConn           atomic.Value

	mutex sync.Mutex
	ctx   context.Context
}

// NewQUICTransporter creates a new QUICTransporter.
func NewQUICTransporter(
	ctx context.Context,
	noticeEmitter func(string),
	udpDialer func(ctx context.Context) (net.PacketConn, *net.UDPAddr, error),
	quicSNIAddress string,
	negotiateQUICVersion string) (*QUICTransporter, error) {

	versionNumber, ok := supportedVersionNumbers[negotiateQUICVersion]
	if !ok {
		return nil, errors.Tracef("unsupported version: %s", negotiateQUICVersion)
	}

	t := &QUICTransporter{
		noticeEmitter:        noticeEmitter,
		udpDialer:            udpDialer,
		quicSNIAddress:       quicSNIAddress,
		negotiateQUICVersion: negotiateQUICVersion,
		ctx:                  ctx,
	}

	if isIETFVersion(versionNumber) {
		t.quicRoundTripper = &http3.RoundTripper{Dial: t.dialIETFQUIC}
	} else {
		t.quicRoundTripper = &h2quic.RoundTripper{Dial: t.dialgQUIC}
	}

	return t, nil
}

func (t *QUICTransporter) SetRequestContext(ctx context.Context) {
	// Note: can't use sync.Value since underlying type of ctx changes.
	t.mutex.Lock()
	defer t.mutex.Unlock()
	t.ctx = ctx
}

// CloseIdleConnections wraps QUIC RoundTripper.Close, which provides the
// necessary functionality for psiphon.transporter as used by
// psiphon.MeekConn. Note that, unlike http.Transport.CloseIdleConnections,
// the connections are closed regardless of idle status.
func (t *QUICTransporter) CloseIdleConnections() {

	// This operation doesn't prevent a concurrent http3.client.dial from
	// establishing a new packet conn; we also rely on the request context to
	// fully interrupt and stop a http3.RoundTripper.

	t.closePacketConn()
	t.quicRoundTripper.Close()
}

func (t *QUICTransporter) closePacketConn() {
	packetConn := t.packetConn.Load()
	if p, ok := packetConn.(net.PacketConn); ok {
		p.Close()
	}
}

func (t *QUICTransporter) dialIETFQUIC(
	_, _ string, _ *tls.Config, _ *ietf_quic.Config) (ietf_quic.Session, error) {
	session, err := t.dialQUIC()
	if err != nil {
		return nil, errors.Trace(err)
	}
	return session.(*ietfQUICSession).Session, nil
}

func (t *QUICTransporter) dialgQUIC(
	_, _ string, _ *tls.Config, _ *gquic.Config) (gquic.Session, error) {
	session, err := t.dialQUIC()
	if err != nil {
		return nil, errors.Trace(err)
	}
	return session.(*gQUICSession).Session, nil
}

func (t *QUICTransporter) dialQUIC() (retSession quicSession, retErr error) {

	defer func() {
		if retErr != nil && t.noticeEmitter != nil {
			t.noticeEmitter(fmt.Sprintf("QUICTransporter.dialQUIC failed: %s", retErr))
		}
	}()

	if t.negotiateQUICVersion == "" {
		return nil, errors.TraceNew("missing version")
	}

	versionNumber, ok := supportedVersionNumbers[t.negotiateQUICVersion]
	if !ok {
		return nil, errors.Tracef("unsupported version: %s", t.negotiateQUICVersion)
	}

	t.mutex.Lock()
	ctx := t.ctx
	t.mutex.Unlock()
	if ctx == nil {
		ctx = context.Background()
	}

	packetConn, remoteAddr, err := t.udpDialer(ctx)
	if err != nil {
		return nil, errors.Trace(err)
	}

	session, err := dialQUIC(
		ctx,
		packetConn,
		remoteAddr,
		t.quicSNIAddress,
		versionNumber)
	if err != nil {
		packetConn.Close()
		return nil, errors.Trace(err)
	}

	// dialQUIC uses quic-go.DialContext as we must create our own UDP sockets to
	// set properties such as BIND_TO_DEVICE. However, when DialContext is used,
	// quic-go does not take responsibiity for closing the underlying packetConn
	// when the QUIC session is closed.
	//
	// We track the most recent packetConn in QUICTransporter and close it:
	// - when CloseIdleConnections is called, as it is by psiphon.MeekConn when
	//   it is closing;
	// - here in dialFunc, with the assumption that only one concurrent QUIC
	//   session is used per h2quic.RoundTripper.
	//
	// This code also assume no concurrent calls to dialFunc, as otherwise a race
	// condition exists between closePacketConn and Store.

	t.closePacketConn()
	t.packetConn.Store(packetConn)

	return session, nil
}

// The following code provides support for using both gQUIC and IETF QUIC,
// which are implemented in two different branches (now forks) of quic-go.
//
// dialQUIC uses the appropriate quic-go and returns quicSession which wraps
// either a ietf_quic.Session or gquic.Session.
//
// muxPacketConn provides a multiplexing listener that directs packets to
// either a ietf_quic.Listener or a gquic.Listener based on the content of the
// packet.

type quicListener interface {
	Close() error
	Accept() (quicSession, error)
}

type quicSession interface {
	io.Closer
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
	AcceptStream() (quicStream, error)
	OpenStream() (quicStream, error)
	isErrorIndicatingClosed(err error) bool
}

type quicStream interface {
	io.Reader
	io.Writer
	io.Closer
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
	SetDeadline(t time.Time) error
}

type quicRoundTripper interface {
	http.RoundTripper
	Close() error
}

type ietfQUICListener struct {
	ietf_quic.Listener
}

func (l *ietfQUICListener) Accept() (quicSession, error) {
	// A specific context is not provided since the interface needs to match the
	// gquic-go API, which lacks context support.
	session, err := l.Listener.Accept(context.Background())
	if err != nil {
		return nil, errors.Trace(err)
	}
	return &ietfQUICSession{Session: session}, nil
}

type ietfQUICSession struct {
	ietf_quic.Session
}

func (s *ietfQUICSession) AcceptStream() (quicStream, error) {
	// A specific context is not provided since the interface needs to match the
	// gquic-go API, which lacks context support.
	//
	// TODO: once gQUIC support is retired, this context may be used in place
	// of the deferredAcceptStream mechanism.
	stream, err := s.Session.AcceptStream(context.Background())
	if err != nil {
		return nil, errors.Trace(err)
	}
	return stream, nil
}

func (s *ietfQUICSession) OpenStream() (quicStream, error) {
	return s.Session.OpenStream()
}

func (s *ietfQUICSession) isErrorIndicatingClosed(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	// The target error is of type *qerr.QuicError, but is not exported.
	return errStr == "Application error 0x0" ||
		errStr == "NO_ERROR: No recent network activity"
}

type gQUICListener struct {
	gquic.Listener
}

func (l *gQUICListener) Accept() (quicSession, error) {
	session, err := l.Listener.Accept()
	if err != nil {
		return nil, errors.Trace(err)
	}
	return &gQUICSession{Session: session}, nil
}

type gQUICSession struct {
	gquic.Session
}

func (s *gQUICSession) AcceptStream() (quicStream, error) {
	stream, err := s.Session.AcceptStream()
	if err != nil {
		return nil, errors.Trace(err)
	}
	return stream, nil
}

func (s *gQUICSession) OpenStream() (quicStream, error) {
	return s.Session.OpenStream()
}

func (s *gQUICSession) isErrorIndicatingClosed(err error) bool {
	if err == nil {
		return false
	}
	if quicErr, ok := err.(*qerr.QuicError); ok {
		switch quicErr.ErrorCode {
		case qerr.PeerGoingAway, qerr.NetworkIdleTimeout:
			return true
		}
	}
	return false
}

func dialQUIC(
	ctx context.Context,
	packetConn net.PacketConn,
	remoteAddr *net.UDPAddr,
	quicSNIAddress string,
	versionNumber uint32) (quicSession, error) {

	if isIETFVersion(versionNumber) {

		quicConfig := &ietf_quic.Config{
			HandshakeTimeout: time.Duration(1<<63 - 1),
			IdleTimeout:      CLIENT_IDLE_TIMEOUT,
			KeepAlive:        true,
			Versions: []ietf_quic.VersionNumber{
				ietf_quic.VersionNumber(versionNumber)},
		}

		deadline, ok := ctx.Deadline()
		if ok {
			quicConfig.HandshakeTimeout = time.Until(deadline)
		}

		dialSession, err := ietf_quic.DialContext(
			ctx,
			packetConn,
			remoteAddr,
			quicSNIAddress,
			&tls.Config{
				InsecureSkipVerify: true,
				NextProtos:         []string{getALPN(versionNumber)},
			},
			quicConfig)
		if err != nil {
			return nil, errors.Trace(err)
		}

		return &ietfQUICSession{Session: dialSession}, nil

	} else {

		quicConfig := &gquic.Config{
			HandshakeTimeout: time.Duration(1<<63 - 1),
			IdleTimeout:      CLIENT_IDLE_TIMEOUT,
			KeepAlive:        true,
			Versions: []gquic.VersionNumber{
				gquic.VersionNumber(versionNumber)},
		}

		deadline, ok := ctx.Deadline()
		if ok {
			quicConfig.HandshakeTimeout = time.Until(deadline)
		}

		dialSession, err := gquic.DialContext(
			ctx,
			packetConn,
			remoteAddr,
			quicSNIAddress,
			&tls.Config{
				InsecureSkipVerify: true,
			},
			quicConfig)
		if err != nil {
			return nil, errors.Trace(err)
		}

		return &gQUICSession{Session: dialSession}, nil
	}
}

const (
	muxPacketQueueSize  = 128
	muxPacketBufferSize = 1452 // quic-go.MaxReceivePacketSize
)

type packet struct {
	addr net.Addr
	size int
	data []byte
}

// muxPacketConn delivers packets to a specific quic-go listener.
type muxPacketConn struct {
	localAddr net.Addr
	listener  *muxListener
	packets   chan *packet
}

func newMuxPacketConn(localAddr net.Addr, listener *muxListener) *muxPacketConn {
	return &muxPacketConn{
		localAddr: localAddr,
		listener:  listener,
		packets:   make(chan *packet, muxPacketQueueSize),
	}
}

func (conn *muxPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {

	select {
	case p := <-conn.packets:

		// If b is too short, the packet is truncated. This won't happen as long as
		// muxPacketBufferSize matches quic-go.MaxReceivePacketSize.
		copy(b, p.data[0:p.size])
		n := p.size
		addr := p.addr

		// Clear and replace packet buffer.
		p.size = 0
		conn.listener.packets <- p

		return n, addr, nil
	case <-conn.listener.stopBroadcast:
		return 0, nil, io.EOF
	}
}

func (conn *muxPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	return conn.listener.conn.WriteTo(b, addr)
}

func (conn *muxPacketConn) Close() error {
	// This Close won't unblock Read/Write operations or propagate the Close
	// signal up to muxListener.  The correct way to shutdown is to call
	// muxListener.Close.
	return nil
}

func (conn *muxPacketConn) LocalAddr() net.Addr {
	return conn.localAddr
}

func (conn *muxPacketConn) SetDeadline(t time.Time) error {
	return errors.TraceNew("not supported")
}

func (conn *muxPacketConn) SetReadDeadline(t time.Time) error {
	return errors.TraceNew("not supported")
}

func (conn *muxPacketConn) SetWriteDeadline(t time.Time) error {
	return errors.TraceNew("not supported")
}

// muxListener is a multiplexing packet conn listener which relays packets to
// multiple quic-go listeners.
type muxListener struct {
	logger           common.Logger
	isClosed         int32
	runWaitGroup     *sync.WaitGroup
	stopBroadcast    chan struct{}
	conn             *ObfuscatedPacketConn
	packets          chan *packet
	acceptedSessions chan quicSession
	ietfQUICConn     *muxPacketConn
	ietfQUICListener quicListener
	gQUICConn        *muxPacketConn
	gQUICListener    quicListener
}

func newMuxListener(
	logger common.Logger,
	conn *ObfuscatedPacketConn,
	tlsCertificate tls.Certificate) (*muxListener, error) {

	listener := &muxListener{
		logger:           logger,
		runWaitGroup:     new(sync.WaitGroup),
		stopBroadcast:    make(chan struct{}),
		conn:             conn,
		packets:          make(chan *packet, muxPacketQueueSize),
		acceptedSessions: make(chan quicSession, 2), // 1 per listener
	}

	// All packet relay buffers are allocated in advance.
	for i := 0; i < muxPacketQueueSize; i++ {
		listener.packets <- &packet{data: make([]byte, muxPacketBufferSize)}
	}

	listener.ietfQUICConn = newMuxPacketConn(conn.LocalAddr(), listener)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCertificate},
		NextProtos:   []string{getALPN(ietfQUICDraft24VersionNumber)},
	}

	ietfQUICConfig := &ietf_quic.Config{
		HandshakeTimeout:      SERVER_HANDSHAKE_TIMEOUT,
		IdleTimeout:           serverIdleTimeout,
		MaxIncomingStreams:    1,
		MaxIncomingUniStreams: -1,
		KeepAlive:             true,
	}

	il, err := ietf_quic.Listen(listener.ietfQUICConn, tlsConfig, ietfQUICConfig)
	if err != nil {
		return nil, errors.Trace(err)
	}
	listener.ietfQUICListener = &ietfQUICListener{Listener: il}

	listener.gQUICConn = newMuxPacketConn(conn.LocalAddr(), listener)

	tlsConfig = &tls.Config{
		Certificates: []tls.Certificate{tlsCertificate},
	}

	gQUICConfig := &gquic.Config{
		HandshakeTimeout:      SERVER_HANDSHAKE_TIMEOUT,
		IdleTimeout:           serverIdleTimeout,
		MaxIncomingStreams:    1,
		MaxIncomingUniStreams: -1,
		KeepAlive:             true,
	}

	gl, err := gquic.Listen(listener.gQUICConn, tlsConfig, gQUICConfig)
	if err != nil {
		listener.ietfQUICListener.Close()
		return nil, errors.Trace(err)
	}
	listener.gQUICListener = &gQUICListener{Listener: gl}

	listener.runWaitGroup.Add(3)
	go listener.relayPackets()
	go listener.relayAcceptedSessions(listener.gQUICListener)
	go listener.relayAcceptedSessions(listener.ietfQUICListener)

	return listener, nil
}

func (listener *muxListener) relayPackets() {
	defer listener.runWaitGroup.Done()

	for {

		var p *packet
		select {
		case p = <-listener.packets:
		case <-listener.stopBroadcast:
			return
		}

		// Read network packets. The DPI functionality of the obfuscation layer
		// identifies the type of QUIC, gQUIC or IETF, in addition to identifying
		// and processing obfuscation. This type information determines which
		// quic-go receives the packet.
		//
		// Network errors are not relayed to quic-go, as it will shut down the
		// server on any error returned from ReadFrom, even net.Error.Temporary()
		// errors.

		var isIETF bool
		var err error
		p.size, p.addr, isIETF, err = listener.conn.readFromWithType(p.data)
		if err != nil {
			if listener.logger != nil {
				message := "readFromWithType failed"
				if e, ok := err.(net.Error); ok && e.Temporary() {
					listener.logger.WithTraceFields(
						common.LogFields{"error": err}).Debug(message)
				} else {
					listener.logger.WithTraceFields(
						common.LogFields{"error": err}).Warning(message)
				}
			}
			// TODO: propagate non-temporary errors to Accept?
			listener.packets <- p
			continue
		}

		// Send the packet to the correct quic-go. The packet is dropped if the
		// target quic-go packet queue is full.

		if isIETF {
			select {
			case listener.ietfQUICConn.packets <- p:
			default:
				listener.packets <- p
			}
		} else {
			select {
			case listener.gQUICConn.packets <- p:
			default:
				listener.packets <- p
			}
		}
	}
}

func (listener *muxListener) relayAcceptedSessions(l quicListener) {
	defer listener.runWaitGroup.Done()
	for {
		session, err := l.Accept()
		if err != nil {
			if listener.logger != nil {
				message := "Accept failed"
				if e, ok := err.(net.Error); ok && e.Temporary() {
					listener.logger.WithTraceFields(
						common.LogFields{"error": err}).Debug(message)
				} else {
					listener.logger.WithTraceFields(
						common.LogFields{"error": err}).Warning(message)
				}
			}
			// TODO: propagate non-temporary errors to Accept?
			select {
			case <-listener.stopBroadcast:
				return
			default:
			}
			continue
		}
		select {
		case listener.acceptedSessions <- session:
		case <-listener.stopBroadcast:
			return
		}
	}
}

func (listener *muxListener) Accept() (quicSession, error) {
	select {
	case conn := <-listener.acceptedSessions:
		return conn, nil
	case <-listener.stopBroadcast:
		return nil, errors.TraceNew("closed")
	}
}

func (listener *muxListener) Close() error {

	// Ensure close channel only called once.
	if !atomic.CompareAndSwapInt32(&listener.isClosed, 0, 1) {
		return nil
	}

	close(listener.stopBroadcast)

	var retErr error

	err := listener.gQUICListener.Close()
	if err != nil && retErr == nil {
		retErr = errors.Trace(err)
	}

	err = listener.ietfQUICListener.Close()
	if err != nil && retErr == nil {
		retErr = errors.Trace(err)
	}

	err = listener.conn.Close()
	if err != nil && retErr == nil {
		retErr = errors.Trace(err)
	}

	listener.runWaitGroup.Wait()

	return retErr
}

func (listener *muxListener) Addr() net.Addr {
	return listener.conn.LocalAddr()
}
