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

/*
Package quic wraps github.com/lucas-clemente/quic-go with net.Listener and
net.Conn types that provide a drop-in replacement for net.TCPConn.

Each QUIC connection has exactly one stream, which is the equivilent of a TCP
stream.

Conns returned from Accept will have an established QUIC connection and are
configured to perform a deferred AcceptStream on the first Read or Write.

Conns returned from Dial have an established QUIC connection and stream. Dial
accepts a Context input which may be used to cancel the dial.

Conns mask or translate qerr.PeerGoingAway to io.EOF as appropriate.

QUIC idle timeouts and keep alives are tuned to mitigate aggressive UDP NAT
timeouts on mobile data networks while accounting for the fact that mobile
devices in standby/sleep may not be able to initiate the keep alive.
*/
package quic

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	std_errors "errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	tls "github.com/Psiphon-Labs/psiphon-tls"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/obfuscator"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/transforms"
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

const ietfQUIC1VersionNumber = 0x1

var supportedVersionNumbers = map[string]uint32{
	protocol.QUIC_VERSION_GQUIC39:       uint32(0x51303339),
	protocol.QUIC_VERSION_GQUIC43:       uint32(0x51303433),
	protocol.QUIC_VERSION_GQUIC44:       uint32(0x51303434),
	protocol.QUIC_VERSION_OBFUSCATED:    uint32(0x51303433),
	protocol.QUIC_VERSION_V1:            ietfQUIC1VersionNumber,
	protocol.QUIC_VERSION_RANDOMIZED_V1: ietfQUIC1VersionNumber,
	protocol.QUIC_VERSION_OBFUSCATED_V1: uint32(ietfQUIC1VersionNumber),
	protocol.QUIC_VERSION_DECOY_V1:      uint32(ietfQUIC1VersionNumber),
}

func isObfuscated(quicVersion string) bool {
	return quicVersion == protocol.QUIC_VERSION_OBFUSCATED ||
		quicVersion == protocol.QUIC_VERSION_OBFUSCATED_V1 ||
		quicVersion == protocol.QUIC_VERSION_DECOY_V1
}

func isDecoy(quicVersion string) bool {
	return quicVersion == protocol.QUIC_VERSION_DECOY_V1
}

func isClientHelloRandomized(quicVersion string) bool {
	return quicVersion == protocol.QUIC_VERSION_RANDOMIZED_V1
}

func isIETF(quicVersion string) bool {
	versionNumber, ok := supportedVersionNumbers[quicVersion]
	if !ok {
		return false
	}
	return isIETFVersionNumber(versionNumber)
}

func isIETFVersionNumber(versionNumber uint32) bool {
	return versionNumber == ietfQUIC1VersionNumber
}

func isGQUIC(quicVersion string) bool {
	return quicVersion == protocol.QUIC_VERSION_GQUIC39 ||
		quicVersion == protocol.QUIC_VERSION_GQUIC43 ||
		quicVersion == protocol.QUIC_VERSION_GQUIC44 ||
		quicVersion == protocol.QUIC_VERSION_OBFUSCATED
}

func getALPN(versionNumber uint32) string {
	return "h3"
}

// quic_test overrides the server idle timeout.
var serverIdleTimeout = SERVER_IDLE_TIMEOUT

// Listener is a net.Listener.
type Listener struct {
	quicListener
	packetConn          *ObfuscatedOOBCapablePacketConn
	clientRandomHistory *obfuscator.SeedHistory
}

// Listen creates a new Listener.
func Listen(
	logger common.Logger,
	irregularTunnelLogger func(string, error, common.LogFields),
	address string,
	disablePathMTUDiscovery bool,
	additionalMaxPacketSizeAdjustment int,
	obfuscationKey string,
	enableGQUIC bool) (net.Listener, error) {

	certificate, privateKey, _, err := common.GenerateWebServerCertificate(
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

	// On the server side, the QUIC UDP socket is always wrapped with an
	// ObfuscatedPacketConn, as the single socket will receive and need to
	// handle both obfuscated and non-obfuscated QUIC protocol variants.
	//
	// The server UDP socket is further unconditionally wrapped with
	// ObfuscatedOOBCapablePacketConn, which enables support for setting the
	// OOB ECN bit, for congestion control, and the DF bit, required for path
	// MTU discovery. Both of these IP packet bits will be set by quic-go.
	//
	// This unconditional wrapping is a trade-off, since this also causes
	// quic-go to set the ECN and DF bits for obfuscated IETF QUIC.
	// This is partially mitigated by the fact that the DF bit is very
	// common, and that the ECN bit isn't set immediately.
	//
	// As a future enhancement, in the Psiphon-Labs/quic-go fork, add support
	// for per-connection enabling of setting the ECN/DF bits.
	//
	// When gQUIC is enabled and the mux listener is used, the
	// OOBCapablePacketConn features are masked and setting the ECN/DF bits
	// and path MTU discovery are dissabled.

	// Note that WriteTimeoutUDPConn is not used here in the server case, as
	// the server UDP conn will have many concurrent writers, and each
	// SetWriteDeadline call by WriteTimeoutUDPConn would extend the deadline
	// for all existing blocked writers. ObfuscatedPacketConn.Close calls
	// SetWriteDeadline once to interrupt any blocked writers to ensure a
	// timely shutdown.

	obfuscatedPacketConn, err := NewServerObfuscatedPacketConn(
		udpConn, false, false, obfuscationKey, seed)
	if err != nil {
		udpConn.Close()
		return nil, errors.Trace(err)
	}

	obfuscatedOOBPacketConn := NewObfuscatedOOBCapablePacketConn(
		obfuscatedPacketConn)

	// QUIC clients must prove knowledge of the obfuscated key via a message
	// sent in the TLS ClientHello random field, or receive no UDP packets
	// back from the server. This anti-probing mechanism is implemented using
	// the existing Passthrough message and SeedHistory replay detection
	// mechanisms. The replay history TTL is set to the validity period of
	// the passthrough message.
	//
	// Irregular events are logged for invalid client activity.

	clientRandomHistory := obfuscator.NewSeedHistory(
		&obfuscator.SeedHistoryConfig{SeedTTL: obfuscator.TLS_PASSTHROUGH_HISTORY_TTL})

	verifyClientHelloRandom := func(remoteAddr net.Addr, clientHelloRandom []byte) bool {

		ok := obfuscator.VerifyTLSPassthroughMessage(
			true, obfuscationKey, clientHelloRandom)
		if !ok {
			irregularTunnelLogger(
				common.IPAddressFromAddr(remoteAddr),
				errors.TraceNew("invalid client random message"),
				nil)
			return false
		}

		// Replay history is set to non-strict mode, allowing for a legitimate
		// client to resend its Initial packet, as may happen. Since the
		// source _port_ should be the same as the source IP in this case, we use
		// the full IP:port value as the client address from which a replay is
		// allowed.
		//
		// The non-strict case where ok is true and logFields is not nil is
		// ignored, and nothing is logged in that scenario.

		strictMode := false

		ok, logFields := clientRandomHistory.AddNew(
			strictMode, remoteAddr.String(), "client-hello-random", clientHelloRandom)
		if !ok && logFields != nil {
			irregularTunnelLogger(
				common.IPAddressFromAddr(remoteAddr),
				errors.TraceNew("duplicate client random message"),
				*logFields)
		}

		return ok
	}

	var quicListener quicListener

	if !enableGQUIC {

		// When gQUIC is disabled, skip the muxListener entirely. This allows
		// quic-go to enable ECN operations as the packet conn is a
		// quic-goOOBCapablePacketConn; this provides some performance
		// optimizations and also generate packets that may be harder to
		// fingerprint, due to lack of ECN bits in IP packets otherwise.
		// Skipping muxListener also avoids the additional overhead of
		// pumping read packets though mux channels.

		tlsConfig, ietfQUICConfig, err := makeServerIETFConfig(
			obfuscatedOOBPacketConn,
			disablePathMTUDiscovery,
			additionalMaxPacketSizeAdjustment,
			verifyClientHelloRandom,
			tlsCertificate,
			obfuscationKey)

		if err != nil {
			obfuscatedOOBPacketConn.Close()
			return nil, errors.Trace(err)
		}

		tr := newIETFTransport(obfuscatedOOBPacketConn)

		listener, err := tr.Listen(tlsConfig, ietfQUICConfig)
		if err != nil {
			obfuscatedPacketConn.Close()
			return nil, errors.Trace(err)
		}

		quicListener = &ietfQUICListener{
			Listener:  listener,
			transport: tr,
		}

	} else {

		// Note that, due to nature of muxListener, full accepts may happen before
		// return and caller calls Accept.

		muxListener, err := newMuxListener(
			logger,
			obfuscatedOOBPacketConn,
			additionalMaxPacketSizeAdjustment,
			verifyClientHelloRandom,
			tlsCertificate,
			obfuscationKey)
		if err != nil {
			obfuscatedOOBPacketConn.Close()
			return nil, errors.Trace(err)
		}

		quicListener = muxListener
	}

	return &Listener{
		quicListener:        quicListener,
		packetConn:          obfuscatedOOBPacketConn,
		clientRandomHistory: clientRandomHistory,
	}, nil
}

// Accept returns a net.Conn that wraps a single QUIC connection and stream.
// The stream establishment is deferred until the first Read or Write,
// allowing Accept to be called in a fast loop while goroutines spawned to
// handle each net.Conn will perform the blocking AcceptStream.
func (listener *Listener) Accept() (net.Conn, error) {

	connection, err := listener.quicListener.Accept()
	if err != nil {
		return nil, errors.Trace(err)
	}

	return &Conn{
		connection:           connection,
		deferredAcceptStream: true,
	}, nil
}

func (listener *Listener) Close() error {
	_ = listener.packetConn.Close()
	return listener.quicListener.Close()
}

func makeServerIETFConfig(
	conn *ObfuscatedOOBCapablePacketConn,
	disablePathMTUDiscovery bool,
	additionalMaxPacketSizeAdjustment int,
	verifyClientHelloRandom func(net.Addr, []byte) bool,
	tlsCertificate tls.Certificate,
	sharedSecret string) (*tls.Config, *ietf_quic.Config, error) {

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCertificate},
		NextProtos:   []string{getALPN(ietfQUIC1VersionNumber)},
	}

	if sharedSecret != "" {
		var obfuscatedSessionTicketKey [32]byte
		key, err := hex.DecodeString(sharedSecret)
		if err == nil && len(key) != 32 {
			err = std_errors.New("invalid obfuscated session key length")
		}
		if err != nil {
			return nil, nil, errors.TraceNew("invalid obfuscated session key length")
		}
		copy(obfuscatedSessionTicketKey[:], key)

		var standardSessionTicketKey [32]byte
		_, err = rand.Read(standardSessionTicketKey[:])
		if err != nil {
			panic(err)
		}

		tlsConfig.SetSessionTicketKeys([][32]byte{
			standardSessionTicketKey,
			obfuscatedSessionTicketKey,
		})
	}

	serverMaxPacketSizeAdjustment :=
		conn.ObfuscatedPacketConn.serverMaxPacketSizeAdjustment

	if additionalMaxPacketSizeAdjustment != 0 {
		serverMaxPacketSizeAdjustment = func(addr net.Addr) int {
			return conn.serverMaxPacketSizeAdjustment(addr) +
				additionalMaxPacketSizeAdjustment
		}
	}

	ietfQUICConfig := &ietf_quic.Config{
		Allow0RTT:             true,
		HandshakeIdleTimeout:  SERVER_HANDSHAKE_TIMEOUT,
		MaxIdleTimeout:        serverIdleTimeout,
		MaxIncomingStreams:    1,
		MaxIncomingUniStreams: -1,
		// TODO: add jitter to keep alive period
		KeepAlivePeriod: CLIENT_IDLE_TIMEOUT / 2,

		VerifyClientHelloRandom:       verifyClientHelloRandom,
		ServerMaxPacketSizeAdjustment: serverMaxPacketSizeAdjustment,
		DisablePathMTUDiscovery:       disablePathMTUDiscovery,
	}

	return tlsConfig, ietfQUICConfig, nil
}

func newIETFTransport(conn net.PacketConn) *ietf_quic.Transport {
	return &ietf_quic.Transport{
		Conn: conn,

		// The quic-go server may respond with a version negotiation packet
		// before reaching the Initial packet processing with its
		// anti-probing defense. This may happen even for a malformed packet.
		// To prevent all responses to probers, version negotiation is
		// disabled, which disables sending these packets. The fact that the
		// server does not issue version negotiation packets may be a
		// fingerprint itself, but, regardless, probers cannot ellicit any
		// reponse from the server without providing a well-formed Initial
		// packet with a valid Client Hello random value.
		//
		// Limitation: once version negotiate is required, the order of
		// quic-go operations may need to be changed in order to first check
		// the Initial/Client Hello, and then issue any required version
		// negotiation packet.
		DisableVersionNegotiationPackets: true,
	}
}

// Dial establishes a new QUIC connection and stream to the server specified
// by address.
//
// packetConn is used as the underlying packet connection for QUIC. The dial
// may be cancelled by ctx; packetConn will be closed if the dial is
// cancelled or fails.
//
// When packetConn is a *net.UDPConn, QUIC ECN bit operations are supported,
// unless the specified QUIC version is obfuscated.
func Dial(
	ctx context.Context,
	packetConn net.PacketConn,
	remoteAddr *net.UDPAddr,
	quicSNIAddress string,
	quicVersion string,
	clientHelloSeed *prng.Seed,
	obfuscationKey string,
	obfuscationPaddingSeed *prng.Seed,
	obfuscationNonceTransformerParameters *transforms.ObfuscatorSeedTransformerParameters,
	disablePathMTUDiscovery bool,
	additionalMaxPacketSizeAdjustment int,
	dialEarly bool,
	useObfuscatedPSK bool,
	tlsClientSessionCache *common.TLSClientSessionCacheWrapper) (net.Conn, error) {

	if quicVersion == "" {
		return nil, errors.TraceNew("missing version")
	}

	if isClientHelloRandomized(quicVersion) && clientHelloSeed == nil {
		return nil, errors.TraceNew("missing client hello randomization values")
	}

	// obfuscationKey is always required, as it is used for anti-probing even
	// when not obfuscating the QUIC payload.
	if (isObfuscated(quicVersion) && obfuscationPaddingSeed == nil) || obfuscationKey == "" {
		return nil, errors.TraceNew("missing obfuscation values")
	}

	versionNumber, ok := supportedVersionNumbers[quicVersion]
	if !ok {
		return nil, errors.Tracef("unsupported version: %s", quicVersion)
	}

	// Fail if the destination port is invalid. Network operations should fail
	// quickly in this case, but IETF quic-go has been observed to timeout,
	// instead of failing quickly, in the case of invalid destination port 0.
	if remoteAddr.Port <= 0 || remoteAddr.Port >= 65536 {
		return nil, errors.Tracef("invalid destination port: %d", remoteAddr.Port)
	}

	udpConn, isUDPConn := packetConn.(*net.UDPConn)

	// Ensure blocked packet writes eventually timeout.
	if isUDPConn {

		packetConn = &common.WriteTimeoutUDPConn{
			UDPConn: udpConn,
		}
	} else {

		packetConn = &common.WriteTimeoutPacketConn{
			PacketConn: packetConn,
		}
	}

	maxPacketSizeAdjustment := additionalMaxPacketSizeAdjustment

	if isObfuscated(quicVersion) {
		obfuscatedPacketConn, err := NewClientObfuscatedPacketConn(
			packetConn,
			remoteAddr,
			isIETFVersionNumber(versionNumber),
			isDecoy(quicVersion),
			obfuscationKey,
			obfuscationPaddingSeed,
			obfuscationNonceTransformerParameters)
		if err != nil {
			return nil, errors.Trace(err)
		}

		// When available, expose the required UDP socket functionality to
		// handle OOB bits, for handling the ECN bit, and the DF bit, for
		// path MTU discovery.
		if isUDPConn {
			packetConn = NewObfuscatedOOBCapablePacketConn(obfuscatedPacketConn)
		} else {
			packetConn = obfuscatedPacketConn
		}

		// Disable path MTU in the client flow. This avoids setting the DF bit
		// for client obfuscated QUIC packets. The downstream server flow
		// will still perform MTU discovery.
		//
		// As a future enhancement, in the Psiphon-Labs/quic-go fork, consider
		// enabling a delay for client flow MTU discovery so that early
		// packets don't include the DF bit.

		disablePathMTUDiscovery = true

		// Reserve additional space for packet obfuscation overhead so that
		// quic-go will continue to produce packets of max size 1280.
		maxPacketSizeAdjustment += OBFUSCATED_MAX_PACKET_SIZE_ADJUSTMENT
	}

	// As an anti-probing measure, QUIC clients must prove knowledge of the
	// server obfuscation key in the first client packet sent to the server. In
	// the case of QUIC, the first packet, the Initial packet, contains a TLS
	// Client Hello, and we set the client random field to a value that both
	// proves knowledge of the obfuscation key and is indistiguishable from
	// random. This is the same "passthrough" technique used for TLS, although
	// for QUIC the server simply doesn't respond to any packets instead of
	// passing traffic through to a different server.
	//
	// Limitation: the legacy gQUIC implementation does not support this
	// anti-probling measure; gQUIC must be disabled to ensure no response
	// from the server.

	var getClientHelloRandom func() ([]byte, error)
	if obfuscationKey != "" {
		getClientHelloRandom = func() ([]byte, error) {
			random, err := obfuscator.MakeTLSPassthroughMessage(true, obfuscationKey)
			if err != nil {
				return nil, errors.Trace(err)
			}
			return random, nil
		}
	}

	obfuscatedPSKKey := ""
	if useObfuscatedPSK {
		obfuscatedPSKKey = obfuscationKey
	}

	connection, err := dialQUIC(
		ctx,
		packetConn,
		remoteAddr,
		quicSNIAddress,
		versionNumber,
		clientHelloSeed,
		getClientHelloRandom,
		maxPacketSizeAdjustment,
		disablePathMTUDiscovery,
		dialEarly,
		obfuscatedPSKKey,
		tlsClientSessionCache)

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

		stream, err := connection.OpenStream()
		if err != nil {
			connection.Close()
			resultChannel <- dialResult{err: err}
			return
		}

		resultChannel <- dialResult{
			conn: &Conn{
				isClient:   true,
				packetConn: packetConn,
				connection: connection,
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
		connection.Close()
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
	isClient   bool
	packetConn net.PacketConn
	connection quicConnection

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

	stream, err := conn.connection.AcceptStream()
	if err != nil {
		conn.connection.Close()
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
	if conn.connection.isErrorIndicatingClosed(err) {
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
	if conn.connection.isErrorIndicatingClosed(err) {
		_ = conn.Close()
		if n == len(b) {
			err = nil
		}
	}
	return n, err
}

func (conn *Conn) Close() error {
	err := conn.connection.Close()
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
	return conn.connection.LocalAddr()
}

func (conn *Conn) RemoteAddr() net.Addr {
	return conn.connection.RemoteAddr()
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

// GetMetrics implements the common.MetricsSource interface.
func (conn *Conn) GetMetrics() common.LogFields {

	logFields := make(common.LogFields)

	// Include metrics, such as inproxy and fragmentor metrics, from the
	// underlying dial conn.
	underlyingMetrics, ok := conn.packetConn.(common.MetricsSource)
	if ok {
		logFields.Add(underlyingMetrics.GetMetrics())
	}

	if conn.isClient {

		metrics := conn.connection.getClientConnMetrics()

		dialEarly := "0"
		if metrics.dialEarly {
			dialEarly = "1"
		}
		logFields["quic_dial_early"] = dialEarly

		quicSentTicket := "0"
		if metrics.tlsClientSentTicket {
			quicSentTicket = "1"
		}
		logFields["quic_sent_ticket"] = quicSentTicket

		quicDidResume := "0"
		if metrics.tlsClientSentTicket {
			quicDidResume = "1"
		}
		logFields["quic_did_resume"] = quicDidResume

		obfuscatedPSK := "0"
		if metrics.obfuscatedPSK {
			obfuscatedPSK = "1"
		}
		logFields["quic_obfuscated_psk"] = obfuscatedPSK
	}

	return logFields
}

// QUICTransporter implements the psiphon.transporter interface, used in
// psiphon.MeekConn for HTTP requests, which requires a RoundTripper and
// CloseIdleConnections.
type QUICTransporter struct {
	quicRoundTripper

	quicClientConnMetrics atomic.Value

	noticeEmitter           func(string)
	udpDialer               func(ctx context.Context) (net.PacketConn, *net.UDPAddr, error)
	quicSNIAddress          string
	quicVersion             string
	clientHelloSeed         *prng.Seed
	disablePathMTUDiscovery bool
	dialEarly               bool
	tlsClientSessionCache   *common.TLSClientSessionCacheWrapper
	packetConn              atomic.Value

	mutex sync.Mutex
	ctx   context.Context
}

// NewQUICTransporter creates a new QUICTransporter.
func NewQUICTransporter(
	ctx context.Context,
	noticeEmitter func(string),
	udpDialer func(ctx context.Context) (net.PacketConn, *net.UDPAddr, error),
	quicSNIAddress string,
	quicVersion string,
	clientHelloSeed *prng.Seed,
	disablePathMTUDiscovery bool,
	dialEarly bool,
	tlsClientSessionCache *common.TLSClientSessionCacheWrapper) (*QUICTransporter, error) {

	if quicVersion == "" {
		return nil, errors.TraceNew("missing version")
	}

	versionNumber, ok := supportedVersionNumbers[quicVersion]
	if !ok {
		return nil, errors.Tracef("unsupported version: %s", quicVersion)
	}

	if isClientHelloRandomized(quicVersion) && clientHelloSeed == nil {
		return nil, errors.TraceNew("missing client hello randomization values")
	}

	t := &QUICTransporter{
		noticeEmitter:           noticeEmitter,
		udpDialer:               udpDialer,
		quicSNIAddress:          quicSNIAddress,
		quicVersion:             quicVersion,
		clientHelloSeed:         clientHelloSeed,
		disablePathMTUDiscovery: disablePathMTUDiscovery,
		dialEarly:               dialEarly,
		tlsClientSessionCache:   tlsClientSessionCache,
		ctx:                     ctx,
	}

	if isIETFVersionNumber(versionNumber) {
		t.quicRoundTripper = &http3.RoundTripper{Dial: t.dialIETFQUIC}
	} else {
		var err error
		t.quicRoundTripper, err = gQUICRoundTripper(t)
		if err != nil {
			return nil, errors.Trace(err)
		}
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

func (t *QUICTransporter) GetMetrics() common.LogFields {
	logFields := make(common.LogFields)

	metrics := t.quicClientConnMetrics.Load().(*quicClientConnMetrics)

	dialEarly := "0"
	if metrics.dialEarly {
		dialEarly = "1"
	}
	logFields["quic_dial_early"] = dialEarly

	quicSentTicket := "0"
	if metrics.tlsClientSentTicket {
		quicSentTicket = "1"
	}
	logFields["quic_sent_ticket"] = quicSentTicket

	quicDidResume := "0"
	if metrics.tlsClientSentTicket {
		quicDidResume = "1"
	}
	logFields["quic_did_resume"] = quicDidResume

	return logFields
}

func (t *QUICTransporter) dialIETFQUIC(
	_ context.Context, _ string, _ *tls.Config, _ *ietf_quic.Config) (ietf_quic.EarlyConnection, error) {
	// quic-go now supports the request context in its RoundTripper.Dial, but
	// we already handle this via t.ctx, so we ignore the input context.
	connection, err := t.dialQUIC()
	if err != nil {
		return nil, errors.Trace(err)
	}
	return connection.(*ietfQUICConnection).Connection.(ietf_quic.EarlyConnection), nil
}

func (t *QUICTransporter) dialQUIC() (retConnection quicConnection, retErr error) {

	defer func() {
		if retErr != nil && t.noticeEmitter != nil {
			t.noticeEmitter(fmt.Sprintf("QUICTransporter.dialQUIC failed: %s", retErr))
		}
	}()

	versionNumber, ok := supportedVersionNumbers[t.quicVersion]
	if !ok {
		return nil, errors.Tracef("unsupported version: %s", t.quicVersion)
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

	// See `udpConn, ok := packetConn.(*net.UDPConn)` block and comment in
	// Dial. The same two cases are implemented here, although there is no
	// obfuscated fronted QUIC.
	//
	// Limitation: for FRONTED-MEEK-QUIC-OSSH, OOB operations to support
	// reading/writing ECN bits will not be enabled due to the
	// meekUnderlyingPacketConn wrapping in the provided udpDialer.

	udpConn, ok := packetConn.(*net.UDPConn)

	if !ok {

		// Ensure blocked packet writes eventually timeout. Note that quic-go
		// manages read deadlines; we set only the write deadline here.
		packetConn = &common.WriteTimeoutPacketConn{
			PacketConn: packetConn,
		}

	} else {

		// Ensure blocked packet writes eventually timeout.
		packetConn = &common.WriteTimeoutUDPConn{
			UDPConn: udpConn,
		}
	}

	connection, err := dialQUIC(
		ctx,
		packetConn,
		remoteAddr,
		t.quicSNIAddress,
		versionNumber,
		t.clientHelloSeed,
		nil,
		0,
		t.disablePathMTUDiscovery,
		t.dialEarly,
		"", // PSK ticket key is not used for fronted connections.
		t.tlsClientSessionCache)

	if err != nil {
		packetConn.Close()
		return nil, errors.Trace(err)
	}

	metrics := connection.getClientConnMetrics()
	t.quicClientConnMetrics.Store(&metrics)

	// dialQUIC uses quic-go.DialContext as we must create our own UDP sockets to
	// set properties such as BIND_TO_DEVICE. However, when DialContext is used,
	// quic-go does not take responsibiity for closing the underlying packetConn
	// when the QUIC connection is closed.
	//
	// We track the most recent packetConn in QUICTransporter and close it:
	// - when CloseIdleConnections is called, as it is by psiphon.MeekConn when
	//   it is closing;
	// - here in dialFunc, with the assumption that only one concurrent QUIC
	//   connection is used per h2quic.RoundTripper.
	//
	// This code also assume no concurrent calls to dialFunc, as otherwise a race
	// condition exists between closePacketConn and Store.

	t.closePacketConn()
	t.packetConn.Store(packetConn)

	return connection, nil
}

// The following code provides support for using both gQUIC and IETF QUIC,
// which are implemented in two different branches (now forks) of quic-go.
// (The gQUIC functions are now located in gquic.go and the entire gQUIC
// quic-go stack may be conditionally excluded from builds).
//
// dialQUIC uses the appropriate quic-go and returns quicConnection which
// wraps either a ietf_quic.Connection or gquic.Session.
//
// muxPacketConn provides a multiplexing listener that directs packets to
// either a ietf_quic.Listener or a gquic.Listener based on the content of the
// packet.

type quicListener interface {
	Close() error
	Addr() net.Addr
	Accept() (quicConnection, error)
}

// quicClientConnMetrics provides metrics for a QUIC client connection,
// after a dial has been made.
type quicClientConnMetrics struct {
	dialEarly           bool
	tlsClientSentTicket bool
	tlsDidResume        bool
	obfuscatedPSK       bool
}

type quicConnection interface {
	io.Closer
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
	AcceptStream() (quicStream, error)
	OpenStream() (quicStream, error)
	isErrorIndicatingClosed(err error) bool
	isEarlyDataRejected(err error) bool
	getClientConnMetrics() quicClientConnMetrics
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
	*ietf_quic.Listener
	transport *ietf_quic.Transport
}

func (l *ietfQUICListener) Accept() (quicConnection, error) {
	// A specific context is not provided since the interface needs to match the
	// gquic-go API, which lacks context support.
	connection, err := l.Listener.Accept(context.Background())
	if err != nil {
		return nil, errors.Trace(err)
	}
	return &ietfQUICConnection{Connection: connection}, nil
}

func (l *ietfQUICListener) Close() error {
	// All quic-go goroutines will be stopped when the transport is closed.
	// https://github.com/quic-go/quic-go/issues/3962
	return l.transport.Close()
}

type ietfQUICConnection struct {
	ietf_quic.Connection
	clientMetrics quicClientConnMetrics
}

func (c *ietfQUICConnection) AcceptStream() (quicStream, error) {
	// A specific context is not provided since the interface needs to match the
	// gquic-go API, which lacks context support.
	//
	// TODO: once gQUIC support is retired, this context may be used in place
	// of the deferredAcceptStream mechanism.
	stream, err := c.Connection.AcceptStream(context.Background())
	if err != nil {
		return nil, errors.Trace(err)
	}
	return stream, nil
}

func (c *ietfQUICConnection) OpenStream() (quicStream, error) {
	return c.Connection.OpenStream()
}

func (c *ietfQUICConnection) Close() error {
	return c.Connection.CloseWithError(0, "")
}

func (c *ietfQUICConnection) isErrorIndicatingClosed(err error) bool {
	if err == nil {
		return false
	}
	return IsIETFErrorIndicatingClosed(err)
}

func IsIETFErrorIndicatingClosed(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	// The target errors are of type qerr.ApplicationError[Code] and
	// qerr.IdleTimeoutError, but these are not both exported by quic-go.
	return strings.HasPrefix(errStr, "Application error 0x0") ||
		errStr == "timeout: no recent network activity"
}

// TODO: TLS handshake still completes even if 0-RTT is rejected, but currently we fail the QUIC connection anyway.
// By checking this error, we can start a new QUIC connection (EarlyConnection.NextConnection)
// and resend any data already sent in the "early_data".
func (c *ietfQUICConnection) isEarlyDataRejected(err error) bool {
	if err == nil {
		return false
	}
	return err == ietf_quic.Err0RTTRejected
}

func (c *ietfQUICConnection) getClientConnMetrics() quicClientConnMetrics {
	return c.clientMetrics
}

func dialQUIC(
	ctx context.Context,
	packetConn net.PacketConn,
	remoteAddr *net.UDPAddr,
	quicSNIAddress string,
	versionNumber uint32,
	clientHelloSeed *prng.Seed,
	getClientHelloRandom func() ([]byte, error),
	maxPacketSizeAdjustment int,
	disablePathMTUDiscovery bool,
	dialEarly bool,
	obfuscatedPSKKey string,
	tlsClientSessionCache *common.TLSClientSessionCacheWrapper) (quicConnection, error) {

	if tlsClientSessionCache == nil {
		return nil, errors.TraceNew("missing TLS client session cache")
	}

	if isIETFVersionNumber(versionNumber) {
		quicConfig := &ietf_quic.Config{
			HandshakeIdleTimeout: time.Duration(1<<63 - 1),
			MaxIdleTimeout:       CLIENT_IDLE_TIMEOUT,
			// TODO: add jitter to keep alive period
			KeepAlivePeriod: CLIENT_IDLE_TIMEOUT / 2,
			Versions: []ietf_quic.Version{
				ietf_quic.Version(versionNumber)},
			ClientHelloSeed:               clientHelloSeed,
			GetClientHelloRandom:          getClientHelloRandom,
			ClientMaxPacketSizeAdjustment: maxPacketSizeAdjustment,
			DisablePathMTUDiscovery:       disablePathMTUDiscovery,
		}

		deadline, ok := ctx.Deadline()
		if ok {
			quicConfig.HandshakeIdleTimeout = time.Until(deadline)
		}

		// Legacy replay values might include a port. If so, strip it.
		// This was a requirement of legacy quic-go API, but is no longer required.
		sni, _, err := net.SplitHostPort(quicSNIAddress)
		if err != nil {
			sni = quicSNIAddress
		}

		var dialConnection ietf_quic.Connection
		tlsConfig := &tls.Config{
			InsecureSkipVerify:     true,
			InsecureSkipTimeVerify: true,
			NextProtos:             []string{getALPN(versionNumber)},
			ServerName:             sni,
			ClientSessionCache:     tlsClientSessionCache,
		}

		// Use the default curves here,
		// https://github.com/Psiphon-Labs/psiphon-tls/blob/2a2fae2d/defaults.go#L26,
		// except for x25519Kyber768Draft00, since it causes the ClientHello
		// size to grow beyond one packet. The current Psiphon-Labs/quic-go
		// server code supports multi-packet ClientHellos, but the
		// verifyClientHelloRandom in older QUIC servers does not. This
		// workaround ensures compatibility with servers running older
		// Psiphon-Labs/quic-go.
		//
		// TODO: remove this workaround when no longer required.
		tlsConfig.CurvePreferences = []tls.CurveID{
			tls.X25519, tls.CurveP256, tls.CurveP384, tls.CurveP521}

		// Creating a session state and storing it in the TLS cache to be used
		// for PSK (Pre-Shared Key) resumption.
		if obfuscatedPSKKey != "" {
			var sharedSecret [32]byte
			key, err := hex.DecodeString(obfuscatedPSKKey)
			if err == nil && len(key) != 32 {
				err = std_errors.New("invalid obfuscated PSK key length")
			}
			if err != nil {
				return nil, errors.Trace(err)
			}
			copy(sharedSecret[:], key)

			obfuscatedSessionState, err := tls.NewObfuscatedClientSessionState(
				sharedSecret, true, false)
			if err != nil {
				return nil, errors.Trace(err)
			}
			sessionState := tls.MakeClientSessionState(
				obfuscatedSessionState.SessionTicket,
				obfuscatedSessionState.Vers,
				obfuscatedSessionState.CipherSuite,
				obfuscatedSessionState.MasterSecret,
				obfuscatedSessionState.CreatedAt,
				obfuscatedSessionState.AgeAdd,
				obfuscatedSessionState.UseBy,
			)
			tlsClientSessionCache.Put("", sessionState)
		}

		if dialEarly {
			// Attempting 0-RTT if possible.
			dialConnection, err = ietf_quic.DialEarly(
				ctx,
				packetConn,
				remoteAddr,
				tlsConfig,
				quicConfig)
		} else {
			dialConnection, err = ietf_quic.Dial(
				ctx,
				packetConn,
				remoteAddr,
				tlsConfig,
				quicConfig)
		}

		if err != nil {
			return nil, errors.Trace(err)
		}

		metrics := quicClientConnMetrics{
			dialEarly:           dialEarly,
			tlsClientSentTicket: dialConnection.TLSConnectionMetrics().ClientSentTicket,
			tlsDidResume:        dialConnection.ConnectionState().TLS.DidResume,
			obfuscatedPSK:       obfuscatedPSKKey != "",
		}

		return &ietfQUICConnection{
			Connection:    dialConnection,
			clientMetrics: metrics,
		}, nil

	} else {

		quicConnection, err := gQUICDialContext(
			ctx,
			packetConn,
			remoteAddr,
			quicSNIAddress,
			versionNumber)
		if err != nil {
			return nil, errors.Trace(err)
		}

		return quicConnection, nil
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
	return errors.Trace(errNotSupported)
}

func (conn *muxPacketConn) SetReadDeadline(t time.Time) error {
	return errors.Trace(errNotSupported)
}

func (conn *muxPacketConn) SetWriteDeadline(t time.Time) error {
	return errors.Trace(errNotSupported)
}

// SetReadBuffer and SetWriteBuffer provide passthroughs to the underlying
// net.UDPConn implementations, used to optimize UDP buffer sizes. See
// https://github.com/quic-go/quic-go/wiki/UDP-Buffer-Sizes and
// ietf_quic.setReceive/SendBuffer. Only the IETF stack will access these
// functions.
//
// Limitations:
//   - SysconnCall is not passed through as it is not required in
//     ietf_quic.setReceive/SendBuffer, and it may cause issues if used, by the
//     IETF stack, to set the DF bit for path MTU discovery. As a result, MTU
//     discovery is not enabled with the multiplexer.
//   - Due to the relayPackets/ReadFrom scheme, this simple passthrough does not
//     suffice to provide access to ReadMsgUDP for
//     https://godoc.org/github.com/quic-go/quic-go#OOBCapablePacketConn.
func (conn *muxPacketConn) SetReadBuffer(bytes int) error {
	c, ok := conn.listener.conn.PacketConn.(interface {
		SetReadBuffer(int) error
	})
	if !ok {
		return errors.Trace(errNotSupported)
	}
	return c.SetReadBuffer(bytes)
}

func (conn *muxPacketConn) SetWriteBuffer(bytes int) error {
	c, ok := conn.listener.conn.PacketConn.(interface {
		SetWriteBuffer(int) error
	})
	if !ok {
		return errors.Trace(errNotSupported)
	}
	return c.SetWriteBuffer(bytes)
}

// muxListener is a multiplexing packet conn listener which relays packets to
// multiple quic-go listeners.
type muxListener struct {
	logger              common.Logger
	isClosed            int32
	runWaitGroup        *sync.WaitGroup
	stopBroadcast       chan struct{}
	conn                *ObfuscatedOOBCapablePacketConn
	packets             chan *packet
	acceptedConnections chan quicConnection
	ietfQUICConn        *muxPacketConn
	ietfQUICListener    quicListener
	gQUICConn           *muxPacketConn
	gQUICListener       quicListener
}

func newMuxListener(
	logger common.Logger,
	conn *ObfuscatedOOBCapablePacketConn,
	additionalMaxPacketSizeAdjustment int,
	verifyClientHelloRandom func(net.Addr, []byte) bool,
	tlsCertificate tls.Certificate,
	sharedSecret string) (*muxListener, error) {

	listener := &muxListener{
		logger:              logger,
		runWaitGroup:        new(sync.WaitGroup),
		stopBroadcast:       make(chan struct{}),
		conn:                conn,
		packets:             make(chan *packet, muxPacketQueueSize),
		acceptedConnections: make(chan quicConnection, 2), // 1 per listener
	}

	// All packet relay buffers are allocated in advance.
	for i := 0; i < muxPacketQueueSize; i++ {
		listener.packets <- &packet{data: make([]byte, muxPacketBufferSize)}
	}

	listener.ietfQUICConn = newMuxPacketConn(conn.LocalAddr(), listener)

	// The muxListener does not expose the quic-go.OOBCapablePacketConn
	// SyscallConn capability required for MTU discovery.
	disablePathMTUDiscovery := true

	tlsConfig, ietfQUICConfig, err := makeServerIETFConfig(
		conn,
		disablePathMTUDiscovery,
		additionalMaxPacketSizeAdjustment,
		verifyClientHelloRandom,
		tlsCertificate,
		sharedSecret)
	if err != nil {
		return nil, errors.Trace(err)
	}

	tr := newIETFTransport(listener.ietfQUICConn)
	il, err := tr.Listen(tlsConfig, ietfQUICConfig)
	if err != nil {
		return nil, errors.Trace(err)
	}
	listener.ietfQUICListener = &ietfQUICListener{
		Listener:  il,
		transport: tr,
	}

	listener.gQUICConn = newMuxPacketConn(conn.LocalAddr(), listener)

	gl, err := gQUICListen(listener.gQUICConn, tlsCertificate, serverIdleTimeout)
	if err != nil {
		listener.ietfQUICListener.Close()
		return nil, errors.Trace(err)
	}
	listener.gQUICListener = gl

	listener.runWaitGroup.Add(3)
	go listener.relayPackets()
	go listener.relayAcceptedConnections(listener.gQUICListener)
	go listener.relayAcceptedConnections(listener.ietfQUICListener)

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
		p.size, _, _, p.addr, isIETF, err = listener.conn.readPacketWithType(p.data, nil)
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

func (listener *muxListener) relayAcceptedConnections(l quicListener) {
	defer listener.runWaitGroup.Done()
	for {
		connection, err := l.Accept()
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
		case listener.acceptedConnections <- connection:
		case <-listener.stopBroadcast:
			return
		}
	}
}

func (listener *muxListener) Accept() (quicConnection, error) {
	select {
	case conn := <-listener.acceptedConnections:
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

var errNotSupported = std_errors.New("not supported")
