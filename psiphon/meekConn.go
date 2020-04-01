/*
 * Copyright (c) 2015, Psiphon Inc.
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

package psiphon

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Psiphon-Labs/net/http2"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/obfuscator"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/parameters"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/quic"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/upstreamproxy"
	"golang.org/x/crypto/nacl/box"
)

// MeekConn is based on meek-client.go from Tor and Psiphon:
//
// https://gitweb.torproject.org/pluggable-transports/meek.git/blob/HEAD:/meek-client/meek-client.go
// CC0 1.0 Universal
//
// https://bitbucket.org/psiphon/psiphon-circumvention-system/src/default/go/meek-client/meek-client.go

const (
	MEEK_PROTOCOL_VERSION           = 3
	MEEK_MAX_REQUEST_PAYLOAD_LENGTH = 65536
)

// MeekConfig specifies the behavior of a MeekConn
type MeekConfig struct {

	// DiagnosticID is the server ID to record in any diagnostics notices.
	DiagnosticID string

	// ClientParameters is the active set of client parameters to use
	// for the meek dial.
	ClientParameters *parameters.ClientParameters

	// DialAddress is the actual network address to dial to establish a
	// connection to the meek server. This may be either a fronted or
	// direct address. The address must be in the form "host:port",
	// where host may be a domain name or IP address.
	DialAddress string

	// UseQUIC indicates whether to use HTTP/2 over QUIC.
	UseQUIC bool

	// QUICVersion indicates which QUIC version to use.
	QUICVersion string

	// UseHTTPS indicates whether to use HTTPS (true) or HTTP (false).
	// Ignored when UseQUIC is true.
	UseHTTPS bool

	// TLSProfile specifies the value for CustomTLSConfig.TLSProfile for all
	// underlying TLS connections created by this meek connection.
	TLSProfile string

	// NoDefaultTLSSessionID specifies the value for
	// CustomTLSConfig.NoDefaultTLSSessionID for all underlying TLS connections
	// created by this meek connection.
	NoDefaultTLSSessionID bool

	// RandomizedTLSProfileSeed specifies the value for
	// CustomTLSConfig.RandomizedTLSProfileSeed for all underlying TLS
	// connections created by this meek connection.
	RandomizedTLSProfileSeed *prng.Seed

	// UseObfuscatedSessionTickets indicates whether to use obfuscated
	// session tickets. Assumes UseHTTPS is true.
	UseObfuscatedSessionTickets bool

	// SNIServerName is the value to place in the TLS/QUIC SNI server_name
	// field when HTTPS or QUIC is used.
	SNIServerName string

	// HostHeader is the value to place in the HTTP request Host header.
	HostHeader string

	// TransformedHostName records whether a hostname transformation is
	// in effect. This value is used for stats reporting.
	TransformedHostName bool

	// ClientTunnelProtocol is the protocol the client is using. It's
	// included in the meek cookie for optional use by the server, in
	// cases where the server cannot unambiguously determine the
	// tunnel protocol.
	// ClientTunnelProtocol is used when selecting tactics targeted at
	// specific protocols.
	ClientTunnelProtocol string

	// RoundTripperOnly sets the MeekConn to operate in round tripper
	// mode, which is used for untunneled tactics requests. In this
	// mode, a connection is established to the meek server as usual,
	// but instead of relaying tunnel traffic, the RoundTrip function
	// may be used to make requests. In this mode, no relay resources
	// incuding buffers are allocated.
	RoundTripperOnly bool

	// NetworkLatencyMultiplier specifies a custom network latency multiplier to
	// apply to client parameters used by this meek connection.
	NetworkLatencyMultiplier float64

	// The following values are used to create the obfuscated meek cookie.

	MeekCookieEncryptionPublicKey string
	MeekObfuscatedKey             string
	MeekObfuscatorPaddingSeed     *prng.Seed
}

// MeekConn is a network connection that tunnels TCP over HTTP and supports "fronting". Meek sends
// client->server flow in HTTP request bodies and receives server->client flow in HTTP response bodies.
// Polling is used to achieve full duplex TCP.
//
// Fronting is an obfuscation technique in which the connection
// to a web server, typically a CDN, is indistinguishable from any other HTTPS connection to the generic
// "fronting domain" -- the HTTP Host header is used to route the requests to the actual destination.
// See https://trac.torproject.org/projects/tor/wiki/doc/meek for more details.
//
// MeekConn also operates in unfronted mode, in which plain HTTP connections are made without routing
// through a CDN.
type MeekConn struct {
	clientParameters          *parameters.ClientParameters
	networkLatencyMultiplier  float64
	isQUIC                    bool
	url                       *url.URL
	additionalHeaders         http.Header
	cookie                    *http.Cookie
	cookieSize                int
	tlsPadding                int
	limitRequestPayloadLength int
	redialTLSProbability      float64
	cachedTLSDialer           *cachedTLSDialer
	transport                 transporter
	mutex                     sync.Mutex
	isClosed                  bool
	runCtx                    context.Context
	stopRunning               context.CancelFunc
	relayWaitGroup            *sync.WaitGroup

	// For round tripper mode
	roundTripperOnly              bool
	meekCookieEncryptionPublicKey string
	meekObfuscatedKey             string
	meekObfuscatorPaddingSeed     *prng.Seed
	clientTunnelProtocol          string

	// For relay mode
	fullReceiveBufferLength int
	readPayloadChunkLength  int
	emptyReceiveBuffer      chan *bytes.Buffer
	partialReceiveBuffer    chan *bytes.Buffer
	fullReceiveBuffer       chan *bytes.Buffer
	emptySendBuffer         chan *bytes.Buffer
	partialSendBuffer       chan *bytes.Buffer
	fullSendBuffer          chan *bytes.Buffer
}

func (conn *MeekConn) getCustomClientParameters() parameters.ClientParametersAccessor {
	return conn.clientParameters.GetCustom(conn.networkLatencyMultiplier)
}

// transporter is implemented by both http.Transport and upstreamproxy.ProxyAuthTransport.
type transporter interface {
	CloseIdleConnections()
	RoundTrip(req *http.Request) (resp *http.Response, err error)
}

// DialMeek returns an initialized meek connection. A meek connection is
// an HTTP session which does not depend on an underlying socket connection (although
// persistent HTTP connections are used for performance). This function does not
// wait for the connection to be "established" before returning. A goroutine
// is spawned which will eventually start HTTP polling.
// When frontingAddress is not "", fronting is used. This option assumes caller has
// already checked server entry capabilities.
func DialMeek(
	ctx context.Context,
	meekConfig *MeekConfig,
	dialConfig *DialConfig) (meek *MeekConn, err error) {

	runCtx, stopRunning := context.WithCancel(context.Background())

	cleanupStopRunning := true
	cleanupCachedTLSDialer := true
	var cachedTLSDialer *cachedTLSDialer

	// Cleanup in error cases
	defer func() {
		if cleanupStopRunning {
			stopRunning()
		}
		if cleanupCachedTLSDialer && cachedTLSDialer != nil {
			cachedTLSDialer.close()
		}
	}()

	meek = &MeekConn{
		clientParameters:         meekConfig.ClientParameters,
		networkLatencyMultiplier: meekConfig.NetworkLatencyMultiplier,
		isClosed:                 false,
		runCtx:                   runCtx,
		stopRunning:              stopRunning,
		relayWaitGroup:           new(sync.WaitGroup),
		roundTripperOnly:         meekConfig.RoundTripperOnly,
	}

	if !meek.roundTripperOnly {

		meek.cookie,
			meek.tlsPadding,
			meek.limitRequestPayloadLength,
			meek.redialTLSProbability,
			err =
			makeMeekObfuscationValues(
				meek.getCustomClientParameters(),
				meekConfig.MeekCookieEncryptionPublicKey,
				meekConfig.MeekObfuscatedKey,
				meekConfig.MeekObfuscatorPaddingSeed,
				meekConfig.ClientTunnelProtocol,
				"")
		if err != nil {
			return nil, errors.Trace(err)
		}
	}

	// Configure transport: QUIC or HTTPS or HTTP

	var (
		scheme            string
		transport         transporter
		additionalHeaders http.Header
		proxyUrl          func(*http.Request) (*url.URL, error)
	)

	if meekConfig.UseQUIC {

		meek.isQUIC = true

		scheme = "https"

		udpDialer := func(ctx context.Context) (net.PacketConn, *net.UDPAddr, error) {
			packetConn, remoteAddr, err := NewUDPConn(
				ctx,
				meekConfig.DialAddress,
				dialConfig)
			if err != nil {
				return nil, nil, errors.Trace(err)
			}
			return packetConn, remoteAddr, nil
		}

		_, port, _ := net.SplitHostPort(meekConfig.DialAddress)
		quicDialSNIAddress := fmt.Sprintf("%s:%s", meekConfig.SNIServerName, port)

		var err error
		transport, err = quic.NewQUICTransporter(
			ctx,
			func(message string) {
				NoticeInfo(message)
			},
			udpDialer,
			quicDialSNIAddress,
			meekConfig.QUICVersion)
		if err != nil {
			return nil, errors.Trace(err)
		}

	} else if meekConfig.UseHTTPS {

		// Custom TLS dialer:
		//
		//  1. ignores the HTTP request address and uses the fronting domain
		//  2. optionally disables SNI -- SNI breaks fronting when used with certain CDNs.
		//  3. skips verifying the server cert.
		//
		// Reasoning for #3:
		//
		// With a TLS MiM attack in place, and server certs verified, we'll fail to connect because the client
		// will refuse to connect. That's not a successful outcome.
		//
		// With a MiM attack in place, and server certs not verified, we'll fail to connect if the MiM is actively
		// targeting Psiphon and classifying the HTTP traffic by Host header or payload signature.
		//
		// However, in the case of a passive MiM that's just recording traffic or an active MiM that's targeting
		// something other than Psiphon, the client will connect. This is a successful outcome.
		//
		// What is exposed to the MiM? The Host header does not contain a Psiphon server IP address, just an
		// unrelated, randomly generated domain name which cannot be used to block direct connections. The
		// Psiphon server IP is sent over meek, but it's in the encrypted cookie.
		//
		// The payload (user traffic) gets its confidentiality and integrity from the underlying SSH protocol.
		// So, nothing is leaked to the MiM apart from signatures which could be used to classify the traffic
		// as Psiphon to possibly block it; but note that not revealing that the client is Psiphon is outside
		// our threat model; we merely seek to evade mass blocking by taking steps that require progressively
		// more effort to block.
		//
		// There is a subtle attack remaining: an adversary that can MiM some CDNs but not others (and so can
		// classify Psiphon traffic on some CDNs but not others) may throttle non-MiM CDNs so that our server
		// selection always chooses tunnels to the MiM CDN (without any server cert verification, we won't
		// exclusively connect to non-MiM CDNs); then the adversary kills the underlying TCP connection after
		// some short period. This is partially mitigated by tactics mechanisms.

		scheme = "https"

		tlsConfig := &CustomTLSConfig{
			ClientParameters:              meekConfig.ClientParameters,
			DialAddr:                      meekConfig.DialAddress,
			Dial:                          NewTCPDialer(dialConfig),
			SNIServerName:                 meekConfig.SNIServerName,
			SkipVerify:                    true,
			TLSProfile:                    meekConfig.TLSProfile,
			NoDefaultTLSSessionID:         &meekConfig.NoDefaultTLSSessionID,
			RandomizedTLSProfileSeed:      meekConfig.RandomizedTLSProfileSeed,
			TLSPadding:                    meek.tlsPadding,
			TrustedCACertificatesFilename: dialConfig.TrustedCACertificatesFilename,
		}
		tlsConfig.EnableClientSessionCache()

		if meekConfig.UseObfuscatedSessionTickets {
			tlsConfig.ObfuscatedSessionTicketKey = meekConfig.MeekObfuscatedKey
		}

		// As the passthrough message is unique and indistinguisbale from a normal
		// TLS client random value, we set it unconditionally and not just for
		// protocols which may support passthrough (even for those protocols,
		// clients don't know which servers are configured to use it).

		passthroughMessage, err := obfuscator.MakeTLSPassthroughMessage(
			meekConfig.MeekObfuscatedKey)
		if err != nil {
			return nil, errors.Trace(err)
		}
		tlsConfig.PassthroughMessage = passthroughMessage

		tlsDialer := NewCustomTLSDialer(tlsConfig)

		// Pre-dial one TLS connection in order to inspect the negotiated
		// application protocol. Then we create an HTTP/2 or HTTP/1.1 transport
		// depending on which protocol was negotiated. The TLS dialer
		// is assumed to negotiate only "h2" or "http/1.1"; or not negotiate
		// an application protocol.
		//
		// We cannot rely on net/http's HTTP/2 support since it's only
		// activated when http.Transport.DialTLS returns a golang crypto/tls.Conn;
		// e.g., https://github.com/golang/go/blob/c8aec4095e089ff6ac50d18e97c3f46561f14f48/src/net/http/transport.go#L1040
		//
		// The pre-dialed connection is stored in a cachedTLSDialer, which will
		// return the cached pre-dialed connection to its first Dial caller, and
		// use the tlsDialer for all other Dials.
		//
		// cachedTLSDialer.close() must be called on all exits paths from this
		// function and in meek.Close() to ensure the cached conn is closed in
		// any case where no Dial call is made.
		//
		// The pre-dial must be interruptible so that DialMeek doesn't block and
		// hang/delay a shutdown or end of establishment. So the pre-dial uses
		// the Controller's PendingConns, not the MeekConn PendingConns. For this
		// purpose, a special preDialer is configured.
		//
		// Only one pre-dial attempt is made; there are no retries. This differs
		// from relayRoundTrip, which retries and may redial for each retry.
		// Retries at the pre-dial phase are less useful since there's no active
		// session to preserve, and establishment will simply try another server.
		// Note that the underlying TCPDial may still try multiple IP addreses when
		// the destination is a domain and it resolves to multiple IP adresses.

		// The pre-dial is made within the parent dial context, so that DialMeek
		// may be interrupted. Subsequent dials are made within the meek round trip
		// request context. Since http.DialTLS doesn't take a context argument
		// (yet; as of Go 1.9 this issue is still open: https://github.com/golang/go/issues/21526),
		// cachedTLSDialer is used as a conduit to send the request context.
		// meekConn.relayRoundTrip sets its request context into cachedTLSDialer,
		// and cachedTLSDialer.dial uses that context.

		// As DialAddr is set in the CustomTLSConfig, no address is required here.
		preConn, err := tlsDialer(ctx, "tcp", "")
		if err != nil {
			return nil, errors.Trace(err)
		}

		cachedTLSDialer = newCachedTLSDialer(preConn, tlsDialer)

		if IsTLSConnUsingHTTP2(preConn) {
			NoticeInfo("negotiated HTTP/2 for %s", meekConfig.DiagnosticID)
			transport = &http2.Transport{
				DialTLS: func(network, addr string, _ *tls.Config) (net.Conn, error) {
					return cachedTLSDialer.dial(network, addr)
				},
			}
		} else {
			transport = &http.Transport{
				DialTLS: func(network, addr string) (net.Conn, error) {
					return cachedTLSDialer.dial(network, addr)
				},
			}
		}

	} else {

		scheme = "http"

		var dialer Dialer

		// For HTTP, and when the meekConfig.DialAddress matches the
		// meekConfig.HostHeader, we let http.Transport handle proxying.
		// http.Transport will put the the HTTP server address in the HTTP
		// request line. In this one case, we can use an HTTP proxy that does
		// not offer CONNECT support.
		if strings.HasPrefix(dialConfig.UpstreamProxyURL, "http://") &&
			(meekConfig.DialAddress == meekConfig.HostHeader ||
				meekConfig.DialAddress == meekConfig.HostHeader+":80") {

			url, err := url.Parse(dialConfig.UpstreamProxyURL)
			if err != nil {
				return nil, errors.Trace(err)
			}
			proxyUrl = http.ProxyURL(url)

			// Here, the dialer must use the address that http.Transport
			// passes in (which will be proxy address).
			copyDialConfig := new(DialConfig)
			*copyDialConfig = *dialConfig
			copyDialConfig.UpstreamProxyURL = ""

			dialer = NewTCPDialer(copyDialConfig)

		} else {

			baseDialer := NewTCPDialer(dialConfig)

			// The dialer ignores any address that http.Transport will pass in
			// (derived from the HTTP request URL) and always dials
			// meekConfig.DialAddress.
			dialer = func(ctx context.Context, network, _ string) (net.Conn, error) {
				return baseDialer(ctx, network, meekConfig.DialAddress)
			}
		}

		httpTransport := &http.Transport{
			Proxy:       proxyUrl,
			DialContext: dialer,
		}

		if proxyUrl != nil {
			// Wrap transport with a transport that can perform HTTP proxy auth negotiation
			transport, err = upstreamproxy.NewProxyAuthTransport(httpTransport, dialConfig.CustomHeaders)
			if err != nil {
				return nil, errors.Trace(err)
			}
		} else {
			transport = httpTransport
		}
	}

	url := &url.URL{
		Scheme: scheme,
		Host:   meekConfig.HostHeader,
		Path:   "/",
	}

	if meekConfig.UseHTTPS {
		host, _, err := net.SplitHostPort(meekConfig.DialAddress)
		if err != nil {
			return nil, errors.Trace(err)
		}
		additionalHeaders = map[string][]string{
			"X-Psiphon-Fronting-Address": {host},
		}
	} else {
		if proxyUrl == nil {
			additionalHeaders = dialConfig.CustomHeaders
		}
	}

	meek.url = url
	meek.additionalHeaders = additionalHeaders
	meek.cachedTLSDialer = cachedTLSDialer
	meek.transport = transport

	// stopRunning and cachedTLSDialer will now be closed in meek.Close()
	cleanupStopRunning = false
	cleanupCachedTLSDialer = false

	// Allocate relay resources, including buffers and running the relay
	// go routine, only when running in relay mode.
	if !meek.roundTripperOnly {

		// The main loop of a MeekConn is run in the relay() goroutine.
		// A MeekConn implements net.Conn concurrency semantics:
		// "Multiple goroutines may invoke methods on a Conn simultaneously."
		//
		// Read() calls and relay() are synchronized by exchanging control of a single
		// receiveBuffer (bytes.Buffer). This single buffer may be:
		// - in the emptyReceiveBuffer channel when it is available and empty;
		// - in the partialReadBuffer channel when it is available and contains data;
		// - in the fullReadBuffer channel when it is available and full of data;
		// - "checked out" by relay or Read when they are are writing to or reading from the
		//   buffer, respectively.
		// relay() will obtain the buffer from either the empty or partial channel but block when
		// the buffer is full. Read will obtain the buffer from the partial or full channel when
		// there is data to read but block when the buffer is empty.
		// Write() calls and relay() are synchronized in a similar way, using a single
		// sendBuffer.

		p := meek.getCustomClientParameters()
		if p.Bool(parameters.MeekLimitBufferSizes) {
			meek.fullReceiveBufferLength = p.Int(parameters.MeekLimitedFullReceiveBufferLength)
			meek.readPayloadChunkLength = p.Int(parameters.MeekLimitedReadPayloadChunkLength)
		} else {
			meek.fullReceiveBufferLength = p.Int(parameters.MeekFullReceiveBufferLength)
			meek.readPayloadChunkLength = p.Int(parameters.MeekReadPayloadChunkLength)
		}

		meek.emptyReceiveBuffer = make(chan *bytes.Buffer, 1)
		meek.partialReceiveBuffer = make(chan *bytes.Buffer, 1)
		meek.fullReceiveBuffer = make(chan *bytes.Buffer, 1)
		meek.emptySendBuffer = make(chan *bytes.Buffer, 1)
		meek.partialSendBuffer = make(chan *bytes.Buffer, 1)
		meek.fullSendBuffer = make(chan *bytes.Buffer, 1)

		meek.emptyReceiveBuffer <- new(bytes.Buffer)
		meek.emptySendBuffer <- new(bytes.Buffer)

		meek.relayWaitGroup.Add(1)
		go meek.relay()

	} else {

		meek.meekCookieEncryptionPublicKey = meekConfig.MeekCookieEncryptionPublicKey
		meek.meekObfuscatedKey = meekConfig.MeekObfuscatedKey
		meek.meekObfuscatorPaddingSeed = meekConfig.MeekObfuscatorPaddingSeed
		meek.clientTunnelProtocol = meekConfig.ClientTunnelProtocol
	}

	return meek, nil
}

type cachedTLSDialer struct {
	usedCachedConn int32
	cachedConn     net.Conn
	dialer         Dialer

	mutex      sync.Mutex
	requestCtx context.Context
}

func newCachedTLSDialer(cachedConn net.Conn, dialer Dialer) *cachedTLSDialer {
	return &cachedTLSDialer{
		cachedConn: cachedConn,
		dialer:     dialer,
	}
}

func (c *cachedTLSDialer) setRequestContext(requestCtx context.Context) {
	// Note: not using sync.Value since underlying type of requestCtx may change.
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.requestCtx = requestCtx
}

func (c *cachedTLSDialer) dial(network, addr string) (net.Conn, error) {
	if atomic.CompareAndSwapInt32(&c.usedCachedConn, 0, 1) {
		conn := c.cachedConn
		c.cachedConn = nil
		return conn, nil
	}

	c.mutex.Lock()
	ctx := c.requestCtx
	c.mutex.Unlock()
	if ctx == nil {
		ctx = context.Background()
	}

	return c.dialer(ctx, network, addr)
}

func (c *cachedTLSDialer) close() {
	if atomic.CompareAndSwapInt32(&c.usedCachedConn, 0, 1) {
		c.cachedConn.Close()
		c.cachedConn = nil
	}
}

// Close terminates the meek connection. Close waits for the relay goroutine
// to stop (in relay mode) and releases HTTP transport resources.
// A mutex is required to support net.Conn concurrency semantics.
func (meek *MeekConn) Close() (err error) {

	meek.mutex.Lock()
	isClosed := meek.isClosed
	meek.isClosed = true
	meek.mutex.Unlock()

	if !isClosed {
		meek.stopRunning()
		if meek.cachedTLSDialer != nil {
			meek.cachedTLSDialer.close()
		}

		// stopRunning interrupts HTTP requests in progress by closing the context
		// associated with the request. In the case of h2quic.RoundTripper, testing
		// indicates that quic-go.receiveStream.readImpl in _not_ interrupted in
		// this case, and so an in-flight FRONTED-MEEK-QUIC round trip may hang shutdown
		// in relayRoundTrip->readPayload->...->quic-go.receiveStream.readImpl.
		//
		// To workaround this, we call CloseIdleConnections _before_ Wait, as, in
		// the case of QUICTransporter, this closes the underlying UDP sockets which
		// interrupts any blocking I/O calls.
		//
		// The standard CloseIdleConnections call _after_ wait is for the net/http
		// case: it only closes idle connections, so the call should be after wait.
		// This call is intended to clean up all network resources deterministically
		// before Close returns.
		if meek.isQUIC {
			meek.transport.CloseIdleConnections()
		}

		meek.relayWaitGroup.Wait()
		meek.transport.CloseIdleConnections()
	}
	return nil
}

// IsClosed implements the Closer interface. The return value
// indicates whether the MeekConn has been closed.
func (meek *MeekConn) IsClosed() bool {

	meek.mutex.Lock()
	isClosed := meek.isClosed
	meek.mutex.Unlock()

	return isClosed
}

// GetMetrics implements the common.MetricsSource interface.
func (meek *MeekConn) GetMetrics() common.LogFields {
	logFields := make(common.LogFields)
	logFields["meek_cookie_size"] = meek.cookieSize
	logFields["meek_tls_padding"] = meek.tlsPadding
	logFields["meek_limit_request"] = meek.limitRequestPayloadLength
	return logFields
}

// RoundTrip makes a request to the meek server and returns the response.
// A new, obfuscated meek cookie is created for every request. The specified
// end point is recorded in the cookie and is not exposed as plaintext in the
// meek traffic. The caller is responsible for obfuscating the request body.
//
// RoundTrip is not safe for concurrent use, and Close must not be called
// concurrently. The caller must ensure onlt one RoundTrip call is active
// at once and that it completes before calling Close.
//
// RoundTrip is only available in round tripper mode.
func (meek *MeekConn) RoundTrip(
	ctx context.Context, endPoint string, requestBody []byte) ([]byte, error) {

	if !meek.roundTripperOnly {
		return nil, errors.TraceNew("operation unsupported")
	}

	cookie, _, _, _, err := makeMeekObfuscationValues(
		meek.getCustomClientParameters(),
		meek.meekCookieEncryptionPublicKey,
		meek.meekObfuscatedKey,
		meek.meekObfuscatorPaddingSeed,
		meek.clientTunnelProtocol,
		endPoint)
	if err != nil {
		return nil, errors.Trace(err)
	}

	// Note:
	//
	// - multiple, concurrent RoundTrip calls are unsafe due to the
	//   setRequestContext calls in newRequest.
	//
	// - concurrent Close and RoundTrip calls are unsafe as Close
	//   does not synchronize with RoundTrip before calling
	//   meek.transport.CloseIdleConnections(), so resources could
	//   be left open.
	//
	// At this time, RoundTrip is used for tactics in Controller and
	// the concurrency constraints are satisfied.

	request, cancelFunc, err := meek.newRequest(
		ctx, cookie, bytes.NewReader(requestBody), 0)
	if err != nil {
		return nil, errors.Trace(err)
	}
	defer cancelFunc()

	// Workaround for h2quic.RoundTripper context issue. See comment in
	// MeekConn.Close.
	if meek.isQUIC {
		go func() {
			<-request.Context().Done()
			meek.transport.CloseIdleConnections()
		}()
	}

	response, err := meek.transport.RoundTrip(request)
	if err == nil {
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			err = fmt.Errorf("unexpected response status code: %d", response.StatusCode)
		}
	}
	if err != nil {
		return nil, errors.Trace(err)
	}

	responseBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, errors.Trace(err)
	}

	return responseBody, nil
}

// Read reads data from the connection.
// net.Conn Deadlines are ignored. net.Conn concurrency semantics are supported.
func (meek *MeekConn) Read(buffer []byte) (n int, err error) {
	if meek.roundTripperOnly {
		return 0, errors.TraceNew("operation unsupported")
	}
	if meek.IsClosed() {
		return 0, errors.TraceNew("meek connection is closed")
	}
	// Block until there is received data to consume
	var receiveBuffer *bytes.Buffer
	select {
	case receiveBuffer = <-meek.partialReceiveBuffer:
	case receiveBuffer = <-meek.fullReceiveBuffer:
	case <-meek.runCtx.Done():
		return 0, errors.TraceNew("meek connection has closed")
	}
	n, err = receiveBuffer.Read(buffer)
	meek.replaceReceiveBuffer(receiveBuffer)
	return n, err
}

// Write writes data to the connection.
// net.Conn Deadlines are ignored. net.Conn concurrency semantics are supported.
func (meek *MeekConn) Write(buffer []byte) (n int, err error) {
	if meek.roundTripperOnly {
		return 0, errors.TraceNew("operation unsupported")
	}
	if meek.IsClosed() {
		return 0, errors.TraceNew("meek connection is closed")
	}
	// Repeats until all n bytes are written
	n = len(buffer)
	for len(buffer) > 0 {
		// Block until there is capacity in the send buffer
		var sendBuffer *bytes.Buffer
		select {
		case sendBuffer = <-meek.emptySendBuffer:
		case sendBuffer = <-meek.partialSendBuffer:
		case <-meek.runCtx.Done():
			return 0, errors.TraceNew("meek connection has closed")
		}
		writeLen := meek.limitRequestPayloadLength - sendBuffer.Len()
		if writeLen > 0 {
			if writeLen > len(buffer) {
				writeLen = len(buffer)
			}
			_, err = sendBuffer.Write(buffer[:writeLen])
			buffer = buffer[writeLen:]
		}
		meek.replaceSendBuffer(sendBuffer)
	}
	return n, err
}

// LocalAddr is a stub implementation of net.Conn.LocalAddr
func (meek *MeekConn) LocalAddr() net.Addr {
	return nil
}

// RemoteAddr is a stub implementation of net.Conn.RemoteAddr
func (meek *MeekConn) RemoteAddr() net.Addr {
	return nil
}

// SetDeadline is a stub implementation of net.Conn.SetDeadline
func (meek *MeekConn) SetDeadline(t time.Time) error {
	return errors.TraceNew("not supported")
}

// SetReadDeadline is a stub implementation of net.Conn.SetReadDeadline
func (meek *MeekConn) SetReadDeadline(t time.Time) error {
	return errors.TraceNew("not supported")
}

// SetWriteDeadline is a stub implementation of net.Conn.SetWriteDeadline
func (meek *MeekConn) SetWriteDeadline(t time.Time) error {
	return errors.TraceNew("not supported")
}

func (meek *MeekConn) replaceReceiveBuffer(receiveBuffer *bytes.Buffer) {
	switch {
	case receiveBuffer.Len() == 0:
		meek.emptyReceiveBuffer <- receiveBuffer
	case receiveBuffer.Len() >= meek.fullReceiveBufferLength:
		meek.fullReceiveBuffer <- receiveBuffer
	default:
		meek.partialReceiveBuffer <- receiveBuffer
	}
}

func (meek *MeekConn) replaceSendBuffer(sendBuffer *bytes.Buffer) {
	switch {
	case sendBuffer.Len() == 0:
		meek.emptySendBuffer <- sendBuffer
	case sendBuffer.Len() >= meek.limitRequestPayloadLength:
		meek.fullSendBuffer <- sendBuffer
	default:
		meek.partialSendBuffer <- sendBuffer
	}
}

// relay sends and receives tunneled traffic (payload). An HTTP request is
// triggered when data is in the write queue or at a polling interval.
// There's a geometric increase, up to a maximum, in the polling interval when
// no data is exchanged. Only one HTTP request is in flight at a time.
func (meek *MeekConn) relay() {
	// Note: meek.Close() calls here in relay() are made asynchronously
	// (using goroutines) since Close() will wait on this WaitGroup.
	defer meek.relayWaitGroup.Done()

	p := meek.getCustomClientParameters()
	interval := prng.JitterDuration(
		p.Duration(parameters.MeekMinPollInterval),
		p.Float(parameters.MeekMinPollIntervalJitter))
	p.Close()

	timeout := time.NewTimer(interval)
	defer timeout.Stop()

	for {
		timeout.Reset(interval)

		// Block until there is payload to send or it is time to poll
		var sendBuffer *bytes.Buffer
		select {
		case sendBuffer = <-meek.partialSendBuffer:
		case sendBuffer = <-meek.fullSendBuffer:
		case <-timeout.C:
			// In the polling case, send an empty payload
		case <-meek.runCtx.Done():
			// Drop through to second Done() check
		}

		// Check Done() again, to ensure it takes precedence
		select {
		case <-meek.runCtx.Done():
			return
		default:
		}

		sendPayloadSize := 0
		if sendBuffer != nil {
			sendPayloadSize = sendBuffer.Len()
		}

		// relayRoundTrip will replace sendBuffer (by calling replaceSendBuffer). This
		// is a compromise to conserve memory. Using a second buffer here, we could
		// copy sendBuffer and immediately replace it, unblocking meekConn.Write() and
		// allowing more upstream payload to immediately enqueue. Instead, the request
		// payload is read directly from sendBuffer, including retries. Only once the
		// server has acknowledged the request payload is sendBuffer replaced. This
		// still allows meekConn.Write() to unblock before the round trip response is
		// read.

		receivedPayloadSize, err := meek.relayRoundTrip(sendBuffer)

		if err != nil {
			select {
			case <-meek.runCtx.Done():
				// In this case, meek.relayRoundTrip encountered Done(). Exit without
				// logging error.
				return
			default:
			}
			NoticeWarning("%s", errors.Trace(err))
			go meek.Close()
			return
		}

		// Periodically re-dial the underlying TLS connection.

		if prng.FlipWeightedCoin(meek.redialTLSProbability) {
			meek.transport.CloseIdleConnections()
		}

		// Calculate polling interval. When data is received,
		// immediately request more. Otherwise, schedule next
		// poll with exponential back off. Jitter and coin
		// flips are used to avoid trivial, static traffic
		// timing patterns.

		p := meek.getCustomClientParameters()

		if receivedPayloadSize > 0 || sendPayloadSize > 0 {

			interval = 0

		} else if interval == 0 {

			interval = prng.JitterDuration(
				p.Duration(parameters.MeekMinPollInterval),
				p.Float(parameters.MeekMinPollIntervalJitter))

		} else {

			if p.WeightedCoinFlip(parameters.MeekApplyPollIntervalMultiplierProbability) {

				interval =
					time.Duration(float64(interval) *
						p.Float(parameters.MeekPollIntervalMultiplier))
			}

			interval = prng.JitterDuration(
				interval,
				p.Float(parameters.MeekPollIntervalJitter))

			if interval >= p.Duration(parameters.MeekMaxPollInterval) {

				interval = prng.JitterDuration(
					p.Duration(parameters.MeekMaxPollInterval),
					p.Float(parameters.MeekMaxPollIntervalJitter))
			}
		}

		p.Close()
	}
}

// readCloseSignaller is an io.ReadCloser wrapper for an io.Reader
// that is passed, as the request body, to http.Transport.RoundTrip.
// readCloseSignaller adds the AwaitClosed call, which is used
// to schedule recycling the buffer underlying the reader only after
// RoundTrip has called Close and will no longer use the buffer.
// See: https://golang.org/pkg/net/http/#RoundTripper
type readCloseSignaller struct {
	context context.Context
	reader  io.Reader
	closed  chan struct{}
}

func NewReadCloseSignaller(
	context context.Context,
	reader io.Reader) *readCloseSignaller {

	return &readCloseSignaller{
		context: context,
		reader:  reader,
		closed:  make(chan struct{}, 1),
	}
}

func (r *readCloseSignaller) Read(p []byte) (int, error) {
	return r.reader.Read(p)
}

func (r *readCloseSignaller) Close() error {
	select {
	case r.closed <- struct{}{}:
	default:
	}
	return nil
}

func (r *readCloseSignaller) AwaitClosed() bool {
	select {
	case <-r.context.Done():
	case <-r.closed:
		return true
	}
	return false
}

// newRequest performs common request setup for both relay and round
// tripper modes.
//
// newRequest is not safe for concurrent calls due to its use of
// setRequestContext.
//
// The caller must call the returned cancelFunc.
func (meek *MeekConn) newRequest(
	ctx context.Context,
	cookie *http.Cookie,
	body io.Reader,
	contentLength int) (*http.Request, context.CancelFunc, error) {

	var requestCtx context.Context
	var cancelFunc context.CancelFunc

	if ctx != nil {
		requestCtx, cancelFunc = context.WithCancel(ctx)
	} else {
		// - meek.stopRunning() will abort a round trip in flight
		// - round trip will abort if it exceeds timeout
		requestCtx, cancelFunc = context.WithTimeout(
			meek.runCtx,
			meek.getCustomClientParameters().Duration(parameters.MeekRoundTripTimeout))
	}

	// Ensure dials are made within the current request context.
	if meek.isQUIC {
		meek.transport.(*quic.QUICTransporter).SetRequestContext(requestCtx)
	} else if meek.cachedTLSDialer != nil {
		meek.cachedTLSDialer.setRequestContext(requestCtx)
	}

	request, err := http.NewRequest("POST", meek.url.String(), body)
	if err != nil {
		cancelFunc()
		return nil, nil, errors.Trace(err)
	}

	request = request.WithContext(requestCtx)

	// Content-Length may not be be set automatically due to the
	// underlying type of requestBody.
	if contentLength > 0 {
		request.ContentLength = int64(contentLength)
	}

	meek.addAdditionalHeaders(request)

	request.Header.Set("Content-Type", "application/octet-stream")

	if cookie == nil {
		cookie = meek.cookie
	}
	request.AddCookie(cookie)

	return request, cancelFunc, nil
}

// relayRoundTrip configures and makes the actual HTTP POST request
func (meek *MeekConn) relayRoundTrip(sendBuffer *bytes.Buffer) (int64, error) {

	// Retries are made when the round trip fails. This adds resiliency
	// to connection interruption and intermittent failures.
	//
	// At least one retry is always attempted, and retries continue
	// while still within a brief deadline -- 5 seconds, currently the
	// deadline for an actively probed SSH connection to timeout. There
	// is a brief delay between retries, allowing for intermittent
	// failure states to resolve.
	//
	// Failure may occur at various stages of the HTTP request:
	//
	// 1. Before the request begins. In this case, the entire request
	//    may be rerun.
	//
	// 2. While sending the request payload. In this case, the client
	//    must resend its request payload. The server will not have
	//    relayed its partially received request payload.
	//
	// 3. After sending the request payload but before receiving
	//    a response. The client cannot distinguish between case 2 and
	//    this case, case 3. The client resends its payload and the
	//    server detects this and skips relaying the request payload.
	//
	// 4. While reading the response payload. The client will omit its
	//    request payload when retrying, as the server has already
	//    acknowledged it. The client will also indicate to the server
	//    the amount of response payload already received, and the
	//    server will skip resending the indicated amount of response
	//    payload.
	//
	// Retries are indicated to the server by adding a Range header,
	// which includes the response payload resend position.

	defer func() {
		// Ensure sendBuffer is replaced, even in error code paths.
		if sendBuffer != nil {
			sendBuffer.Truncate(0)
			meek.replaceSendBuffer(sendBuffer)
		}
	}()

	retries := uint(0)

	p := meek.getCustomClientParameters()
	retryDeadline := time.Now().Add(p.Duration(parameters.MeekRoundTripRetryDeadline))
	retryDelay := p.Duration(parameters.MeekRoundTripRetryMinDelay)
	retryMaxDelay := p.Duration(parameters.MeekRoundTripRetryMaxDelay)
	retryMultiplier := p.Float(parameters.MeekRoundTripRetryMultiplier)
	p.Close()

	serverAcknowledgedRequestPayload := false

	receivedPayloadSize := int64(0)

	for try := 0; ; try++ {

		// Omit the request payload when retrying after receiving a
		// partial server response.

		var signaller *readCloseSignaller
		var requestBody io.ReadCloser
		contentLength := 0
		if !serverAcknowledgedRequestPayload && sendBuffer != nil {

			// sendBuffer will be replaced once the data is no longer needed,
			// when RoundTrip calls Close on the Body; this allows meekConn.Write()
			// to unblock and start buffering data for the next roung trip while
			// still reading the current round trip response. signaller provides
			// the hook for awaiting RoundTrip's call to Close.

			signaller = NewReadCloseSignaller(meek.runCtx, bytes.NewReader(sendBuffer.Bytes()))
			requestBody = signaller
			contentLength = sendBuffer.Len()
		}

		request, cancelFunc, err := meek.newRequest(
			//lint:ignore SA1012 meek.newRequest expects/handles nil context
			nil,
			nil,
			requestBody,
			contentLength)
		if err != nil {
			// Don't retry when can't initialize a Request
			return 0, errors.Trace(err)
		}

		expectedStatusCode := http.StatusOK

		// When retrying, add a Range header to indicate how much
		// of the response was already received.

		if try > 0 {
			expectedStatusCode = http.StatusPartialContent
			request.Header.Set("Range", fmt.Sprintf("bytes=%d-", receivedPayloadSize))
		}

		response, err := meek.transport.RoundTrip(request)

		// Wait for RoundTrip to call Close on the request body, when
		// there is one. This is necessary to ensure it's safe to
		// subsequently replace sendBuffer in both the success and
		// error cases.
		if signaller != nil {
			if !signaller.AwaitClosed() {
				// AwaitClosed encountered Done(). Abort immediately. Do not
				// replace sendBuffer, as we cannot be certain RoundTrip is
				// done with it. MeekConn.Write will exit on Done and not hang
				// awaiting sendBuffer.
				sendBuffer = nil
				return 0, errors.TraceNew("meek connection has closed")
			}
		}

		if err != nil {
			select {
			case <-meek.runCtx.Done():
				// Exit without retrying and without logging error.
				return 0, errors.Trace(err)
			default:
			}
			NoticeWarning("meek round trip failed: %s", err)
			// ...continue to retry
		}

		if err == nil {

			if response.StatusCode != expectedStatusCode &&
				// Certain http servers return 200 OK where we expect 206, so accept that.
				!(expectedStatusCode == http.StatusPartialContent && response.StatusCode == http.StatusOK) {

				// Don't retry when the status code is incorrect
				response.Body.Close()
				return 0, errors.Tracef(
					"unexpected status code: %d instead of %d",
					response.StatusCode, expectedStatusCode)
			}

			// Update meek session cookie
			for _, c := range response.Cookies() {
				if meek.cookie.Name == c.Name {
					meek.cookie.Value = c.Value
					break
				}
			}

			// Received the response status code, so the server
			// must have received the request payload.
			serverAcknowledgedRequestPayload = true

			// sendBuffer is now no longer required for retries, and the
			// buffer may be replaced; this allows meekConn.Write() to unblock
			// and start buffering data for the next round trip while still
			// reading the current round trip response.
			if sendBuffer != nil {
				// Assumes signaller.AwaitClosed is called above, so
				// sendBuffer will no longer be accessed by RoundTrip.
				sendBuffer.Truncate(0)
				meek.replaceSendBuffer(sendBuffer)
				sendBuffer = nil
			}

			readPayloadSize, err := meek.readPayload(response.Body)
			response.Body.Close()

			// receivedPayloadSize is the number of response
			// payload bytes received and relayed. A retry can
			// resume after this position.
			receivedPayloadSize += readPayloadSize

			if err != nil {
				NoticeWarning("meek read payload failed: %s", err)
				// ...continue to retry
			} else {
				// Round trip completed successfully
				break
			}
		}

		// Release context resources now.
		cancelFunc()

		// Either the request failed entirely, or there was a failure
		// streaming the response payload. Always retry once. Then
		// retry if time remains; when the next delay exceeds the time
		// remaining until the deadline, do not retry.

		now := time.Now()

		if retries >= 1 &&
			(now.After(retryDeadline) || retryDeadline.Sub(now) <= retryDelay) {
			return 0, errors.Trace(err)
		}
		retries += 1

		delayTimer := time.NewTimer(retryDelay)

		select {
		case <-delayTimer.C:
		case <-meek.runCtx.Done():
			delayTimer.Stop()
			return 0, errors.Trace(err)
		}

		// Increase the next delay, to back off and avoid excessive
		// activity in conditions such as no network connectivity.

		retryDelay = time.Duration(
			float64(retryDelay) * retryMultiplier)
		if retryDelay >= retryMaxDelay {
			retryDelay = retryMaxDelay
		}
	}

	return receivedPayloadSize, nil
}

// Add additional headers to the HTTP request using the same method we use for adding
// custom headers to HTTP proxy requests.
func (meek *MeekConn) addAdditionalHeaders(request *http.Request) {
	for name, value := range meek.additionalHeaders {
		// hack around special case of "Host" header
		// https://golang.org/src/net/http/request.go#L474
		// using URL.Opaque, see URL.RequestURI() https://golang.org/src/net/url/url.go#L915
		if name == "Host" {
			if len(value) > 0 {
				if request.URL.Opaque == "" {
					request.URL.Opaque = request.URL.Scheme + "://" + request.Host + request.URL.RequestURI()
				}
				request.Host = value[0]
			}
		} else {
			request.Header[name] = value
		}
	}
}

// readPayload reads the HTTP response in chunks, making the read buffer available
// to MeekConn.Read() calls after each chunk; the intention is to allow bytes to
// flow back to the reader as soon as possible instead of buffering the entire payload.
//
// When readPayload returns an error, the totalSize output is remains valid -- it's the
// number of payload bytes successfully read and relayed.
func (meek *MeekConn) readPayload(
	receivedPayload io.ReadCloser) (totalSize int64, err error) {

	defer receivedPayload.Close()
	totalSize = 0
	for {
		reader := io.LimitReader(receivedPayload, int64(meek.readPayloadChunkLength))
		// Block until there is capacity in the receive buffer
		var receiveBuffer *bytes.Buffer
		select {
		case receiveBuffer = <-meek.emptyReceiveBuffer:
		case receiveBuffer = <-meek.partialReceiveBuffer:
		case <-meek.runCtx.Done():
			return 0, nil
		}
		// Note: receiveBuffer size may exceed meek.fullReceiveBufferLength by up to the size
		// of one received payload. The meek.fullReceiveBufferLength value is just a guideline.
		n, err := receiveBuffer.ReadFrom(reader)
		meek.replaceReceiveBuffer(receiveBuffer)
		totalSize += n
		if err != nil {
			return totalSize, errors.Trace(err)
		}
		if n == 0 {
			break
		}
	}
	return totalSize, nil
}

// makeMeekObfuscationValues creates the meek cookie, to be sent with initial
// meek HTTP request, and other meek obfuscation values. The cookies contains
// obfuscated metadata, including meek version and other protocol information.
//
// In round tripper mode, the cookie contains the destination endpoint for the
// round trip request.
//
// In relay mode, the server will create a session using the cookie values and
// send the session ID back to the client via Set-Cookie header. The client
// must use that value with all consequent HTTP requests.
//
// In plain HTTP meek protocols, the cookie is visible over the adversary
// network, so the cookie is encrypted and obfuscated.
//
// Obsolete meek cookie fields used by the legacy server stack are no longer
// sent. These include ServerAddress and SessionID.
//
// The request payload limit and TLS redial probability apply only to relay
// mode and are selected once and used for the duration of a meek connction.
func makeMeekObfuscationValues(
	p parameters.ClientParametersAccessor,
	meekCookieEncryptionPublicKey string,
	meekObfuscatedKey string,
	meekObfuscatorPaddingPRNGSeed *prng.Seed,
	clientTunnelProtocol string,
	endPoint string,

) (cookie *http.Cookie,
	tlsPadding int,
	limitRequestPayloadLength int,
	redialTLSProbability float64,
	err error) {

	cookieData := &protocol.MeekCookieData{
		MeekProtocolVersion:  MEEK_PROTOCOL_VERSION,
		ClientTunnelProtocol: clientTunnelProtocol,
		EndPoint:             endPoint,
	}
	serializedCookie, err := json.Marshal(cookieData)
	if err != nil {
		return nil, 0, 0, 0.0, errors.Trace(err)
	}

	// Encrypt the JSON data
	// NaCl box is used for encryption. The peer public key comes from the server entry.
	// Nonce is always all zeros, and is not sent in the cookie (the server also uses an all-zero nonce).
	// http://nacl.cace-project.eu/box.html:
	// "There is no harm in having the same nonce for different messages if the {sender, receiver} sets are
	// different. This is true even if the sets overlap. For example, a sender can use the same nonce for two
	// different messages if the messages are sent to two different public keys."
	var nonce [24]byte
	var publicKey [32]byte
	decodedPublicKey, err := base64.StdEncoding.DecodeString(meekCookieEncryptionPublicKey)
	if err != nil {
		return nil, 0, 0, 0.0, errors.Trace(err)
	}
	copy(publicKey[:], decodedPublicKey)
	ephemeralPublicKey, ephemeralPrivateKey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, 0, 0, 0.0, errors.Trace(err)
	}
	box := box.Seal(nil, serializedCookie, &nonce, &publicKey, ephemeralPrivateKey)
	encryptedCookie := make([]byte, 32+len(box))
	copy(encryptedCookie[0:32], ephemeralPublicKey[0:32])
	copy(encryptedCookie[32:], box)

	maxPadding := p.Int(parameters.MeekCookieMaxPadding)

	// Obfuscate the encrypted data
	obfuscator, err := obfuscator.NewClientObfuscator(
		&obfuscator.ObfuscatorConfig{
			Keyword:         meekObfuscatedKey,
			PaddingPRNGSeed: meekObfuscatorPaddingPRNGSeed,
			MaxPadding:      &maxPadding})
	if err != nil {
		return nil, 0, 0, 0.0, errors.Trace(err)
	}
	obfuscatedCookie := obfuscator.SendSeedMessage()
	seedLen := len(obfuscatedCookie)
	obfuscatedCookie = append(obfuscatedCookie, encryptedCookie...)
	obfuscator.ObfuscateClientToServer(obfuscatedCookie[seedLen:])

	cookieNamePRNG, err := obfuscator.GetDerivedPRNG("meek-cookie-name")
	if err != nil {
		return nil, 0, 0, 0.0, errors.Trace(err)
	}

	// Format the HTTP cookie
	// The format is <random letter 'A'-'Z'>=<base64 data>, which is intended to match common cookie formats.
	A := int('A')
	Z := int('Z')
	// letterIndex is integer in range [int('A'), int('Z')]
	letterIndex := cookieNamePRNG.Intn(Z - A + 1)

	cookie = &http.Cookie{
		Name:  string(byte(A + letterIndex)),
		Value: base64.StdEncoding.EncodeToString(obfuscatedCookie)}

	tlsPadding = 0
	limitRequestPayloadLength = MEEK_MAX_REQUEST_PAYLOAD_LENGTH
	redialTLSProbability = 0.0

	tunnelProtocols := p.TunnelProtocols(parameters.MeekTrafficShapingLimitProtocols)
	if (len(tunnelProtocols) == 0 ||
		common.Contains(tunnelProtocols, clientTunnelProtocol)) &&
		p.WeightedCoinFlip(parameters.MeekTrafficShapingProbability) {

		limitRequestPayloadLengthPRNG, err := obfuscator.GetDerivedPRNG(
			"meek-limit-request-payload-length")
		if err != nil {
			return nil, 0, 0, 0.0, errors.Trace(err)
		}

		minLength := p.Int(parameters.MeekMinLimitRequestPayloadLength)
		if minLength > MEEK_MAX_REQUEST_PAYLOAD_LENGTH {
			minLength = MEEK_MAX_REQUEST_PAYLOAD_LENGTH
		}
		maxLength := p.Int(parameters.MeekMaxLimitRequestPayloadLength)
		if maxLength > MEEK_MAX_REQUEST_PAYLOAD_LENGTH {
			maxLength = MEEK_MAX_REQUEST_PAYLOAD_LENGTH
		}

		limitRequestPayloadLength = limitRequestPayloadLengthPRNG.Range(
			minLength, maxLength)

		minPadding := p.Int(parameters.MeekMinTLSPadding)
		maxPadding := p.Int(parameters.MeekMaxTLSPadding)

		// Maximum padding size per RFC 7685
		if maxPadding > 65535 {
			maxPadding = 65535
		}

		if maxPadding > 0 {
			tlsPaddingPRNG, err := obfuscator.GetDerivedPRNG(
				"meek-tls-padding")
			if err != nil {
				return nil, 0, 0, 0.0, errors.Trace(err)
			}

			tlsPadding = tlsPaddingPRNG.Range(minPadding, maxPadding)
		}

		redialTLSProbability = p.Float(parameters.MeekRedialTLSProbability)
	}

	return cookie, tlsPadding, limitRequestPayloadLength, redialTLSProbability, nil
}
