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
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/obfuscator"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/parameters"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/quic"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/transforms"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/values"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/upstreamproxy"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/net/http2"
)

// MeekConn is based on meek-client.go from Tor:
//
// https://gitweb.torproject.org/pluggable-transports/meek.git/blob/HEAD:/meek-client/meek-client.go
// CC0 1.0 Universal

const (
	MEEK_PROTOCOL_VERSION           = 4
	MEEK_MAX_REQUEST_PAYLOAD_LENGTH = 65536
)

type MeekMode int

const (
	MeekModeRelay = iota
	MeekModeObfuscatedRoundTrip
	MeekModePlaintextRoundTrip
	MeekModeWrappedPlaintextRoundTrip
)

// MeekConfig specifies the behavior of a MeekConn.
type MeekConfig struct {

	// DiagnosticID is the server ID to record in any diagnostics notices.
	DiagnosticID string

	// Parameters is the active set of parameters.Parameters to use
	// for the meek dial.
	Parameters *parameters.Parameters

	// Mode selects the mode of operation:
	//
	// MeekModeRelay: encapsulates net.Conn flows in HTTP requests and responses;
	// secures and obfuscates metadata in an encrypted HTTP cookie, making it
	// suitable for non-TLS HTTP and HTTPS with unverifed server certificates;
	// the caller is responsible for securing and obfuscating the net.Conn flows;
	// the origin server should be a meek server; used for the meek tunnel
	// protocols.
	//
	// MeekModeObfuscatedRoundTrip: enables ObfuscatedRoundTrip, which performs
	// HTTP round trips; secures and obfuscates metadata, including the end point
	// (or path), in an encrypted HTTP cookie, making it suitable for non-TLS
	// HTTP and HTTPS with unverifed server certificates; the caller is
	// responsible for securing and obfuscating request/response payloads; the
	// origin server should be a meek server; used for tactics requests.
	//
	// MeekModePlaintextRoundTrip: enables RoundTrip; the MeekConn is an
	// http.RoundTripper; there are no security or obfuscation measures at the
	// HTTP level; TLS and server certificate verification is required; the
	// origin server may be any HTTP(S) server.
	//
	// MeekModeWrappedPlaintextRoundTrip: is equivalent to
	// MeekModePlaintextRoundTrip, except skipping of server certificate
	// verification is permitted. In this mode, the caller is asserting that
	// the HTTP plaintext payload is wrapped in its own transport security
	// layer.
	//
	// As with the other modes, MeekMode[Wrapped]PlaintextRoundTrip supports
	// HTTP/2 with utls, and integration with DialParameters for replay --
	// which are not otherwise implemented if using just CustomTLSDialer and
	// net.http.
	Mode MeekMode

	// DialAddress is the actual network address to dial to establish a
	// connection to the meek server. This may be either a fronted or
	// direct address. The address must be in the form "host:port",
	// where host may be a domain name or IP address.
	DialAddress string

	// UseQUIC indicates whether to use HTTP/2 over QUIC.
	UseQUIC bool

	// QUICVersion indicates which QUIC version to use.
	QUICVersion string

	// QUICClientHelloSeed is used for randomized QUIC Client Hellos.
	QUICClientHelloSeed *prng.Seed

	// QUICDialEarly indicates whether the client should attempt 0-RTT.
	QUICDialEarly bool

	// QUICDisablePathMTUDiscovery indicates whether to disable path MTU
	// discovery in the QUIC client.
	QUICDisablePathMTUDiscovery bool

	// UseHTTPS indicates whether to use HTTPS (true) or HTTP (false).
	UseHTTPS bool

	// TLSProfile specifies the value for CustomTLSConfig.TLSProfile for all
	// underlying TLS connections created by this meek connection.
	TLSProfile string

	// QUICTLSClientSessionCache specifies the TLS session cache to use
	// for Meek connections that use HTTP/2 over QUIC.
	QUICTLSClientSessionCache *common.TLSClientSessionCacheWrapper

	// TLSClientSessionCache specifies the TLS session cache to use for
	// HTTPS (non-QUIC) Meek connections.
	TLSClientSessionCache *common.UtlsClientSessionCacheWrapper

	// TLSFragmentClientHello specifies whether to fragment the TLS Client Hello.
	TLSFragmentClientHello bool

	// LegacyPassthrough indicates that the server expects a legacy passthrough
	// message.
	LegacyPassthrough bool

	// NoDefaultTLSSessionID specifies the value for
	// CustomTLSConfig.NoDefaultTLSSessionID for all underlying TLS connections
	// created by this meek connection.
	NoDefaultTLSSessionID bool

	// RandomizedTLSProfileSeed specifies the value for
	// CustomTLSConfig.RandomizedTLSProfileSeed for all underlying TLS
	// connections created by this meek connection.
	RandomizedTLSProfileSeed *prng.Seed

	// UseObfuscatedSessionTickets indicates whether to use obfuscated session
	// tickets. Assumes UseHTTPS is true.
	// Ignored for MeekMode[Wrapped]PlaintextRoundTrip.
	UseObfuscatedSessionTickets bool

	// SNIServerName is the value to place in the TLS/QUIC SNI server_name field
	// when HTTPS or QUIC is used.
	SNIServerName string

	// HostHeader is the value to place in the HTTP request Host header.
	HostHeader string

	// TransformedHostName records whether a hostname transformation is
	// in effect. This value is used for stats reporting.
	TransformedHostName bool

	// AddPsiphonFrontingHeader specifies whether to add the
	// X-Psiphon-Fronting-Address custom header.
	AddPsiphonFrontingHeader bool

	// VerifyServerName specifies a domain name that must appear in the server
	// certificate. When blank, server certificate verification is disabled.
	VerifyServerName string

	// VerifyPins specifies one or more certificate pin values, one of which must
	// appear in the verified server certificate chain. A pin value is the
	// base64-encoded SHA2 digest of a certificate's public key. When specified,
	// at least one pin must match at least one certificate in the chain, at any
	// position; e.g., the root CA may be pinned, or the server certificate,
	// etc.
	VerifyPins []string

	// DisableSystemRootCAs, when true, disables loading system root CAs when
	// verifying the server certificate chain. Set DisableSystemRootCAs only in
	// cases where system root CAs cannot be loaded and there is additional
	// security at the payload level; for example, if unsupported (iOS < 12) or
	// insufficient memory (VPN extension on iOS < 15).
	//
	// When DisableSystemRootCAs is set, both VerifyServerName and VerifyPins
	// must not be set.
	DisableSystemRootCAs bool

	// ClientTunnelProtocol is the protocol the client is using. It's included in
	// the meek cookie for optional use by the server, in cases where the server
	// cannot unambiguously determine the tunnel protocol. ClientTunnelProtocol
	// is used when selecting tactics targeted at specific protocols.
	// Ignored for MeekMode[Wrapped]PlaintextRoundTrip.
	ClientTunnelProtocol string

	// NetworkLatencyMultiplier specifies a custom network latency multiplier to
	// apply to client parameters used by this meek connection.
	NetworkLatencyMultiplier float64

	// The following values are used to create the obfuscated meek cookie.
	// Ignored for MeekMode[Wrapped]PlaintextRoundTrip.

	MeekCookieEncryptionPublicKey string
	MeekObfuscatedKey             string
	MeekObfuscatorPaddingSeed     *prng.Seed

	// HTTPTransformerParameters specifies an HTTP transformer to apply to the
	// meek connection if it uses HTTP.
	HTTPTransformerParameters *transforms.HTTPTransformerParameters

	// AdditionalHeaders is a set of additional arbitrary HTTP headers that
	// are added to all meek HTTP requests. An additional header is ignored
	// when the header name is already present in a meek request.
	AdditionalHeaders http.Header

	// EnablePayloadPadding and PayloadPadding fields enable and configure
	// optional padding of empty meek payloads.
	EnablePayloadPadding          bool
	PayloadPaddingMinSize         int
	PayloadPaddingMaxSize         int
	PayloadPaddingOmitProbability float64
}

// MeekConn is a network connection that tunnels net.Conn flows over HTTP and supports
// "domain fronting". Meek sends client->server flow in HTTP request bodies and
// receives server->client flow in HTTP response bodies. Polling is used to
// approximate full duplex TCP. MeekConn also offers HTTP round trip modes.
//
// Domain fronting is a network obfuscation technique in which the connection to a web
// server, typically a CDN, is indistinguishable from any other HTTPS
// connection to the generic "fronting domain" -- the HTTP Host header is used
// to route the requests to the actual destination. See
// https://trac.torproject.org/projects/tor/wiki/doc/meek for more details.
//
// MeekConn also support unfronted operation, in which connections are made
// without routing through a CDN; and plain HTTP operation, without TLS or
// QUIC, with connection metadata obfuscated in HTTP cookies.
type MeekConn struct {
	params                    *parameters.Parameters
	mode                      MeekMode
	networkLatencyMultiplier  float64
	isQUIC                    bool
	url                       *url.URL
	additionalHeaders         http.Header
	cookie                    *http.Cookie
	contentType               string
	cookieSize                int
	tlsPadding                int
	limitRequestPayloadLength int
	redialTLSProbability      float64
	transport                 transporter
	connManager               *meekUnderlyingConnManager

	mutex          sync.Mutex
	isClosed       bool
	runCtx         context.Context
	stopRunning    context.CancelFunc
	relayWaitGroup *sync.WaitGroup

	// For MeekModeObfuscatedRoundTrip
	meekCookieEncryptionPublicKey string
	meekObfuscatedKey             string
	meekObfuscatorPaddingSeed     *prng.Seed
	clientTunnelProtocol          string

	// For MeekModeRelay
	fullReceiveBufferLength int
	readPayloadChunkLength  int
	emptyReceiveBuffer      chan *bytes.Buffer
	partialReceiveBuffer    chan *bytes.Buffer
	fullReceiveBuffer       chan *bytes.Buffer
	emptySendBuffer         chan *bytes.Buffer
	partialSendBuffer       chan *bytes.Buffer
	fullSendBuffer          chan *bytes.Buffer

	requestPaddingState  *protocol.MeekPayloadPaddingState
	responsePaddingState *protocol.MeekPayloadPaddingState
	requestPaddingBuffer *bytes.Buffer
}

func (conn *MeekConn) getCustomParameters() parameters.ParametersAccessor {
	return conn.params.GetCustom(conn.networkLatencyMultiplier)
}

// transporter is implemented by both http.Transport and upstreamproxy.ProxyAuthTransport.
type transporter interface {
	CloseIdleConnections()
	RoundTrip(req *http.Request) (resp *http.Response, err error)
}

// DialMeek returns an initialized meek connection. A meek connection is
// an HTTP session which does not depend on an underlying socket connection (although
// persistent HTTP connections are used for performance). This function may not
// wait for the connection to be established before returning.
func DialMeek(
	ctx context.Context,
	meekConfig *MeekConfig,
	dialConfig *DialConfig) (*MeekConn, error) {

	if meekConfig.UseQUIC && meekConfig.UseHTTPS {
		return nil, errors.TraceNew(
			"invalid config: only one of UseQUIC or UseHTTPS may be set")
	}

	if meekConfig.UseQUIC && meekConfig.QUICTLSClientSessionCache == nil {
		return nil, errors.TraceNew(
			"invalid config: QUICTLSClientSessionCache must be set when UseQUIC is set")
	}

	if meekConfig.UseHTTPS && meekConfig.TLSClientSessionCache == nil {
		return nil, errors.TraceNew(
			"invalid config: TLSClientSessionCache must be set when UseHTTPS is set")
	}

	if meekConfig.UseQUIC &&
		(meekConfig.VerifyServerName != "" || len(meekConfig.VerifyPins) > 0) {

		// TODO: UseQUIC VerifyServerName and VerifyPins support (required for MeekModePlaintextRoundTrip).

		return nil, errors.TraceNew(
			"invalid config: VerifyServerName and VerifyPins not supported for UseQUIC")
	}

	skipVerify := meekConfig.VerifyServerName == ""
	if len(meekConfig.VerifyPins) > 0 && skipVerify {
		return nil, errors.TraceNew(
			"invalid config: VerifyServerName must be set when VerifyPins is set")
	}

	if meekConfig.DisableSystemRootCAs &&
		(len(meekConfig.VerifyServerName) > 0 || len(meekConfig.VerifyPins) > 0) {
		return nil, errors.TraceNew(
			"invalid config: VerifyServerName and VerifyPins must not be set when DisableSystemRootCAs is set")
	}

	if meekConfig.Mode == MeekModePlaintextRoundTrip &&
		(!meekConfig.UseHTTPS || (skipVerify && !meekConfig.DisableSystemRootCAs)) {
		return nil, errors.TraceNew(
			"invalid config: MeekModePlaintextRoundTrip requires UseHTTPS and VerifyServerName when system root CAs can be loaded")
	}

	runCtx, stopRunning := context.WithCancel(context.Background())

	meek := &MeekConn{
		params:                   meekConfig.Parameters,
		mode:                     meekConfig.Mode,
		networkLatencyMultiplier: meekConfig.NetworkLatencyMultiplier,
		isClosed:                 false,
		runCtx:                   runCtx,
		stopRunning:              stopRunning,
		relayWaitGroup:           new(sync.WaitGroup),
	}

	cleanupStopRunning := true
	cleanupConns := true

	// Cleanup in error cases
	defer func() {
		if cleanupStopRunning {
			meek.stopRunning()
		}
		if cleanupConns && meek.connManager != nil {
			meek.connManager.closeAll()
		}
	}()

	if meek.mode == MeekModeRelay {
		var err error
		meek.cookie,
			meek.contentType,
			meek.tlsPadding,
			meek.limitRequestPayloadLength,
			meek.redialTLSProbability,
			err =
			makeMeekObfuscationValues(
				meek.getCustomParameters(),
				meekConfig.MeekCookieEncryptionPublicKey,
				meekConfig.MeekObfuscatedKey,
				meekConfig.MeekObfuscatorPaddingSeed,
				meekConfig.EnablePayloadPadding,
				meekConfig.ClientTunnelProtocol,
				"")
		if err != nil {
			return nil, errors.Trace(err)
		}

		// For stats, record the size of the initial obfuscated cookie.
		meek.cookieSize = len(meek.cookie.Name) + len(meek.cookie.Value)
	}

	// Configure transport: QUIC or HTTPS or HTTP

	var (
		scheme            string
		opaqueURL         string
		transport         transporter
		additionalHeaders http.Header
		proxyUrl          func(*http.Request) (*url.URL, error)
	)

	if meekConfig.UseQUIC {

		meek.isQUIC = true

		scheme = "https"

		udpDialer := func(ctx context.Context) (net.PacketConn, *net.UDPAddr, error) {
			packetConn, remoteAddr, err := NewUDPConn(
				ctx, "udp", false, "", meekConfig.DialAddress, dialConfig)
			if err != nil {
				return nil, nil, errors.Trace(err)
			}
			return packetConn, remoteAddr, nil
		}

		meek.connManager = newMeekUnderlyingConnManager(nil, nil, udpDialer)

		// Limitation: currently, the meekUnderlyingPacketConn wrapping done by
		// dialPacketConn masks the quic-go.OOBCapablePacketConn capabilities
		// of the underlying *net.UDPConn. With these capabilities unavailable,
		// path MTU discovery and UDP socket buffer optimizations will be disabled.

		var err error
		transport, err = quic.NewQUICTransporter(
			ctx,
			func(message string) {
				NoticeInfo(message)
			},
			meek.connManager.dialPacketConn,
			meekConfig.SNIServerName,
			meekConfig.QUICVersion,
			meekConfig.QUICClientHelloSeed,
			meekConfig.QUICDisablePathMTUDiscovery,
			meekConfig.QUICDialEarly,
			meekConfig.QUICTLSClientSessionCache)
		if err != nil {
			return nil, errors.Trace(err)
		}

	} else if meekConfig.UseHTTPS {

		// Custom TLS dialer:
		//
		//  1. ignores the HTTP request address and uses the fronting domain
		//  2. optionally disables SNI -- SNI breaks fronting when used with certain CDNs.
		//  3. may skip verifying the server cert.
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
			Parameters:                    meekConfig.Parameters,
			DialAddr:                      meekConfig.DialAddress,
			Dial:                          NewTCPDialer(dialConfig),
			SNIServerName:                 meekConfig.SNIServerName,
			SkipVerify:                    skipVerify,
			VerifyServerName:              meekConfig.VerifyServerName,
			VerifyPins:                    meekConfig.VerifyPins,
			DisableSystemRootCAs:          meekConfig.DisableSystemRootCAs,
			TLSProfile:                    meekConfig.TLSProfile,
			NoDefaultTLSSessionID:         &meekConfig.NoDefaultTLSSessionID,
			RandomizedTLSProfileSeed:      meekConfig.RandomizedTLSProfileSeed,
			TLSPadding:                    meek.tlsPadding,
			TrustedCACertificatesFilename: dialConfig.TrustedCACertificatesFilename,
			FragmentClientHello:           meekConfig.TLSFragmentClientHello,
			ClientSessionCache:            meekConfig.TLSClientSessionCache,
		}

		if meekConfig.UseObfuscatedSessionTickets {
			tlsConfig.ObfuscatedSessionTicketKey = meekConfig.MeekObfuscatedKey
		}

		if meekConfig.Mode != MeekModePlaintextRoundTrip &&
			meekConfig.Mode != MeekModeWrappedPlaintextRoundTrip &&
			meekConfig.MeekObfuscatedKey != "" {

			// As the passthrough message is unique and indistinguishable from a normal
			// TLS client random value, we set it unconditionally and not just for
			// protocols which may support passthrough (even for those protocols,
			// clients don't know which servers are configured to use it).

			passthroughMessage, err := obfuscator.MakeTLSPassthroughMessage(
				!meekConfig.LegacyPassthrough,
				meekConfig.MeekObfuscatedKey)
			if err != nil {
				return nil, errors.Trace(err)
			}
			tlsConfig.PassthroughMessage = passthroughMessage
		}

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
		//
		// The pre-dial is made within the parent dial context, so that DialMeek
		// may be interrupted. Subsequent dials are made within the meek round trip
		// request context.

		// As DialAddr is set in the CustomTLSConfig, no address is required here.
		preConn, err := tlsDialer(ctx, "tcp", "")
		if err != nil {
			return nil, errors.Trace(err)
		}

		meek.connManager = newMeekUnderlyingConnManager(preConn, tlsDialer, nil)

		if IsTLSConnUsingHTTP2(preConn) {
			NoticeInfo("negotiated HTTP/2 for %s", meekConfig.DiagnosticID)
			transport = &http2.Transport{
				DialTLSContext: func(
					ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
					return meek.connManager.dial(ctx, network, addr)
				},
			}
		} else {
			transport = &http.Transport{
				DialTLSContext: meek.connManager.dial,
			}
		}

	} else {

		scheme = "http"

		var dialer common.Dialer

		// For HTTP, and when the meekConfig.DialAddress matches the
		// meekConfig.HostHeader, we let http.Transport handle proxying.
		// http.Transport will put the the HTTP server address in the HTTP
		// request line. In this one case, we can use an HTTP proxy that does
		// not offer CONNECT support.
		if strings.HasPrefix(dialConfig.UpstreamProxyURL, "http://") &&
			(meekConfig.DialAddress == meekConfig.HostHeader ||
				meekConfig.DialAddress == meekConfig.HostHeader+":80") {

			url, err := common.SafeParseURL(dialConfig.UpstreamProxyURL)
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

			// In this proxy case, the destination server address is in the
			// request line URL. net/http will render the request line using
			// the URL but preferring the Host header for the host value,
			// which means any custom host header will clobber the true
			// destination address. The URL.Opaque logic is applied in this
			// case, to force the request line URL value.
			//
			// This URL.Opaque setting assumes MeekModeRelay, with no path; at
			// this time plain HTTP is used only with MeekModeRelay.
			// x/net/http2 will reject requests where the URL.Opaque contains
			// more than the path; but HTTP/2 is not used in this case.

			values := dialConfig.CustomHeaders["Host"]
			if len(values) > 0 {
				opaqueURL = "http://" + meekConfig.DialAddress + "/"
			}

		} else {

			// If dialConfig.UpstreamProxyURL is set, HTTP proxying via
			// CONNECT will be used by the dialer.

			baseDialer := NewTCPDialer(dialConfig)

			// The dialer ignores any address that http.Transport will pass in
			// (derived from the HTTP request URL) and always dials
			// meekConfig.DialAddress.
			dialer = func(ctx context.Context, network, _ string) (net.Conn, error) {
				return baseDialer(ctx, network, meekConfig.DialAddress)
			}
		}

		if protocol.TunnelProtocolUsesMeekHTTP(meekConfig.ClientTunnelProtocol) {
			// Only apply transformer if it will perform a transform; otherwise
			// applying a no-op transform will incur an unnecessary performance
			// cost.
			if meekConfig.HTTPTransformerParameters != nil &&
				meekConfig.HTTPTransformerParameters.ProtocolTransformSpec != nil {

				dialer = transforms.WrapDialerWithHTTPTransformer(
					dialer, meekConfig.HTTPTransformerParameters)
			}
		}

		meek.connManager = newMeekUnderlyingConnManager(nil, dialer, nil)

		httpTransport := &http.Transport{
			Proxy:       proxyUrl,
			DialContext: meek.connManager.dial,
		}

		if proxyUrl != nil {

			// When http.Transport is handling proxying, wrap transport with a
			// transport that (a) adds custom headers; (b) can perform HTTP
			// proxy auth negotiation.

			var err error
			transport, err = upstreamproxy.NewProxyAuthTransport(
				httpTransport, dialConfig.CustomHeaders)
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
		Opaque: opaqueURL,
	}

	if scheme == "http" && proxyUrl == nil {

		// Add custom headers to HTTP. This may be unproxied HTTP, or CONNECT
		// method proxied HTTP, which is handled implicitly by DialTCP (in the
		// latter case, the CONNECT request itself will also have custom
		// headers via upstreamproxy applied by the dialer).
		//
		// When proxyUrl != nil, proxying is handled by http.Transport and
		// custom headers are set in upstreamproxy.NewProxyAuthTransport, above.

		additionalHeaders = dialConfig.CustomHeaders

	} else {

		additionalHeaders = make(http.Header)

		// User-Agent is passed in via dialConfig.CustomHeaders. Always use
		// any User-Agent header, even when not using all custom headers.

		userAgent := dialConfig.CustomHeaders.Get("User-Agent")
		if userAgent != "" {
			additionalHeaders.Set("User-Agent", userAgent)
		}
	}

	if meekConfig.AddPsiphonFrontingHeader {
		host, _, err := net.SplitHostPort(meekConfig.DialAddress)
		if err != nil {
			return nil, errors.Trace(err)
		}
		additionalHeaders.Set("X-Psiphon-Fronting-Address", host)
	}

	if meekConfig.AdditionalHeaders != nil {
		for name, value := range meekConfig.AdditionalHeaders {
			if _, ok := additionalHeaders[name]; !ok {
				additionalHeaders[name] = value
			}
		}
	}

	meek.url = url
	meek.additionalHeaders = additionalHeaders
	meek.transport = transport

	// stopRunning and cachedTLSDialer will now be closed in meek.Close()
	cleanupStopRunning = false
	cleanupConns = false

	// Allocate relay resources, including buffers and running the relay
	// go routine, only when running in relay mode.
	if meek.mode == MeekModeRelay {

		if meekConfig.EnablePayloadPadding {

			// Initialize payload padding mode. The meek server will be
			// signaled, via the meek cookie, to expect request padding and
			// perform response padding.

			var err error
			meek.requestPaddingState, err = protocol.NewMeekRequestPayloadPaddingState(
				meekConfig.MeekObfuscatedKey,
				meek.cookie.Value,
				meekConfig.PayloadPaddingOmitProbability,
				meekConfig.PayloadPaddingMinSize,
				meekConfig.PayloadPaddingMaxSize)
			if err != nil {
				return nil, errors.Trace(err)
			}
			meek.responsePaddingState, err = protocol.NewMeekResponsePayloadPaddingState(
				meekConfig.MeekObfuscatedKey,
				meek.cookie.Value,
				0.0, 0, 0)
			if err != nil {
				return nil, errors.Trace(err)
			}
			meek.requestPaddingBuffer = new(bytes.Buffer)
		}

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

		p := meek.getCustomParameters()
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

		meek.replaceReceiveBuffer(new(bytes.Buffer))

		// In payload padding mode, a padding prefix placeholder is added to
		// empty send buffers. This is handled by truncateAndReplaceSendBuffer.
		meek.truncateAndReplaceSendBuffer(new(bytes.Buffer))

		meek.relayWaitGroup.Add(1)
		go meek.relay()

	} else if meek.mode == MeekModeObfuscatedRoundTrip {

		meek.meekCookieEncryptionPublicKey = meekConfig.MeekCookieEncryptionPublicKey
		meek.meekObfuscatedKey = meekConfig.MeekObfuscatedKey
		meek.meekObfuscatorPaddingSeed = meekConfig.MeekObfuscatorPaddingSeed
		meek.clientTunnelProtocol = meekConfig.ClientTunnelProtocol

	} else if meek.mode == MeekModePlaintextRoundTrip ||
		meek.mode == MeekModeWrappedPlaintextRoundTrip {

		// MeekModeRelay and MeekModeObfuscatedRoundTrip set the Host header
		// implicitly via meek.url; MeekMode[Wrapped]PlaintextRoundTrip does
		// not use meek.url; it uses the RoundTrip input request.URL instead.
		// So the Host header is set to meekConfig.HostHeader explicitly here.
		meek.additionalHeaders.Add("Host", meekConfig.HostHeader)
	}

	return meek, nil
}

type meekPacketConnDialer func(ctx context.Context) (net.PacketConn, *net.UDPAddr, error)

// meekUnderlyingConnManager tracks the TCP/TLS and UDP connections underlying
// the meek HTTP/HTTPS/QUIC transports. This tracking is used to:
//
//   - Use the cached predial TLS conn created in DialMeek.
//   - Gather metrics from mechanisms enabled in the underlying conns, such as
//     the fragmentor, or inproxy.
//   - Fully close all underlying connections with the MeekConn is closed.
type meekUnderlyingConnManager struct {
	mutex           sync.Mutex
	cachedConn      net.Conn
	firstConn       net.Conn
	firstPacketConn net.PacketConn

	dialer       common.Dialer
	managedConns *common.Conns[net.Conn]

	packetConnDialer   meekPacketConnDialer
	managedPacketConns *common.Conns[net.PacketConn]
}

type meekUnderlyingConn struct {
	net.Conn
	connManager *meekUnderlyingConnManager
}

func (conn *meekUnderlyingConn) Close() error {
	conn.connManager.managedConns.Remove(conn)

	// Note: no trace error to preserve error type
	return conn.Conn.Close()
}

type meekUnderlyingPacketConn struct {
	net.PacketConn
	connManager *meekUnderlyingConnManager
}

func (packetConn *meekUnderlyingPacketConn) Close() error {
	packetConn.connManager.managedPacketConns.Remove(packetConn)
	return packetConn.PacketConn.Close()
}

func newMeekUnderlyingConnManager(
	cachedConn net.Conn,
	dialer common.Dialer,
	packetConnDialer meekPacketConnDialer) *meekUnderlyingConnManager {

	m := &meekUnderlyingConnManager{
		dialer:       dialer,
		managedConns: common.NewConns[net.Conn](),

		packetConnDialer:   packetConnDialer,
		managedPacketConns: common.NewConns[net.PacketConn](),
	}

	if cachedConn != nil {
		m.cachedConn = &meekUnderlyingConn{Conn: cachedConn, connManager: m}
		m.firstConn = cachedConn
	}

	return m
}

func (m *meekUnderlyingConnManager) GetMetrics() common.LogFields {

	logFields := common.LogFields{}

	m.mutex.Lock()
	underlyingMetrics, ok := m.firstConn.(common.MetricsSource)
	if ok {
		logFields.Add(underlyingMetrics.GetMetrics())
	}

	underlyingMetrics, ok = m.firstPacketConn.(common.MetricsSource)
	if ok {
		logFields.Add(underlyingMetrics.GetMetrics())
	}
	m.mutex.Unlock()

	return logFields
}

func (m *meekUnderlyingConnManager) dial(
	ctx context.Context, network, addr string) (net.Conn, error) {

	if m.managedConns.IsClosed() {
		return nil, errors.TraceNew("closed")
	}

	// Consume the cached conn when present.

	m.mutex.Lock()
	var conn net.Conn
	if m.cachedConn != nil {
		conn = m.cachedConn
		m.cachedConn = nil
	}
	m.mutex.Unlock()

	if conn != nil {
		return conn, nil
	}

	// The mutex lock is not held for the duration of dial, allowing for
	// concurrent dials.

	conn, err := m.dialer(ctx, network, addr)
	if err != nil {
		// Note: no trace error to preserve error type
		return nil, err
	}

	// Keep a reference to the first underlying conn to be used as a
	// common.MetricsSource in GetMetrics. This enables capturing metrics
	// such as fragmentor configuration.

	m.mutex.Lock()
	if m.firstConn == nil {
		m.firstConn = conn
	}
	m.mutex.Unlock()

	// Wrap the dialed conn with meekUnderlyingConn, which will remove the
	// conn from the set of tracked conns when the conn is closed.

	conn = &meekUnderlyingConn{Conn: conn, connManager: m}

	if !m.managedConns.Add(conn) {
		_ = conn.Close()
		return nil, errors.TraceNew("closed")
	}

	return conn, nil
}

func (m *meekUnderlyingConnManager) dialPacketConn(
	ctx context.Context) (net.PacketConn, *net.UDPAddr, error) {

	if m.managedPacketConns.IsClosed() {
		return nil, nil, errors.TraceNew("closed")
	}

	packetConn, addr, err := m.packetConnDialer(ctx)
	if err != nil {
		// Note: no trace error to preserve error type
		return nil, nil, err
	}

	m.mutex.Lock()
	if m.firstPacketConn != nil {
		m.firstPacketConn = packetConn
	}
	m.mutex.Unlock()

	packetConn = &meekUnderlyingPacketConn{PacketConn: packetConn, connManager: m}

	if !m.managedPacketConns.Add(packetConn) {
		_ = packetConn.Close()
		return nil, nil, errors.TraceNew("closed")
	}

	return packetConn, addr, nil
}

func (m *meekUnderlyingConnManager) closeAll() {
	m.managedConns.CloseAll()
	m.managedPacketConns.CloseAll()
}

// Close terminates the meek connection and releases its resources. In in
// MeekModeRelay, Close waits for the relay goroutine to stop.
func (meek *MeekConn) Close() (err error) {

	// A mutex is required to support net.Conn concurrency semantics.

	meek.mutex.Lock()
	isClosed := meek.isClosed
	meek.isClosed = true
	meek.mutex.Unlock()

	if !isClosed {
		meek.stopRunning()
		meek.connManager.closeAll()
		meek.relayWaitGroup.Wait()

		// meek.transport.CloseIdleConnections is no longed called here since
		// meekUnderlyingConnManager.closeAll will terminate all underlying
		// connections and prevent opening any new connections.
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
	if meek.mode == MeekModeRelay {
		logFields["meek_cookie_size"] = meek.cookieSize
		logFields["meek_tls_padding"] = meek.tlsPadding
		logFields["meek_limit_request"] = meek.limitRequestPayloadLength
		logFields["meek_redial_probability"] = meek.redialTLSProbability
	}

	// Include metrics, such as fragmentor metrics, from the _first_ underlying
	// dial conn. Properties of subsequent underlying dial conns are not reflected
	// in these metrics; we assume that the first dial conn, which most likely
	// transits the various protocol handshakes, is most significant.
	logFields.Add(meek.connManager.GetMetrics())
	return logFields
}

// GetNoticeMetrics implements the common.NoticeMetricsSource interface.
func (meek *MeekConn) GetNoticeMetrics() common.LogFields {

	// These fields are logged only in notices, for diagnostics. The server
	// will log the same values, but derives them from HTTP headers, so they
	// don't need to be sent in the API request.

	logFields := make(common.LogFields)
	logFields["meek_cookie_name"] = meek.cookie.Name
	logFields["meek_content_type"] = meek.contentType
	return logFields
}

// ObfuscatedRoundTrip makes a request to the meek server and returns the
// response. A new, obfuscated meek cookie is created for every request. The
// specified end point is recorded in the cookie and is not exposed as
// plaintext in the meek traffic. The caller is responsible for securing and
// obfuscating the request body.
//
// If Close is called before or concurrent with ObfuscatedRoundTrip, or before
// the response body is read, idle connections may be left open.
func (meek *MeekConn) ObfuscatedRoundTrip(
	requestCtx context.Context, endPoint string, requestBody []byte) ([]byte, error) {

	if meek.mode != MeekModeObfuscatedRoundTrip {
		return nil, errors.TraceNew("operation unsupported")
	}

	cookie, contentType, _, _, _, err := makeMeekObfuscationValues(
		meek.getCustomParameters(),
		meek.meekCookieEncryptionPublicKey,
		meek.meekObfuscatedKey,
		meek.meekObfuscatorPaddingSeed,
		false,
		meek.clientTunnelProtocol,
		endPoint)
	if err != nil {
		return nil, errors.Trace(err)
	}

	request, err := meek.newRequest(
		requestCtx, cookie, contentType, bytes.NewReader(requestBody), 0)
	if err != nil {
		return nil, errors.Trace(err)
	}

	meek.scheduleQUICCloseIdle(request)

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

// RoundTrip implements the http.RoundTripper interface. RoundTrip may only be
// used when TLS and server certificate verification are configured. RoundTrip
// does not implement any security or obfuscation at the HTTP layer.
//
// If Close is called before or concurrent with RoundTrip, or before the
// response body is read, idle connections may be left open.
func (meek *MeekConn) RoundTrip(request *http.Request) (*http.Response, error) {

	if meek.mode != MeekModePlaintextRoundTrip &&
		meek.mode != MeekModeWrappedPlaintextRoundTrip {
		return nil, errors.TraceNew("operation unsupported")
	}

	requestCtx := request.Context()

	// Clone the request to apply addtional headers without modifying the input.
	request = request.Clone(requestCtx)
	meek.addAdditionalHeaders(request)

	meek.scheduleQUICCloseIdle(request)

	response, err := meek.transport.RoundTrip(request)
	if err != nil {
		return nil, errors.Trace(err)
	}

	return response, nil
}

// Read reads data from the connection.
// net.Conn Deadlines are ignored. net.Conn concurrency semantics are supported.
func (meek *MeekConn) Read(buffer []byte) (n int, err error) {
	if meek.mode != MeekModeRelay {
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
	if meek.mode != MeekModeRelay {
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

func (meek *MeekConn) truncateAndReplaceSendBuffer(sendBuffer *bytes.Buffer) {
	sendBuffer.Truncate(0)

	// In payload padding mode, add a placeholder for the payload padding
	// prefix that's required at the start of all payload request bodies.
	// Adding a placeholder avoids any memory shifts later.

	if meek.requestPaddingState != nil {
		for i := 0; i < protocol.MeekPayloadPaddingPrefixSize; i++ {
			sendBuffer.WriteByte(0)
		}
	}

	meek.emptySendBuffer <- sendBuffer
}

// relay sends and receives tunneled traffic (payload). An HTTP request is
// triggered when data is in the write queue or at a polling interval.
// There's a geometric increase, up to a maximum, in the polling interval when
// no data is exchanged. Only one HTTP request is in flight at a time.
func (meek *MeekConn) relay() (retErr error) {
	// Note: meek.Close() calls here in relay() are made asynchronously
	// (using goroutines) since Close() will wait on this WaitGroup.
	defer meek.relayWaitGroup.Done()

	defer func() {

		// Since MeekConn.relay is invoked as a goroutine, log any error
		// returns in a notice. On error, close the MeekConn
		// (asynchronously due to the relayWaitGroup synchronization).

		if retErr != nil {
			NoticeWarning("%v", errors.Trace(retErr))
			go meek.Close()
		}
	}()

	p := meek.getCustomParameters()
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
			// In payload padding mode, sendPayloadSize will include the
			// placeholder padding prefix.
			sendPayloadSize = sendBuffer.Len()
		}

		// Send buffers are exchanged back and forth between MeekConn.Write
		// and MeekConn.relay as the request payload is assembled.
		//
		// In the polling case, there is no send buffer, and in payload
		// padding mode, meek.requestPaddingBuffer is instead used as a
		// temporary buffer to construct a padded payload. Don't replace
		// meek.requestPaddingBuffer back into the buffer exchange channels.

		replaceSendBuffer := sendBuffer != nil

		if meek.requestPaddingState != nil {

			// In payload padding mode, set a padding prefix and, for empty
			// payloads, add a full padding header and padding to empty payloads.
			//
			// Retries, if any, are performed in relayRoundTrip using the same
			// padding bytes; the padding cipher stream state is advanced
			// only once per payload, here.

			addPadding := sendBuffer == nil

			paddingHeader, err := meek.requestPaddingState.SenderGetNextPadding(
				addPadding)
			if err != nil {
				return errors.Trace(err)
			}

			if addPadding {

				if len(paddingHeader) == 0 {

					// SenderGetNextPadding may indicate no padding, including
					// prefix, at all, so revert to the no-sendBuffer empty
					// body polling case.
					sendBuffer = nil

				} else {

					// Full padding case.

					meek.requestPaddingBuffer.Truncate(0)
					meek.requestPaddingBuffer.Write(paddingHeader)

					sendBuffer = meek.requestPaddingBuffer
					replaceSendBuffer = false
				}

			} else {

				// Update the padding prefix placeholder at the start of the payload.

				var err error
				if len(paddingHeader) != protocol.MeekPayloadPaddingPrefixSize {
					err = errors.TraceNew("unexpected meek payload padding header size")
				}
				if sendBuffer.Len() < protocol.MeekPayloadPaddingPrefixSize+1 {
					err = errors.TraceNew("unexpected meek send buffer size")
				}
				if err != nil {
					return errors.Trace(err)
				}
				for i := 0; i < protocol.MeekPayloadPaddingPrefixSize; i++ {
					sendBuffer.Bytes()[i] = paddingHeader[i]
				}
			}
		}

		// relayRoundTrip will replace sendBuffer (by calling replaceSendBuffer). This
		// is a compromise to conserve memory. Using a second buffer here, we could
		// copy sendBuffer and immediately replace it, unblocking meekConn.Write() and
		// allowing more upstream payload to immediately enqueue. Instead, the request
		// payload is read directly from sendBuffer, including retries. Only once the
		// server has acknowledged the request payload is sendBuffer replaced. This
		// still allows meekConn.Write() to unblock before the round trip response is
		// read.

		receivedPayloadSize, paddingOnly, err := meek.relayRoundTrip(
			sendBuffer, replaceSendBuffer)
		if err != nil {
			select {
			case <-meek.runCtx.Done():
				// In this case, meek.relayRoundTrip encountered Done(). Exit without
				// logging error.
				return
			default:
			}
			return errors.Trace(err)
		}

		// Periodically re-dial the underlying TLS/TCP connection
		// (notwithstanding the parameter name, this also applies to TCP
		// connections for HTTP protocols).
		if prng.FlipWeightedCoin(meek.redialTLSProbability) {
			meek.transport.CloseIdleConnections()
		}

		// Calculate polling interval. When non-padding data is received,
		// immediately request more. Otherwise, schedule next poll with
		// exponential back off. Jitter and coin flips are used to avoid
		// trivial, static traffic timing patterns.

		p := meek.getCustomParameters()

		if (receivedPayloadSize > 0 && !paddingOnly) || sendPayloadSize > 0 {

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

// newRequest performs common request setup for both MeekModeRelay and
// MeekModeObfuscatedRoundTrip.
//
// newRequest is not safe for concurrent calls due to its use of
// setRequestContext.
//
// The caller must call the returned cancelFunc.
func (meek *MeekConn) newRequest(
	requestCtx context.Context,
	cookie *http.Cookie,
	contentType string,
	body io.Reader,
	contentLength int) (*http.Request, error) {

	request, err := http.NewRequest("POST", meek.url.String(), body)
	if err != nil {
		return nil, errors.Trace(err)
	}

	request = request.WithContext(requestCtx)

	// Content-Length may not be be set automatically due to the
	// underlying type of requestBody.
	if contentLength > 0 {
		request.ContentLength = int64(contentLength)
	}

	meek.addAdditionalHeaders(request)

	request.Header.Set("Content-Type", contentType)

	if cookie == nil {
		cookie = meek.cookie
	}
	request.AddCookie(cookie)

	return request, nil
}

// Workaround for h2quic.RoundTripper context issue. See comment in
// MeekConn.Close.
func (meek *MeekConn) scheduleQUICCloseIdle(request *http.Request) {
	requestCtx := request.Context()
	if meek.isQUIC && requestCtx != context.Background() {
		go func() {
			<-requestCtx.Done()
			meek.transport.CloseIdleConnections()
		}()
	}
}

// relayRoundTrip configures and makes the actual HTTP POST request
func (meek *MeekConn) relayRoundTrip(
	sendBuffer *bytes.Buffer,
	replaceSendBuffer bool) (int64, bool, error) {

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
		if sendBuffer != nil && replaceSendBuffer {
			meek.truncateAndReplaceSendBuffer(sendBuffer)
		}
	}()

	retries := uint(0)

	p := meek.getCustomParameters()
	retryDeadline := time.Now().Add(p.Duration(parameters.MeekRoundTripRetryDeadline))
	retryDelay := p.Duration(parameters.MeekRoundTripRetryMinDelay)
	retryMaxDelay := p.Duration(parameters.MeekRoundTripRetryMaxDelay)
	retryMultiplier := p.Float(parameters.MeekRoundTripRetryMultiplier)
	p.Close()

	serverAcknowledgedRequestPayload := false

	receivedPayloadSize := int64(0)
	totalPaddingSize := int64(0)

	morePadding := meek.responsePaddingState != nil

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

		// - meek.stopRunning() will abort a round trip in flight
		// - round trip will abort if it exceeds timeout
		requestCtx, cancelFunc := context.WithTimeout(
			meek.runCtx,
			meek.getCustomParameters().Duration(parameters.MeekRoundTripTimeout))
		defer cancelFunc()

		request, err := meek.newRequest(
			requestCtx,
			nil,
			meek.contentType,
			requestBody,
			contentLength)
		if err != nil {
			// Don't retry when can't initialize a Request
			return 0, false, errors.Trace(err)
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
				return 0, false, errors.TraceNew("meek connection has closed")
			}
		}

		if err != nil {
			select {
			case <-meek.runCtx.Done():
				// Exit without retrying and without logging error.
				return 0, false, errors.Trace(err)
			default:
			}
			NoticeWarning("meek round trip failed: %s", err)
			// ...continue to retry
		}

		if err == nil {

			if response.StatusCode != expectedStatusCode &&
				// Certain http servers return 200 OK where we expect 206, so
				// accept that.
				!(expectedStatusCode == http.StatusPartialContent &&
					response.StatusCode == http.StatusOK) {

				// Don't retry when the status code is incorrect
				response.Body.Close()
				return 0, false, errors.Tracef(
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
			if sendBuffer != nil && replaceSendBuffer {
				// Assumes signaller.AwaitClosed is called above, so
				// sendBuffer will no longer be accessed by RoundTrip.
				meek.truncateAndReplaceSendBuffer(sendBuffer)
				sendBuffer = nil
			}

			if meek.responsePaddingState != nil && morePadding {

				// With retries, the response payload may be read in
				// increments. In payload padding mode, the start of the
				// payload contains at least a padding prefix, and
				// potentially a full padding and padding itself. morePadding
				// remains true as long as ReceiverConsumePadding indicates
				// that more padding bytes need to be read and consumed.
				//
				// ErrMeekPaddingStateImmediateEOF supports the special case
				// where an empty payload was left empty with no padding
				// prefix or padding at all.

				readPaddingSize, more, err := meek.responsePaddingState.
					ReceiverConsumePadding(response.Body)

				if err == protocol.ErrMeekPaddingStateImmediateEOF {

					// A 0 byte payload with no padding.

					response.Body.Close()
					// Round trip completed successfully
					break
				}

				morePadding = more

				// Add padding bytes read, required for the correct Range
				// header in case of retry.
				receivedPayloadSize += readPaddingSize

				totalPaddingSize += readPaddingSize

				if err != nil {
					NoticeWarning("meek read padding failed: %v", err)
					response.Body.Close()
					// ...continue to retry
					continue

				}
			}

			readPayloadSize, err := meek.readPayload(response.Body)
			response.Body.Close()

			// receivedPayloadSize is the number of response
			// payload bytes received and relayed. A retry can
			// resume after this position.
			receivedPayloadSize += readPayloadSize

			if err != nil {
				NoticeWarning("meek read payload failed: %v", err)
				// ...continue to retry
			} else {
				// Round trip completed successfully
				break
			}
		}

		// Release context resources immediately.
		cancelFunc()

		// Either the request failed entirely, or there was a failure
		// streaming the response payload. Always retry once. Then
		// retry if time remains; when the next delay exceeds the time
		// remaining until the deadline, do not retry.

		now := time.Now()

		if retries >= 1 &&
			(now.After(retryDeadline) || retryDeadline.Sub(now) <= retryDelay) {
			return 0, false, errors.Trace(err)
		}
		retries += 1

		delayTimer := time.NewTimer(retryDelay)

		select {
		case <-delayTimer.C:
		case <-meek.runCtx.Done():
			delayTimer.Stop()
			return 0, false, errors.Trace(err)
		}

		// Increase the next delay, to back off and avoid excessive
		// activity in conditions such as no network connectivity.

		retryDelay = time.Duration(
			float64(retryDelay) * retryMultiplier)
		if retryDelay >= retryMaxDelay {
			retryDelay = retryMaxDelay
		}
	}

	paddingOnly := totalPaddingSize > 0 &&
		receivedPayloadSize <= totalPaddingSize

	return receivedPayloadSize, paddingOnly, nil
}

// Add additional headers to the HTTP request using the same method we use for adding
// custom headers to HTTP proxy requests.
func (meek *MeekConn) addAdditionalHeaders(request *http.Request) {
	for name, value := range meek.additionalHeaders {
		if name == "Host" {
			if len(value) > 0 {
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
	p parameters.ParametersAccessor,
	meekCookieEncryptionPublicKey string,
	meekObfuscatedKey string,
	meekObfuscatorPaddingPRNGSeed *prng.Seed,
	enablePayloadPadding bool,
	clientTunnelProtocol string,
	endPoint string,

) (cookie *http.Cookie,
	contentType string,
	tlsPadding int,
	limitRequestPayloadLength int,
	redialTLSProbability float64,
	err error) {

	if meekCookieEncryptionPublicKey == "" {
		return nil, "", 0, 0, 0.0, errors.TraceNew("missing public key")
	}

	cookieData := &protocol.MeekCookieData{
		MeekProtocolVersion:  MEEK_PROTOCOL_VERSION,
		EnablePayloadPadding: enablePayloadPadding,
		ClientTunnelProtocol: clientTunnelProtocol,
		EndPoint:             endPoint,
	}
	serializedCookie, err := json.Marshal(cookieData)
	if err != nil {
		return nil, "", 0, 0, 0.0, errors.Trace(err)
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
		return nil, "", 0, 0, 0.0, errors.Trace(err)
	}
	copy(publicKey[:], decodedPublicKey)
	ephemeralPublicKey, ephemeralPrivateKey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, "", 0, 0, 0.0, errors.Trace(err)
	}
	box := box.Seal(nil, serializedCookie, &nonce, &publicKey, ephemeralPrivateKey)
	encryptedCookie := make([]byte, 32+len(box))
	copy(encryptedCookie[0:32], ephemeralPublicKey[0:32])
	copy(encryptedCookie[32:], box)

	maxPadding := p.Int(parameters.MeekCookieMaxPadding)

	// Obfuscate the encrypted data. NewClientObfuscator checks that
	// meekObfuscatedKey isn't missing.
	obfuscator, err := obfuscator.NewClientObfuscator(
		&obfuscator.ObfuscatorConfig{
			Keyword:         meekObfuscatedKey,
			PaddingPRNGSeed: meekObfuscatorPaddingPRNGSeed,
			MaxPadding:      &maxPadding})
	if err != nil {
		return nil, "", 0, 0, 0.0, errors.Trace(err)
	}
	obfuscatedCookie, _ := obfuscator.SendPreamble()
	seedLen := len(obfuscatedCookie)
	obfuscatedCookie = append(obfuscatedCookie, encryptedCookie...)
	obfuscator.ObfuscateClientToServer(obfuscatedCookie[seedLen:])

	cookieNamePRNG, err := obfuscator.GetDerivedPRNG("meek-cookie-name")
	if err != nil {
		return nil, "", 0, 0, 0.0, errors.Trace(err)
	}
	var cookieName string
	if cookieNamePRNG.FlipWeightedCoin(p.Float(parameters.MeekAlternateCookieNameProbability)) {
		cookieName = values.GetCookieName(cookieNamePRNG)
	} else {
		// Format the HTTP cookie
		// The format is <random letter 'A'-'Z'>=<base64 data>, which is intended to match common cookie formats.
		A := int('A')
		Z := int('Z')
		// letterIndex is integer in range [int('A'), int('Z')]
		letterIndex := cookieNamePRNG.Intn(Z - A + 1)
		cookieName = string(byte(A + letterIndex))
	}

	cookie = &http.Cookie{
		Name:  cookieName,
		Value: base64.StdEncoding.EncodeToString(obfuscatedCookie)}

	contentTypePRNG, err := obfuscator.GetDerivedPRNG("meek-content-type")
	if err != nil {
		return nil, "", 0, 0, 0.0, errors.Trace(err)
	}
	if contentTypePRNG.FlipWeightedCoin(p.Float(parameters.MeekAlternateContentTypeProbability)) {
		contentType = values.GetContentType(contentTypePRNG)
	} else {
		contentType = "application/octet-stream"
	}

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
			return nil, "", 0, 0, 0.0, errors.Trace(err)
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

		// In payload padding mode, the maximum request payload size is
		// adjusted to allow for the padding prefix and at least one real
		// payload byte.
		if enablePayloadPadding &&
			limitRequestPayloadLength == protocol.MeekPayloadPaddingPrefixSize {

			limitRequestPayloadLength += 1
		}

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
				return nil, "", 0, 0, 0.0, errors.Trace(err)
			}

			tlsPadding = tlsPaddingPRNG.Range(minPadding, maxPadding)
		}

		redialTLSProbability = p.Float(parameters.MeekRedialTLSProbability)
	}

	return cookie, contentType, tlsPadding, limitRequestPayloadLength, redialTLSProbability, nil
}
