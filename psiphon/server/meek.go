/*
 * Copyright (c) 2016, Psiphon Inc.
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

package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	std_errors "errors"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	psiphon_tls "github.com/Psiphon-Labs/psiphon-tls"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/inproxy"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/monotime"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/obfuscator"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/parameters"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/tactics"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/transforms"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/values"
	lrucache "github.com/cognusion/go-cache-lru"
	"github.com/minio/crc64nvme"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/time/rate"
)

// MeekServer is based on meek-server.go from Tor and Psiphon:
//
// https://gitweb.torproject.org/pluggable-transports/meek.git/blob/HEAD:/meek-client/meek-client.go
// CC0 1.0 Universal
//
// https://bitbucket.org/psiphon/psiphon-circumvention-system/src/default/go/meek-client/meek-client.go

const (

	// Protocol version 1 clients can handle arbitrary length response bodies. Older clients
	// report no version number and expect at most 64K response bodies.
	MEEK_PROTOCOL_VERSION_1 = 1

	// Protocol version 2 clients initiate a session by sending an encrypted and obfuscated meek
	// cookie with their initial HTTP request. Connection information is contained within the
	// encrypted cookie payload. The server inspects the cookie and establishes a new session and
	// returns a new random session ID back to client via Set-Cookie header. The client uses this
	// session ID on all subsequent requests for the remainder of the session.
	MEEK_PROTOCOL_VERSION_2 = 2

	// Protocol version 3 clients include resiliency enhancements and will add a Range header
	// when retrying a request for a partially downloaded response payload.
	MEEK_PROTOCOL_VERSION_3 = 3

	// Protocol version 4 add support for meek payload padding, which is
	// enabled via the meek cookie.
	MEEK_PROTOCOL_VERSION_4 = 4

	MEEK_MAX_REQUEST_PAYLOAD_LENGTH                  = 65536
	MEEK_MIN_SESSION_ID_LENGTH                       = 8
	MEEK_MAX_SESSION_ID_LENGTH                       = 20
	MEEK_DEFAULT_TURN_AROUND_TIMEOUT                 = 10 * time.Millisecond
	MEEK_DEFAULT_EXTENDED_TURN_AROUND_TIMEOUT        = 100 * time.Millisecond
	MEEK_DEFAULT_SKIP_EXTENDED_TURN_AROUND_THRESHOLD = 8192
	MEEK_DEFAULT_MAX_SESSION_STALENESS               = 45 * time.Second
	MEEK_DEFAULT_HTTP_CLIENT_IO_TIMEOUT              = 45 * time.Second
	MEEK_DEFAULT_FRONTED_HTTP_CLIENT_IO_TIMEOUT      = 360 * time.Second
	MEEK_DEFAULT_RESPONSE_BUFFER_LENGTH              = 65536
	MEEK_DEFAULT_POOL_BUFFER_LENGTH                  = 65536
	MEEK_DEFAULT_POOL_BUFFER_COUNT                   = 2048
	MEEK_DEFAULT_POOL_BUFFER_CLIENT_LIMIT            = 32
	MEEK_ENDPOINT_MAX_REQUEST_PAYLOAD_LENGTH         = 65536
	MEEK_MAX_SESSION_COUNT                           = 1000000
)

// MeekServer implements the meek protocol, which tunnels TCP traffic (in the case of Psiphon,
// Obfuscated SSH traffic) over HTTP. Meek may be fronted (through a CDN) or direct and may be
// HTTP or HTTPS.
//
// Upstream traffic arrives in HTTP request bodies and downstream traffic is sent in response
// bodies. The sequence of traffic for a given flow is associated using a session ID that's
// set as a HTTP cookie for the client to submit with each request.
//
// MeekServer hooks into TunnelServer via the net.Conn interface by transforming the
// HTTP payload traffic for a given session into net.Conn conforming Read()s and Write()s via
// the meekConn struct.
type MeekServer struct {
	support                         *SupportServices
	listener                        net.Listener
	listenerTunnelProtocol          string
	listenerPort                    int
	isFronted                       bool
	passthroughAddress              string
	turnAroundTimeout               time.Duration
	extendedTurnAroundTimeout       time.Duration
	skipExtendedTurnAroundThreshold int
	maxSessionStaleness             time.Duration
	httpClientIOTimeout             time.Duration
	stdTLSConfig                    *tls.Config
	psiphonTLSConfig                *psiphon_tls.Config
	obfuscatorSeedHistory           *obfuscator.SeedHistory
	clientHandler                   func(clientConn net.Conn, data *additionalTransportData)
	openConns                       *common.Conns[net.Conn]
	stopBroadcast                   <-chan struct{}
	sessionsLock                    sync.RWMutex
	sessions                        map[string]*meekSession
	bufferPool                      *CachedResponseBufferPool
	rateLimitLock                   sync.Mutex
	rateLimitHistory                *lrucache.Cache
	rateLimitCount                  int
	rateLimitSignalGC               chan struct{}
	normalizer                      *transforms.HTTPNormalizerListener
	inproxyBroker                   *inproxy.Broker
	inproxyCheckAllowMatch          atomic.Value
}

// NewMeekServer initializes a new meek server.
func NewMeekServer(
	support *SupportServices,
	listener net.Listener,
	listenerTunnelProtocol string,
	listenerPort int,
	useTLS, isFronted, useObfuscatedSessionTickets, useHTTPNormalizer bool,
	clientHandler func(clientConn net.Conn, data *additionalTransportData),
	stopBroadcast <-chan struct{}) (*MeekServer, error) {

	// With fronting, MeekRequiredHeaders can be used to ensure that the
	// request is coming through a CDN that's configured to add the
	// specified, secret header values. Configuring the MeekRequiredHeaders
	// scheme is required when running an in-proxy broker.
	if isFronted &&
		support.Config.MeekServerRunInproxyBroker &&
		len(support.Config.MeekRequiredHeaders) < 1 {

		return nil, errors.TraceNew("missing required header")
	}

	passthroughAddress := support.Config.TunnelProtocolPassthroughAddresses[listenerTunnelProtocol]

	turnAroundTimeout := MEEK_DEFAULT_TURN_AROUND_TIMEOUT
	if support.Config.MeekTurnAroundTimeoutMilliseconds != nil {
		turnAroundTimeout = time.Duration(
			*support.Config.MeekTurnAroundTimeoutMilliseconds) * time.Millisecond
	}

	extendedTurnAroundTimeout := MEEK_DEFAULT_EXTENDED_TURN_AROUND_TIMEOUT
	if support.Config.MeekExtendedTurnAroundTimeoutMilliseconds != nil {
		extendedTurnAroundTimeout = time.Duration(
			*support.Config.MeekExtendedTurnAroundTimeoutMilliseconds) * time.Millisecond
	}

	skipExtendedTurnAroundThreshold := MEEK_DEFAULT_SKIP_EXTENDED_TURN_AROUND_THRESHOLD
	if support.Config.MeekSkipExtendedTurnAroundThresholdBytes != nil {
		skipExtendedTurnAroundThreshold = *support.Config.MeekSkipExtendedTurnAroundThresholdBytes
	}

	maxSessionStaleness := MEEK_DEFAULT_MAX_SESSION_STALENESS
	if support.Config.MeekMaxSessionStalenessMilliseconds != nil {
		maxSessionStaleness = time.Duration(
			*support.Config.MeekMaxSessionStalenessMilliseconds) * time.Millisecond
	}

	var httpClientIOTimeout time.Duration
	if isFronted {

		// Fronted has a distinct timeout, and the default is higher since new
		// clients may connect to a CDN edge and start using an existing
		// persistent connection.

		httpClientIOTimeout = MEEK_DEFAULT_FRONTED_HTTP_CLIENT_IO_TIMEOUT
		if support.Config.MeekFrontedHTTPClientIOTimeoutMilliseconds != nil {
			httpClientIOTimeout = time.Duration(
				*support.Config.MeekFrontedHTTPClientIOTimeoutMilliseconds) * time.Millisecond
		}
	} else {
		httpClientIOTimeout = MEEK_DEFAULT_HTTP_CLIENT_IO_TIMEOUT
		if support.Config.MeekHTTPClientIOTimeoutMilliseconds != nil {
			httpClientIOTimeout = time.Duration(
				*support.Config.MeekHTTPClientIOTimeoutMilliseconds) * time.Millisecond
		}
	}

	bufferLength := MEEK_DEFAULT_POOL_BUFFER_LENGTH
	if support.Config.MeekCachedResponsePoolBufferSize != 0 {
		bufferLength = support.Config.MeekCachedResponsePoolBufferSize
	}

	bufferCount := MEEK_DEFAULT_POOL_BUFFER_COUNT
	if support.Config.MeekCachedResponsePoolBufferCount != 0 {
		bufferCount = support.Config.MeekCachedResponsePoolBufferCount
	}

	bufferPoolClientLimit := MEEK_DEFAULT_POOL_BUFFER_CLIENT_LIMIT
	if support.Config.MeekCachedResponsePoolBufferClientLimit != 0 {
		bufferPoolClientLimit = support.Config.MeekCachedResponsePoolBufferClientLimit
	}

	_, thresholdSeconds, _, _, _, _, _, _, reapFrequencySeconds, maxEntries :=
		support.TrafficRulesSet.GetMeekRateLimiterConfig()

	rateLimitHistory := lrucache.NewWithLRU(
		time.Duration(thresholdSeconds)*time.Second,
		time.Duration(reapFrequencySeconds)*time.Second,
		maxEntries)

	bufferPool := NewCachedResponseBufferPool(
		bufferLength, bufferCount, bufferPoolClientLimit)

	// Limitation: rate limiting and resource limiting are handled by external
	// components, and MeekServer enforces only a sanity check limit on the
	// number the number of entries in MeekServer.sessions.
	//
	// See comment in newSSHServer for more details.

	meekServer := &MeekServer{
		support:                         support,
		listener:                        listener,
		listenerTunnelProtocol:          listenerTunnelProtocol,
		listenerPort:                    listenerPort,
		isFronted:                       isFronted,
		passthroughAddress:              passthroughAddress,
		turnAroundTimeout:               turnAroundTimeout,
		extendedTurnAroundTimeout:       extendedTurnAroundTimeout,
		skipExtendedTurnAroundThreshold: skipExtendedTurnAroundThreshold,
		maxSessionStaleness:             maxSessionStaleness,
		httpClientIOTimeout:             httpClientIOTimeout,
		obfuscatorSeedHistory:           obfuscator.NewSeedHistory(nil),
		clientHandler:                   clientHandler,
		openConns:                       common.NewConns[net.Conn](),
		stopBroadcast:                   stopBroadcast,
		sessions:                        make(map[string]*meekSession),
		bufferPool:                      bufferPool,
		rateLimitHistory:                rateLimitHistory,
		rateLimitSignalGC:               make(chan struct{}, 1),
	}

	if useTLS {

		// For fronted meek servers, crypto/tls is used to ensure that
		// net/http.Server.Serve will find *crypto/tls.Conn types, as
		// required for enabling HTTP/2. The fronted case does not not
		// support or require the TLS passthrough or obfuscated session
		// ticket mechanisms, which are implemented in psiphon-tls. HTTP/2 is
		// preferred for fronted meek servers in order to multiplex many
		// concurrent requests, either from many tunnel clients or
		// many/individual in-proxy broker clients, over a single network
		// connection.
		//
		// For direct meek servers, psiphon-tls is used to provide the TLS
		// passthrough or obfuscated session ticket obfuscation mechanisms.
		// Direct meek servers do not enable HTTP/1.1 Each individual meek
		// tunnel client will have its own network connection and each client
		// has only a single in-flight meek request at a time.

		if isFronted {

			if useObfuscatedSessionTickets {
				return nil, errors.TraceNew("obfuscated session tickets unsupported")
			}
			if meekServer.passthroughAddress != "" {
				return nil, errors.TraceNew("passthrough unsupported")
			}
			tlsConfig, err := meekServer.makeFrontedMeekTLSConfig()
			if err != nil {
				return nil, errors.Trace(err)
			}
			meekServer.stdTLSConfig = tlsConfig
		} else {

			tlsConfig, err := meekServer.makeDirectMeekTLSConfig(
				useObfuscatedSessionTickets)
			if err != nil {
				return nil, errors.Trace(err)
			}
			meekServer.psiphonTLSConfig = tlsConfig
		}
	}

	if useHTTPNormalizer && protocol.TunnelProtocolUsesMeekHTTPNormalizer(listenerTunnelProtocol) {

		normalizer := meekServer.makeMeekHTTPNormalizerListener()
		meekServer.normalizer = normalizer
		meekServer.listener = normalizer
	}

	// Initialize in-proxy broker service

	if support.Config.MeekServerRunInproxyBroker {

		if !inproxy.Enabled() {
			// Note that, technically, it may be possible to allow this case,
			// since !PSIPHON_DISABLE_INPROXY is currently required only for
			// client/proxy-side WebRTC functionality, although that could change.
			return nil, errors.TraceNew("inproxy implementation is not enabled")
		}

		if support.Config.InproxyBrokerAllowCommonASNMatching {
			inproxy.SetAllowCommonASNMatching(true)
		}

		if support.Config.InproxyBrokerAllowBogonWebRTCConnections {
			inproxy.SetAllowBogonWebRTCConnections(true)
		}

		sessionPrivateKey, err := inproxy.SessionPrivateKeyFromString(
			support.Config.InproxyBrokerSessionPrivateKey)
		if err != nil {
			return nil, errors.Trace(err)
		}

		obfuscationRootSecret, err := inproxy.ObfuscationSecretFromString(
			support.Config.InproxyBrokerObfuscationRootSecret)
		if err != nil {
			return nil, errors.Trace(err)
		}

		lookupGeoIPData := func(IP string) common.GeoIPData {
			return common.GeoIPData(support.GeoIPService.Lookup(IP))
		}

		inproxyBroker, err := inproxy.NewBroker(
			&inproxy.BrokerConfig{
				Logger:                         CommonLogger(log),
				AllowProxy:                     meekServer.inproxyBrokerAllowProxy,
				PrioritizeProxy:                meekServer.inproxyBrokerPrioritizeProxy,
				AllowClient:                    meekServer.inproxyBrokerAllowClient,
				AllowDomainFrontedDestinations: meekServer.inproxyBrokerAllowDomainFrontedDestinations,
				AllowMatch:                     meekServer.inproxyBrokerAllowMatch,
				LookupGeoIP:                    lookupGeoIPData,
				APIParameterValidator:          getInproxyBrokerAPIParameterValidator(),
				APIParameterLogFieldFormatter:  getInproxyBrokerAPIParameterLogFieldFormatter(),
				IsValidServerEntryTag:          support.PsinetDatabase.IsValidServerEntryTag,
				GetTacticsPayload:              meekServer.inproxyBrokerGetTacticsPayload,
				IsLoadLimiting:                 meekServer.support.TunnelServer.CheckLoadLimiting,
				RelayDSLRequest:                meekServer.inproxyBrokerRelayDSLRequest,
				PrivateKey:                     sessionPrivateKey,
				ObfuscationRootSecret:          obfuscationRootSecret,
				ServerEntrySignaturePublicKey:  support.Config.InproxyBrokerServerEntrySignaturePublicKey,
			})
		if err != nil {
			return nil, errors.Trace(err)
		}

		meekServer.inproxyBroker = inproxyBroker

		// inproxyReloadTactics initializes compartment ID, timeouts, and
		// other broker parameter values from tactics.
		err = meekServer.inproxyReloadTactics()
		if err != nil {
			return nil, errors.Trace(err)
		}

	}

	return meekServer, nil
}

// ReloadTactics signals components to reload tactics and reinitialize as
// required when tactics may have changed.
func (server *MeekServer) ReloadTactics() error {
	if server.support.Config.MeekServerRunInproxyBroker {
		err := server.inproxyReloadTactics()
		if err != nil {
			return errors.Trace(err)
		}
	}
	return nil
}

type meekContextKey struct {
	key string
}

var meekNetConnContextKey = &meekContextKey{"net.Conn"}

// Run runs the meek server; this function blocks while serving HTTP or
// HTTPS connections on the specified listener. This function also runs
// a goroutine which cleans up expired meek client sessions.
//
// To stop the meek server, both Close() the listener and set the stopBroadcast
// signal specified in NewMeekServer.
func (server *MeekServer) Run() error {

	waitGroup := new(sync.WaitGroup)

	waitGroup.Add(1)
	go func() {
		defer waitGroup.Done()
		ticker := time.NewTicker(server.maxSessionStaleness / 2)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				server.deleteExpiredSessions()
			case <-server.stopBroadcast:
				return
			}
		}
	}()

	waitGroup.Add(1)
	go func() {
		defer waitGroup.Done()
		server.rateLimitWorker()
	}()

	if server.inproxyBroker != nil {
		err := server.inproxyBroker.Start()
		if err != nil {
			return errors.Trace(err)
		}
		defer server.inproxyBroker.Stop()
	}

	// Serve HTTP or HTTPS
	//
	// - WriteTimeout may include time awaiting request, as per:
	//   https://blog.cloudflare.com/the-complete-guide-to-golang-net-http-timeouts
	//
	// - Legacy meek-server wrapped each client HTTP connection with an explicit idle
	//   timeout net.Conn and didn't use http.Server timeouts. We could do the same
	//   here (use ActivityMonitoredConn) but the stock http.Server timeouts should
	//   now be sufficient.
	//
	// - HTTP/2 is enabled (the default), which is required for efficient
	//   in-proxy broker connection sharing.
	//
	// - Any CDN fronting a meek server running an in-proxy broker should be
	//   configured with timeouts that accomodate the proxy announcement
	//   request long polling.

	httpServer := &http.Server{
		ReadTimeout:  server.httpClientIOTimeout,
		WriteTimeout: server.httpClientIOTimeout,
		Handler:      server,
		ConnState:    server.httpConnStateCallback,
		ConnContext: func(ctx context.Context, conn net.Conn) context.Context {
			return context.WithValue(ctx, meekNetConnContextKey, conn)
		},
	}

	// Note: Serve() will be interrupted by server.listener.Close() call
	listener := server.listener
	if server.stdTLSConfig != nil {
		listener = tls.NewListener(server.listener, server.stdTLSConfig)
	} else if server.psiphonTLSConfig != nil {
		listener = psiphon_tls.NewListener(server.listener, server.psiphonTLSConfig)

		// Disable auto HTTP/2
		httpServer.TLSNextProto = make(map[string]func(*http.Server, *tls.Conn, http.Handler))
	}
	err := httpServer.Serve(listener)

	// Can't check for the exact error that Close() will cause in Accept(),
	// (see: https://code.google.com/p/go/issues/detail?id=4373). So using an
	// explicit stop signal to stop gracefully.
	select {
	case <-server.stopBroadcast:
		err = nil
	default:
	}

	// deleteExpiredSessions calls deleteSession which may block waiting
	// for active request handlers to complete; timely shutdown requires
	// stopping the listener and closing all existing connections before
	// awaiting the reaperWaitGroup.

	server.listener.Close()
	server.openConns.CloseAll()

	waitGroup.Wait()

	return err
}

func handleServeHTTPPanic() {

	// Disable panic recovery, to ensure panics are captured and logged by
	// panicwrap.
	//
	// The net.http ServeHTTP caller will recover any ServeHTTP panic, so
	// re-panic in another goroutine after capturing the panicking goroutine
	// call stack.

	if r := recover(); r != nil {
		var stack [4096]byte
		n := runtime.Stack(stack[:], false)
		err := errors.Tracef("ServeHTTP panic: %v\n%s", r, stack[:n])
		go panic(err.Error())
	}
}

// ServeHTTP handles meek client HTTP requests, where the request body
// contains upstream traffic and the response will contain downstream
// traffic.
func (server *MeekServer) ServeHTTP(responseWriter http.ResponseWriter, request *http.Request) {

	defer handleServeHTTPPanic()

	// Note: no longer requiring that the request method is POST

	// Check for required headers and values. For fronting, required headers
	// may be used to identify a CDN edge. When this check fails,
	// TerminateHTTPConnection is called instead of handleError, so any
	// persistent connection is always closed.

	if len(server.support.Config.MeekRequiredHeaders) > 0 {
		for header, value := range server.support.Config.MeekRequiredHeaders {
			requestValue := request.Header.Get(header)

			// There's no ConstantTimeCompare for strings. While the
			// conversion from string to byte slice may leak the length of
			// the expected value, ConstantTimeCompare also takes time that's
			// a function of the length of the input byte slices; leaking the
			// expected value length isn't a vulnerability as long as the
			// secret is long enough and random.
			if subtle.ConstantTimeCompare([]byte(requestValue), []byte(value)) != 1 {
				log.WithTraceFields(LogFields{
					"header": header,
					"value":  requestValue,
				}).Warning("invalid required meek header")

				common.TerminateHTTPConnection(responseWriter, request)
				return
			}
		}
	}

	// Check for the expected meek/session ID cookie. in-proxy broker requests
	// do not use or expect a meek cookie (the broker session protocol
	// encapsulated in the HTTP request/response payloads has its own
	// obfuscation and anti-replay mechanisms).
	//
	// TODO: log irregular tunnels for unexpected cookie cases?

	var meekCookie *http.Cookie
	for _, c := range request.Cookies() {
		meekCookie = c
		break
	}

	if (meekCookie == nil || len(meekCookie.Value) == 0) &&
		!server.support.Config.MeekServerRunInproxyBroker {

		log.WithTrace().Warning("missing meek cookie")
		common.TerminateHTTPConnection(responseWriter, request)
		return
	}

	if meekCookie != nil && server.support.Config.MeekServerInproxyBrokerOnly {

		log.WithTrace().Warning("unexpected meek cookie")
		common.TerminateHTTPConnection(responseWriter, request)
		return
	}

	// Check for prohibited HTTP headers.

	if len(server.support.Config.MeekProhibitedHeaders) > 0 {
		for _, header := range server.support.Config.MeekProhibitedHeaders {
			value := request.Header.Get(header)
			if header != "" {
				log.WithTraceFields(LogFields{
					"header": header,
					"value":  value,
				}).Warning("prohibited meek header")
				server.handleError(responseWriter, request)
				return
			}
		}
	}

	// A valid meek cookie indicates which class of request this is:
	//
	// 1. A new meek session. Create a new session ID and proceed with
	// relaying tunnel traffic.
	//
	// 2. An existing meek session. Resume relaying tunnel traffic.
	//
	// 3. A request to an endpoint. This meek connection is not for relaying
	// tunnel traffic. Instead, the request is handed off to a custom handler.
	//
	// In the in-proxy broker case, there is no meek cookie, which avoids the
	// size and resource overhead of sending and processing a meek cookie
	// with each endpoint request.
	//
	// The broker session protocol encapsulated in the HTTP request/response
	// payloads has its own obfuscation and anti-replay mechanisms.
	//
	// In RunInproxyBroker mode, non-meek cookie requests are routed to the
	// in-proxy broker. getSessionOrEndpoint is still invoked in all cases,
	// to process GeoIP headers, invoke the meek rate limiter, etc.
	//
	// Limitations:
	//
	// - Adding arbirary cookies, as camouflage for plain HTTP for example, is
	//   not supported.
	//
	// - the HTTP normalizer depends on the meek cookie
	//   (see makeMeekHTTPNormalizerListener) so RunInproxyBroker mode is
	//   incompatible with the HTTP normalizer.

	sessionID,
		session,
		underlyingConn,
		endPoint,
		endPointClientIP,
		endPointGeoIPData,
		err := server.getSessionOrEndpoint(request, meekCookie)

	if err != nil {
		// Debug since session cookie errors commonly occur during
		// normal operation.
		log.WithTraceFields(LogFields{"error": err}).Debug("session lookup failed")
		server.handleError(responseWriter, request)
		return
	}

	if endPoint != "" {

		// Route to endpoint handlers and return.

		handled := false

		switch endPoint {
		case tactics.TACTICS_END_POINT, tactics.SPEED_TEST_END_POINT:
			handled = server.support.TacticsServer.HandleEndPoint(
				endPoint,
				common.GeoIPData(*endPointGeoIPData),
				responseWriter,
				request)

			// Currently, TacticsServer.HandleEndPoint handles returning a 404 instead
			// leaving that up to server.handleError.
			//
			// TODO: call server.handleError, for its isFronting special case.

		case inproxy.BrokerEndPointName:
			handled = true
			err := server.inproxyBrokerHandler(
				endPointClientIP,
				common.GeoIPData(*endPointGeoIPData),
				responseWriter,
				request)
			if err != nil {

				var brokerLoggedEvent *inproxy.BrokerLoggedEvent
				var deobfuscationAnomoly *inproxy.DeobfuscationAnomoly
				alreadyLogged := std_errors.As(err, &brokerLoggedEvent) ||
					std_errors.As(err, &deobfuscationAnomoly)

				if !alreadyLogged {
					log.WithTraceFields(
						LogFields{"error": err}).Warning("inproxyBrokerHandler failed")
				}

				server.handleError(responseWriter, request)
			}
		}

		if !handled {
			log.WithTraceFields(LogFields{"endPoint": endPoint}).Warning("unhandled endpoint")
			server.handleError(responseWriter, request)
		}

		return
	}

	// Tunnel relay mode.

	// Ensure that there's only one concurrent request handler per client
	// session. Depending on the nature of a network disruption, it can
	// happen that a client detects a failure and retries while the server
	// is still streaming response in the handler for the _previous_ client
	// request.
	//
	// Even if the session.cachedResponse were safe for concurrent
	// use (it is not), concurrent handling could lead to loss of session
	// since upstream data read by the first request may not reach the
	// cached response before the second request reads the cached data.
	//
	// The existing handler will stream response data, holding the lock,
	// for no more than MEEK_EXTENDED_TURN_AROUND_TIMEOUT.
	//
	// TODO: interrupt an existing handler? The existing handler will be
	// sending data to the cached response, but if that buffer fills, the
	// session will be lost.

	requestNumber := session.requestCount.Add(1)

	// Wait for the existing request to complete.
	session.lock.Lock()
	defer session.lock.Unlock()

	// Count this metric once the lock is acquired, to avoid concurrent and
	// potentially incorrect session.underlyingConn updates.
	//
	// It should never be the case that a new underlyingConn has the same
	// value as the previous session.underlyingConn, as each is a net.Conn
	// interface which includes a pointer, and the previous value cannot
	// be garbage collected until session.underlyingConn is updated.
	if session.underlyingConn != underlyingConn {
		session.metricUnderlyingConnCount.Add(1)
		session.underlyingConn = underlyingConn
	}

	// If a newer request has arrived while waiting, discard this one.
	// Do not delay processing the newest request.
	if session.requestCount.Load() > requestNumber {

		// Do not return 404 in this error case. Keep session open to allow
		// client to retry.
		return
	}

	// If the session expired and was deleted while this request was waiting,
	// discard this request. The session is no longer valid, and the final call
	// to session.cachedResponse.Reset may have already occured, so any further
	// session.cachedResponse access may deplete resources (fail to refill the pool).
	if session.deleted {
		server.handleError(responseWriter, request)
		return
	}

	// pumpReads causes a TunnelServer/SSH goroutine blocking on a Read to
	// read the request body as upstream traffic.
	// TODO: run pumpReads and pumpWrites concurrently?

	// pumpReads checksums the request payload and skips relaying it when
	// it matches the immediately previous request payload. This allows
	// clients to resend request payloads, when retrying due to connection
	// interruption, without knowing whether the server has received or
	// relayed the data.
	//
	// pumpReads also handles discarding meek request payload padding.

	requestSize, allowCachedResponse, err := session.clientConn.pumpReads(request.Body)
	if err != nil {
		if err != io.EOF {
			// Debug since errors such as "i/o timeout" occur during normal operation;
			// also, golang network error messages may contain client IP.
			log.WithTraceFields(LogFields{"error": err}).Debug("read request failed")
		}

		// Do not return 404 in this error case. Keep session open to allow
		// client to retry.
		return
	}

	// The extended turn around mechanism optimizes for downstream flows by
	// sending more data in the response as long as it's available. As a
	// heuristic, when the request size meets a threshold, optimize instead
	// of upstream flows by skipping the extended turn around.
	skipExtendedTurnAround := requestSize >= int64(server.skipExtendedTurnAroundThreshold)

	// Set cookie before writing the response.

	if session.meekProtocolVersion >= MEEK_PROTOCOL_VERSION_2 && !session.sessionIDSent {
		// Replace the meek cookie with the session ID.
		// SetCookie for the the session ID cookie is only set once, to reduce overhead. This
		// session ID value replaces the original meek cookie value.
		http.SetCookie(responseWriter, &http.Cookie{Name: meekCookie.Name, Value: sessionID})
		session.sessionIDSent = true
	}

	// When streaming data into the response body, a copy is
	// retained in the cachedResponse buffer. This allows the
	// client to retry and request that the response be resent
	// when the HTTP connection is interrupted.
	//
	// If a Range header is present, the client is retrying,
	// possibly after having received a partial response. In
	// this case, use any cached response to attempt to resend
	// the response, starting from the resend position the client
	// indicates.
	//
	// When the resend position is not available -- because the
	// cachedResponse buffer could not hold it -- the client session
	// is closed, as there's no way to resume streaming the payload
	// uninterrupted.
	//
	// The client may retry before a cached response is prepared,
	// so a cached response is not always used when a Range header
	// is present.
	//
	// TODO: invalid Range header is ignored; should it be otherwise?

	position, isRetry := checkRangeHeader(request)
	if isRetry {
		session.metricClientRetries.Add(1)
	}

	hasCompleteCachedResponse := session.cachedResponse.HasPosition(0)

	// The client is not expected to send position > 0 when there is
	// no cached response; let that case fall through to the next
	// HasPosition check which will fail and close the session.
	//
	// Limitation: when a client sends a request that never reaches the
	// server, it will retry with a Range header and position 0. This case
	// leads to a flaw in the resiliency design, since the server may have a
	// stale cached response from a _previous_ request and this can lead to
	// sending a response body twice, breaking the stream. To partially
	// mitigate this, the pumpReads allowCachedResponse value is used as a
	// heuristic to distinguish Range 0 cases that should not use cached
	// responses.

	var responseSize int
	var responseError error

	if isRetry &&
		(position > 0 || (hasCompleteCachedResponse && allowCachedResponse)) {

		if !session.cachedResponse.HasPosition(position) {
			greaterThanSwapInt64(&session.metricCachedResponseMissPosition, int64(position))
			server.handleError(responseWriter, request)
			session.delete(true)
			return
		}

		responseWriter.WriteHeader(http.StatusPartialContent)

		// TODO: cachedResponse can now start releasing extended buffers, as
		// response bytes before "position" will never be requested again?

		responseSize, responseError = session.cachedResponse.CopyFromPosition(position, responseWriter)
		greaterThanSwapInt64(&session.metricPeakCachedResponseHitSize, int64(responseSize))

		// The client may again fail to receive the payload and may again
		// retry, so not yet releasing cachedResponse buffers.

	} else {

		// _Now_ we release buffers holding data from the previous
		// response. And then immediately stream the new response into
		// newly acquired buffers.
		session.cachedResponse.Reset()

		// Note: this code depends on an implementation detail of
		// io.MultiWriter: a Write() to the MultiWriter writes first
		// to the cache, and then to the response writer. So if the
		// write to the response writer fails, the payload is cached.
		multiWriter := io.MultiWriter(session.cachedResponse, responseWriter)

		// The client expects 206, not 200, whenever it sets a Range header,
		// which it may do even when no cached response is prepared.
		if isRetry {
			responseWriter.WriteHeader(http.StatusPartialContent)
		}

		// pumpWrites causes a TunnelServer/SSH goroutine blocking on a Write to
		// write its downstream traffic through to the response body.

		// Limitation: pumpWrites may write more response bytes than can be
		// cached for future retries, either due to no extended buffers
		// available, or exceeding the per-client extended buffer limit. In
		// practice, with throttling in place and servers running under load
		// limiting, metrics indicate that this rarely occurs. A potential
		// future enhancement could be for pumpWrites to stop writing and
		// send the response once there's no buffers remaining, favoring
		// connection resilience over performance.
		//
		// TODO: use geo-targeted per-client extended buffer limit to reserve
		// extended cache buffers for regions or ISPs with active or expected
		// network connection interruptions?

		responseSize, responseError = session.clientConn.pumpWrites(multiWriter, skipExtendedTurnAround)
		greaterThanSwapInt64(&session.metricPeakResponseSize, int64(responseSize))
		greaterThanSwapInt64(&session.metricPeakCachedResponseSize, int64(session.cachedResponse.Available()))
	}

	// responseError is the result of writing the body either from CopyFromPosition or pumpWrites
	if responseError != nil {
		if responseError != io.EOF {
			// Debug since errors such as "i/o timeout" occur during normal operation;
			// also, golang network error messages may contain client IP.
			log.WithTraceFields(LogFields{"error": responseError}).Debug("write response failed")
		}

		// Do not return 404 in this error case. Keep session open to allow
		// client to retry.
		return
	}
}

func (server *MeekServer) handleError(responseWriter http.ResponseWriter, request *http.Request) {

	// When fronted, keep the persistent connection open since it may be used
	// by many clients coming through the same edge. For performance reasons,
	// an error, including invalid input, from one client shouldn't close the
	// persistent connection used by other clients.

	if server.isFronted {
		http.NotFound(responseWriter, request)
		return
	}
	common.TerminateHTTPConnection(responseWriter, request)
}

func checkRangeHeader(request *http.Request) (int, bool) {
	rangeHeader := request.Header.Get("Range")
	if rangeHeader == "" {
		return 0, false
	}

	prefix := "bytes="
	suffix := "-"

	if !strings.HasPrefix(rangeHeader, prefix) ||
		!strings.HasSuffix(rangeHeader, suffix) {

		return 0, false
	}

	rangeHeader = strings.TrimPrefix(rangeHeader, prefix)
	rangeHeader = strings.TrimSuffix(rangeHeader, suffix)
	position, err := strconv.Atoi(rangeHeader)

	if err != nil {
		return 0, false
	}

	return position, true
}

// getSessionOrEndpoint checks if the cookie corresponds to an existing tunnel
// relay session ID. If no session is found, the cookie must be an obfuscated
// meek cookie. A new session is created when the meek cookie indicates relay
// mode; or the endpoint is returned when the meek cookie indicates endpoint
// mode.
//
// For performance reasons, in-proxy broker requests are allowed to omit the
// meek cookie and pass in nil for meekCookie; getSessionOrEndpoint still
// performs rate limiting and header handling for the in-proxy broker case.
func (server *MeekServer) getSessionOrEndpoint(
	request *http.Request,
	meekCookie *http.Cookie) (string, *meekSession, net.Conn, string, string, *GeoIPData, error) {

	underlyingConn := request.Context().Value(meekNetConnContextKey).(net.Conn)

	// Check for an existing meek tunnel session.

	if meekCookie != nil {

		server.sessionsLock.RLock()
		existingSessionID := meekCookie.Value
		session, ok := server.sessions[existingSessionID]
		server.sessionsLock.RUnlock()
		if ok {
			// TODO: can multiple http client connections using same session cookie
			// cause race conditions on session struct?
			session.touch()
			return existingSessionID, session, underlyingConn, "", "", nil, nil
		}
	}

	// TODO: rename clientIP to peerIP to reflect the new terminology used in
	// psiphon/server code where the immediate peer may be an in-proxy proxy,
	// not the client.

	// Determine the client or peer remote address, which is used for
	// geolocation stats, rate limiting, anti-probing, discovery, and tactics
	// selection logic.
	//
	// When an intermediate proxy or CDN is in use, we may be
	// able to determine the original client address by inspecting HTTP
	// headers such as X-Forwarded-For.
	//
	// We trust only headers provided by CDNs. Fronted Psiphon server hosts
	// should be configured to accept tunnel connections only from CDN edges.
	// When the CDN passes along a chain of IPs, as in X-Forwarded-For, we
	// trust only the right-most IP, which is provided by the CDN.

	clientIP, _, err := net.SplitHostPort(request.RemoteAddr)
	if err != nil {
		return "", nil, nil, "", "", nil, errors.Trace(err)
	}
	if net.ParseIP(clientIP) == nil {
		return "", nil, nil, "", "", nil, errors.TraceNew("invalid IP address")
	}

	if server.isFronted && len(server.support.Config.MeekProxyForwardedForHeaders) > 0 {

		// When there are multiple header names in MeekProxyForwardedForHeaders,
		// the first valid match is preferred. MeekProxyForwardedForHeaders should be
		// configured to use header names that are always provided by the CDN(s) and
		// not header names that may be passed through from clients.
		for _, header := range server.support.Config.MeekProxyForwardedForHeaders {

			// In the case where there are multiple headers,
			// request.Header.Get returns the first header, but we want the
			// last header; so use request.Header.Values and select the last
			// value. As per RFC 2616 section 4.2, a proxy must not change
			// the order of field values, which implies that it should append
			// values to the last header.
			values := request.Header.Values(header)
			if len(values) > 0 {
				value := values[len(values)-1]

				// Some headers, such as X-Forwarded-For, are a comma-separated
				// list of IPs (each proxy in a chain). Select the last IP.
				IPs := strings.Split(value, ",")
				IP := IPs[len(IPs)-1]

				// Remove optional whitespace surrounding the commas.
				IP = strings.TrimSpace(IP)

				if net.ParseIP(IP) != nil {
					clientIP = IP
					break
				}
			}
		}
	}

	geoIPData := server.support.GeoIPService.Lookup(clientIP)

	// Check for a steering IP header, which contains an alternate dial IP to
	// be returned to the client via the secure API handshake response.
	// Steering may be used to load balance CDN traffic.
	//
	// The steering IP header is added by a CDN or CDN service process. To
	// prevent steering IP spoofing, the service process must filter out any
	// steering IP headers injected into ingress requests.
	//
	// Steering IP headers must appear in the first request of a meek session
	// in order to be recorded here and relayed to the client.

	var steeringIP string
	if server.isFronted && server.support.Config.EnableSteeringIPs {
		steeringIP = request.Header.Get("X-Psiphon-Steering-Ip")
		if steeringIP != "" {
			IP := net.ParseIP(steeringIP)
			if IP == nil || common.IsBogon(IP) {
				steeringIP = ""
				log.WithTraceFields(LogFields{"steeringIP": steeringIP}).Warning("invalid steering IP")
			}
		}
	}

	// The session is new (or expired). Treat the cookie value as a new meek
	// cookie, extract the payload, and create a new session.

	// Limitation: when the cookie is a session ID for an expired session, we
	// still attempt to treat it as a meek cookie. As it stands, that yields
	// either base64 decoding errors (RawStdEncoding vs. StdEncoding) or
	// length errors. We could log cleaner errors ("session is expired") by
	// checking that the cookie is a well-formed (base64.RawStdEncoding) value
	// between MEEK_MIN_SESSION_ID_LENGTH and MEEK_MAX_SESSION_ID_LENGTH
	// bytes -- assuming that MEEK_MAX_SESSION_ID_LENGTH is too short to be a
	// valid meek cookie.

	var payloadJSON []byte

	if server.normalizer != nil {

		// Limitation: RunInproxyBroker mode with no meek cookies is not
		// compatible with the HTTP normalizer.

		// NOTE: operates on the assumption that the normalizer is not wrapped
		// with a further conn.
		underlyingConn := request.Context().Value(meekNetConnContextKey).(net.Conn)
		normalizedConn := underlyingConn.(*transforms.HTTPNormalizer)
		payloadJSON = normalizedConn.ValidateMeekCookieResult

	} else {

		if meekCookie != nil {

			payloadJSON, err = server.getMeekCookiePayload(clientIP, meekCookie.Value)
			if err != nil {
				return "", nil, nil, "", "", nil, errors.Trace(err)
			}
		}
	}

	// Note: this meek server ignores legacy values PsiphonClientSessionId
	// and PsiphonServerAddress.
	var clientSessionData protocol.MeekCookieData

	if meekCookie != nil {

		err = json.Unmarshal(payloadJSON, &clientSessionData)
		if err != nil {
			return "", nil, nil, "", "", nil, errors.Trace(err)
		}

	} else {

		// Assume the in-proxy broker endpoint when there's no meek cookie.
		clientSessionData.EndPoint = inproxy.BrokerEndPointName
	}

	// Any rate limit is enforced after the meek cookie is validated, so a prober
	// without the obfuscation secret will be unable to fingerprint the server
	// based on response time combined with the rate limit configuration. The
	// rate limit is primarily intended to limit memory resource consumption and
	// not the overhead incurred by cookie validation.
	//
	// The meek rate limit is applied to new meek tunnel sessions and tactics
	// requests, both of which may reasonably be limited to as low as 1 event
	// per time period. The in-proxy broker is excluded from meek rate
	// limiting since it has its own rate limiter and in-proxy requests are
	// allowed to be more frequent.

	if clientSessionData.EndPoint != inproxy.BrokerEndPointName &&
		server.rateLimit(clientIP, geoIPData, server.listenerTunnelProtocol) {
		return "", nil, nil, "", "", nil, errors.TraceNew("rate limit exceeded")
	}

	// Handle endpoints before enforcing CheckEstablishTunnels.
	// Currently, endpoints are tactics requests, and we allow these to be
	// handled by servers which would otherwise reject new tunnels.

	if clientSessionData.EndPoint != "" {
		return "", nil, nil, clientSessionData.EndPoint, clientIP, &geoIPData, nil
	}

	// After this point, for the meek tunnel new session case, a meek cookie
	// is required and meekCookie must not be nil.
	if meekCookie == nil {
		return "", nil, nil, "", "", nil, errors.TraceNew("missing meek cookie")
	}

	// Don't create new sessions when not establishing. A subsequent SSH handshake
	// will not succeed, so creating a meek session just wastes resources.

	if server.support.TunnelServer != nil &&
		!server.support.TunnelServer.CheckEstablishTunnels() {
		return "", nil, nil, "", "", nil, errors.TraceNew("not establishing tunnels")
	}

	// Disconnect immediately if the tactics for the client restricts usage of
	// the fronting provider ID. The probability may be used to influence
	// usage of a given fronting provider; but when only that provider works
	// for a given client, and the probability is less than 1.0, the client
	// can retry until it gets a successful coin flip.
	//
	// Clients will also skip candidates with restricted fronting provider IDs.
	// The client-side probability, RestrictFrontingProviderIDsClientProbability,
	// is applied independently of the server-side coin flip here.
	//
	// At this stage, GeoIP tactics filters are active, but handshake API
	// parameters are not.
	//
	// See the comment in server.LoadConfig regarding fronting provider ID
	// limitations.

	p, err := server.support.ServerTacticsParametersCache.Get(geoIPData)
	if err != nil {
		return "", nil, nil, "", "", nil, errors.Trace(err)
	}

	if protocol.TunnelProtocolUsesFrontedMeek(server.listenerTunnelProtocol) {

		if !p.IsNil() &&
			common.Contains(
				p.Strings(parameters.RestrictFrontingProviderIDs),
				server.support.Config.GetFrontingProviderID()) {
			if p.WeightedCoinFlip(
				parameters.RestrictFrontingProviderIDsServerProbability) {
				return "", nil, nil, "", "", nil, errors.TraceNew("restricted fronting provider")
			}
		}
	}

	// The tunnel protocol name is used for stats and traffic rules. In many
	// cases, its value is unambiguously determined by the listener port. In
	// certain cases, such as multiple fronted protocols with a single
	// backend listener, the client's reported tunnel protocol value is used.
	// The caller must validate clientTunnelProtocol with
	// protocol.IsValidClientTunnelProtocol.

	var clientTunnelProtocol string
	if clientSessionData.ClientTunnelProtocol != "" {

		if !protocol.IsValidClientTunnelProtocol(
			clientSessionData.ClientTunnelProtocol,
			server.listenerTunnelProtocol,
			server.support.Config.GetRunningProtocols()) {

			return "", nil, nil, "", "", nil, errors.Tracef(
				"invalid client tunnel protocol: %s", clientSessionData.ClientTunnelProtocol)
		}

		clientTunnelProtocol = clientSessionData.ClientTunnelProtocol
	}

	// Create a new session

	bufferLength := MEEK_DEFAULT_RESPONSE_BUFFER_LENGTH
	if server.support.Config.MeekCachedResponseBufferSize != 0 {
		bufferLength = server.support.Config.MeekCachedResponseBufferSize
	}
	cachedResponse := NewCachedResponse(bufferLength, server.bufferPool)

	// The cookie name, Content-Type, and HTTP version of the first request in
	// the session are recorded for stats. It's possible, but not expected,
	// that later requests will have different values.

	session := &meekSession{
		meekProtocolVersion: clientSessionData.MeekProtocolVersion,
		sessionIDSent:       false,
		cachedResponse:      cachedResponse,
		cookieName:          meekCookie.Name,
		contentType:         request.Header.Get("Content-Type"),
		httpVersion:         request.Proto,
	}

	session.touch()

	if clientSessionData.EnablePayloadPadding {

		// Initialize meek payload padding when the client signals
		// use of payload padding via the meek cookie.

		if p.IsNil() {
			return "", nil, nil, "", "", nil,
				errors.TraceNew("unsupported payload padding")
		}

		limitTunnelProtocols := p.TunnelProtocols(
			parameters.MeekPayloadPaddingLimitTunnelProtocols)
		if len(limitTunnelProtocols) > 0 &&
			!common.Contains(limitTunnelProtocols,
				clientSessionData.ClientTunnelProtocol) {

			return "", nil, nil, "", "", nil,
				errors.TraceNew("unexpected payload padding")
		}

		session.requestPaddingState, err = protocol.NewMeekRequestPayloadPaddingState(
			server.support.Config.MeekObfuscatedKey,
			meekCookie.Value,
			0.0, 0, 0)
		if err != nil {
			return "", nil, nil, "", "", nil, errors.Trace(err)
		}
		session.responsePaddingState, err = protocol.NewMeekResponsePayloadPaddingState(
			server.support.Config.MeekObfuscatedKey,
			meekCookie.Value,
			p.Float(parameters.MeekPayloadPaddingServerOmitProbability),
			p.Int(parameters.MeekPayloadPaddingServerMinSize),
			p.Int(parameters.MeekPayloadPaddingServerMaxSize))
		if err != nil {
			return "", nil, nil, "", "", nil, errors.Trace(err)
		}
	}

	// Create a new meek conn that will relay the payload
	// between meek request/responses and the tunnel server client
	// handler. The client IP is also used to initialize the
	// meek conn with a useful value to return when the tunnel
	// server calls conn.RemoteAddr() to get the client's IP address.

	// Assumes clientIP is a valid IP address; the port value is a stub
	// and is expected to be ignored.
	clientConn := newMeekConn(
		server,
		session,
		underlyingConn,
		&net.TCPAddr{
			IP:   net.ParseIP(clientIP),
			Port: 0,
		},
		clientSessionData.MeekProtocolVersion)

	session.clientConn = clientConn

	// Note: MEEK_PROTOCOL_VERSION_1 doesn't support changing the
	// meek cookie to a session ID; v1 clients always send the
	// original meek cookie value with each request. The issue with
	// v1 is that clients which wake after a device sleep will attempt
	// to resume a meek session and the server can't differentiate
	// between resuming a session and creating a new session. This
	// causes the v1 client connection to hang/timeout.
	sessionID := meekCookie.Value
	if clientSessionData.MeekProtocolVersion >= MEEK_PROTOCOL_VERSION_2 {
		sessionID, err = makeMeekSessionID()
		if err != nil {
			return "", nil, nil, "", "", nil, errors.Trace(err)
		}
	}

	server.sessionsLock.Lock()

	// MEEK_MAX_SESSION_COUNT is a simple sanity check and failsafe. Load
	// limiting tuned to each server's host resources is provided by external
	// components. See comment in newSSHServer for more details.
	if len(server.sessions) >= MEEK_MAX_SESSION_COUNT {
		server.sessionsLock.Unlock()
		err := std_errors.New("MEEK_MAX_SESSION_COUNT exceeded")
		log.WithTrace().Warning(err.Error())
		return "", nil, nil, "", "", nil, errors.Trace(err)
	}

	server.sessions[sessionID] = session
	server.sessionsLock.Unlock()

	var additionalData *additionalTransportData
	if clientTunnelProtocol != "" || steeringIP != "" {
		additionalData = &additionalTransportData{
			overrideTunnelProtocol: clientTunnelProtocol,
			steeringIP:             steeringIP,
		}
	}

	// Note: from the tunnel server's perspective, this client connection
	// will close when session.delete calls Close() on the meekConn.
	server.clientHandler(session.clientConn, additionalData)

	return sessionID, session, underlyingConn, "", "", nil, nil
}

func (server *MeekServer) rateLimit(
	clientIP string, geoIPData GeoIPData, tunnelProtocol string) bool {

	historySize,
		thresholdSeconds,
		tunnelProtocols,
		regions,
		ISPs,
		ASNs,
		cities,
		GCTriggerCount, _, _ :=
		server.support.TrafficRulesSet.GetMeekRateLimiterConfig()

	if historySize == 0 {
		return false
	}

	if len(tunnelProtocols) > 0 {
		if !common.Contains(tunnelProtocols, tunnelProtocol) {
			return false
		}
	}

	if len(regions) > 0 || len(ISPs) > 0 || len(ASNs) > 0 || len(cities) > 0 {

		if len(regions) > 0 {
			if !common.Contains(regions, geoIPData.Country) {
				return false
			}
		}

		if len(ISPs) > 0 {
			if !common.Contains(ISPs, geoIPData.ISP) {
				return false
			}
		}

		if len(ASNs) > 0 {
			if !common.Contains(ASNs, geoIPData.ASN) {
				return false
			}
		}

		if len(cities) > 0 {
			if !common.Contains(cities, geoIPData.City) {
				return false
			}
		}
	}

	// With IPv6, individual users or sites are users commonly allocated a /64
	// or /56, so rate limit by /56.
	rateLimitIP := clientIP
	IP := net.ParseIP(clientIP)
	if IP != nil && IP.To4() == nil {
		rateLimitIP = IP.Mask(net.CIDRMask(56, 128)).String()
	}

	// go-cache-lru is safe for concurrent access, but lacks an atomic
	// compare-and-set type operations to check if an entry exists before
	// adding a new one. This mutex ensures the Get and Add are atomic
	// (as well as synchronizing access to rateLimitCount).
	server.rateLimitLock.Lock()

	var rateLimiter *rate.Limiter
	entry, ok := server.rateLimitHistory.Get(rateLimitIP)
	if ok {
		rateLimiter = entry.(*rate.Limiter)
	} else {

		// Set bursts to 1, which is appropriate for new meek tunnels and
		// tactics requests.

		limit := float64(historySize) / float64(thresholdSeconds)
		bursts := 1
		rateLimiter = rate.NewLimiter(rate.Limit(limit), bursts)
		server.rateLimitHistory.Set(
			rateLimitIP,
			rateLimiter,
			time.Duration(thresholdSeconds)*time.Second)
	}

	limit := !rateLimiter.Allow()

	triggerGC := false
	if limit {
		server.rateLimitCount += 1
		if server.rateLimitCount >= GCTriggerCount {
			triggerGC = true
			server.rateLimitCount = 0
		}
	}

	server.rateLimitLock.Unlock()

	if triggerGC {
		select {
		case server.rateLimitSignalGC <- struct{}{}:
		default:
		}
	}

	return limit
}

func (server *MeekServer) rateLimitWorker() {
	for {
		select {
		case <-server.rateLimitSignalGC:
			runtime.GC()
		case <-server.stopBroadcast:
			return
		}
	}
}

func (server *MeekServer) deleteSession(sessionID string) {

	// Don't obtain the server.sessionsLock write lock until modifying
	// server.sessions, as the session.delete can block for up to
	// MEEK_HTTP_CLIENT_IO_TIMEOUT. Allow new sessions to be added
	// concurrently.
	//
	// Since a lock isn't held for the duration, concurrent calls to
	// deleteSession with the same sessionID could happen; this is
	// not expected since only the reaper goroutine calls deleteExpiredSessions
	// (and in any case concurrent execution of the ok block is not an issue).
	server.sessionsLock.RLock()
	session, ok := server.sessions[sessionID]
	server.sessionsLock.RUnlock()

	if ok {
		session.delete(false)

		server.sessionsLock.Lock()
		delete(server.sessions, sessionID)
		server.sessionsLock.Unlock()
	}
}

func (server *MeekServer) deleteExpiredSessions() {

	// A deleteSession call may block for up to MEEK_HTTP_CLIENT_IO_TIMEOUT,
	// so grab a snapshot list of expired sessions and do not hold a lock for
	// the duration of deleteExpiredSessions. This allows new sessions to be
	// added concurrently.
	//
	// New sessions added after the snapshot is taken will be checked for
	// expiry on subsequent periodic calls to deleteExpiredSessions.
	//
	// To avoid long delays in releasing resources, individual deletes are
	// performed concurrently.

	server.sessionsLock.Lock()
	expiredSessionIDs := make([]string, 0)
	for sessionID, session := range server.sessions {
		if session.expired() {
			expiredSessionIDs = append(expiredSessionIDs, sessionID)
		}
	}
	server.sessionsLock.Unlock()

	start := time.Now()

	deleteWaitGroup := new(sync.WaitGroup)
	for _, sessionID := range expiredSessionIDs {
		deleteWaitGroup.Add(1)
		go func(sessionID string) {
			defer deleteWaitGroup.Done()
			server.deleteSession(sessionID)
		}(sessionID)
	}
	deleteWaitGroup.Wait()

	log.WithTraceFields(
		LogFields{"elapsed time": time.Since(start)}).Debug("deleted expired sessions")
}

// httpConnStateCallback tracks open persistent HTTP/HTTPS connections to the
// meek server.
func (server *MeekServer) httpConnStateCallback(conn net.Conn, connState http.ConnState) {
	switch connState {
	case http.StateNew:
		server.openConns.Add(conn)
	case http.StateHijacked, http.StateClosed:
		server.openConns.Remove(conn)
	}
}

// getMeekCookiePayload extracts the payload from a meek cookie. The cookie
// payload is base64 encoded, obfuscated, and NaCl encrypted.
func (server *MeekServer) getMeekCookiePayload(
	clientIP string, cookieValue string) ([]byte, error) {

	decodedValue, err := base64.StdEncoding.DecodeString(cookieValue)
	if err != nil {
		return nil, errors.Trace(err)
	}

	// The data consists of an obfuscated seed message prepended
	// to the obfuscated, encrypted payload. The server obfuscator
	// will read the seed message, leaving the remaining encrypted
	// data in the reader.

	reader := bytes.NewReader(decodedValue[:])

	obfuscator, err := obfuscator.NewServerObfuscator(
		&obfuscator.ObfuscatorConfig{
			Keyword:     server.support.Config.MeekObfuscatedKey,
			SeedHistory: server.obfuscatorSeedHistory,
			IrregularLogger: func(clientIP string, err error, logFields common.LogFields) {
				logIrregularTunnel(
					server.support,
					server.listenerTunnelProtocol,
					server.listenerPort,
					clientIP,
					errors.Trace(err),
					LogFields(logFields))
			},

			// To allow for meek retries, replay of the same meek cookie is
			// permitted (but only from the same source IP).
			DisableStrictHistoryMode: true,
		},
		clientIP,
		reader)
	if err != nil {
		return nil, errors.Trace(err)
	}

	offset, err := reader.Seek(0, 1)
	if err != nil {
		return nil, errors.Trace(err)
	}
	encryptedPayload := decodedValue[offset:]

	obfuscator.ObfuscateClientToServer(encryptedPayload)

	var nonce [24]byte
	var privateKey, ephemeralPublicKey [32]byte

	decodedPrivateKey, err := base64.StdEncoding.DecodeString(
		server.support.Config.MeekCookieEncryptionPrivateKey)
	if err != nil {
		return nil, errors.Trace(err)
	}
	copy(privateKey[:], decodedPrivateKey)

	if len(encryptedPayload) < 32 {
		return nil, errors.TraceNew("unexpected encrypted payload size")
	}
	copy(ephemeralPublicKey[0:32], encryptedPayload[0:32])

	payload, ok := box.Open(nil, encryptedPayload[32:], &nonce, &ephemeralPublicKey, &privateKey)
	if !ok {
		return nil, errors.TraceNew("open box failed")
	}

	return payload, nil
}

func (server *MeekServer) getWebServerCertificate() ([]byte, []byte, error) {

	var certificate, privateKey string

	if server.support.Config.MeekServerCertificate != "" {
		certificate = server.support.Config.MeekServerCertificate
		privateKey = server.support.Config.MeekServerPrivateKey

	} else {
		var err error
		certificate, privateKey, _, err = common.GenerateWebServerCertificate(values.GetHostName())
		if err != nil {
			return nil, nil, errors.Trace(err)
		}
	}

	return []byte(certificate), []byte(privateKey), nil
}

// makeFrontedMeekTLSConfig creates a TLS config for a fronted meek HTTPS
// listener.
func (server *MeekServer) makeFrontedMeekTLSConfig() (*tls.Config, error) {

	certificate, privateKey, err := server.getWebServerCertificate()
	if err != nil {
		return nil, errors.Trace(err)
	}

	tlsCertificate, err := tls.X509KeyPair(
		[]byte(certificate), []byte(privateKey))
	if err != nil {
		return nil, errors.Trace(err)
	}

	// Vary the minimum version to frustrate scanning/fingerprinting of unfronted servers.
	// Limitation: like the certificate, this value changes on restart.
	minVersionCandidates := []uint16{tls.VersionTLS10, tls.VersionTLS11, tls.VersionTLS12}
	minVersion := minVersionCandidates[prng.Intn(len(minVersionCandidates))]

	// This is a reordering of the supported CipherSuites in golang 1.6[*]. Non-ephemeral key
	// CipherSuites greatly reduce server load, and we try to select these since the meek
	// protocol is providing obfuscation, not privacy/integrity (this is provided by the
	// tunneled SSH), so we don't benefit from the perfect forward secrecy property provided
	// by ephemeral key CipherSuites.
	// https://github.com/golang/go/blob/1cb3044c9fcd88e1557eca1bf35845a4108bc1db/src/crypto/tls/cipher_suites.go#L75
	//
	// This optimization is applied only when there's a CDN in front of the meek server; in
	// unfronted cases we prefer a more natural TLS handshake.
	//
	// [*] the list has since been updated, removing CipherSuites using RC4 and 3DES.
	cipherSuites := []uint16{
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{tlsCertificate},
		// Offer and prefer "h2" for HTTP/2 support.
		NextProtos:   []string{"h2", "http/1.1"},
		MinVersion:   minVersion,
		CipherSuites: cipherSuites,
	}

	return config, nil
}

// makeDirectMeekTLSConfig creates a TLS config for a direct meek HTTPS
// listener.
func (server *MeekServer) makeDirectMeekTLSConfig(
	useObfuscatedSessionTickets bool) (*psiphon_tls.Config, error) {

	certificate, privateKey, err := server.getWebServerCertificate()
	if err != nil {
		return nil, errors.Trace(err)
	}

	tlsCertificate, err := psiphon_tls.X509KeyPair(
		[]byte(certificate), []byte(privateKey))
	if err != nil {
		return nil, errors.Trace(err)
	}

	// Vary the minimum version to frustrate scanning/fingerprinting of unfronted servers.
	// Limitation: like the certificate, this value changes on restart.
	minVersionCandidates := []uint16{tls.VersionTLS10, tls.VersionTLS11, tls.VersionTLS12}
	minVersion := minVersionCandidates[prng.Intn(len(minVersionCandidates))]

	config := &psiphon_tls.Config{
		Certificates: []psiphon_tls.Certificate{tlsCertificate},
		// Omit "h2", so HTTP/2 is not negotiated. Note that the
		// negotiated-ALPN extension in the ServerHello is plaintext, even in
		// TLS 1.3.
		NextProtos: []string{"http/1.1"},
		MinVersion: minVersion,
	}

	if useObfuscatedSessionTickets {

		// See obfuscated session ticket overview
		// in NewObfuscatedClientSessionState.

		config.UseObfuscatedSessionTickets = true

		var obfuscatedSessionTicketKey [32]byte
		key, err := hex.DecodeString(server.support.Config.MeekObfuscatedKey)
		if err == nil && len(key) != 32 {
			err = std_errors.New("invalid obfuscated session key length")
		}
		if err != nil {
			return nil, errors.Trace(err)
		}
		copy(obfuscatedSessionTicketKey[:], key)

		var standardSessionTicketKey [32]byte
		_, err = rand.Read(standardSessionTicketKey[:])
		if err != nil {
			return nil, errors.Trace(err)
		}

		// Note: SessionTicketKey needs to be set, or else, it appears,
		// tris.Config.serverInit() will clobber the value set by
		// SetSessionTicketKeys.
		config.SessionTicketKey = obfuscatedSessionTicketKey
		config.SetSessionTicketKeys([][32]byte{
			standardSessionTicketKey,
			obfuscatedSessionTicketKey})
	}

	// When configured, initialize passthrough mode, an anti-probing defense.
	// Clients must prove knowledge of the obfuscated key via a message sent in
	// the TLS ClientHello random field.
	//
	// When clients fail to provide a valid message, the client connection is
	// relayed to the designated passthrough address, typically another web site.
	// The entire flow is relayed, including the original ClientHello, so the
	// client will perform a TLS handshake with the passthrough target.
	//
	// Irregular events are logged for invalid client activity.

	if server.passthroughAddress != "" {

		config.PassthroughAddress = server.passthroughAddress

		config.PassthroughVerifyMessage = func(
			message []byte) bool {

			return obfuscator.VerifyTLSPassthroughMessage(
				!server.support.Config.LegacyPassthrough,
				server.support.Config.MeekObfuscatedKey,
				message)
		}

		config.PassthroughLogInvalidMessage = func(
			clientIP string) {

			logIrregularTunnel(
				server.support,
				server.listenerTunnelProtocol,
				server.listenerPort,
				clientIP,
				errors.TraceNew("invalid passthrough message"),
				nil)
		}

		config.PassthroughHistoryAddNew = func(
			clientIP string,
			clientRandom []byte) bool {

			// Use a custom, shorter TTL based on the validity period of the
			// passthrough message.
			TTL := obfuscator.TLS_PASSTHROUGH_HISTORY_TTL
			if server.support.Config.LegacyPassthrough {
				TTL = obfuscator.HISTORY_SEED_TTL
			}

			// strictMode is true as, unlike with meek cookies, legitimate meek clients
			// never retry TLS connections using a previous random value.

			ok, logFields := server.obfuscatorSeedHistory.AddNewWithTTL(
				true,
				clientIP,
				"client-random",
				clientRandom,
				TTL)

			if logFields != nil {
				logIrregularTunnel(
					server.support,
					server.listenerTunnelProtocol,
					server.listenerPort,
					clientIP,
					errors.TraceNew("duplicate passthrough message"),
					LogFields(*logFields))
			}

			return ok
		}
	}

	return config, nil
}

// makeMeekHTTPNormalizerListener returns the meek server listener wrapped in
// an HTTP normalizer.
func (server *MeekServer) makeMeekHTTPNormalizerListener() *transforms.HTTPNormalizerListener {

	normalizer := transforms.WrapListenerWithHTTPNormalizer(server.listener)

	normalizer.ProhibitedHeaders = server.support.Config.MeekProhibitedHeaders

	normalizer.MaxReqLineAndHeadersSize = 8192 // max number of header bytes common web servers will read before returning an error

	if server.passthroughAddress != "" {
		normalizer.PassthroughAddress = server.passthroughAddress
		normalizer.PassthroughDialer = net.Dial
	}
	normalizer.PassthroughLogPassthrough = func(
		clientIP string, tunnelError error, logFields map[string]interface{}) {

		logIrregularTunnel(
			server.support,
			server.listenerTunnelProtocol,
			server.listenerPort,
			clientIP,
			errors.Trace(tunnelError),
			logFields)
	}

	// ValidateMeekCookie is invoked by the normalizer with the value of the
	// cookie header (if present), before ServeHTTP gets the request and calls
	// getSessionOrEndpoint; and then any valid meek cookie payload, or meek
	// session ID, extracted in this callback is stored to be fetched by
	// getSessionOrEndpoint.
	// Note: if there are multiple cookie headers, even though prohibited by
	// rfc6265, then ValidateMeekCookie will only be invoked once with the
	// first one received.
	normalizer.ValidateMeekCookie = func(clientIP string, rawCookies []byte) ([]byte, error) {

		// Parse cookie.

		if len(rawCookies) == 0 {
			return nil, errors.TraceNew("no cookies")
		}

		// TODO/perf: readCookies in net/http is not exported, use a local
		// implementation which does not require allocating an http.header
		// each time.
		request := http.Request{
			Header: http.Header{
				"Cookie": []string{string(rawCookies)},
			},
		}
		cookies := request.Cookies()
		if len(rawCookies) == 0 {
			return nil, errors.Tracef("invalid cookies: %s", string(rawCookies))
		}

		// Use value of the first cookie.
		meekCookieValue := cookies[0].Value

		// Check for an existing session.

		server.sessionsLock.RLock()
		existingSessionID := meekCookieValue
		_, ok := server.sessions[existingSessionID]
		server.sessionsLock.RUnlock()
		if ok {
			// The cookie is a session ID for an active (not expired) session.
			// Return it and then it will be stored and later fetched by
			// getSessionOrEndpoint where it will be mapped to the existing
			// session.
			// Note: it's possible for the session to expire between this check
			// and when getSessionOrEndpoint looks up the session.
			return rawCookies, nil
		}

		// The session is new (or expired). Treat the cookie value as a new
		// meek cookie, extract the payload, and return it; and then it will be
		// stored and later fetched by getSessionOrEndpoint.

		payloadJSON, err := server.getMeekCookiePayload(clientIP, meekCookieValue)
		if err != nil {
			return nil, errors.Trace(err)
		}

		return payloadJSON, nil
	}

	return normalizer
}

func (server *MeekServer) inproxyReloadTactics() error {

	// Assumes no GeoIP targeting for InproxyAllCommonCompartmentIDs, in-proxy
	// quality configuration, and other general broker tactics.

	p, err := server.support.ServerTacticsParametersCache.Get(NewGeoIPData())
	if err != nil {
		return errors.Trace(err)
	}
	defer p.Close()
	if p.IsNil() {
		return nil
	}

	commonCompartmentIDs, err := inproxy.IDsFromStrings(
		p.Strings(parameters.InproxyAllCommonCompartmentIDs))
	if err != nil {
		return errors.Trace(err)
	}

	err = server.inproxyBroker.SetCommonCompartmentIDs(commonCompartmentIDs)
	if err != nil {
		return errors.Trace(err)
	}

	server.inproxyBroker.SetTimeouts(
		p.Duration(parameters.InproxyBrokerProxyAnnounceTimeout),
		p.Duration(parameters.InproxyBrokerClientOfferTimeout),
		p.Duration(parameters.InproxyBrokerClientOfferPersonalTimeout),
		p.Duration(parameters.InproxyBrokerPendingServerRequestsTTL),
		p.KeyDurations(parameters.InproxyFrontingProviderServerMaxRequestTimeouts))

	nonlimitedProxyIDs, err := inproxy.IDsFromStrings(
		p.Strings(parameters.InproxyBrokerMatcherAnnouncementNonlimitedProxyIDs))
	if err != nil {
		return errors.Trace(err)
	}
	server.inproxyBroker.SetLimits(
		p.Int(parameters.InproxyBrokerMatcherAnnouncementLimitEntryCount),
		p.Int(parameters.InproxyBrokerMatcherAnnouncementRateLimitQuantity),
		p.Duration(parameters.InproxyBrokerMatcherAnnouncementRateLimitInterval),
		nonlimitedProxyIDs,
		p.Int(parameters.InproxyBrokerMatcherOfferLimitEntryCount),
		p.Int(parameters.InproxyBrokerMatcherOfferRateLimitQuantity),
		p.Duration(parameters.InproxyBrokerMatcherOfferRateLimitInterval),
		p.Duration(parameters.InproxyBrokerMatcherOfferMinimumDeadline),
		p.Int(parameters.InproxyMaxCompartmentIDListLength),
		p.Int(parameters.InproxyBrokerDSLRequestRateLimitQuantity),
		p.Duration(parameters.InproxyBrokerDSLRequestRateLimitInterval))

	server.inproxyBroker.SetProxyQualityParameters(
		p.Bool(parameters.InproxyEnableProxyQuality),
		p.Duration(parameters.InproxyProxyQualityTTL),
		p.Duration(parameters.InproxyProxyQualityPendingFailedMatchDeadline),
		p.Int(parameters.InproxyProxyQualityFailedMatchThreshold))

	// Configure proxy/client match checklists.
	//
	// When an allow list is set, the client GeoIP data must appear in the
	// proxy's list or the match isn't allowed. When a disallow list is set,
	// the match isn't allowed if the client GeoIP data appears in the
	// proxy's list.

	makeCheckListLookup := func(
		lists map[string][]string,
		isAllowList bool) func(string, string) bool {

		if len(lists) == 0 {
			return func(string, string) bool {
				// Allow when no list
				return true
			}
		}
		lookup := make(map[string]map[string]struct{})
		for key, items := range lists {
			// TODO: use linear search for lists below stringLookupThreshold?
			itemLookup := make(map[string]struct{})
			for _, item := range items {
				itemLookup[item] = struct{}{}
			}
			lookup[key] = itemLookup
		}
		return func(key, item string) bool {
			itemLookup := lookup[key]
			if itemLookup == nil {
				// Allow when no list
				return true
			}
			_, found := itemLookup[item]
			// Allow or disallow based on list type
			return found == isAllowList
		}
	}

	inproxyCheckAllowMatchByRegion := makeCheckListLookup(p.KeyStringsValue(
		parameters.InproxyAllowMatchByRegion), true)
	inproxyCheckAllowMatchByASN := makeCheckListLookup(p.KeyStringsValue(
		parameters.InproxyAllowMatchByASN), true)
	inproxyCheckDisallowMatchByRegion := makeCheckListLookup(p.KeyStringsValue(
		parameters.InproxyDisallowMatchByRegion), false)
	inproxyCheckDisallowMatchByASN := makeCheckListLookup(p.KeyStringsValue(
		parameters.InproxyDisallowMatchByASN), false)

	checkAllowMatch := func(proxyGeoIPData, clientGeoIPData common.GeoIPData) bool {
		return inproxyCheckAllowMatchByRegion(proxyGeoIPData.Country, clientGeoIPData.Country) &&
			inproxyCheckAllowMatchByASN(proxyGeoIPData.ASN, clientGeoIPData.ASN) &&
			inproxyCheckDisallowMatchByRegion(proxyGeoIPData.Country, clientGeoIPData.Country) &&
			inproxyCheckDisallowMatchByASN(proxyGeoIPData.ASN, clientGeoIPData.ASN)
	}

	server.inproxyCheckAllowMatch.Store(checkAllowMatch)

	return nil
}

func (server *MeekServer) lookupAllowTactic(geoIPData common.GeoIPData, parameterName string) bool {

	// Fallback to not-allow on failure or nil tactics.
	p, err := server.support.ServerTacticsParametersCache.Get(GeoIPData(geoIPData))
	if err != nil {
		log.WithTraceFields(LogFields{"error": err}).Warning("ServerTacticsParametersCache.Get failed")
		return false
	}
	defer p.Close()
	if p.IsNil() {
		return false
	}
	return p.Bool(parameterName)
}

func (server *MeekServer) inproxyBrokerAllowProxy(proxyGeoIPData common.GeoIPData) bool {
	return server.lookupAllowTactic(proxyGeoIPData, parameters.InproxyAllowProxy)
}

func (server *MeekServer) inproxyBrokerAllowClient(clientGeoIPData common.GeoIPData) bool {
	return server.lookupAllowTactic(clientGeoIPData, parameters.InproxyAllowClient)
}

func (server *MeekServer) inproxyBrokerAllowDomainFrontedDestinations(clientGeoIPData common.GeoIPData) bool {
	return server.lookupAllowTactic(clientGeoIPData, parameters.InproxyAllowDomainFrontedDestinations)
}

func (server *MeekServer) inproxyBrokerAllowMatch(
	proxyGeoIPData common.GeoIPData, clientGeoIPData common.GeoIPData) bool {

	return server.inproxyCheckAllowMatch.Load().(func(proxy, client common.GeoIPData) bool)(
		proxyGeoIPData, clientGeoIPData)
}

func (server *MeekServer) inproxyBrokerPrioritizeProxy(
	proxyInproxyProtocolVersion int,
	proxyGeoIPData common.GeoIPData,
	proxyAPIParams common.APIParameters) bool {

	// Fallback to not-prioritized on failure or nil tactics.
	p, err := server.support.ServerTacticsParametersCache.Get(GeoIPData(proxyGeoIPData))
	if err != nil {
		log.WithTraceFields(LogFields{"error": err}).Warning("ServerTacticsParametersCache.Get failed")
		return false
	}
	defer p.Close()
	if p.IsNil() {
		return false
	}

	// As API parameter filtering currently does not support range matching, the minimum version
	// constraint is specified in a seperate parameter.
	minProtocolVersion := p.Int(parameters.InproxyBrokerMatcherPrioritizeProxiesMinVersion)
	if proxyInproxyProtocolVersion < minProtocolVersion {
		return false
	}

	filter := p.KeyStringsValue(parameters.InproxyBrokerMatcherPrioritizeProxiesFilter)
	if len(filter) == 0 {
		// When InproxyBrokerMatcherPrioritizeProxiesFilter is empty, the
		// default value, no proxies are prioritized.
		return false
	}
	for name, values := range filter {
		proxyValue, err := getStringRequestParam(proxyAPIParams, name)
		if err != nil || !common.ContainsWildcard(values, proxyValue) {
			return false
		}
	}

	if !p.WeightedCoinFlip(parameters.InproxyBrokerMatcherPrioritizeProxiesProbability) {
		return false
	}

	return true
}

// inproxyBrokerGetTacticsPayload is a callback used by the in-proxy broker to
// provide tactics to proxies.
//
// The proxy sends its current tactics tag in apiParameters, and, when there
// are new tactics, inproxyBrokerGetTacticsPayload returns the payload and the new
// tactics tag. The broker should log new_tactics_tag in its ProxyAnnounce
// handler.
func (server *MeekServer) inproxyBrokerGetTacticsPayload(
	geoIPData common.GeoIPData,
	apiParameters common.APIParameters) ([]byte, string, error) {

	// When compressed tactics are requested, use CBOR binary encoding for the
	// response.

	var responseMarshaler func(any) ([]byte, error)
	responseMarshaler = json.Marshal

	compressTactics := protocol.GetCompressTactics(apiParameters)

	if compressTactics {
		responseMarshaler = protocol.CBOREncoding.Marshal
	}

	tacticsPayload, err := server.support.TacticsServer.GetTacticsPayload(
		geoIPData, apiParameters, compressTactics)
	if err != nil {
		return nil, "", errors.Trace(err)
	}

	var marshaledTacticsPayload []byte
	newTacticsTag := ""

	if tacticsPayload != nil {

		marshaledTacticsPayload, err = responseMarshaler(tacticsPayload)
		if err != nil {
			return nil, "", errors.Trace(err)
		}

		if len(tacticsPayload.Tactics) > 0 {
			newTacticsTag = tacticsPayload.Tag
		}
	}

	return marshaledTacticsPayload, newTacticsTag, nil
}

// inproxyBrokerRelayDSLRequest is a callback used by the in-proxy broker to
// relay client DSL requests.
func (server *MeekServer) inproxyBrokerRelayDSLRequest(
	ctx context.Context,
	extendTimeout inproxy.ExtendTransportTimeout,
	clientIP string,
	clientGeoIPData common.GeoIPData,
	requestPayload []byte) ([]byte, error) {

	responsePayload, err := dslHandleRequest(
		ctx,
		server.support,
		extendTimeout,
		clientIP,
		clientGeoIPData,
		false, // client request is untunneled
		requestPayload)
	return responsePayload, errors.Trace(err)
}

// inproxyBrokerHandler reads an in-proxy broker session protocol message from
// the HTTP request body, dispatches the message to the broker, and writes
// the broker session response message to the HTTP response body.
//
// The HTTP response write timeout may be extended be the broker, as required.
// Error cases can return without writing any HTTP response. The caller
// should invoke server.handleError when an error is returned.
func (server *MeekServer) inproxyBrokerHandler(
	clientIP string,
	geoIPData common.GeoIPData,
	w http.ResponseWriter,
	r *http.Request) (retErr error) {

	// Don't read more than MEEK_ENDPOINT_MAX_REQUEST_PAYLOAD_LENGTH bytes, as
	// a sanity check and defense against potential resource exhaustion.
	packet, err := ioutil.ReadAll(http.MaxBytesReader(
		w, r.Body, MEEK_ENDPOINT_MAX_REQUEST_PAYLOAD_LENGTH))
	if err != nil {
		return errors.Trace(err)
	}

	extendTimeout := func(timeout time.Duration) {

		// Extend the HTTP response write timeout to accomodate the timeout
		// specified by the broker, such as in the case of the ProxyAnnounce
		// request long poll. The base httpClientIOTimeout value is added, as
		// it covers HTTP transport network operations, which are not
		// necessarily included in the broker's timeouts.
		//
		// Note that any existing write timeout of httpClientIOTimeout would
		// have been set before the body read, which may have consumed time,
		// so adding the full httpClientIOTimeout value again may exceed the
		// original httpClientIOTimeout target.

		http.NewResponseController(w).SetWriteDeadline(
			time.Now().Add(server.httpClientIOTimeout + timeout))
	}

	// Per https://pkg.go.dev/net/http#Request.Context, the request context is
	// canceled when the client's connection closes or an HTTP/2 request is
	// canceled. So it is expected that the broker operation will abort and
	// stop waiting (in the case of long polling) if the client disconnects
	// for any reason before a response is sent.
	//
	// When fronted by a CDN using persistent connections used to multiplex
	// many clients, it is expected that CDNs will perform an HTTP/3 request
	// cancellation in this scenario.

	transportLogFields := common.LogFields{
		"meek_server_http_version": r.Proto,
	}

	packet, err = server.inproxyBroker.HandleSessionPacket(
		r.Context(),
		extendTimeout,
		transportLogFields,
		clientIP,
		geoIPData,
		packet)
	if err != nil {

		var deobfuscationAnomoly *inproxy.DeobfuscationAnomoly
		isAnomolous := std_errors.As(err, &deobfuscationAnomoly)
		if isAnomolous {
			logIrregularTunnel(
				server.support,
				server.listenerTunnelProtocol,
				server.listenerPort,
				clientIP,
				errors.Trace(err),
				nil)
		}

		return errors.Trace(err)
	}

	w.WriteHeader(http.StatusOK)
	_, err = w.Write(packet)
	if err != nil {
		return errors.Trace(err)
	}

	return nil
}

type meekSession struct {
	lastActivity                     atomic.Int64
	requestCount                     atomic.Int64
	metricClientRetries              atomic.Int64
	metricPeakResponseSize           atomic.Int64
	metricPeakCachedResponseSize     atomic.Int64
	metricPeakCachedResponseHitSize  atomic.Int64
	metricCachedResponseMissPosition atomic.Int64
	metricUnderlyingConnCount        atomic.Int64
	lock                             sync.Mutex
	deleted                          bool
	underlyingConn                   net.Conn
	clientConn                       *meekConn
	meekProtocolVersion              int
	sessionIDSent                    bool
	cachedResponse                   *CachedResponse
	cookieName                       string
	contentType                      string
	httpVersion                      string
	requestPaddingState              *protocol.MeekPayloadPaddingState
	responsePaddingState             *protocol.MeekPayloadPaddingState
}

func (session *meekSession) touch() {
	session.lastActivity.Store(int64(monotime.Now()))
}

func (session *meekSession) expired() bool {
	if session.clientConn == nil {
		// Not fully initialized. meekSession.clientConn will be set before adding
		// the session to MeekServer.sessions.
		return false
	}
	lastActivity := monotime.Time(session.lastActivity.Load())
	return monotime.Since(lastActivity) >
		session.clientConn.meekServer.maxSessionStaleness
}

// delete releases all resources allocated by a session.
func (session *meekSession) delete(haveLock bool) {

	// TODO: close the persistent HTTP client connection, if one exists?

	// This final call session.cachedResponse.Reset releases shared resources.
	//
	// This call requires exclusive access. session.lock is be obtained before
	// calling session.cachedResponse.Reset. Once the lock is obtained, no
	// request for this session is being processed concurrently, and pending
	// requests will block at session.lock.
	//
	// This logic assumes that no further session.cachedResponse access occurs,
	// or else resources may deplete (buffers won't be returned to the pool).
	// These requirements are achieved by obtaining the lock, setting
	// session.deleted, and any subsequent request handlers checking
	// session.deleted immediately after obtaining the lock.
	//
	// session.lock.Lock may block for up to MEEK_HTTP_CLIENT_IO_TIMEOUT,
	// the timeout for any active request handler processing a session
	// request.
	//
	// When the lock must be acquired, clientConn.Close is called first, to
	// interrupt any existing request handler blocking on pumpReads or pumpWrites.

	session.clientConn.Close()

	if !haveLock {
		session.lock.Lock()
	}

	// Release all extended buffers back to the pool.
	// session.cachedResponse.Reset is not safe for concurrent calls.
	session.cachedResponse.Reset()

	session.deleted = true

	if !haveLock {
		session.lock.Unlock()
	}
}

// GetMetrics implements the common.MetricsSource interface.
func (session *meekSession) GetMetrics() common.LogFields {
	logFields := make(common.LogFields)
	logFields["meek_client_retries"] = session.metricClientRetries.Load()
	logFields["meek_peak_response_size"] = session.metricPeakResponseSize.Load()
	logFields["meek_peak_cached_response_size"] = session.metricPeakCachedResponseSize.Load()
	logFields["meek_peak_cached_response_hit_size"] = session.metricPeakCachedResponseHitSize.Load()
	logFields["meek_cached_response_miss_position"] = session.metricCachedResponseMissPosition.Load()
	logFields["meek_underlying_connection_count"] = session.metricUnderlyingConnCount.Load()
	logFields["meek_cookie_name"] = session.cookieName
	logFields["meek_content_type"] = session.contentType
	logFields["meek_server_http_version"] = session.httpVersion
	logFields["meek_payload_padding"] =
		session.requestPaddingState != nil || session.responsePaddingState != nil
	return logFields
}

// makeMeekSessionID creates a new session ID. The variable size is intended to
// frustrate traffic analysis of both plaintext and TLS meek traffic.
func makeMeekSessionID() (string, error) {

	size := MEEK_MIN_SESSION_ID_LENGTH +
		prng.Intn(MEEK_MAX_SESSION_ID_LENGTH-MEEK_MIN_SESSION_ID_LENGTH)

	sessionID, err := common.MakeSecureRandomBytes(size)
	if err != nil {
		return "", errors.Trace(err)
	}

	// Omit padding to maximize variable size space. To the client, the session
	// ID is an opaque string cookie value.

	return base64.RawStdEncoding.EncodeToString(sessionID), nil
}

// meekConn implements the net.Conn interface and is to be used as a client
// connection by the tunnel server (being passed to sshServer.handleClient).
// meekConn bridges net/http request/response payload readers and writers
// and goroutines calling Read()s and Write()s.
type meekConn struct {
	meekServer          *MeekServer
	meekSession         *meekSession
	firstUnderlyingConn net.Conn
	remoteAddr          net.Addr
	protocolVersion     int
	closeBroadcast      chan struct{}
	closed              int32
	lastReadChecksum    *uint64
	readLock            sync.Mutex
	emptyReadBuffer     chan *bytes.Buffer
	partialReadBuffer   chan *bytes.Buffer
	fullReadBuffer      chan *bytes.Buffer
	writeLock           sync.Mutex
	nextWriteBuffer     chan []byte
	writeResult         chan error
}

func newMeekConn(
	meekServer *MeekServer,
	meekSession *meekSession,
	underlyingConn net.Conn,
	remoteAddr net.Addr,
	protocolVersion int) *meekConn {

	// In order to inspect its properties, meekConn will hold a reference to
	// firstUnderlyingConn, the _first_ underlying TCP conn, for the full
	// lifetime of meekConn, which may exceed the lifetime of firstUnderlyingConn
	// and include subsequent underlying TCP conns. In this case, it is expected
	// that firstUnderlyingConn will be closed by "net/http", so no OS resources
	// (e.g., a socket) are retained longer than necessary.

	conn := &meekConn{
		meekServer:          meekServer,
		meekSession:         meekSession,
		firstUnderlyingConn: underlyingConn,
		remoteAddr:          remoteAddr,
		protocolVersion:     protocolVersion,
		closeBroadcast:      make(chan struct{}),
		closed:              0,
		emptyReadBuffer:     make(chan *bytes.Buffer, 1),
		partialReadBuffer:   make(chan *bytes.Buffer, 1),
		fullReadBuffer:      make(chan *bytes.Buffer, 1),
		nextWriteBuffer:     make(chan []byte, 1),
		writeResult:         make(chan error, 1),
	}
	// Read() calls and pumpReads() are synchronized by exchanging control
	// of a single readBuffer. This is the same scheme used in and described
	// in psiphon.MeekConn.
	conn.emptyReadBuffer <- new(bytes.Buffer)
	return conn
}

// GetMetrics implements the common.MetricsSource interface. The metrics are
// maintained in the meek session type; but logTunnel, which calls
// MetricsSource.GetMetrics, has a pointer only to this conn, so it calls
// through to the session.
func (conn *meekConn) GetMetrics() common.LogFields {

	logFields := conn.meekSession.GetMetrics()

	if conn.meekServer.passthroughAddress != "" {
		logFields["passthrough_address"] = conn.meekServer.passthroughAddress
	}

	// Include metrics, such as fragmentor metrics, from the _first_ underlying
	// TCP conn. Properties of subsequent underlying TCP conns are not reflected
	// in these metrics; we assume that the first TCP conn, which most likely
	// transits the various protocol handshakes, is most significant.
	underlyingMetrics, ok := conn.firstUnderlyingConn.(common.MetricsSource)
	if ok {
		logFields.Add(underlyingMetrics.GetMetrics())
	}

	return logFields
}

// GetUnderlyingTCPAddrs implements the common.UnderlyingTCPAddrSource
// interface, returning the TCP addresses for the _first_ underlying TCP
// connection in the meek tunnel.
func (conn *meekConn) GetUnderlyingTCPAddrs() (*net.TCPAddr, *net.TCPAddr, bool) {
	localAddr, ok := conn.firstUnderlyingConn.LocalAddr().(*net.TCPAddr)
	if !ok {
		return nil, nil, false
	}
	remoteAddr, ok := conn.firstUnderlyingConn.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return nil, nil, false
	}
	return localAddr, remoteAddr, true
}

// SetReplay implements the common.FragmentorReplayAccessor interface, applying
// the inputs to the _first_ underlying TCP connection in the meek tunnel. If
// the underlying connection is closed, then SetSeed call will have no effect.
func (conn *meekConn) SetReplay(PRNG *prng.PRNG) {
	underlyingConn := conn.firstUnderlyingConn

	if conn.meekServer.normalizer != nil {
		// The underlying conn is wrapped with a normalizer.
		normalizer, ok := underlyingConn.(*transforms.HTTPNormalizer)
		if ok {
			underlyingConn = normalizer.Conn
		}
	}

	fragmentor, ok := underlyingConn.(common.FragmentorAccessor)
	if ok {
		fragmentor.SetReplay(PRNG)
	}
}

// GetReplay implements the FragmentorReplayAccessor interface, getting the
// outputs from the _first_ underlying TCP connection in the meek tunnel.
//
// We assume that the first TCP conn is most significant: the initial TCP
// connection most likely fragments protocol handshakes; and, in the case the
// packet manipulation, any selected packet manipulation spec would have been
// successful.
func (conn *meekConn) GetReplay() (*prng.Seed, bool) {
	underlyingConn := conn.firstUnderlyingConn

	if conn.meekServer.normalizer != nil {
		// The underlying conn is wrapped with a normalizer.
		normalizer, ok := underlyingConn.(*transforms.HTTPNormalizer)
		if ok {
			underlyingConn = normalizer.Conn
		}
	}

	fragmentor, ok := underlyingConn.(common.FragmentorAccessor)
	if ok {
		return fragmentor.GetReplay()
	}
	return nil, false
}

func (conn *meekConn) StopFragmenting() {
	fragmentor, ok := conn.firstUnderlyingConn.(common.FragmentorAccessor)
	if ok {
		fragmentor.StopFragmenting()
	}
}

// pumpReads causes goroutines blocking on meekConn.Read() to read
// from the specified reader. This function blocks until the reader
// is fully consumed or the meekConn is closed. A read buffer allows
// up to MEEK_MAX_REQUEST_PAYLOAD_LENGTH bytes to be read and buffered
// without a Read() immediately consuming the bytes, but there's still
// a possibility of a stall if no Read() calls are made after this
// read buffer is full.
//
// Returns the number of request bytes read, excluding any payload padding
// bytes, and whether an existing cached response _may_ be safely used for
// this request.
//
// It's safe to use cached response if the request body is a duplicate,
// ambiguous when the request body is empty with no padding, and not safe
// when the request body is not a duplicate. pumpReads returns true in the
// first two cases.
//
// Note: assumes only one concurrent call to pumpReads
func (conn *meekConn) pumpReads(reader io.Reader) (int64, bool, error) {

	// Use either an empty or partial buffer. By using a partial
	// buffer, pumpReads will not block if the Read() caller has
	// not fully drained the read buffer.

	var readBuffer *bytes.Buffer
	select {
	case readBuffer = <-conn.emptyReadBuffer:
	case readBuffer = <-conn.partialReadBuffer:
	case <-conn.closeBroadcast:
		return 0, false, io.EOF
	}

	newDataOffset := readBuffer.Len()

	// Since we need to read the full request payload in order to
	// take its checksum before relaying it, the read buffer can
	// grow to up to 2 x MEEK_MAX_REQUEST_PAYLOAD_LENGTH + 1.

	// +1 allows for an explicit check for request payloads that
	// exceed the maximum permitted length.
	reader = io.LimitReader(reader, MEEK_MAX_REQUEST_PAYLOAD_LENGTH+1)

	checksumWriter := crc64nvme.New()
	reader = io.TeeReader(reader, checksumWriter)

	n, err := readBuffer.ReadFrom(reader)
	if err == nil && n == MEEK_MAX_REQUEST_PAYLOAD_LENGTH+1 {
		err = std_errors.New("invalid request payload length")
	}

	// If the request read fails, don't relay the new data. This allows
	// the client to retry and resend its request payload without
	// interrupting/duplicating the payload flow.
	//
	// Also return early here, and don't update the retry checksum, when an
	// empty payload is read. In some retry cases, the client will skip
	// resending the payload when it knows the server received it. In payload
	// padding mode, this handles the case when padding is omitted for an
	// empty payload.

	if err != nil {
		readBuffer.Truncate(newDataOffset)
		conn.replaceReadBuffer(readBuffer)
		return 0, false, errors.Trace(err)
	}

	if n == 0 {
		readBuffer.Truncate(newDataOffset)
		conn.replaceReadBuffer(readBuffer)
		return 0, true, nil
	}

	// Check if request payload checksum matches immediately
	// previous payload. On match, assume this is a client retry
	// sending payload that was already relayed and skip this
	// payload. Payload is OSSH ciphertext and almost surely
	// will not repeat. In the highly unlikely case that it does,
	// the underlying SSH connection will fail and the client
	// must reconnect.
	//
	// In payload padding mode, any padding -- prefix, header, padding
	// itself -- is treated as part of the payload checksum; client retries
	// will resend the same padding.

	checksum := checksumWriter.Sum64()

	if conn.lastReadChecksum == nil {
		conn.lastReadChecksum = new(uint64)
	} else if *conn.lastReadChecksum == checksum {
		readBuffer.Truncate(newDataOffset)
		conn.replaceReadBuffer(readBuffer)
		return 0, true, nil
	}

	*conn.lastReadChecksum = checksum

	paddingBytesRead := int64(0)

	if conn.meekSession.requestPaddingState != nil {

		// In payload padding mode, any non empty request body is expected to
		// have a padding prefix and possibly a full padding header with
		// padding itself.
		//
		// At this point, the request body has been fully read without error,
		// and any client retry repeats of the same request body have been
		// skipped. The ReceiverConsumePadding call will unconditionally
		// advance the padding cipher stream state, and no short reads
		// (ErrMeekPaddingStateImmediateEOF) are expected.

		var paddingReader io.Reader
		if newDataOffset == 0 {

			// Fast path: ReceiverConsumePadding consumes from the start of
			// readBuffer.

			paddingReader = readBuffer
		} else {

			// Slower path: the new payload has been appended to a non-empty
			// readBuffer, so ReceiverConsumePadding will consume from the
			// middle of the readBuffer and the post-padding bytes will be
			// shifted forward. This approach doesn't require any additional
			// buffer allocations.

			paddingReader = bytes.NewReader(readBuffer.Bytes()[newDataOffset:])
		}

		paddingBytesRead, _, err = conn.meekSession.requestPaddingState.
			ReceiverConsumePadding(paddingReader)
		if paddingBytesRead > n {
			err = errors.TraceNew("unexpected padding bytes read")
		}
		if err != nil {
			readBuffer.Truncate(newDataOffset)
			conn.replaceReadBuffer(readBuffer)
			return 0, false, errors.Trace(err)
		}

		// Return only the actual payload size read, which is important for
		// caller's skipExtendedTurnAround heuristic.
		n -= paddingBytesRead

		if newDataOffset > 0 {
			// TODO: shift in the other direction, pre-newDataOffset forward,
			// if that's fewer bytes?
			buf := readBuffer.Bytes()
			bufLen := readBuffer.Len()
			paddingSize := bufLen - newDataOffset - paddingReader.(*bytes.Reader).Len()
			copy(buf[newDataOffset:],
				buf[newDataOffset+paddingSize:])
			readBuffer.Truncate(bufLen - paddingSize)
		}
	}

	conn.replaceReadBuffer(readBuffer)

	return n, false, nil
}

var errMeekConnectionHasClosed = std_errors.New("meek connection has closed")

// Read reads from the meekConn into buffer. Read blocks until
// some data is read or the meekConn closes. Under the hood, it
// waits for pumpReads to submit a reader to read from.
// Note: lock is to conform with net.Conn concurrency semantics
func (conn *meekConn) Read(buffer []byte) (int, error) {
	conn.readLock.Lock()
	defer conn.readLock.Unlock()

	var readBuffer *bytes.Buffer
	select {
	case readBuffer = <-conn.partialReadBuffer:
	case readBuffer = <-conn.fullReadBuffer:
	case <-conn.closeBroadcast:
		return 0, errors.Trace(errMeekConnectionHasClosed)
	}

	n, err := readBuffer.Read(buffer)

	conn.replaceReadBuffer(readBuffer)

	return n, err
}

func (conn *meekConn) replaceReadBuffer(readBuffer *bytes.Buffer) {
	length := readBuffer.Len()
	if length >= MEEK_MAX_REQUEST_PAYLOAD_LENGTH {
		conn.fullReadBuffer <- readBuffer
	} else if length == 0 {
		conn.emptyReadBuffer <- readBuffer
	} else {
		conn.partialReadBuffer <- readBuffer
	}
}

// pumpWrites causes goroutines blocking on meekConn.Write() to write
// to the specified writer. This function blocks until the meek response
// body limits (size for protocol v1, turn around time for protocol v2+)
// are met, or the meekConn is closed.
//
// Note: channel scheme assumes only one concurrent call to pumpWrites
func (conn *meekConn) pumpWrites(
	writer io.Writer, skipExtendedTurnAround bool) (int, error) {

	startTime := time.Now()
	timeout := time.NewTimer(conn.meekServer.turnAroundTimeout)
	defer timeout.Stop()

	n := 0
	for {
		select {
		case buffer := <-conn.nextWriteBuffer:

			if conn.meekSession.responsePaddingState != nil && n == 0 {

				// When in payload padding mode, every payload has an initial padding
				// prefix. In this case, receiving nextWriteBuffer implies
				// there are payload bytes, so the prefix indicates no padding.

				paddingHeader, err := conn.meekSession.responsePaddingState.
					SenderGetNextPadding(false)
				if err == nil {
					var written int
					written, err = writer.Write(paddingHeader)
					n += written
				}
				if err != nil {
					err = errors.Trace(err)
					// See "always send" comment below.
					conn.writeResult <- err
					return n, err
				}
			}

			written, err := writer.Write(buffer)
			n += written
			// Assumes that writeResult won't block.
			// Note: always send the err to writeResult,
			// as the Write() caller is blocking on this.
			err = errors.Trace(err)
			conn.writeResult <- err
			if err != nil {
				return n, err
			}

			if conn.protocolVersion < MEEK_PROTOCOL_VERSION_1 {
				// Pre-protocol version 1 clients expect at most
				// MEEK_MAX_REQUEST_PAYLOAD_LENGTH response bodies
				return n, nil
			}

			if skipExtendedTurnAround {
				// When fast turn around is indicated, skip the extended turn
				// around timeout. This optimizes for upstream flows.
				return n, nil
			}

			totalElapsedTime := time.Since(startTime) / time.Millisecond
			if totalElapsedTime >= conn.meekServer.extendedTurnAroundTimeout {
				return n, nil
			}
			timeout.Reset(conn.meekServer.turnAroundTimeout)

		case <-timeout.C:

			if conn.meekSession.responsePaddingState != nil && n == 0 {

				// When in payload padding mode, and there's no payload, add padding.

				paddingHeader, err := conn.meekSession.responsePaddingState.
					SenderGetNextPadding(true)
				if err != nil {
					return n, errors.Trace(err)
				}

				if len(paddingHeader) > 0 {
					written, err := writer.Write(paddingHeader)
					n += written
					if err != nil {
						return n, errors.Trace(err)
					}
				}
			}

			return n, nil

		case <-conn.closeBroadcast:
			return n, errors.Trace(errMeekConnectionHasClosed)
		}
	}
}

// Write writes the buffer to the meekConn. It blocks until the
// entire buffer is written to or the meekConn closes. Under the
// hood, it waits for sufficient pumpWrites calls to consume the
// write buffer.
// Note: lock is to conform with net.Conn concurrency semantics
func (conn *meekConn) Write(buffer []byte) (int, error) {
	conn.writeLock.Lock()
	defer conn.writeLock.Unlock()

	// TODO: may be more efficient to send whole buffer
	// and have pumpWrites stash partial buffer when can't
	// send it all.

	n := 0
	for n < len(buffer) {
		end := n + MEEK_MAX_REQUEST_PAYLOAD_LENGTH
		if end > len(buffer) {
			end = len(buffer)
		}

		// Only write MEEK_MAX_REQUEST_PAYLOAD_LENGTH at a time,
		// to ensure compatibility with v1 protocol.
		chunk := buffer[n:end]

		select {
		case conn.nextWriteBuffer <- chunk:
		case <-conn.closeBroadcast:
			return n, errors.Trace(errMeekConnectionHasClosed)
		}

		// Wait for the buffer to be processed.
		select {
		case <-conn.writeResult:
			// The err from conn.writeResult comes from the
			// io.MultiWriter used in pumpWrites, which writes
			// to both the cached response and the HTTP response.
			//
			// Don't stop on error here, since only writing
			// to the HTTP response will fail, and the client
			// may retry and use the cached response.
			//
			// It's possible that the cached response buffer
			// is too small for the client to successfully
			// retry, but that cannot be determined. In this
			// case, the meek connection will eventually fail.
			//
			// err is already logged in ServeHTTP.
		case <-conn.closeBroadcast:
			return n, errors.Trace(errMeekConnectionHasClosed)
		}
		n += len(chunk)
	}
	return n, nil
}

// Close closes the meekConn. This will interrupt any blocked
// Read, Write, pumpReads, and pumpWrites.
func (conn *meekConn) Close() error {
	if atomic.CompareAndSwapInt32(&conn.closed, 0, 1) {
		close(conn.closeBroadcast)

		// In general, we rely on "net/http" to close underlying TCP conns. In
		// this case, we can directly close the first once, if it's still
		// open. Don't close a persistent connection when fronted, as it may
		// be still be used by other clients.
		if !conn.meekServer.isFronted {
			conn.firstUnderlyingConn.Close()
		}
	}
	return nil
}

// Stub implementation of net.Conn.LocalAddr
func (conn *meekConn) LocalAddr() net.Addr {
	return nil
}

// RemoteAddr returns the remoteAddr specified in newMeekConn. This
// acts as a proxy for the actual remote address, which is either a
// direct HTTP/HTTPS connection remote address, or in the case of
// downstream proxy of CDN fronts, some other value determined via
// HTTP headers.
func (conn *meekConn) RemoteAddr() net.Addr {
	return conn.remoteAddr
}

// SetDeadline is not a true implementation of net.Conn.SetDeadline. It
// merely checks that the requested timeout exceeds the MEEK_MAX_SESSION_STALENESS
// period. When it does, and the session is idle, the meekConn Read/Write will
// be interrupted and return an error (not a timeout error) before the deadline.
// In other words, this conn will approximate the desired functionality of
// timing out on idle on or before the requested deadline.
func (conn *meekConn) SetDeadline(t time.Time) error {
	// Overhead: nanoseconds (https://blog.cloudflare.com/its-go-time-on-linux/)
	if time.Now().Add(conn.meekServer.maxSessionStaleness).Before(t) {
		return nil
	}
	return errors.TraceNew("not supported")
}

// Stub implementation of net.Conn.SetReadDeadline
func (conn *meekConn) SetReadDeadline(t time.Time) error {
	return errors.TraceNew("not supported")
}

// Stub implementation of net.Conn.SetWriteDeadline
func (conn *meekConn) SetWriteDeadline(t time.Time) error {
	return errors.TraceNew("not supported")
}
