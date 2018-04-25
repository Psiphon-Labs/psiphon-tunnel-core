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
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"hash/crc64"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Psiphon-Inc/goarista/monotime"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/crypto/nacl/box"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	utls "github.com/Psiphon-Labs/utls"
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

	MEEK_MAX_REQUEST_PAYLOAD_LENGTH     = 65536
	MEEK_TURN_AROUND_TIMEOUT            = 20 * time.Millisecond
	MEEK_EXTENDED_TURN_AROUND_TIMEOUT   = 100 * time.Millisecond
	MEEK_MAX_SESSION_STALENESS          = 45 * time.Second
	MEEK_HTTP_CLIENT_IO_TIMEOUT         = 45 * time.Second
	MEEK_MIN_SESSION_ID_LENGTH          = 8
	MEEK_MAX_SESSION_ID_LENGTH          = 20
	MEEK_DEFAULT_RESPONSE_BUFFER_LENGTH = 65536
	MEEK_DEFAULT_POOL_BUFFER_LENGTH     = 65536
	MEEK_DEFAULT_POOL_BUFFER_COUNT      = 2048
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
	support       *SupportServices
	listener      net.Listener
	tlsConfig     *utls.Config
	clientHandler func(clientTunnelProtocol string, clientConn net.Conn)
	openConns     *common.Conns
	stopBroadcast <-chan struct{}
	sessionsLock  sync.RWMutex
	sessions      map[string]*meekSession
	checksumTable *crc64.Table
	bufferPool    *CachedResponseBufferPool
}

// NewMeekServer initializes a new meek server.
func NewMeekServer(
	support *SupportServices,
	listener net.Listener,
	useTLS, useObfuscatedSessionTickets bool,
	clientHandler func(clientTunnelProtocol string, clientConn net.Conn),
	stopBroadcast <-chan struct{}) (*MeekServer, error) {

	checksumTable := crc64.MakeTable(crc64.ECMA)

	bufferLength := MEEK_DEFAULT_POOL_BUFFER_LENGTH
	if support.Config.MeekCachedResponsePoolBufferSize != 0 {
		bufferLength = support.Config.MeekCachedResponsePoolBufferSize
	}

	bufferCount := MEEK_DEFAULT_POOL_BUFFER_COUNT
	if support.Config.MeekCachedResponsePoolBufferCount != 0 {
		bufferCount = support.Config.MeekCachedResponsePoolBufferCount
	}

	bufferPool := NewCachedResponseBufferPool(bufferLength, bufferCount)

	meekServer := &MeekServer{
		support:       support,
		listener:      listener,
		clientHandler: clientHandler,
		openConns:     new(common.Conns),
		stopBroadcast: stopBroadcast,
		sessions:      make(map[string]*meekSession),
		checksumTable: checksumTable,
		bufferPool:    bufferPool,
	}

	if useTLS {
		tlsConfig, err := makeMeekTLSConfig(
			support, useObfuscatedSessionTickets)
		if err != nil {
			return nil, common.ContextError(err)
		}
		meekServer.tlsConfig = tlsConfig
	}

	return meekServer, nil
}

// Run runs the meek server; this function blocks while serving HTTP or
// HTTPS connections on the specified listener. This function also runs
// a goroutine which cleans up expired meek client sessions.
//
// To stop the meek server, both Close() the listener and set the stopBroadcast
// signal specified in NewMeekServer.
func (server *MeekServer) Run() error {

	// Expire sessions

	reaperWaitGroup := new(sync.WaitGroup)
	reaperWaitGroup.Add(1)
	go func() {
		defer reaperWaitGroup.Done()
		ticker := time.NewTicker(MEEK_MAX_SESSION_STALENESS / 2)
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

	// Serve HTTP or HTTPS

	// Notes:
	// - WriteTimeout may include time awaiting request, as per:
	//   https://blog.cloudflare.com/the-complete-guide-to-golang-net-http-timeouts
	// - Legacy meek-server wrapped each client HTTP connection with an explicit idle
	//   timeout net.Conn and didn't use http.Server timeouts. We could do the same
	//   here (use ActivityMonitoredConn) but the stock http.Server timeouts should
	//   now be sufficient.

	httpServer := &http.Server{
		ReadTimeout:  MEEK_HTTP_CLIENT_IO_TIMEOUT,
		WriteTimeout: MEEK_HTTP_CLIENT_IO_TIMEOUT,
		Handler:      server,
		ConnState:    server.httpConnStateCallback,

		// Disable auto HTTP/2 (https://golang.org/doc/go1.6)
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}

	// Note: Serve() will be interrupted by listener.Close() call
	var err error
	if server.tlsConfig != nil {
		httpsServer := HTTPSServer{Server: httpServer}
		err = httpsServer.ServeTLS(server.listener, server.tlsConfig)
	} else {
		err = httpServer.Serve(server.listener)
	}

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

	reaperWaitGroup.Wait()

	return err
}

// ServeHTTP handles meek client HTTP requests, where the request body
// contains upstream traffic and the response will contain downstream
// traffic.
func (server *MeekServer) ServeHTTP(responseWriter http.ResponseWriter, request *http.Request) {

	// Note: no longer requiring that the request method is POST

	// Check for the expected meek/session ID cookie.
	// Also check for prohibited HTTP headers.

	var meekCookie *http.Cookie
	for _, c := range request.Cookies() {
		meekCookie = c
		break
	}
	if meekCookie == nil || len(meekCookie.Value) == 0 {
		log.WithContext().Warning("missing meek cookie")
		server.terminateConnection(responseWriter, request)
		return
	}

	if len(server.support.Config.MeekProhibitedHeaders) > 0 {
		for _, header := range server.support.Config.MeekProhibitedHeaders {
			value := request.Header.Get(header)
			if header != "" {
				log.WithContextFields(LogFields{
					"header": header,
					"value":  value,
				}).Warning("prohibited meek header")
				server.terminateConnection(responseWriter, request)
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

	sessionID, session, endPoint, clientIP, err := server.getSessionOrEndpoint(request, meekCookie)
	if err != nil {
		// Debug since session cookie errors commonly occur during
		// normal operation.
		log.WithContextFields(LogFields{"error": err}).Debug("session lookup failed")
		server.terminateConnection(responseWriter, request)
		return
	}

	if endPoint != "" {

		// Endpoint mode. Currently, this means it's handled by the tactics
		// request handler.

		geoIPData := server.support.GeoIPService.Lookup(clientIP)
		handled := server.support.TacticsServer.HandleEndPoint(
			endPoint, common.GeoIPData(geoIPData), responseWriter, request)
		if !handled {
			log.WithContextFields(LogFields{"endPoint": endPoint}).Info("unhandled endpoint")
			server.terminateConnection(responseWriter, request)
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

	requestNumber := atomic.AddInt64(&session.requestCount, 1)

	// Wait for the existing request to complete.
	session.lock.Lock()
	defer session.lock.Unlock()

	// If a newer request has arrived while waiting, discard this one.
	// Do not delay processing the newest request.
	//
	// If the session expired and was deleted while this request was waiting,
	// discard this request. The session is no longer valid, and the final call
	// to session.cachedResponse.Reset may have already occured, so any further
	// session.cachedResponse access may deplete resources (fail to refill the pool).
	if atomic.LoadInt64(&session.requestCount) > requestNumber || session.deleted {
		server.terminateConnection(responseWriter, request)
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

	err = session.clientConn.pumpReads(request.Body)
	if err != nil {
		if err != io.EOF {
			// Debug since errors such as "i/o timeout" occur during normal operation;
			// also, golang network error messages may contain client IP.
			log.WithContextFields(LogFields{"error": err}).Debug("read request failed")
		}
		server.terminateConnection(responseWriter, request)

		// Note: keep session open to allow client to retry

		return
	}

	// Set cookie before writing the response.

	if session.meekProtocolVersion >= MEEK_PROTOCOL_VERSION_2 && session.sessionIDSent == false {
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
		atomic.AddInt64(&session.metricClientRetries, 1)
	}

	hasCompleteCachedResponse := session.cachedResponse.HasPosition(0)

	// The client is not expected to send position > 0 when there is
	// no cached response; let that case fall through to the next
	// HasPosition check which will fail and close the session.

	var responseSize int
	var responseError error

	if isRetry && (hasCompleteCachedResponse || position > 0) {

		if !session.cachedResponse.HasPosition(position) {
			greaterThanSwapInt64(&session.metricCachedResponseMissPosition, int64(position))
			server.terminateConnection(responseWriter, request)
			session.delete(true)
			return
		}

		responseWriter.WriteHeader(http.StatusPartialContent)

		// TODO:
		// - enforce a max extended buffer count per client, for
		//   fairness? Throttling may make this unnecessary.
		// - cachedResponse can now start releasing extended buffers,
		//   as response bytes before "position" will never be requested
		//   again?

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

		responseSize, responseError = session.clientConn.pumpWrites(multiWriter)
		greaterThanSwapInt64(&session.metricPeakResponseSize, int64(responseSize))
		greaterThanSwapInt64(&session.metricPeakCachedResponseSize, int64(session.cachedResponse.Available()))
	}

	// responseError is the result of writing the body either from CopyFromPosition or pumpWrites
	if responseError != nil {
		if responseError != io.EOF {
			// Debug since errors such as "i/o timeout" occur during normal operation;
			// also, golang network error messages may contain client IP.
			log.WithContextFields(LogFields{"error": responseError}).Debug("write response failed")
		}
		server.terminateConnection(responseWriter, request)

		// Note: keep session open to allow client to retry

		return
	}
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
func (server *MeekServer) getSessionOrEndpoint(
	request *http.Request, meekCookie *http.Cookie) (string, *meekSession, string, string, error) {

	// Check for an existing session

	server.sessionsLock.RLock()
	existingSessionID := meekCookie.Value
	session, ok := server.sessions[existingSessionID]
	server.sessionsLock.RUnlock()
	if ok {
		session.touch()
		return existingSessionID, session, "", "", nil
	}

	// TODO: can multiple http client connections using same session cookie
	// cause race conditions on session struct?

	// The session is new (or expired). Treat the cookie value as a new meek
	// cookie, extract the payload, and create a new session.

	payloadJSON, err := getMeekCookiePayload(server.support, meekCookie.Value)
	if err != nil {
		return "", nil, "", "", common.ContextError(err)
	}

	// Note: this meek server ignores legacy values PsiphonClientSessionId
	// and PsiphonServerAddress.
	var clientSessionData protocol.MeekCookieData

	err = json.Unmarshal(payloadJSON, &clientSessionData)
	if err != nil {
		return "", nil, "", "", common.ContextError(err)
	}

	// Determine the client remote address, which is used for geolocation
	// and stats. When an intermediate proxy or CDN is in use, we may be
	// able to determine the original client address by inspecting HTTP
	// headers such as X-Forwarded-For.

	clientIP := strings.Split(request.RemoteAddr, ":")[0]

	if len(server.support.Config.MeekProxyForwardedForHeaders) > 0 {
		for _, header := range server.support.Config.MeekProxyForwardedForHeaders {
			value := request.Header.Get(header)
			if len(value) > 0 {
				// Some headers, such as X-Forwarded-For, are a comma-separated
				// list of IPs (each proxy in a chain). The first IP should be
				// the client IP.
				proxyClientIP := strings.Split(value, ",")[0]
				if net.ParseIP(proxyClientIP) != nil &&
					server.support.GeoIPService.Lookup(proxyClientIP).Country != GEOIP_UNKNOWN_VALUE {

					clientIP = proxyClientIP
					break
				}
			}
		}
	}

	// Handle endpoints before enforcing the GetEstablishTunnels check.
	// Currently, endpoints are tactics requests, and we allow these to be
	// handled by servers which would otherwise reject new tunnels.

	if clientSessionData.EndPoint != "" {
		return "", nil, clientSessionData.EndPoint, clientIP, nil
	}

	// Don't create new sessions when not establishing. A subsequent SSH handshake
	// will not succeed, so creating a meek session just wastes resources.

	if server.support.TunnelServer != nil &&
		!server.support.TunnelServer.GetEstablishTunnels() {
		return "", nil, "", "", common.ContextError(errors.New("not establishing tunnels"))
	}

	// Create a new session

	bufferLength := MEEK_DEFAULT_RESPONSE_BUFFER_LENGTH
	if server.support.Config.MeekCachedResponseBufferSize != 0 {
		bufferLength = server.support.Config.MeekCachedResponseBufferSize
	}
	cachedResponse := NewCachedResponse(bufferLength, server.bufferPool)

	session = &meekSession{
		meekProtocolVersion: clientSessionData.MeekProtocolVersion,
		sessionIDSent:       false,
		cachedResponse:      cachedResponse,
	}

	session.touch()

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
			return "", nil, "", "", common.ContextError(err)
		}
	}

	server.sessionsLock.Lock()
	server.sessions[sessionID] = session
	server.sessionsLock.Unlock()

	// Note: from the tunnel server's perspective, this client connection
	// will close when session.delete calls Close() on the meekConn.
	server.clientHandler(clientSessionData.ClientTunnelProtocol, session.clientConn)

	return sessionID, session, "", "", nil
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

	start := monotime.Now()

	deleteWaitGroup := new(sync.WaitGroup)
	for _, sessionID := range expiredSessionIDs {
		deleteWaitGroup.Add(1)
		go func(sessionID string) {
			defer deleteWaitGroup.Done()
			server.deleteSession(sessionID)
		}(sessionID)
	}
	deleteWaitGroup.Wait()

	log.WithContextFields(
		LogFields{"elapsed time": monotime.Since(start)}).Debug("deleted expired sessions")
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

// terminateConnection sends a 404 response to a client and also closes
// the persistent connection.
func (server *MeekServer) terminateConnection(
	responseWriter http.ResponseWriter, request *http.Request) {

	http.NotFound(responseWriter, request)

	hijack, ok := responseWriter.(http.Hijacker)
	if !ok {
		return
	}
	conn, buffer, err := hijack.Hijack()
	if err != nil {
		return
	}
	buffer.Flush()
	conn.Close()
}

type meekSession struct {
	// Note: 64-bit ints used with atomic operations are placed
	// at the start of struct to ensure 64-bit alignment.
	// (https://golang.org/pkg/sync/atomic/#pkg-note-BUG)
	lastActivity                     int64
	requestCount                     int64
	metricClientRetries              int64
	metricPeakResponseSize           int64
	metricPeakCachedResponseSize     int64
	metricPeakCachedResponseHitSize  int64
	metricCachedResponseMissPosition int64
	lock                             sync.Mutex
	deleted                          bool
	clientConn                       *meekConn
	meekProtocolVersion              int
	sessionIDSent                    bool
	cachedResponse                   *CachedResponse
}

func (session *meekSession) touch() {
	atomic.StoreInt64(&session.lastActivity, int64(monotime.Now()))
}

func (session *meekSession) expired() bool {
	lastActivity := monotime.Time(atomic.LoadInt64(&session.lastActivity))
	return monotime.Since(lastActivity) > MEEK_MAX_SESSION_STALENESS
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

// GetMetrics implements the MetricsSource interface.
func (session *meekSession) GetMetrics() LogFields {
	logFields := make(LogFields)
	logFields["meek_client_retries"] = atomic.LoadInt64(&session.metricClientRetries)
	logFields["meek_peak_response_size"] = atomic.LoadInt64(&session.metricPeakResponseSize)
	logFields["meek_peak_cached_response_size"] = atomic.LoadInt64(&session.metricPeakCachedResponseSize)
	logFields["meek_peak_cached_response_hit_size"] = atomic.LoadInt64(&session.metricPeakCachedResponseHitSize)
	logFields["meek_cached_response_miss_position"] = atomic.LoadInt64(&session.metricCachedResponseMissPosition)
	return logFields
}

// makeMeekTLSConfig creates a TLS config for a meek HTTPS listener.
// Currently, this config is optimized for fronted meek where the nature
// of the connection is non-circumvention; it's optimized for performance
// assuming the peer is an uncensored CDN.
func makeMeekTLSConfig(
	support *SupportServices,
	useObfuscatedSessionTickets bool) (*utls.Config, error) {

	certificate, privateKey, err := GenerateWebServerCertificate(common.GenerateHostName())
	if err != nil {
		return nil, common.ContextError(err)
	}

	tlsCertificate, err := utls.X509KeyPair(
		[]byte(certificate), []byte(privateKey))
	if err != nil {
		return nil, common.ContextError(err)
	}

	config := &utls.Config{
		Certificates: []utls.Certificate{tlsCertificate},
		NextProtos:   []string{"http/1.1"},
		MinVersion:   utls.VersionTLS10,

		// This is a reordering of the supported CipherSuites in golang 1.6. Non-ephemeral key
		// CipherSuites greatly reduce server load, and we try to select these since the meek
		// protocol is providing obfuscation, not privacy/integrity (this is provided by the
		// tunneled SSH), so we don't benefit from the perfect forward secrecy property provided
		// by ephemeral key CipherSuites.
		// https://github.com/golang/go/blob/1cb3044c9fcd88e1557eca1bf35845a4108bc1db/src/crypto/tls/cipher_suites.go#L75
		CipherSuites: []uint16{
			utls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_RSA_WITH_RC4_128_SHA,
			utls.TLS_RSA_WITH_AES_128_CBC_SHA,
			utls.TLS_RSA_WITH_AES_256_CBC_SHA,
			utls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
			utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
			utls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
			utls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			utls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			utls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			utls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			utls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
		},
		PreferServerCipherSuites: true,
	}

	if useObfuscatedSessionTickets {

		// See obfuscated session ticket overview
		// in utls.NewObfuscatedClientSessionCache

		var obfuscatedSessionTicketKey [32]byte
		key, err := hex.DecodeString(support.Config.MeekObfuscatedKey)
		if err == nil && len(key) != 32 {
			err = errors.New("invalid obfuscated session key length")
		}
		if err != nil {
			return nil, common.ContextError(err)
		}
		copy(obfuscatedSessionTicketKey[:], key)

		var standardSessionTicketKey [32]byte
		_, err = rand.Read(standardSessionTicketKey[:])
		if err != nil {
			return nil, common.ContextError(err)
		}

		// Note: SessionTicketKey needs to be set, or else, it appears,
		// utls.Config.serverInit() will clobber the value set by
		// SetSessionTicketKeys.
		config.SessionTicketKey = obfuscatedSessionTicketKey
		config.SetSessionTicketKeys([][32]byte{
			standardSessionTicketKey,
			obfuscatedSessionTicketKey})
	}

	return config, nil
}

// getMeekCookiePayload extracts the payload from a meek cookie. The cookie
// payload is base64 encoded, obfuscated, and NaCl encrypted.
func getMeekCookiePayload(support *SupportServices, cookieValue string) ([]byte, error) {
	decodedValue, err := base64.StdEncoding.DecodeString(cookieValue)
	if err != nil {
		return nil, common.ContextError(err)
	}

	// The data consists of an obfuscated seed message prepended
	// to the obfuscated, encrypted payload. The server obfuscator
	// will read the seed message, leaving the remaining encrypted
	// data in the reader.

	reader := bytes.NewReader(decodedValue[:])

	obfuscator, err := common.NewServerObfuscator(
		reader,
		&common.ObfuscatorConfig{Keyword: support.Config.MeekObfuscatedKey})
	if err != nil {
		return nil, common.ContextError(err)
	}

	offset, err := reader.Seek(0, 1)
	if err != nil {
		return nil, common.ContextError(err)
	}
	encryptedPayload := decodedValue[offset:]

	obfuscator.ObfuscateClientToServer(encryptedPayload)

	var nonce [24]byte
	var privateKey, ephemeralPublicKey [32]byte

	decodedPrivateKey, err := base64.StdEncoding.DecodeString(
		support.Config.MeekCookieEncryptionPrivateKey)
	if err != nil {
		return nil, common.ContextError(err)
	}
	copy(privateKey[:], decodedPrivateKey)

	if len(encryptedPayload) < 32 {
		return nil, common.ContextError(errors.New("unexpected encrypted payload size"))
	}
	copy(ephemeralPublicKey[0:32], encryptedPayload[0:32])

	payload, ok := box.Open(nil, encryptedPayload[32:], &nonce, &ephemeralPublicKey, &privateKey)
	if !ok {
		return nil, common.ContextError(errors.New("open box failed"))
	}

	return payload, nil
}

// makeMeekSessionID creates a new session ID. The variable size is intended to
// frustrate traffic analysis of both plaintext and TLS meek traffic.
func makeMeekSessionID() (string, error) {
	size := MEEK_MIN_SESSION_ID_LENGTH
	n, err := common.MakeSecureRandomInt(MEEK_MAX_SESSION_ID_LENGTH - MEEK_MIN_SESSION_ID_LENGTH)
	if err != nil {
		return "", common.ContextError(err)
	}
	size += n
	sessionID, err := common.MakeRandomStringBase64(size)
	if err != nil {
		return "", common.ContextError(err)
	}
	return sessionID, nil
}

// meekConn implements the net.Conn interface and is to be used as a client
// connection by the tunnel server (being passed to sshServer.handleClient).
// meekConn bridges net/http request/response payload readers and writers
// and goroutines calling Read()s and Write()s.
type meekConn struct {
	meekServer        *MeekServer
	meekSession       *meekSession
	remoteAddr        net.Addr
	protocolVersion   int
	closeBroadcast    chan struct{}
	closed            int32
	lastReadChecksum  *uint64
	readLock          sync.Mutex
	emptyReadBuffer   chan *bytes.Buffer
	partialReadBuffer chan *bytes.Buffer
	fullReadBuffer    chan *bytes.Buffer
	writeLock         sync.Mutex
	nextWriteBuffer   chan []byte
	writeResult       chan error
}

func newMeekConn(
	meekServer *MeekServer,
	meekSession *meekSession,
	remoteAddr net.Addr,
	protocolVersion int) *meekConn {

	conn := &meekConn{
		meekServer:        meekServer,
		meekSession:       meekSession,
		remoteAddr:        remoteAddr,
		protocolVersion:   protocolVersion,
		closeBroadcast:    make(chan struct{}),
		closed:            0,
		emptyReadBuffer:   make(chan *bytes.Buffer, 1),
		partialReadBuffer: make(chan *bytes.Buffer, 1),
		fullReadBuffer:    make(chan *bytes.Buffer, 1),
		nextWriteBuffer:   make(chan []byte, 1),
		writeResult:       make(chan error, 1),
	}
	// Read() calls and pumpReads() are synchronized by exchanging control
	// of a single readBuffer. This is the same scheme used in and described
	// in psiphon.MeekConn.
	conn.emptyReadBuffer <- new(bytes.Buffer)
	return conn
}

// pumpReads causes goroutines blocking on meekConn.Read() to read
// from the specified reader. This function blocks until the reader
// is fully consumed or the meekConn is closed. A read buffer allows
// up to MEEK_MAX_REQUEST_PAYLOAD_LENGTH bytes to be read and buffered
// without a Read() immediately consuming the bytes, but there's still
// a possibility of a stall if no Read() calls are made after this
// read buffer is full.
// Note: assumes only one concurrent call to pumpReads
func (conn *meekConn) pumpReads(reader io.Reader) error {

	// Use either an empty or partial buffer. By using a partial
	// buffer, pumpReads will not block if the Read() caller has
	// not fully drained the read buffer.

	var readBuffer *bytes.Buffer
	select {
	case readBuffer = <-conn.emptyReadBuffer:
	case readBuffer = <-conn.partialReadBuffer:
	case <-conn.closeBroadcast:
		return io.EOF
	}

	newDataOffset := readBuffer.Len()

	// Since we need to read the full request payload in order to
	// take its checksum before relaying it, the read buffer can
	// grow to up to 2 x MEEK_MAX_REQUEST_PAYLOAD_LENGTH + 1.

	// +1 allows for an explicit check for request payloads that
	// exceed the maximum permitted length.
	limitReader := io.LimitReader(reader, MEEK_MAX_REQUEST_PAYLOAD_LENGTH+1)
	n, err := readBuffer.ReadFrom(limitReader)

	if err == nil && n == MEEK_MAX_REQUEST_PAYLOAD_LENGTH+1 {
		err = errors.New("invalid request payload length")
	}

	// If the request read fails, don't relay the new data. This allows
	// the client to retry and resend its request payload without
	// interrupting/duplicating the payload flow.
	if err != nil {
		readBuffer.Truncate(newDataOffset)
		conn.replaceReadBuffer(readBuffer)
		return common.ContextError(err)
	}

	// Check if request payload checksum matches immediately
	// previous payload. On match, assume this is a client retry
	// sending payload that was already relayed and skip this
	// payload. Payload is OSSH ciphertext and almost surely
	// will not repeat. In the highly unlikely case that it does,
	// the underlying SSH connection will fail and the client
	// must reconnect.

	checksum := crc64.Checksum(
		readBuffer.Bytes()[newDataOffset:], conn.meekServer.checksumTable)

	if conn.lastReadChecksum == nil {
		conn.lastReadChecksum = new(uint64)
	} else if *conn.lastReadChecksum == checksum {
		readBuffer.Truncate(newDataOffset)
	}

	*conn.lastReadChecksum = checksum

	conn.replaceReadBuffer(readBuffer)

	return nil
}

var errMeekConnectionHasClosed = errors.New("meek connection has closed")

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
		return 0, common.ContextError(errMeekConnectionHasClosed)
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
// Note: channel scheme assumes only one concurrent call to pumpWrites
func (conn *meekConn) pumpWrites(writer io.Writer) (int, error) {

	startTime := monotime.Now()
	timeout := time.NewTimer(MEEK_TURN_AROUND_TIMEOUT)
	defer timeout.Stop()

	n := 0
	for {
		select {
		case buffer := <-conn.nextWriteBuffer:
			written, err := writer.Write(buffer)
			n += written
			// Assumes that writeResult won't block.
			// Note: always send the err to writeResult,
			// as the Write() caller is blocking on this.
			conn.writeResult <- err

			if err != nil {
				return n, err
			}

			if conn.protocolVersion < MEEK_PROTOCOL_VERSION_1 {
				// Pre-protocol version 1 clients expect at most
				// MEEK_MAX_REQUEST_PAYLOAD_LENGTH response bodies
				return n, nil
			}
			totalElapsedTime := monotime.Since(startTime) / time.Millisecond
			if totalElapsedTime >= MEEK_EXTENDED_TURN_AROUND_TIMEOUT {
				return n, nil
			}
			timeout.Reset(MEEK_TURN_AROUND_TIMEOUT)
		case <-timeout.C:
			return n, nil
		case <-conn.closeBroadcast:
			return n, common.ContextError(errMeekConnectionHasClosed)
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
			return n, common.ContextError(errMeekConnectionHasClosed)
		}

		// Wait for the buffer to be processed.
		select {
		case _ = <-conn.writeResult:
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
			return n, common.ContextError(errMeekConnectionHasClosed)
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
	if time.Now().Add(MEEK_MAX_SESSION_STALENESS).Before(t) {
		return nil
	}
	return common.ContextError(errors.New("not supported"))
}

// Stub implementation of net.Conn.SetReadDeadline
func (conn *meekConn) SetReadDeadline(t time.Time) error {
	return common.ContextError(errors.New("not supported"))
}

// Stub implementation of net.Conn.SetWriteDeadline
func (conn *meekConn) SetWriteDeadline(t time.Time) error {
	return common.ContextError(errors.New("not supported"))
}

// GetMetrics implements the MetricsSource interface. The metrics are maintained
// in the meek session type; but logTunnel, which calls MetricsSource.GetMetrics,
// has a pointer only to this conn, so it calls through to the session.
func (conn *meekConn) GetMetrics() LogFields {
	return conn.meekSession.GetMetrics()
}
