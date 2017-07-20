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
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Psiphon-Inc/goarista/monotime"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/crypto/nacl/box"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/upstreamproxy"
)

// MeekConn is based on meek-client.go from Tor and Psiphon:
//
// https://gitweb.torproject.org/pluggable-transports/meek.git/blob/HEAD:/meek-client/meek-client.go
// CC0 1.0 Universal
//
// https://bitbucket.org/psiphon/psiphon-circumvention-system/src/default/go/meek-client/meek-client.go

const (
	MEEK_PROTOCOL_VERSION          = 3
	MEEK_COOKIE_MAX_PADDING        = 32
	MAX_SEND_PAYLOAD_LENGTH        = 65536
	FULL_RECEIVE_BUFFER_LENGTH     = 4194304
	READ_PAYLOAD_CHUNK_LENGTH      = 65536
	MIN_POLL_INTERVAL              = 100 * time.Millisecond
	MIN_POLL_INTERVAL_JITTER       = 0.3
	MAX_POLL_INTERVAL              = 5 * time.Second
	MAX_POLL_INTERVAL_JITTER       = 0.1
	POLL_INTERVAL_MULTIPLIER       = 1.5
	POLL_INTERVAL_JITTER           = 0.1
	MEEK_ROUND_TRIP_RETRY_DEADLINE = 5 * time.Second
	MEEK_ROUND_TRIP_RETRY_DELAY    = 50 * time.Millisecond
	MEEK_ROUND_TRIP_TIMEOUT        = 20 * time.Second
)

// MeekConfig specifies the behavior of a MeekConn
type MeekConfig struct {

	// DialAddress is the actual network address to dial to establish a
	// connection to the meek server. This may be either a fronted or
	// direct address. The address must be in the form "host:port",
	// where host may be a domain name or IP address.
	DialAddress string

	// UseHTTPS indicates whether to use HTTPS (true) or HTTP (false).
	UseHTTPS bool

	// TLSProfile specifies the TLS profile to use for all underlying
	// TLS connections created by this meek connection. Valid values
	// are the possible values for CustomTLSConfig.TLSProfile.
	// TLSProfile will be used only when DialConfig.UseIndistinguishableTLS
	// is set in the DialConfig passed in to DialMeek.
	TLSProfile string

	// UseObfuscatedSessionTickets indicates whether to use obfuscated
	// session tickets. Assumes UseHTTPS is true.
	UseObfuscatedSessionTickets bool

	// SNIServerName is the value to place in the TLS SNI server_name
	// field when HTTPS is used.
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
	ClientTunnelProtocol string

	// The following values are used to create the obfuscated meek cookie.

	PsiphonServerAddress          string
	SessionID                     string
	MeekCookieEncryptionPublicKey string
	MeekObfuscatedKey             string
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
	url                  *url.URL
	additionalHeaders    http.Header
	cookie               *http.Cookie
	pendingConns         *common.Conns
	transport            transporter
	mutex                sync.Mutex
	isClosed             bool
	runContext           context.Context
	stopRunning          context.CancelFunc
	relayWaitGroup       *sync.WaitGroup
	emptyReceiveBuffer   chan *bytes.Buffer
	partialReceiveBuffer chan *bytes.Buffer
	fullReceiveBuffer    chan *bytes.Buffer
	emptySendBuffer      chan *bytes.Buffer
	partialSendBuffer    chan *bytes.Buffer
	fullSendBuffer       chan *bytes.Buffer
}

// transporter is implemented by both http.Transport and upstreamproxy.ProxyAuthTransport.
type transporter interface {
	CancelRequest(req *http.Request)
	CloseIdleConnections()
	RegisterProtocol(scheme string, rt http.RoundTripper)
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
	meekConfig *MeekConfig,
	dialConfig *DialConfig) (meek *MeekConn, err error) {

	// Configure transport
	// Note: MeekConn has its own PendingConns to manage the underlying HTTP transport connections,
	// which may be interrupted on MeekConn.Close(). This code previously used the establishTunnel
	// pendingConns here, but that was a lifecycle mismatch: we don't want to abort HTTP transport
	// connections while MeekConn is still in use
	pendingConns := new(common.Conns)

	// Use a copy of DialConfig with the meek pendingConns
	meekDialConfig := new(DialConfig)
	*meekDialConfig = *dialConfig
	meekDialConfig.PendingConns = pendingConns

	var transport transporter
	var additionalHeaders http.Header
	var proxyUrl func(*http.Request) (*url.URL, error)

	if meekConfig.UseHTTPS {
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
		// some short period. This is mitigated by the "impaired" protocol classification mechanism.

		tlsConfig := &CustomTLSConfig{
			DialAddr:                      meekConfig.DialAddress,
			Dial:                          NewTCPDialer(meekDialConfig),
			Timeout:                       meekDialConfig.ConnectTimeout,
			SNIServerName:                 meekConfig.SNIServerName,
			SkipVerify:                    true,
			UseIndistinguishableTLS:       meekDialConfig.UseIndistinguishableTLS,
			TLSProfile:                    meekConfig.TLSProfile,
			TrustedCACertificatesFilename: meekDialConfig.TrustedCACertificatesFilename,
		}

		if meekConfig.UseObfuscatedSessionTickets {
			tlsConfig.ObfuscatedSessionTicketKey = meekConfig.MeekObfuscatedKey
		}

		dialer := NewCustomTLSDialer(tlsConfig)

		// TODO: wrap in an http.Client and use http.Client.Timeout which actually covers round trip
		transport = &http.Transport{
			Dial: dialer,
			ResponseHeaderTimeout: MEEK_ROUND_TRIP_TIMEOUT,
		}
	} else {

		// The dialer ignores address that http.Transport will pass in (derived
		// from the HTTP request URL) and always dials meekConfig.DialAddress.
		dialer := func(string, string) (net.Conn, error) {
			return NewTCPDialer(meekDialConfig)("tcp", meekConfig.DialAddress)
		}

		// For HTTP, and when the meekConfig.DialAddress matches the
		// meekConfig.HostHeader, we let http.Transport handle proxying.
		// http.Transport will put the the HTTP server address in the HTTP
		// request line. In this one case, we can use an HTTP proxy that does
		// not offer CONNECT support.
		if strings.HasPrefix(meekDialConfig.UpstreamProxyUrl, "http://") &&
			(meekConfig.DialAddress == meekConfig.HostHeader ||
				meekConfig.DialAddress == meekConfig.HostHeader+":80") {
			url, err := url.Parse(meekDialConfig.UpstreamProxyUrl)
			if err != nil {
				return nil, common.ContextError(err)
			}
			proxyUrl = http.ProxyURL(url)
			meekDialConfig.UpstreamProxyUrl = ""

			// Here, the dialer must use the address that http.Transport
			// passes in (which will be proxy address).
			dialer = NewTCPDialer(meekDialConfig)
		}

		// TODO: wrap in an http.Client and use http.Client.Timeout which actually covers round trip
		httpTransport := &http.Transport{
			Proxy: proxyUrl,
			Dial:  dialer,
			ResponseHeaderTimeout: MEEK_ROUND_TRIP_TIMEOUT,
		}
		if proxyUrl != nil {
			// Wrap transport with a transport that can perform HTTP proxy auth negotiation
			transport, err = upstreamproxy.NewProxyAuthTransport(httpTransport, meekDialConfig.CustomHeaders)
			if err != nil {
				return nil, common.ContextError(err)
			}
		} else {
			transport = httpTransport
		}
	}

	// Scheme is always "http". Otherwise http.Transport will try to do another TLS
	// handshake inside the explicit TLS session (in fronting mode).
	url := &url.URL{
		Scheme: "http",
		Host:   meekConfig.HostHeader,
		Path:   "/",
	}

	if meekConfig.UseHTTPS {
		host, _, err := net.SplitHostPort(meekConfig.DialAddress)
		if err != nil {
			return nil, common.ContextError(err)
		}
		additionalHeaders = map[string][]string{
			"X-Psiphon-Fronting-Address": {host},
		}
	} else {
		if proxyUrl == nil {
			additionalHeaders = meekDialConfig.CustomHeaders
		}
	}

	cookie, err := makeMeekCookie(meekConfig)
	if err != nil {
		return nil, common.ContextError(err)
	}

	runContext, stopRunning := context.WithCancel(context.Background())

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
	meek = &MeekConn{
		url:                  url,
		additionalHeaders:    additionalHeaders,
		cookie:               cookie,
		pendingConns:         pendingConns,
		transport:            transport,
		isClosed:             false,
		runContext:           runContext,
		stopRunning:          stopRunning,
		relayWaitGroup:       new(sync.WaitGroup),
		emptyReceiveBuffer:   make(chan *bytes.Buffer, 1),
		partialReceiveBuffer: make(chan *bytes.Buffer, 1),
		fullReceiveBuffer:    make(chan *bytes.Buffer, 1),
		emptySendBuffer:      make(chan *bytes.Buffer, 1),
		partialSendBuffer:    make(chan *bytes.Buffer, 1),
		fullSendBuffer:       make(chan *bytes.Buffer, 1),
	}
	// TODO: benchmark bytes.Buffer vs. built-in append with slices?
	meek.emptyReceiveBuffer <- new(bytes.Buffer)
	meek.emptySendBuffer <- new(bytes.Buffer)
	meek.relayWaitGroup.Add(1)
	go meek.relay()

	// Enable interruption
	if !dialConfig.PendingConns.Add(meek) {
		meek.Close()
		return nil, common.ContextError(errors.New("pending connections already closed"))
	}

	return meek, nil
}

// Close terminates the meek connection. Close waits for the relay processing goroutine
// to stop and releases HTTP transport resources.
// A mutex is required to support net.Conn concurrency semantics.
func (meek *MeekConn) Close() (err error) {

	meek.mutex.Lock()
	isClosed := meek.isClosed
	meek.isClosed = true
	meek.mutex.Unlock()

	if !isClosed {
		meek.stopRunning()
		meek.pendingConns.CloseAll()
		meek.relayWaitGroup.Wait()
		meek.transport.CloseIdleConnections()
	}
	return nil
}

// IsClosed implements the Closer iterface. The return value
// indicates whether the MeekConn has been closed.
func (meek *MeekConn) IsClosed() bool {

	meek.mutex.Lock()
	isClosed := meek.isClosed
	meek.mutex.Unlock()

	return isClosed
}

// Read reads data from the connection.
// net.Conn Deadlines are ignored. net.Conn concurrency semantics are supported.
func (meek *MeekConn) Read(buffer []byte) (n int, err error) {
	if meek.IsClosed() {
		return 0, common.ContextError(errors.New("meek connection is closed"))
	}
	// Block until there is received data to consume
	var receiveBuffer *bytes.Buffer
	select {
	case receiveBuffer = <-meek.partialReceiveBuffer:
	case receiveBuffer = <-meek.fullReceiveBuffer:
	case <-meek.runContext.Done():
		return 0, common.ContextError(errors.New("meek connection has closed"))
	}
	n, err = receiveBuffer.Read(buffer)
	meek.replaceReceiveBuffer(receiveBuffer)
	return n, err
}

// Write writes data to the connection.
// net.Conn Deadlines are ignored. net.Conn concurrency semantics are supported.
func (meek *MeekConn) Write(buffer []byte) (n int, err error) {
	if meek.IsClosed() {
		return 0, common.ContextError(errors.New("meek connection is closed"))
	}
	// Repeats until all n bytes are written
	n = len(buffer)
	for len(buffer) > 0 {
		// Block until there is capacity in the send buffer
		var sendBuffer *bytes.Buffer
		select {
		case sendBuffer = <-meek.emptySendBuffer:
		case sendBuffer = <-meek.partialSendBuffer:
		case <-meek.runContext.Done():
			return 0, common.ContextError(errors.New("meek connection has closed"))
		}
		writeLen := MAX_SEND_PAYLOAD_LENGTH - sendBuffer.Len()
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

// Stub implementation of net.Conn.LocalAddr
func (meek *MeekConn) LocalAddr() net.Addr {
	return nil
}

// Stub implementation of net.Conn.RemoteAddr
func (meek *MeekConn) RemoteAddr() net.Addr {
	return nil
}

// Stub implementation of net.Conn.SetDeadline
func (meek *MeekConn) SetDeadline(t time.Time) error {
	return common.ContextError(errors.New("not supported"))
}

// Stub implementation of net.Conn.SetReadDeadline
func (meek *MeekConn) SetReadDeadline(t time.Time) error {
	return common.ContextError(errors.New("not supported"))
}

// Stub implementation of net.Conn.SetWriteDeadline
func (meek *MeekConn) SetWriteDeadline(t time.Time) error {
	return common.ContextError(errors.New("not supported"))
}

func (meek *MeekConn) replaceReceiveBuffer(receiveBuffer *bytes.Buffer) {
	switch {
	case receiveBuffer.Len() == 0:
		meek.emptyReceiveBuffer <- receiveBuffer
	case receiveBuffer.Len() >= FULL_RECEIVE_BUFFER_LENGTH:
		meek.fullReceiveBuffer <- receiveBuffer
	default:
		meek.partialReceiveBuffer <- receiveBuffer
	}
}

func (meek *MeekConn) replaceSendBuffer(sendBuffer *bytes.Buffer) {
	switch {
	case sendBuffer.Len() == 0:
		meek.emptySendBuffer <- sendBuffer
	case sendBuffer.Len() >= MAX_SEND_PAYLOAD_LENGTH:
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

	interval := common.JitterDuration(
		MIN_POLL_INTERVAL,
		MIN_POLL_INTERVAL_JITTER)

	timeout := time.NewTimer(interval)

	sendPayload := make([]byte, MAX_SEND_PAYLOAD_LENGTH)

	for {
		timeout.Reset(interval)

		// Block until there is payload to send or it is time to poll
		var sendBuffer *bytes.Buffer
		select {
		case sendBuffer = <-meek.partialSendBuffer:
		case sendBuffer = <-meek.fullSendBuffer:
		case <-timeout.C:
			// In the polling case, send an empty payload
		case <-meek.runContext.Done():
			// Drop through to second Done() check
		}

		// Check Done() again, to ensure it takes precedence
		select {
		case <-meek.runContext.Done():
			return
		default:
		}

		sendPayloadSize := 0
		if sendBuffer != nil {
			var err error
			sendPayloadSize, err = sendBuffer.Read(sendPayload)
			meek.replaceSendBuffer(sendBuffer)
			if err != nil {
				NoticeAlert("%s", common.ContextError(err))
				go meek.Close()
				return
			}
		}

		receivedPayloadSize, err := meek.roundTrip(sendPayload[:sendPayloadSize])

		if err != nil {
			select {
			case <-meek.runContext.Done():
				// In this case, meek.roundTrip encountered Done(). Exit without logging error.
				return
			default:
			}
			NoticeAlert("%s", common.ContextError(err))
			go meek.Close()
			return
		}

		// Calculate polling interval. When data is received,
		// immediately request more. Otherwise, schedule next
		// poll with exponential back off. Jitter and coin
		// flips are used to avoid trivial, static traffic
		// timing patterns.

		if receivedPayloadSize > 0 || sendPayloadSize > 0 {

			interval = 0

		} else if interval == 0 {

			interval = common.JitterDuration(
				MIN_POLL_INTERVAL,
				MIN_POLL_INTERVAL_JITTER)

		} else {

			if common.FlipCoin() {
				interval = common.JitterDuration(
					interval,
					POLL_INTERVAL_JITTER)
			} else {
				interval = common.JitterDuration(
					time.Duration(float64(interval)*POLL_INTERVAL_MULTIPLIER),
					POLL_INTERVAL_JITTER)
			}

			if interval >= MAX_POLL_INTERVAL {
				interval = common.JitterDuration(
					MAX_POLL_INTERVAL,
					MAX_POLL_INTERVAL_JITTER)
			}
		}
	}
}

// roundTrip configures and makes the actual HTTP POST request
func (meek *MeekConn) roundTrip(sendPayload []byte) (int64, error) {

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
	//    acknowleged it. The client will also indicate to the server
	//    the amount of response payload already received, and the
	//    server will skip resending the indicated amount of response
	//    payload.
	//
	// Retries are indicated to the server by adding a Range header,
	// which includes the response payload resend position.

	retries := uint(0)
	retryDeadline := monotime.Now().Add(MEEK_ROUND_TRIP_RETRY_DEADLINE)
	serverAcknowlegedRequestPayload := false
	receivedPayloadSize := int64(0)

	for try := 0; ; try++ {

		// Omit the request payload when retrying after receiving a
		// partial server response.

		var sendPayloadReader io.Reader
		if !serverAcknowlegedRequestPayload {
			sendPayloadReader = bytes.NewReader(sendPayload)
		}

		var request *http.Request
		request, err := http.NewRequest("POST", meek.url.String(), sendPayloadReader)
		if err != nil {
			// Don't retry when can't initialize a Request
			return 0, common.ContextError(err)
		}

		// Note: meek.stopRunning() will abort a round trip in flight
		request = request.WithContext(meek.runContext)

		meek.addAdditionalHeaders(request)

		request.Header.Set("Content-Type", "application/octet-stream")
		request.AddCookie(meek.cookie)

		expectedStatusCode := http.StatusOK

		// When retrying, add a Range header to indicate how much
		// of the response was already received.

		if try > 0 {
			expectedStatusCode = http.StatusPartialContent
			request.Header.Set("Range", fmt.Sprintf("bytes=%d-", receivedPayloadSize))
		}

		response, err := meek.transport.RoundTrip(request)
		if err != nil {
			select {
			case <-meek.runContext.Done():
				// Exit without retrying and without logging error.
				return 0, common.ContextError(err)
			default:
			}
			NoticeAlert("meek round trip failed: %s", err)
			// ...continue to retry
		}

		if err == nil {

			if response.StatusCode != expectedStatusCode {
				// Don't retry when the status code is incorrect
				response.Body.Close()
				return 0, common.ContextError(
					fmt.Errorf(
						"unexpected status code: %d instead of %d",
						response.StatusCode, expectedStatusCode))
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
			serverAcknowlegedRequestPayload = true

			readPayloadSize, err := meek.readPayload(response.Body)
			response.Body.Close()

			// receivedPayloadSize is the number of response
			// payload bytes received and relayed. A retry can
			// resume after this position.
			receivedPayloadSize += readPayloadSize

			if err != nil {
				NoticeAlert("meek read payload failed: %s", err)
				// ...continue to retry
			} else {
				// Round trip completed successfully
				break
			}
		}

		// Either the request failed entirely, or there was a failure
		// streaming the response payload. Retry, if time remains.

		if retries >= 1 && monotime.Now().After(retryDeadline) {
			return 0, common.ContextError(err)
		}
		retries += 1

		time.Sleep(MEEK_ROUND_TRIP_RETRY_DELAY)
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
		reader := io.LimitReader(receivedPayload, READ_PAYLOAD_CHUNK_LENGTH)
		// Block until there is capacity in the receive buffer
		var receiveBuffer *bytes.Buffer
		select {
		case receiveBuffer = <-meek.emptyReceiveBuffer:
		case receiveBuffer = <-meek.partialReceiveBuffer:
		case <-meek.runContext.Done():
			return 0, nil
		}
		// Note: receiveBuffer size may exceed FULL_RECEIVE_BUFFER_LENGTH by up to the size
		// of one received payload. The FULL_RECEIVE_BUFFER_LENGTH value is just a guideline.
		n, err := receiveBuffer.ReadFrom(reader)
		meek.replaceReceiveBuffer(receiveBuffer)
		totalSize += n
		if err != nil {
			return totalSize, common.ContextError(err)
		}
		if n == 0 {
			break
		}
	}
	return totalSize, nil
}

// makeCookie creates the cookie to be sent with initial meek HTTP request.
// The purpose of the cookie is to send the following to the server:
//   ServerAddress -- the Psiphon Server address the meek server should relay to
//   SessionID -- the Psiphon session ID (used by meek server to relay geolocation
//     information obtained from the CDN through to the Psiphon Server)
//   MeekProtocolVersion -- tells the meek server that this client understands
//     the latest protocol.
// The server will create a session using these values and send the session ID
// back to the client via Set-Cookie header. Client must use that value with
// all consequent HTTP requests
// In unfronted meek mode, the cookie is visible over the adversary network, so the
// cookie is encrypted and obfuscated.
func makeMeekCookie(meekConfig *MeekConfig) (cookie *http.Cookie, err error) {

	// Make the JSON data
	serverAddress := meekConfig.PsiphonServerAddress
	cookieData := &protocol.MeekCookieData{
		ServerAddress:        serverAddress,
		SessionID:            meekConfig.SessionID,
		MeekProtocolVersion:  MEEK_PROTOCOL_VERSION,
		ClientTunnelProtocol: meekConfig.ClientTunnelProtocol,
	}
	serializedCookie, err := json.Marshal(cookieData)
	if err != nil {
		return nil, common.ContextError(err)
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
	decodedPublicKey, err := base64.StdEncoding.DecodeString(meekConfig.MeekCookieEncryptionPublicKey)
	if err != nil {
		return nil, common.ContextError(err)
	}
	copy(publicKey[:], decodedPublicKey)
	ephemeralPublicKey, ephemeralPrivateKey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, common.ContextError(err)
	}
	box := box.Seal(nil, serializedCookie, &nonce, &publicKey, ephemeralPrivateKey)
	encryptedCookie := make([]byte, 32+len(box))
	copy(encryptedCookie[0:32], ephemeralPublicKey[0:32])
	copy(encryptedCookie[32:], box)

	// Obfuscate the encrypted data
	obfuscator, err := common.NewClientObfuscator(
		&common.ObfuscatorConfig{Keyword: meekConfig.MeekObfuscatedKey, MaxPadding: MEEK_COOKIE_MAX_PADDING})
	if err != nil {
		return nil, common.ContextError(err)
	}
	obfuscatedCookie := obfuscator.SendSeedMessage()
	seedLen := len(obfuscatedCookie)
	obfuscatedCookie = append(obfuscatedCookie, encryptedCookie...)
	obfuscator.ObfuscateClientToServer(obfuscatedCookie[seedLen:])

	// Format the HTTP cookie
	// The format is <random letter 'A'-'Z'>=<base64 data>, which is intended to match common cookie formats.
	A := int('A')
	Z := int('Z')
	// letterIndex is integer in range [int('A'), int('Z')]
	letterIndex, err := common.MakeSecureRandomInt(Z - A + 1)
	if err != nil {
		return nil, common.ContextError(err)
	}
	return &http.Cookie{
			Name:  string(byte(A + letterIndex)),
			Value: base64.StdEncoding.EncodeToString(obfuscatedCookie)},
		nil
}
