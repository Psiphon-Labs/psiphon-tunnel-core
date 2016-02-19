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
	MEEK_PROTOCOL_VERSION          = 2
	MEEK_COOKIE_MAX_PADDING        = 32
	MAX_SEND_PAYLOAD_LENGTH        = 65536
	FULL_RECEIVE_BUFFER_LENGTH     = 4194304
	READ_PAYLOAD_CHUNK_LENGTH      = 65536
	MIN_POLL_INTERVAL              = 100 * time.Millisecond
	MAX_POLL_INTERVAL              = 5 * time.Second
	POLL_INTERNAL_MULTIPLIER       = 1.5
	MEEK_ROUND_TRIP_RETRY_DEADLINE = 1 * time.Second
	MEEK_ROUND_TRIP_RETRY_DELAY    = 50 * time.Millisecond
	MEEK_ROUND_TRIP_TIMEOUT        = 20 * time.Second
)

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
	frontingAddress      string
	useHTTPS             bool
	url                  *url.URL
	cookie               *http.Cookie
	pendingConns         *Conns
	transport            transporter
	mutex                sync.Mutex
	isClosed             bool
	broadcastClosed      chan struct{}
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
	serverEntry *ServerEntry, sessionId string,
	useHTTPS, useSNI bool,
	frontingAddress, frontingHost string,
	config *DialConfig) (meek *MeekConn, err error) {

	// Configure transport
	// Note: MeekConn has its own PendingConns to manage the underlying HTTP transport connections,
	// which may be interrupted on MeekConn.Close(). This code previously used the establishTunnel
	// pendingConns here, but that was a lifecycle mismatch: we don't want to abort HTTP transport
	// connections while MeekConn is still in use
	pendingConns := new(Conns)

	// Use a copy of DialConfig with the meek pendingConns
	meekConfig := new(DialConfig)
	*meekConfig = *config
	meekConfig.PendingConns = pendingConns

	var host string
	var dialer Dialer
	var proxyUrl func(*http.Request) (*url.URL, error)

	if frontingAddress != "" {

		// In this case, host is not what is dialed but is what ends up in the HTTP Host header
		host = frontingHost

		if useHTTPS {

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

			customTLSConfig := &CustomTLSConfig{
				FrontingAddr:                  fmt.Sprintf("%s:%d", frontingAddress, 443),
				Dial:                          NewTCPDialer(meekConfig),
				Timeout:                       meekConfig.ConnectTimeout,
				SendServerName:                useSNI,
				SkipVerify:                    true,
				UseIndistinguishableTLS:       config.UseIndistinguishableTLS,
				TrustedCACertificatesFilename: config.TrustedCACertificatesFilename,
			}

			dialer = NewCustomTLSDialer(customTLSConfig)

		} else { // !useHTTPS

			dialer = func(string, string) (net.Conn, error) {
				return NewTCPDialer(meekConfig)("tcp", frontingAddress+":80")
			}
		}

	} else { // frontingAddress == ""

		// host is both what is dialed and what ends up in the HTTP Host header
		host = fmt.Sprintf("%s:%d", serverEntry.IpAddress, serverEntry.MeekServerPort)

		if useHTTPS {

			customTLSConfig := &CustomTLSConfig{
				Dial:                          NewTCPDialer(meekConfig),
				Timeout:                       meekConfig.ConnectTimeout,
				SendServerName:                useSNI,
				SkipVerify:                    true,
				UseIndistinguishableTLS:       config.UseIndistinguishableTLS,
				TrustedCACertificatesFilename: config.TrustedCACertificatesFilename,
			}

			dialer = NewCustomTLSDialer(customTLSConfig)

		} else { // !useHTTPS

			if strings.HasPrefix(meekConfig.UpstreamProxyUrl, "http://") {
				// For unfronted meek, we let the http.Transport handle proxying, as the
				// target server hostname has to be in the HTTP request line. Also, in this
				// case, we don't require the proxy to support CONNECT and so we can work
				// through HTTP proxies that don't support it.
				url, err := url.Parse(meekConfig.UpstreamProxyUrl)
				if err != nil {
					return nil, ContextError(err)
				}
				proxyUrl = http.ProxyURL(url)
				meekConfig.UpstreamProxyUrl = ""
			}

			dialer = NewTCPDialer(meekConfig)
		}

	}

	// Scheme is always "http". Otherwise http.Transport will try to do another TLS
	// handshake inside the explicit TLS session (in fronting mode).
	url := &url.URL{
		Scheme: "http",
		Host:   host,
		Path:   "/",
	}
	cookie, err := makeCookie(serverEntry, sessionId)
	if err != nil {
		return nil, ContextError(err)
	}
	httpTransport := &http.Transport{
		Proxy: proxyUrl,
		Dial:  dialer,
		ResponseHeaderTimeout: MEEK_ROUND_TRIP_TIMEOUT,
	}
	var transport transporter
	if proxyUrl != nil {
		// Wrap transport with a transport that can perform HTTP proxy auth negotiation
		transport, err = upstreamproxy.NewProxyAuthTransport(httpTransport)
		if err != nil {
			return nil, ContextError(err)
		}
	} else {
		transport = httpTransport
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
	meek = &MeekConn{
		frontingAddress:      frontingAddress,
		useHTTPS:             useHTTPS,
		url:                  url,
		cookie:               cookie,
		pendingConns:         pendingConns,
		transport:            transport,
		isClosed:             false,
		broadcastClosed:      make(chan struct{}),
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
	if !config.PendingConns.Add(meek) {
		meek.Close()
		return nil, ContextError(errors.New("pending connections already closed"))
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
		close(meek.broadcastClosed)
		meek.pendingConns.CloseAll()
		meek.relayWaitGroup.Wait()
		meek.transport.CloseIdleConnections()
	}
	return nil
}

func (meek *MeekConn) closed() bool {

	meek.mutex.Lock()
	isClosed := meek.isClosed
	meek.mutex.Unlock()

	return isClosed
}

// Read reads data from the connection.
// net.Conn Deadlines are ignored. net.Conn concurrency semantics are supported.
func (meek *MeekConn) Read(buffer []byte) (n int, err error) {
	if meek.closed() {
		return 0, ContextError(errors.New("meek connection is closed"))
	}
	// Block until there is received data to consume
	var receiveBuffer *bytes.Buffer
	select {
	case receiveBuffer = <-meek.partialReceiveBuffer:
	case receiveBuffer = <-meek.fullReceiveBuffer:
	case <-meek.broadcastClosed:
		return 0, ContextError(errors.New("meek connection has closed"))
	}
	n, err = receiveBuffer.Read(buffer)
	meek.replaceReceiveBuffer(receiveBuffer)
	return n, err
}

// Write writes data to the connection.
// net.Conn Deadlines are ignored. net.Conn concurrency semantics are supported.
func (meek *MeekConn) Write(buffer []byte) (n int, err error) {
	if meek.closed() {
		return 0, ContextError(errors.New("meek connection is closed"))
	}
	// Repeats until all n bytes are written
	n = len(buffer)
	for len(buffer) > 0 {
		// Block until there is capacity in the send buffer
		var sendBuffer *bytes.Buffer
		select {
		case sendBuffer = <-meek.emptySendBuffer:
		case sendBuffer = <-meek.partialSendBuffer:
		case <-meek.broadcastClosed:
			return 0, ContextError(errors.New("meek connection has closed"))
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
	return ContextError(errors.New("not supported"))
}

// Stub implementation of net.Conn.SetReadDeadline
func (meek *MeekConn) SetReadDeadline(t time.Time) error {
	return ContextError(errors.New("not supported"))
}

// Stub implementation of net.Conn.SetWriteDeadline
func (meek *MeekConn) SetWriteDeadline(t time.Time) error {
	return ContextError(errors.New("not supported"))
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
	interval := MIN_POLL_INTERVAL
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
		case <-meek.broadcastClosed:
			// TODO: timeout case may be selected when broadcastClosed is set?
			return
		}
		sendPayloadSize := 0
		if sendBuffer != nil {
			var err error
			sendPayloadSize, err = sendBuffer.Read(sendPayload)
			meek.replaceSendBuffer(sendBuffer)
			if err != nil {
				NoticeAlert("%s", ContextError(err))
				go meek.Close()
				return
			}
		}
		receivedPayload, err := meek.roundTrip(sendPayload[:sendPayloadSize])
		if err != nil {
			NoticeAlert("%s", ContextError(err))
			go meek.Close()
			return
		}
		if receivedPayload == nil {
			// In this case, meek.roundTrip encountered broadcastClosed. Exit without error.
			return
		}
		receivedPayloadSize, err := meek.readPayload(receivedPayload)
		if err != nil {
			NoticeAlert("%s", ContextError(err))
			go meek.Close()
			return
		}
		if receivedPayloadSize > 0 || sendPayloadSize > 0 {
			interval = 0
		} else if interval == 0 {
			interval = MIN_POLL_INTERVAL
		} else {
			interval = time.Duration(float64(interval) * POLL_INTERNAL_MULTIPLIER)
			if interval >= MAX_POLL_INTERVAL {
				interval = MAX_POLL_INTERVAL
			}
		}
	}
}

// readPayload reads the HTTP response  in chunks, making the read buffer available
// to MeekConn.Read() calls after each chunk; the intention is to allow bytes to
// flow back to the reader as soon as possible instead of buffering the entire payload.
func (meek *MeekConn) readPayload(receivedPayload io.ReadCloser) (totalSize int64, err error) {
	defer receivedPayload.Close()
	totalSize = 0
	for {
		reader := io.LimitReader(receivedPayload, READ_PAYLOAD_CHUNK_LENGTH)
		// Block until there is capacity in the receive buffer
		var receiveBuffer *bytes.Buffer
		select {
		case receiveBuffer = <-meek.emptyReceiveBuffer:
		case receiveBuffer = <-meek.partialReceiveBuffer:
		case <-meek.broadcastClosed:
			return 0, nil
		}
		// Note: receiveBuffer size may exceed FULL_RECEIVE_BUFFER_LENGTH by up to the size
		// of one received payload. The FULL_RECEIVE_BUFFER_LENGTH value is just a threshold.
		n, err := receiveBuffer.ReadFrom(reader)
		meek.replaceReceiveBuffer(receiveBuffer)
		if err != nil {
			return 0, ContextError(err)
		}
		totalSize += n
		if n == 0 {
			break
		}
	}
	return totalSize, nil
}

// roundTrip configures and makes the actual HTTP POST request
func (meek *MeekConn) roundTrip(sendPayload []byte) (receivedPayload io.ReadCloser, err error) {
	request, err := http.NewRequest("POST", meek.url.String(), bytes.NewReader(sendPayload))
	if err != nil {
		return nil, ContextError(err)
	}

	if meek.useHTTPS {
		request.Header.Set("X-Psiphon-Fronting-Address", meek.frontingAddress)
	}

	// Don't use the default user agent ("Go 1.1 package http").
	// For now, just omit the header (net/http/request.go: "may be blank to not send the header").
	request.Header.Set("User-Agent", "")

	request.Header.Set("Content-Type", "application/octet-stream")

	request.AddCookie(meek.cookie)

	// The retry mitigates intermittent failures between the client and front/server.
	//
	// Note: Retry will only be effective if entire request failed (underlying transport protocol
	// such as SSH will fail if extra bytes are replayed in either direction due to partial relay
	// success followed by retry).
	// At least one retry is always attempted. We retry when still within a brief deadline and wait
	// for a short time before re-dialing.
	//
	// TODO: in principle, we could retry for min(TUNNEL_WRITE_TIMEOUT, meek-server.MAX_SESSION_STALENESS),
	// i.e., as long as the underlying tunnel has not timed out and as long as the server has not
	// expired the current meek session. Presently not doing this to avoid excessive connection attempts
	// through the first hop. In addition, this will require additional support for timely shutdown.

	retries := uint(0)
	retryDeadline := time.Now().Add(MEEK_ROUND_TRIP_RETRY_DEADLINE)

	var response *http.Response
	for {

		// The http.Transport.RoundTrip is run in a goroutine to enable cancelling a request in-flight.
		type roundTripResponse struct {
			response *http.Response
			err      error
		}
		roundTripResponseChannel := make(chan *roundTripResponse, 1)
		roundTripWaitGroup := new(sync.WaitGroup)
		roundTripWaitGroup.Add(1)
		go func() {
			defer roundTripWaitGroup.Done()
			r, err := meek.transport.RoundTrip(request)
			roundTripResponseChannel <- &roundTripResponse{r, err}
		}()
		select {
		case roundTripResponse := <-roundTripResponseChannel:
			response = roundTripResponse.response
			err = roundTripResponse.err
		case <-meek.broadcastClosed:
			meek.transport.CancelRequest(request)
			return nil, nil
		}
		roundTripWaitGroup.Wait()

		if err == nil {
			break
		}

		if retries >= 1 && time.Now().After(retryDeadline) {
			break
		}
		retries += 1

		time.Sleep(MEEK_ROUND_TRIP_RETRY_DELAY)
	}
	if err != nil {
		return nil, ContextError(err)
	}
	if response.StatusCode != http.StatusOK {
		return nil, ContextError(fmt.Errorf("http request failed %d", response.StatusCode))
	}
	// observe response cookies for meek session key token.
	// Once found it must be used for all consecutive requests made to the server
	for _, c := range response.Cookies() {
		if meek.cookie.Name == c.Name {
			meek.cookie.Value = c.Value
			break
		}
	}
	return response.Body, nil
}

type meekCookieData struct {
	ServerAddress       string `json:"p"`
	SessionID           string `json:"s"`
	MeekProtocolVersion int    `json:"v"`
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
func makeCookie(serverEntry *ServerEntry, sessionId string) (cookie *http.Cookie, err error) {

	// Make the JSON data
	serverAddress := fmt.Sprintf("%s:%d", serverEntry.IpAddress, serverEntry.SshObfuscatedPort)
	cookieData := &meekCookieData{
		ServerAddress:       serverAddress,
		SessionID:           sessionId,
		MeekProtocolVersion: MEEK_PROTOCOL_VERSION,
	}
	serializedCookie, err := json.Marshal(cookieData)
	if err != nil {
		return nil, ContextError(err)
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
	decodedPublicKey, err := base64.StdEncoding.DecodeString(serverEntry.MeekCookieEncryptionPublicKey)
	if err != nil {
		return nil, ContextError(err)
	}
	copy(publicKey[:], decodedPublicKey)
	ephemeralPublicKey, ephemeralPrivateKey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, ContextError(err)
	}
	box := box.Seal(nil, serializedCookie, &nonce, &publicKey, ephemeralPrivateKey)
	encryptedCookie := make([]byte, 32+len(box))
	copy(encryptedCookie[0:32], ephemeralPublicKey[0:32])
	copy(encryptedCookie[32:], box)

	// Obfuscate the encrypted data
	obfuscator, err := NewObfuscator(
		&ObfuscatorConfig{Keyword: serverEntry.MeekObfuscatedKey, MaxPadding: MEEK_COOKIE_MAX_PADDING})
	if err != nil {
		return nil, ContextError(err)
	}
	obfuscatedCookie := obfuscator.ConsumeSeedMessage()
	seedLen := len(obfuscatedCookie)
	obfuscatedCookie = append(obfuscatedCookie, encryptedCookie...)
	obfuscator.ObfuscateClientToServer(obfuscatedCookie[seedLen:])

	// Format the HTTP cookie
	// The format is <random letter 'A'-'Z'>=<base64 data>, which is intended to match common cookie formats.
	A := int('A')
	Z := int('Z')
	// letterIndex is integer in range [int('A'), int('Z')]
	letterIndex, err := MakeSecureRandomInt(Z - A + 1)
	if err != nil {
		return nil, ContextError(err)
	}
	return &http.Cookie{
			Name:  string(byte(A + letterIndex)),
			Value: base64.StdEncoding.EncodeToString(obfuscatedCookie)},
		nil
}
