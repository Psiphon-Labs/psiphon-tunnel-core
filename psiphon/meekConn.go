/*
 * Copyright (c) 2014, Psiphon Inc.
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
	"code.google.com/p/go.crypto/nacl/box"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// MeekConn is based on meek-client.go from Tor and Psiphon:
//
// https://gitweb.torproject.org/pluggable-transports/meek.git/blob/HEAD:/meek-client/meek-client.go
// CC0 1.0 Universal
//
// https://bitbucket.org/psiphon/psiphon-circumvention-system/src/default/go/meek-client/meek-client.go

const (
	MEEK_PROTOCOL_VERSION     = 1
	MEEK_COOKIE_MAX_PADDING   = 32
	MAX_SEND_PAYLOAD_LENGTH   = 65536
	READ_PAYLOAD_CHUNK_LENGTH = 65536
	MIN_POLL_INTERVAL         = 100 * time.Millisecond
	MAX_POLL_INTERVAL         = 5 * time.Second
	POLL_INTERNAL_MULTIPLIER  = 1.5
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
	url                 *url.URL
	cookie              *http.Cookie
	transport           *http.Transport
	mutex               sync.Mutex
	isClosed            bool
	closedSignal        chan struct{}
	broadcastClosed     chan struct{}
	relayWaitGroup      *sync.WaitGroup
	availableReadBuffer chan *bytes.Buffer
	emptyReadBuffer     chan *bytes.Buffer
	writeQueue          chan []byte
}

// NewMeekConn returns an initialized meek connection. A meek connection is
// an HTTP session which does not depend on an underlying socket connection (although
// persistent HTTP connections are used for performance). This function does not
// wait for the connection to be "established" before returning. A goroutine
// is spawned which will eventually start HTTP polling.
// useFronting assumes caller has already checked server entry capabilities.
func NewMeekConn(
	serverEntry *ServerEntry, sessionId string, useFronting bool,
	connectTimeout, readTimeout, writeTimeout time.Duration,
	pendingConns *PendingConns) (meek *MeekConn, err error) {
	// Configure transport
	var host string
	var dialer Dialer
	directDialer := NewDirectDialer(connectTimeout, readTimeout, writeTimeout, pendingConns)
	if useFronting {
		// In this case, host is not what is dialed but is what ends up in the HTTP Host header
		host = serverEntry.MeekFrontingHost
		// Custom TLS dialer:
		//  - ignores the HTTP request address and uses the fronting domain
		//  - disables SNI -- SNI breaks fronting when used with CDNs that support SNI on the server side.
		dialer = NewCustomTLSDialer(
			&CustomTLSConfig{
				Dial:           directDialer,
				Timeout:        connectTimeout,
				FrontingAddr:   fmt.Sprintf("%s:%d", serverEntry.MeekFrontingDomain, 443),
				SendServerName: false,
			})
	} else {
		// In this case, host is both what is dialed and what ends up in the HTTP Host header
		host = fmt.Sprintf("%s:%d", serverEntry.IpAddress, serverEntry.MeekServerPort)
		dialer = directDialer
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
	transport := &http.Transport{
		Dial: dialer,
		ResponseHeaderTimeout: TUNNEL_WRITE_TIMEOUT,
	}
	// The main loop of a MeekConn is run in the relay() goroutine.
	// A MeekConn net.Conn concurrency semantics:
	// "Multiple goroutines may invoke methods on a Conn simultaneously."
	//
	// Write() calls and relay() are synchronized with the writeQueue channel. Write sends
	// payloads into the writeQueue, blocking when a payload is already in the queue as only
	// one HTTP request is in flight at a time (the channel size is 1).
	//
	// Read() calls and relay() are synchronized by passing control of a single readBuffer
	// (bytes.Buffer). This single buffer may be in the emptyReadBuffer channel (when it is
	// available and empty), the availableReadBuffer channel (when it is available and contains
	// data), or "checked out" by relay or Read when they are are writing to or reading from the
	// buffer, respectively. relay will obtain the buffer from either channel, but Read will only
	// obtain the buffer from availableReadBuffer, so it blocks when there is no data available
	// to read.
	meek = &MeekConn{
		url:                 url,
		cookie:              cookie,
		transport:           transport,
		broadcastClosed:     make(chan struct{}),
		relayWaitGroup:      new(sync.WaitGroup),
		availableReadBuffer: make(chan *bytes.Buffer, 1),
		emptyReadBuffer:     make(chan *bytes.Buffer, 1),
		writeQueue:          make(chan []byte, 1),
	}
	// TODO: benchmark bytes.Buffer vs. built-in append with slices?
	meek.emptyReadBuffer <- new(bytes.Buffer)
	meek.relayWaitGroup.Add(1)
	go meek.relay()
	return meek, nil
}

// SetClosedSignal implements psiphon.Conn.SetClosedSignal
func (meek *MeekConn) SetClosedSignal(closedSignal chan struct{}) (err error) {
	meek.mutex.Lock()
	defer meek.mutex.Unlock()
	if meek.isClosed {
		return ContextError(errors.New("connection is already closed"))
	}
	meek.closedSignal = closedSignal
	return nil
}

// Close terminates the meek connection. Close waits for the relay processing goroutine
// to stop and releases HTTP transport resources.
// A mutex is required to support psiphon.Conn.SetClosedSignal concurrency semantics.
// NOTE: currently doesn't interrupt any HTTP request in flight.
func (meek *MeekConn) Close() (err error) {
	meek.mutex.Lock()
	defer meek.mutex.Unlock()
	if !meek.isClosed {
		// TODO: meek.transport.CancelRequest() for current request?
		close(meek.broadcastClosed)
		meek.relayWaitGroup.Wait()
		meek.transport.CloseIdleConnections()
		meek.isClosed = true
		select {
		case meek.closedSignal <- *new(struct{}):
		default:
		}
	}
	return nil
}

func (meek *MeekConn) closed() bool {
	meek.mutex.Lock()
	defer meek.mutex.Unlock()
	return meek.isClosed
}

// Read reads data from the connection.
// net.Conn Deadlines are ignored. net.Conn concurrency semantics are supported.
func (meek *MeekConn) Read(buffer []byte) (n int, err error) {
	if meek.closed() {
		return 0, ContextError(errors.New("meek connection is closed"))
	}
	select {
	case readBuffer := <-meek.availableReadBuffer:
		n, err = readBuffer.Read(buffer)
		if readBuffer.Len() > 0 {
			meek.availableReadBuffer <- readBuffer
		} else {
			meek.emptyReadBuffer <- readBuffer
		}
		return n, err
	case <-meek.broadcastClosed:
		return 0, ContextError(errors.New("meek connection has closed"))
	}
}

// Write writes data to the connection.
// net.Conn Deadlines are ignored. net.Conn concurrency semantics are supported.
func (meek *MeekConn) Write(buffer []byte) (n int, err error) {
	if meek.closed() {
		return 0, ContextError(errors.New("meek connection is closed"))
	}
	n = len(buffer)
	// The data to send is split into MAX_SEND_PAYLOAD_LENGTH chunks as
	// this is the most that will be sent per HTTP request.
	for len(buffer) > 0 {
		nextWrite := MAX_SEND_PAYLOAD_LENGTH
		if len(buffer) < nextWrite {
			nextWrite = len(buffer)
		}
		// TODO: pool of reusable buffers?
		queuedWrite := make([]byte, nextWrite)
		copy(queuedWrite, buffer)
		buffer = buffer[nextWrite:]
		select {
		case meek.writeQueue <- queuedWrite:
		case <-meek.broadcastClosed:
			return 0, ContextError(errors.New("meek connection has closed"))
		}
	}
	return n, nil
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

// relay sends and receives tunnelled traffic (payload). An HTTP request is
// triggered when data is in the write queue or at a polling interval.
// There's a geometric increase, up to a maximum, in the polling interval when
// no data is exchanged. Only one HTTP request is in flight at a time.
func (meek *MeekConn) relay() {
	defer meek.relayWaitGroup.Done()
	interval := MIN_POLL_INTERVAL
	var sendPayload []byte
	for {
		sendPayload = nil
		select {
		case sendPayload = <-meek.writeQueue:
		case <-time.After(interval):
		case <-meek.broadcastClosed:
			return
		}
		receivedPayload, err := meek.roundTrip(sendPayload)
		if err != nil {
			Notice(NOTICE_ALERT, "%s", ContextError(err))
			meek.Close()
			return
		}
		receivedPayloadSize, err := meek.readPayload(receivedPayload)
		if err != nil {
			Notice(NOTICE_ALERT, "%s", ContextError(err))
			meek.Close()
			return
		}
		if receivedPayloadSize > 0 || sendPayload != nil {
			interval = 0
		} else if interval == 0 {
			interval = MIN_POLL_INTERVAL
		} else {
			interval = time.Duration(float64(interval) * POLL_INTERNAL_MULTIPLIER)
			if interval >= MAX_POLL_INTERVAL {
				interval = MIN_POLL_INTERVAL
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
		var readBuffer *bytes.Buffer
		select {
		case readBuffer = <-meek.availableReadBuffer:
		case readBuffer = <-meek.emptyReadBuffer:
		}
		// TODO: block when readBuffer is too large?
		n, err := readBuffer.ReadFrom(reader)
		if err != nil {
			return 0, ContextError(err)
		}
		totalSize += n
		if readBuffer.Len() > 0 {
			meek.availableReadBuffer <- readBuffer
		} else {
			meek.emptyReadBuffer <- readBuffer
		}
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
		return nil, err
	}
	// Don't use the default user agent ("Go 1.1 package http").
	// For now, just omit the header (net/http/request.go: "may be blank to not send the header").
	request.Header.Set("User-Agent", "")
	request.Header.Set("Content-Type", "application/octet-stream")
	request.AddCookie(meek.cookie)
	// This retry mitigates intermittent failures between the client and front/server.
	// Note: Retry will only be effective if entire request failed (underlying transport protocol
	// such as SSH will fail if extra bytes are replayed in either direction due to partial relay
	// success followed by retry).
	var response *http.Response
	for i := 0; i <= 1; i++ {
		response, err = meek.transport.RoundTrip(request)
		if err == nil {
			break
		}
	}
	if err != nil {
		return nil, ContextError(err)
	}
	if response.StatusCode != http.StatusOK {
		return nil, ContextError(fmt.Errorf("http request failed %d", response.StatusCode))
	}
	return response.Body, nil
}

type meekCookieData struct {
	ServerAddress       string `json:"p"`
	SessionID           string `json:"s"`
	MeekProtocolVersion int    `json:"v"`
}

// makeCookie creates the cookie to be sent with all meek HTTP requests.
// The purpose of the cookie is to send the following to the server:
//   ServerAddress -- the Psiphon Server address the meek server should relay to
//   SessionID -- the Psiphon session ID (used by meek server to relay geolocation
//     information obtained from the CDN through to the Psiphon Server)
//   MeekProtocolVersion -- tells the meek server that this client understands
//     the latest protocol.
// The entire cookie also acts as an meek/HTTP session ID.
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
		&ObfuscatorParams{Keyword: serverEntry.MeekObfuscatedKey, MaxPadding: MEEK_COOKIE_MAX_PADDING})
	if err != nil {
		return nil, ContextError(err)
	}
	obfuscatedCookie := obfuscator.ConsumeSeedMessage()
	seedLen := len(obfuscatedCookie)
	obfuscatedCookie = append(obfuscatedCookie, encryptedCookie...)
	obfuscator.ObfuscateClientToServer(obfuscatedCookie[seedLen:])
	// Format the HTTP cookie
	// The format is <random letter 'A'-'Z'>=<base64 data>, which is intended to match common cookie formats.
	A := int([]byte("A")[0])
	Z := int([]byte("Z")[0])
	letterIndex, err := MakeSecureRandomInt(Z - A)
	if err != nil {
		return nil, ContextError(err)
	}
	return &http.Cookie{
			Name:  string(byte(A + letterIndex)),
			Value: base64.StdEncoding.EncodeToString(obfuscatedCookie)},
		nil
}
