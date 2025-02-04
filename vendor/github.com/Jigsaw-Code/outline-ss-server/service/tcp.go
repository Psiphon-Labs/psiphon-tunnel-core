// Copyright 2018 Jigsaw Operations LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package service

import (
	"bytes"
	"container/list"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/Jigsaw-Code/outline-sdk/transport"
	"github.com/Jigsaw-Code/outline-sdk/transport/shadowsocks"
	"github.com/shadowsocks/go-shadowsocks2/socks"

	onet "github.com/Jigsaw-Code/outline-ss-server/net"
	"github.com/Jigsaw-Code/outline-ss-server/service/metrics"
)

// TCPConnMetrics is used to report metrics on TCP connections.
type TCPConnMetrics interface {
	AddAuthenticated(accessKey string)
	AddClosed(status string, data metrics.ProxyMetrics, duration time.Duration)
	AddProbe(status, drainResult string, clientProxyBytes int64)
}

func remoteIP(conn net.Conn) netip.Addr {
	addr := conn.RemoteAddr()
	if addr == nil {
		return netip.Addr{}
	}
	if tcpaddr, ok := addr.(*net.TCPAddr); ok {
		return tcpaddr.AddrPort().Addr()
	}
	addrPort, err := netip.ParseAddrPort(addr.String())
	if err == nil {
		return addrPort.Addr()
	}
	return netip.Addr{}
}

// Wrapper for slog.Debug during TCP access key searches.
func debugTCP(l *slog.Logger, template string, cipherID string, attr slog.Attr) {
	// This is an optimization to reduce unnecessary allocations due to an interaction
	// between Go's inlining/escape analysis and varargs functions like slog.Debug.
	if l.Enabled(nil, slog.LevelDebug) {
		l.LogAttrs(nil, slog.LevelDebug, fmt.Sprintf("TCP: %s", template), slog.String("ID", cipherID), attr)
	}
}

// bytesForKeyFinding is the number of bytes to read for finding the AccessKey.
// Is must satisfy provided >= bytesForKeyFinding >= required for every cipher in the list.
// provided = saltSize + 2 + 2 * cipher.TagSize, the minimum number of bytes we will see in a valid connection
// required = saltSize + 2 + cipher.TagSize, the number of bytes needed to authenticate the connection.
const bytesForKeyFinding = 50

func findAccessKey(clientReader io.Reader, clientIP netip.Addr, cipherList CipherList, l *slog.Logger) (*CipherEntry, io.Reader, []byte, time.Duration, error) {
	// We snapshot the list because it may be modified while we use it.
	ciphers := cipherList.SnapshotForClientIP(clientIP)
	firstBytes := make([]byte, bytesForKeyFinding)
	if n, err := io.ReadFull(clientReader, firstBytes); err != nil {
		return nil, clientReader, nil, 0, fmt.Errorf("reading header failed after %d bytes: %w", n, err)
	}

	findStartTime := time.Now()
	entry, elt := findEntry(firstBytes, ciphers, l)
	timeToCipher := time.Since(findStartTime)
	if entry == nil {
		// TODO: Ban and log client IPs with too many failures too quick to protect against DoS.
		return nil, clientReader, nil, timeToCipher, fmt.Errorf("could not find valid TCP cipher")
	}

	// Move the active cipher to the front, so that the search is quicker next time.
	cipherList.MarkUsedByClientIP(elt, clientIP)
	salt := firstBytes[:entry.CryptoKey.SaltSize()]
	return entry, io.MultiReader(bytes.NewReader(firstBytes), clientReader), salt, timeToCipher, nil
}

// Implements a trial decryption search.  This assumes that all ciphers are AEAD.
func findEntry(firstBytes []byte, ciphers []*list.Element, l *slog.Logger) (*CipherEntry, *list.Element) {
	// To hold the decrypted chunk length.
	chunkLenBuf := [2]byte{}
	for ci, elt := range ciphers {
		entry := elt.Value.(*CipherEntry)
		cryptoKey := entry.CryptoKey
		_, err := shadowsocks.Unpack(chunkLenBuf[:0], firstBytes[:cryptoKey.SaltSize()+2+cryptoKey.TagSize()], cryptoKey)
		if err != nil {
			debugTCP(l, "Failed to decrypt length.", entry.ID, slog.Any("err", err))
			continue
		}
		debugTCP(l, "Found cipher.", entry.ID, slog.Int("index", ci))
		return entry, elt
	}
	return nil, nil
}

type StreamAuthenticateFunc func(clientConn transport.StreamConn) (string, transport.StreamConn, *onet.ConnectionError)

// NewShadowsocksStreamAuthenticator creates a stream authenticator that uses Shadowsocks.
// TODO(fortuna): Offer alternative transports.
func NewShadowsocksStreamAuthenticator(ciphers CipherList, replayCache *ReplayCache, metrics ShadowsocksConnMetrics, l *slog.Logger) StreamAuthenticateFunc {
	if metrics == nil {
		metrics = &NoOpShadowsocksConnMetrics{}
	}
	if l == nil {
		l = noopLogger()
	}
	return func(clientConn transport.StreamConn) (string, transport.StreamConn, *onet.ConnectionError) {
		// Find the cipher and acess key id.
		cipherEntry, clientReader, clientSalt, timeToCipher, keyErr := findAccessKey(clientConn, remoteIP(clientConn), ciphers, l)
		metrics.AddCipherSearch(keyErr == nil, timeToCipher)
		if keyErr != nil {
			const status = "ERR_CIPHER"
			return "", nil, onet.NewConnectionError(status, "Failed to find a valid cipher", keyErr)
		}
		var id string
		if cipherEntry != nil {
			id = cipherEntry.ID
		}

		// Check if the connection is a replay.
		isServerSalt := cipherEntry.SaltGenerator.IsServerSalt(clientSalt)
		// Only check the cache if findAccessKey succeeded and the salt is unrecognized.
		if isServerSalt || !replayCache.Add(cipherEntry.ID, clientSalt) {
			var status string
			if isServerSalt {
				status = "ERR_REPLAY_SERVER"
			} else {
				status = "ERR_REPLAY_CLIENT"
			}
			return id, nil, onet.NewConnectionError(status, "Replay detected", nil)
		}

		ssr := shadowsocks.NewReader(clientReader, cipherEntry.CryptoKey)
		ssw := shadowsocks.NewWriter(clientConn, cipherEntry.CryptoKey)
		ssw.SetSaltGenerator(cipherEntry.SaltGenerator)
		return id, transport.WrapConn(clientConn, ssr, ssw), nil
	}
}

type streamHandler struct {
	logger       *slog.Logger
	listenerId   string
	readTimeout  time.Duration
	authenticate StreamAuthenticateFunc
	dialer       transport.StreamDialer
}

// NewStreamHandler creates a StreamHandler
func NewStreamHandler(authenticate StreamAuthenticateFunc, timeout time.Duration) StreamHandler {
	return &streamHandler{
		logger:       noopLogger(),
		readTimeout:  timeout,
		authenticate: authenticate,
		dialer:       MakeValidatingTCPStreamDialer(onet.RequirePublicIP, 0),
	}
}

// StreamHandler is a handler that handles stream connections.
type StreamHandler interface {
	Handle(ctx context.Context, conn transport.StreamConn, connMetrics TCPConnMetrics)
	// SetLogger sets the logger used to log messages. Uses a no-op logger if nil.
	SetLogger(l *slog.Logger)
	// SetTargetDialer sets the [transport.StreamDialer] to be used to connect to target addresses.
	SetTargetDialer(dialer transport.StreamDialer)
}

func (s *streamHandler) SetLogger(l *slog.Logger) {
	if l == nil {
		l = noopLogger()
	}
	s.logger = l
}

func (s *streamHandler) SetTargetDialer(dialer transport.StreamDialer) {
	s.dialer = dialer
}

func ensureConnectionError(err error, fallbackStatus string, fallbackMsg string) *onet.ConnectionError {
	if err == nil {
		return nil
	}
	var connErr *onet.ConnectionError
	if errors.As(err, &connErr) {
		return connErr
	} else {
		return onet.NewConnectionError(fallbackStatus, fallbackMsg, err)
	}
}

type StreamAcceptFunc func() (transport.StreamConn, error)

func WrapStreamAcceptFunc[T transport.StreamConn](f func() (T, error)) StreamAcceptFunc {
	return func() (transport.StreamConn, error) {
		return f()
	}
}

type StreamHandleFunc func(ctx context.Context, conn transport.StreamConn)

// StreamServe repeatedly calls `accept` to obtain connections and `handle` to handle them until
// accept() returns [ErrClosed]. When that happens, all connection handlers will be notified
// via their [context.Context]. StreamServe will return after all pending handlers return.
func StreamServe(accept StreamAcceptFunc, handle StreamHandleFunc) {
	var running sync.WaitGroup
	defer running.Wait()
	ctx, contextCancel := context.WithCancel(context.Background())
	defer contextCancel()
	for {
		clientConn, err := accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				break
			}
			slog.Warn("Accept failed. Continuing to listen.", "err", err)
			continue
		}

		running.Add(1)
		go func() {
			defer running.Done()
			defer clientConn.Close()
			defer func() {
				if r := recover(); r != nil {
					slog.Warn("Panic in TCP handler. Continuing to listen.", "err", r)
				}
			}()
			handle(ctx, clientConn)
		}()
	}
}

func (h *streamHandler) Handle(ctx context.Context, clientConn transport.StreamConn, connMetrics TCPConnMetrics) {
	if connMetrics == nil {
		connMetrics = &NoOpTCPConnMetrics{}
	}
	var proxyMetrics metrics.ProxyMetrics
	measuredClientConn := metrics.MeasureConn(clientConn, &proxyMetrics.ProxyClient, &proxyMetrics.ClientProxy)
	connStart := time.Now()

	connError := h.handleConnection(ctx, measuredClientConn, connMetrics, &proxyMetrics)

	connDuration := time.Since(connStart)
	status := "OK"
	if connError != nil {
		status = connError.Status
		h.logger.LogAttrs(nil, slog.LevelDebug, "TCP: Error", slog.String("msg", connError.Message), slog.Any("cause", connError.Cause))
	}
	connMetrics.AddClosed(status, proxyMetrics, connDuration)
	measuredClientConn.Close() // Closing after the metrics are added aids integration testing.
	h.logger.LogAttrs(nil, slog.LevelDebug, "TCP: Done.", slog.String("status", status), slog.Duration("duration", connDuration))
}

func getProxyRequest(clientConn transport.StreamConn) (string, error) {
	// TODO(fortuna): Use Shadowsocks proxy, HTTP CONNECT or SOCKS5 based on first byte:
	// case 1, 3 or 4: Shadowsocks (address type)
	// case 5: SOCKS5 (protocol version)
	// case "C": HTTP CONNECT (first char of method)
	tgtAddr, err := socks.ReadAddr(clientConn)
	if err != nil {
		return "", err
	}
	return tgtAddr.String(), nil
}

func proxyConnection(l *slog.Logger, ctx context.Context, dialer transport.StreamDialer, tgtAddr string, clientConn transport.StreamConn) *onet.ConnectionError {
	tgtConn, dialErr := dialer.DialStream(ctx, tgtAddr)
	if dialErr != nil {
		// We don't drain so dial errors and invalid addresses are communicated quickly.
		return ensureConnectionError(dialErr, "ERR_CONNECT", "Failed to connect to target")
	}
	defer tgtConn.Close()
	l.LogAttrs(nil, slog.LevelDebug, "Proxy connection.", slog.String("client", clientConn.RemoteAddr().String()), slog.String("target", tgtConn.RemoteAddr().String()))

	fromClientErrCh := make(chan error)
	go func() {
		_, fromClientErr := io.Copy(tgtConn, clientConn)
		if fromClientErr != nil {
			// Drain to prevent a close in the case of a cipher error.
			io.Copy(io.Discard, clientConn)
		}
		clientConn.CloseRead()
		// Send FIN to target.
		// We must do this after the drain is completed, otherwise the target will close its
		// connection with the proxy, which will, in turn, close the connection with the client.
		tgtConn.CloseWrite()
		fromClientErrCh <- fromClientErr
	}()
	_, fromTargetErr := io.Copy(clientConn, tgtConn)
	// Send FIN to client.
	clientConn.CloseWrite()
	tgtConn.CloseRead()

	fromClientErr := <-fromClientErrCh
	if fromClientErr != nil {
		return onet.NewConnectionError("ERR_RELAY_CLIENT", "Failed to relay traffic from client", fromClientErr)
	}
	if fromTargetErr != nil {
		return onet.NewConnectionError("ERR_RELAY_TARGET", "Failed to relay traffic from target", fromTargetErr)
	}
	return nil
}

func (h *streamHandler) handleConnection(ctx context.Context, outerConn transport.StreamConn, connMetrics TCPConnMetrics, proxyMetrics *metrics.ProxyMetrics) *onet.ConnectionError {
	// Set a deadline to receive the address to the target.
	readDeadline := time.Now().Add(h.readTimeout)
	if deadline, ok := ctx.Deadline(); ok {
		outerConn.SetDeadline(deadline)
		if deadline.Before(readDeadline) {
			readDeadline = deadline
		}
	}
	outerConn.SetReadDeadline(readDeadline)

	id, innerConn, authErr := h.authenticate(outerConn)
	if authErr != nil {
		// Drain to protect against probing attacks.
		h.absorbProbe(outerConn, connMetrics, authErr.Status, proxyMetrics)
		return authErr
	}
	connMetrics.AddAuthenticated(id)

	// Read target address and dial it.
	tgtAddr, err := getProxyRequest(innerConn)
	// Clear the deadline for the target address
	outerConn.SetReadDeadline(time.Time{})
	if err != nil {
		// Drain to prevent a close on cipher error.
		io.Copy(io.Discard, outerConn)
		return onet.NewConnectionError("ERR_READ_ADDRESS", "Failed to get target address", err)
	}

	dialer := transport.FuncStreamDialer(func(ctx context.Context, addr string) (transport.StreamConn, error) {
		tgtConn, err := h.dialer.DialStream(ctx, tgtAddr)
		if err != nil {
			return nil, err
		}
		tgtConn = metrics.MeasureConn(tgtConn, &proxyMetrics.ProxyTarget, &proxyMetrics.TargetProxy)
		return tgtConn, nil
	})
	return proxyConnection(h.logger, ctx, dialer, tgtAddr, innerConn)
}

// Keep the connection open until we hit the authentication deadline to protect against probing attacks
// `proxyMetrics` is a pointer because its value is being mutated by `clientConn`.
func (h *streamHandler) absorbProbe(clientConn io.ReadCloser, connMetrics TCPConnMetrics, status string, proxyMetrics *metrics.ProxyMetrics) {
	// This line updates proxyMetrics.ClientProxy before it's used in AddTCPProbe.
	_, drainErr := io.Copy(io.Discard, clientConn) // drain socket
	drainResult := drainErrToString(drainErr)
	h.logger.LogAttrs(nil, slog.LevelDebug, "Drain error.", slog.Any("err", drainErr), slog.String("result", drainResult))
	connMetrics.AddProbe(status, drainResult, proxyMetrics.ClientProxy)
}

func drainErrToString(drainErr error) string {
	netErr, ok := drainErr.(net.Error)
	switch {
	case drainErr == nil:
		return "eof"
	case ok && netErr.Timeout():
		return "timeout"
	default:
		return "other"
	}
}

// NoOpTCPConnMetrics is a [TCPConnMetrics] that doesn't do anything. Useful in tests
// or if you don't want to track metrics.
type NoOpTCPConnMetrics struct{}

var _ TCPConnMetrics = (*NoOpTCPConnMetrics)(nil)

func (m *NoOpTCPConnMetrics) AddAuthenticated(accessKey string) {}

func (m *NoOpTCPConnMetrics) AddClosed(status string, data metrics.ProxyMetrics, duration time.Duration) {
}

func (m *NoOpTCPConnMetrics) AddProbe(status, drainResult string, clientProxyBytes int64) {}
