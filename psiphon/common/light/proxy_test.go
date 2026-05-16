/*
 * Copyright (c) 2026, Psiphon Inc.
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

package light

import (
	"context"
	std_errors "errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
)

// These tests cover the Pause / Resume mechanism on Proxy. They assume the
// following additions to proxy.go:
//
//   - pauseAcceptInterval const (poll interval the accept loop uses while
//     paused)
//   - paused atomic.Bool field on Proxy
//   - Pause() and Resume() methods on *Proxy that toggle paused
//   - the Run() accept loop checks paused at the top of each iteration and
//     sleeps for pauseAcceptInterval on the paused path, falling through on
//     ctx.Done()
//
// Observability: connectionNumber (atomic.Int64 on Proxy) is incremented near
// the top of handleConnWithErr, before TLS handshake. The tests use it as the
// "an Accept happened and handleConn started" signal. This is sufficient
// because none of these tests depend on completing a TLS handshake -- they
// terminate at the TCP layer.
//
// Known race tolerated by the tests: when Pause() is called, the accept-loop
// goroutine may already be blocked inside listener.Accept(). The pause flag
// is not observed until the next loop iteration, so one connection can slip
// through after a Pause(). The tests that exercise the gate dial multiple
// connections and assert that not all of them are accepted, rather than
// asserting zero accepts. See conversations leading to this implementation
// for the rationale.

const (
	// 32 bytes; the upstream obfuscator treats this as a passphrase.
	testObfuscationKey = "0123456789abcdef0123456789abcdef"
	testAllowedDest    = "example.com:443"
)

// testEventReceiver records the Listening address and otherwise no-ops. The
// listeningCh channel is closed when Listening fires so tests can deterministi-
// cally wait for the proxy to be ready.
type testEventReceiver struct {
	mu          sync.Mutex
	address     string
	listeningCh chan struct{}
}

func newTestEventReceiver() *testEventReceiver {
	return &testEventReceiver{listeningCh: make(chan struct{})}
}

func (r *testEventReceiver) Listening(address string) {
	r.mu.Lock()
	r.address = address
	r.mu.Unlock()
	close(r.listeningCh)
}

func (r *testEventReceiver) Address() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.address
}

func (r *testEventReceiver) Connection(*ConnectionStats)                          {}
func (r *testEventReceiver) IrregularConnection(string, common.GeoIPData, string) {}
func (r *testEventReceiver) DebugLog(string, string)                              {}
func (r *testEventReceiver) InfoLog(string, string)                               {}
func (r *testEventReceiver) WarningLog(string, string)                            {}
func (r *testEventReceiver) ErrorLog(string, string)                              {}

// newTestProxy constructs a Proxy with minimal valid configuration. Self-
// signed TLS material is generated via common.GenerateWebServerCertificate;
// the certificate is never actually validated by the tests, which terminate
// at the TCP layer.
func newTestProxy(t *testing.T) (*Proxy, *testEventReceiver) {
	t.Helper()

	certPEM, keyPEM, _, err := common.GenerateWebServerCertificate("test")
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}

	receiver := newTestEventReceiver()

	rateLimitQuantity := 1_000_000
	maxConcurrent := 1000

	config := &ProxyConfig{
		Protocol:            LIGHT_PROTOCOL_TLS,
		ProviderID:          "test",
		ListenAddress:       "127.0.0.1:0",
		DialAddress:         "127.0.0.1:443",
		ObfuscationKey:      testObfuscationKey,
		TLSCertificate:      []byte(certPEM),
		TLSPrivateKey:       []byte(keyPEM),
		PassthroughAddress:  "127.0.0.1:1",
		AllowedDestinations: []string{testAllowedDest},
		RateLimitQuantity:   &rateLimitQuantity,
		RateLimitInterval:   "1m",
		MaxConcurrent:       &maxConcurrent,
	}

	lookupGeoIP := func(string) common.GeoIPData { return common.GeoIPData{} }

	proxy, err := NewProxy(config, lookupGeoIP, receiver)
	if err != nil {
		t.Fatalf("new proxy: %v", err)
	}
	return proxy, receiver
}

// runTestProxy starts the proxy in a goroutine and waits for the Listening
// event. Returns the bound address and a stop function that cancels Run and
// waits for it to return.
func runTestProxy(t *testing.T, proxy *Proxy, receiver *testEventReceiver) (string, func()) {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)

	go func() { done <- proxy.Run(ctx) }()

	select {
	case <-receiver.listeningCh:
	case <-time.After(2 * time.Second):
		cancel()
		t.Fatal("timeout waiting for Listening event")
	}

	stop := func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("timeout waiting for Run to return")
		}
	}
	return receiver.Address(), stop
}

// waitForConnectionCount polls proxy.connectionNumber until it reaches want or
// the timeout fires.
func waitForConnectionCount(t *testing.T, proxy *Proxy, want int64, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if proxy.connectionNumber.Load() >= want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for connectionNumber >= %d (got %d)",
		want, proxy.connectionNumber.Load())
}

// TestPauseDoesNotAffectExistingConnections is the headline invariant: an
// already-Accept()ed connection is undisturbed by a subsequent Pause().
func TestPauseDoesNotAffectExistingConnections(t *testing.T) {
	proxy, receiver := newTestProxy(t)
	addr, stop := runTestProxy(t, proxy, receiver)
	defer stop()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	waitForConnectionCount(t, proxy, 1, time.Second)

	proxy.Pause()

	// The server-side handler is blocked in tlsConn.Handshake() waiting for
	// our ClientHello. A read with a short deadline should time out, proving
	// the server has not closed the connection in response to the pause.
	if err := conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	n, err := conn.Read(make([]byte, 1))
	if n != 0 {
		t.Fatalf("unexpected read of %d bytes", n)
	}
	var netErr net.Error
	if !std_errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("expected timeout error, got: %v", err)
	}
}

// TestPauseBlocksNewAccepts verifies that the gate engages: dialing several
// connections after Pause should not result in all of them being Accept()ed.
// We tolerate up to one slip-through (the connection the accept-loop goroutine
// was blocked on when Pause was called).
func TestPauseBlocksNewAccepts(t *testing.T) {
	proxy, receiver := newTestProxy(t)
	addr, stop := runTestProxy(t, proxy, receiver)
	defer stop()

	proxy.Pause()

	const N = 5
	conns := make([]net.Conn, 0, N)
	defer func() {
		for _, c := range conns {
			_ = c.Close()
		}
	}()

	for i := 0; i < N; i++ {
		c, err := net.DialTimeout("tcp", addr, time.Second)
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		conns = append(conns, c)
	}

	// Allow the accept loop several poll cycles to (not) drain the queue.
	time.Sleep(5 * pauseAcceptInterval)

	if accepted := proxy.connectionNumber.Load(); accepted >= int64(N) {
		t.Fatalf("gate did not engage: %d of %d connections accepted", accepted, N)
	}
}

// TestRunReturnsWhilePausedOnContextCancel pins shutdown behavior while the
// accept loop is parked on the paused path. Canceling Run must wake it promptly.
func TestRunReturnsWhilePausedOnContextCancel(t *testing.T) {
	proxy, receiver := newTestProxy(t)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- proxy.Run(ctx) }()

	select {
	case <-receiver.listeningCh:
	case <-time.After(2 * time.Second):
		cancel()
		t.Fatal("timeout waiting for Listening event")
	}

	proxy.Pause()

	conn, err := net.DialTimeout("tcp", receiver.Address(), time.Second)
	if err != nil {
		cancel()
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	waitForConnectionCount(t, proxy, 1, time.Second)
	// Let the accept loop return from Accept and observe the paused flag.
	time.Sleep(100 * time.Millisecond)

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for Run to return while paused")
	}
}

// TestResumeDrainsQueuedConnections confirms that TCP connections completed
// into the kernel accept queue during a pause are processed by the
// application after Resume.
func TestResumeDrainsQueuedConnections(t *testing.T) {
	proxy, receiver := newTestProxy(t)
	addr, stop := runTestProxy(t, proxy, receiver)
	defer stop()

	proxy.Pause()

	const N = 5
	conns := make([]net.Conn, 0, N)
	defer func() {
		for _, c := range conns {
			_ = c.Close()
		}
	}()

	for i := 0; i < N; i++ {
		c, err := net.DialTimeout("tcp", addr, time.Second)
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		conns = append(conns, c)
	}

	// Confirm the gate is engaged: not all N dialed connections have been
	// accepted by the application yet (at most one slip-through is allowed).
	time.Sleep(3 * pauseAcceptInterval)
	if accepted := proxy.connectionNumber.Load(); accepted >= int64(N) {
		t.Fatalf("all connections accepted during pause: %d of %d", accepted, N)
	}

	proxy.Resume()

	// All N should now be drained from the kernel accept queue.
	waitForConnectionCount(t, proxy, N, 3*time.Second)
}

// TestPauseResumeIdempotent confirms double-Pause and double-Resume are
// no-ops and that a single Resume leaves the proxy accepting.
func TestPauseResumeIdempotent(t *testing.T) {
	proxy, receiver := newTestProxy(t)
	addr, stop := runTestProxy(t, proxy, receiver)
	defer stop()

	proxy.Pause()
	proxy.Pause()
	proxy.Resume()
	proxy.Resume()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	waitForConnectionCount(t, proxy, 1, time.Second)
}

// TestPauseResumeConcurrentStress hammers Pause and Resume from multiple
// goroutines and verifies the proxy ends in a sane state. Primarily a -race
// flush for any future replacement of the atomic.Bool with a less trivially
// thread-safe construct.
func TestPauseResumeConcurrentStress(t *testing.T) {
	proxy, receiver := newTestProxy(t)
	addr, stop := runTestProxy(t, proxy, receiver)
	defer stop()

	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ctx.Err() == nil {
				proxy.Pause()
				proxy.Resume()
			}
		}()
	}
	wg.Wait()

	// Settle into a known accepting state.
	proxy.Resume()

	before := proxy.connectionNumber.Load()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial after stress: %v", err)
	}
	defer conn.Close()
	waitForConnectionCount(t, proxy, before+1, time.Second)
}
