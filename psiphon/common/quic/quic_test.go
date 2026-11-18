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

package quic

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	tls "github.com/Psiphon-Labs/psiphon-tls"
	ietf_quic "github.com/Psiphon-Labs/quic-go"
	"github.com/Psiphon-Labs/quic-go/logging"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/obfuscator"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/sync/errgroup"
)

func TestQUIC(t *testing.T) {
	for quicVersion := range supportedVersionNumbers {

		t.Run(fmt.Sprintf("%s", quicVersion), func(t *testing.T) {
			if isGQUIC(quicVersion) && !GQUICEnabled() {
				t.Skipf("gQUIC is not enabled")
			}
			runQUIC(t, quicVersion, GQUICEnabled(),
				false,
				false, // obfuscated PSK not supported in gQUIC
				false)
		})

		for _, useObfuscatedPSK := range []bool{false, true} {
			if isIETF(quicVersion) {
				t.Run(fmt.Sprintf("%s (invoke anti-probing)|PSK=%v", quicVersion, useObfuscatedPSK), func(t *testing.T) {
					runQUIC(t, quicVersion, GQUICEnabled(), true, useObfuscatedPSK, false)
				})
			}
			if isIETF(quicVersion) {
				t.Run(fmt.Sprintf("%s (disable gQUIC)|PSK=%v", quicVersion, useObfuscatedPSK), func(t *testing.T) {
					runQUIC(t, quicVersion, false, false, useObfuscatedPSK, false)
				})
			}
			if isIETF(quicVersion) {
				t.Run(fmt.Sprintf("%s (require source address validation)|PSK=%v", quicVersion, useObfuscatedPSK), func(t *testing.T) {
					runQUIC(t, quicVersion, GQUICEnabled(), false, useObfuscatedPSK, true)
				})
			}
		}
	}
}

func runQUIC(
	t *testing.T,
	quicVersion string,
	enableGQUIC bool,
	invokeAntiProbing bool,
	useObfuscatedPSK bool,
	requireSourceAddressValidation bool) {

	initGoroutines := getGoroutines()

	clients := 10
	bytesToSend := 1 << 20

	serverReceivedBytes := int64(0)
	clientReceivedBytes := int64(0)

	// Intermittently, on some platforms, the client connection termination
	// packet is not received even when sent/received locally; set a brief
	// idle timeout to ensure the server-side client handler doesn't block too
	// long on Read, causing the test to fail.
	//
	// In realistic network conditions, and especially under adversarial
	// network conditions, we should not expect to regularly receive client
	// connection termination packets.
	serverIdleTimeout = 1 * time.Second

	// Shorten peer mode lifetimes so the peer maps drain within the test.
	// With requireSourceAddressValidation, every Initial requires it.
	pendingPeerTimeout = 1 * time.Second
	unestablishedPeerTimeout = 1 * time.Second
	if requireSourceAddressValidation {
		sourceAddressValidationTriggerConcurrentHandshakes = 0
	}
	defer func() {
		serverIdleTimeout = SERVER_IDLE_TIMEOUT
		pendingPeerTimeout = PENDING_PEER_TIMEOUT
		unestablishedPeerTimeout = UNESTABLISHED_PEER_TIMEOUT
		sourceAddressValidationTriggerConcurrentHandshakes = SOURCE_ADDRESS_VALIDATION_TRIGGER_CONCURRENT_HANDSHAKES
	}()

	irregularTunnelLogger := func(_ string, err error, _ common.LogFields) {
		if !invokeAntiProbing {
			t.Errorf("unexpected irregular tunnel event: %v", err)
		}
	}

	obfuscationKey := prng.HexString(32)

	// Disabling MTU discovery is exercised in in-proxy test cases.
	disablePathMTUDiscovery := false

	listener, err := Listen(
		nil,
		irregularTunnelLogger,
		"127.0.0.1:0",
		disablePathMTUDiscovery,
		0,
		obfuscationKey,
		enableGQUIC)
	if err != nil {
		t.Fatalf("Listen failed: %s", err)
	}

	serverAddress := listener.Addr().String()

	testGroup, testCtx := errgroup.WithContext(context.Background())

	testGroup.Go(func() error {

		if invokeAntiProbing {
			// The quic-go server can still handshake new sessions even if
			// Accept isn't called.
			return nil
		}

		var serverGroup errgroup.Group

		for i := 0; i < clients; i++ {

			conn, err := listener.Accept()
			if err != nil {
				return errors.Trace(err)
			}

			serverGroup.Go(func() error {
				b := make([]byte, 1024)
				for {
					n, err := conn.Read(b)
					atomic.AddInt64(&serverReceivedBytes, int64(n))
					if err == io.EOF {
						return nil
					} else if err != nil {
						return errors.Trace(err)
					}
					_, err = conn.Write(b[:n])
					if err != nil {
						return errors.Trace(err)
					}
				}
			})
		}

		err := serverGroup.Wait()
		if err != nil {
			return errors.Trace(err)
		}

		return nil
	})

	for i := 0; i < clients; i++ {

		disablePathMTUDiscovery := i%2 == 0

		testGroup.Go(func() error {

			ctx, cancelFunc := context.WithTimeout(
				context.Background(), 1*time.Second)
			defer cancelFunc()

			remoteAddr, err := net.ResolveUDPAddr("udp", serverAddress)
			if err != nil {
				return errors.Trace(err)
			}

			packetConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				return errors.Trace(err)
			}

			clientObfuscationKey := obfuscationKey
			if invokeAntiProbing {
				clientObfuscationKey = prng.HexString(32)
				packetConn = &countReadsConn{PacketConn: packetConn}
			}

			obfuscationPaddingSeed, err := prng.NewSeed()
			if err != nil {
				return errors.Trace(err)
			}

			var clientHelloSeed *prng.Seed
			if isClientHelloRandomized(quicVersion) {
				clientHelloSeed, err = prng.NewSeed()
				if err != nil {
					return errors.Trace(err)
				}
			}

			quicSNIAddress, _, err := net.SplitHostPort(serverAddress)
			if err != nil {
				return errors.Trace(err)
			}

			clientSessionCache := common.WrapClientSessionCache(tls.NewLRUClientSessionCache(0), "localhost")

			conn, err := Dial(
				ctx,
				packetConn,
				remoteAddr,
				quicSNIAddress,
				quicVersion,
				clientHelloSeed,
				clientObfuscationKey,
				obfuscationPaddingSeed,
				nil,
				disablePathMTUDiscovery,
				0,
				true,
				useObfuscatedPSK,
				clientSessionCache)

			if invokeAntiProbing {

				if err == nil {
					return errors.TraceNew(
						"unexpected dial success with invalid client hello random")
				}

				readCount := packetConn.(*countReadsConn).getReadCount()

				if readCount > 0 {
					return errors.Tracef(
						"unexpected %d read packets with invalid client hello random",
						readCount)
				}

				return nil
			}

			if err != nil {
				return errors.Trace(err)
			}

			if isObfuscated(quicVersion) {
				// Wait for server establishment before attempting a mode change.
				serverPacketConn := listener.(*Listener).packetConn.ObfuscatedPacketConn
				address := peerAddress(packetConn.LocalAddr().(*net.UDPAddr))
				for {
					serverPacketConn.peerModesMutex.Lock()
					_, state, ok := serverPacketConn.lookupPeer(address)
					serverPacketConn.peerModesMutex.Unlock()
					if ok && state == peerEstablished {
						break
					}
					select {
					case <-ctx.Done():
						conn.Close()
						return errors.Trace(ctx.Err())
					case <-time.After(10 * time.Millisecond):
					}
				}

				// A plain Initial from the same address must not break the
				// obfuscated connection's subsequent data transfer.
				_, err = packetConn.WriteTo(
					makeInitialPacket(t, func([]byte) {}), remoteAddr)
				if err != nil {
					conn.Close()
					return errors.Trace(err)
				}
			}

			// Cancel should interrupt dialing only
			cancelFunc()

			var clientGroup errgroup.Group

			clientGroup.Go(func() error {
				defer conn.Close()
				b := make([]byte, 1024)
				bytesRead := 0
				for bytesRead < bytesToSend {
					n, err := conn.Read(b)
					bytesRead += n
					atomic.AddInt64(&clientReceivedBytes, int64(n))
					if err == io.EOF {
						break
					} else if err != nil {
						return errors.Trace(err)
					}
				}
				return nil
			})

			clientGroup.Go(func() error {
				b := make([]byte, bytesToSend)
				_, err := conn.Write(b)
				if err != nil {
					return errors.Trace(err)
				}
				return nil
			})

			return clientGroup.Wait()
		})

	}

	go func() {
		testGroup.Wait()
	}()

	<-testCtx.Done()

	// Peers lacking the obfuscation key are never promoted from pending.
	if invokeAntiProbing {
		_, responded, _, _ := getPeerCounts(listener)
		if responded != 0 {
			t.Errorf("unexpected responded peers: %d", responded)
		}
	}

	metrics := listener.(*Listener).GetQUICCounterMetrics()
	droppedFlows := metrics["quic_dropped_flow_count"].(int64)
	evictedFlows := metrics["quic_evicted_flow_count"].(int64)
	if droppedFlows != 0 || evictedFlows != 0 {
		t.Errorf("unexpected dropped flows: %d, evicted flows: %d", droppedFlows, evictedFlows)
	}
	if requireSourceAddressValidation && metrics["quic_source_address_validation_count"].(int64) == 0 {
		t.Errorf("unexpected no source address validations")
	}

	// Both peer maps drain once connections close.
	if !waitForPeerCounts(listener, 0, 0, 0, 0) {
		t.Errorf("unexpected peer counts: %s", peerCountsString(listener))
	}

	listener.Close()

	err = testGroup.Wait()
	if err != nil {
		t.Errorf("goroutine failed: %s", err)
	}

	bytes := atomic.LoadInt64(&serverReceivedBytes)
	expectedBytes := int64(clients * bytesToSend)
	if invokeAntiProbing {
		expectedBytes = 0
	}
	if bytes != expectedBytes {
		t.Errorf("unexpected serverReceivedBytes: %d vs. %d", bytes, expectedBytes)
	}

	bytes = atomic.LoadInt64(&clientReceivedBytes)
	if bytes != expectedBytes {
		t.Errorf("unexpected clientReceivedBytes: %d vs. %d", bytes, expectedBytes)
	}

	_, err = listener.Accept()
	if err == nil {
		t.Error("unexpected Accept after Close")
	}

	// Check for unexpected dangling goroutines after shutdown.
	//
	// quic-go.packetHandlerMap.listen shutdown is async and some quic-go
	// goroutines and/or timers dangle so this test makes allowances for these
	// known dangling goroutinees.

	expectedDanglingGoroutines := []string{
		"quic-go.(*packetHandlerMap).Retire.func1",
		"quic-go.(*packetHandlerMap).ReplaceWithClosed.func1",
		"quic-go.(*packetHandlerMap).ReplaceWithClosed.func2",
		"quic-go.(*packetHandlerMap).RetireResetToken.func1",
		"gquic-go.(*packetHandlerMap).removeByConnectionIDAsString.func1",
	}

	sleepTime := 100 * time.Millisecond

	// The longest expected dangling goroutine is in gquic-go and is launched by a timer
	// that fires after ClosedSessionDeleteTimeout, which is 1m. Allow one extra second
	// to ensure this period elapses and the time.AfterFunc runs.
	//
	// To avoid taking 1m to run this test every time, the dangling goroutine check exits
	// early once no dangling goroutines are found. Note that this doesn't account for
	// any timers still pending at the early exit time.
	n := int((61 * time.Second) / sleepTime)

	for i := 0; i < n; i++ {

		// Sleep before making any checks, since quic-go.packetHandlerMap.listen
		// shutdown is asynchronous.
		time.Sleep(100 * time.Millisecond)

		// After the full 61s, no dangling goroutines are expected.
		if i == n-1 {
			expectedDanglingGoroutines = []string{}
		}

		hasDangling, onlyExpectedDangling := checkDanglingGoroutines(
			t, initGoroutines, expectedDanglingGoroutines)
		if !hasDangling {
			break
		} else if !onlyExpectedDangling {
			t.Fatalf("unexpected dangling goroutines")
		}
	}
}

// getPeerCounts returns the pending, responded, and unestablished peer
// counts, and the handshakes in flight, which must return to 0 whenever
// connections close.
func getPeerCounts(listener net.Listener) (int, int, int, int) {
	conn := listener.(*Listener).packetConn.ObfuscatedPacketConn
	conn.peerModesMutex.Lock()
	defer conn.peerModesMutex.Unlock()
	unestablished := len(conn.peers[peerUnestablished])
	responded := unestablished + len(conn.peers[peerEstablished])
	return len(conn.peers[peerPending]), responded, unestablished,
		int(conn.concurrentHandshakeCount.Load())
}

func peerCountsString(listener net.Listener) string {
	pending, responded, unestablished, handshakes := getPeerCounts(listener)
	return fmt.Sprintf("%d pending, %d responded, %d unestablished, %d handshakes",
		pending, responded, unestablished, handshakes)
}

func waitForPeerCounts(
	listener net.Listener, pending, responded, unestablished, handshakes int) bool {

	for i := 0; i < 100; i++ {
		p, r, u, h := getPeerCounts(listener)
		if p == pending && r == responded && u == unestablished && h == handshakes {
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}

type countReadsConn struct {
	net.PacketConn
	readCount int32
}

func (conn *countReadsConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, addr, err := conn.PacketConn.ReadFrom(p)
	if n > 0 {
		atomic.AddInt32(&conn.readCount, 1)
	}
	return n, addr, err
}

func (conn *countReadsConn) getReadCount() int {
	return int(atomic.LoadInt32(&conn.readCount))
}

func getGoroutines() []runtime.StackRecord {
	n, _ := runtime.GoroutineProfile(nil)
	for {
		r := make([]runtime.StackRecord, n)
		var ok bool
		n, ok = runtime.GoroutineProfile(r)
		if ok {
			return r[:n]
		}
		// Retry; a goroutine may have spawned between GoroutineProfile calls,
		// so n is now too small.
	}
}

func checkDanglingGoroutines(
	t *testing.T,
	initGoroutines []runtime.StackRecord,
	expectedDanglingGoroutines []string) (bool, bool) {

	hasDangling := false
	onlyExpectedDangling := true
	current := getGoroutines()
	for _, g := range current {
		found := false
		for _, h := range initGoroutines {
			if g == h {
				found = true
				break
			}
		}
		if !found {
			stack := g.Stack()
			funcNames := make([]string, len(stack))
			skip := false
			isExpected := false
			for i := 0; i < len(stack); i++ {
				funcNames[i] = getFunctionName(stack[i])

				// The current goroutine won't have the same stack as in initGoroutines.
				if strings.Contains(funcNames[i], "checkDanglingGoroutines") {
					skip = true
					break
				}

				// testing.T.Run runs the the test function, f, in another goroutine. f is
				// the current goroutine, which captures initGoroutines.
				// https://github.com/golang/go/blob/release-branch.go1.13/src/testing/testing.go#L960-L961:
				//
				//     go tRunner(t, f)
				//     if !<-t.signal {
				//     ...
				//
				// f may capture initGoroutines before or after testing.T.Run advances to
				// the channel receive, so the stack of the testing.T.Run goroutine may or
				// may not match initGoroutines. Skip it.
				if strings.Contains(funcNames[i], "testing.(*T).Run") {
					skip = true
					break
				}

				// This goroutine, created by Listener.clientRandomHistory,
				// terminates nondeterministically, based on garbage
				// collection. Skip it.
				if strings.Contains(funcNames[i], "go-cache-lru.(*janitor).Run") {
					skip = true
					break
				}

				for _, expected := range expectedDanglingGoroutines {
					if strings.Contains(funcNames[i], expected) {
						isExpected = true
						break
					}
				}
				if isExpected {
					break
				}
			}
			if !skip {
				hasDangling = true
				if !isExpected {
					onlyExpectedDangling = false
					s := strings.Join(funcNames, " <- ")
					t.Logf("found unexpected dangling goroutine: %s", s)
				}
			}
		}
	}
	return hasDangling, onlyExpectedDangling
}

func getFunctionName(pc uintptr) string {
	funcName := runtime.FuncForPC(pc).Name()
	index := strings.LastIndex(funcName, "/")
	if index != -1 {
		funcName = funcName[index+1:]
	}
	return funcName
}

func TestQUICPeerLimits(t *testing.T) {

	var quicVersion string
	for v := range supportedVersionNumbers {
		if isIETF(v) {
			quicVersion = v
			break
		}
	}

	maxPeers = 2
	pendingPeerTimeout = 3 * time.Second
	unestablishedPeerTimeout = 1 * time.Second
	sourceAddressValidationTriggerConcurrentHandshakes = 1
	maxConcurrentHandshakesPerIP = 1
	maxConcurrentHandshakes = 2
	defer func() {
		maxPeers = MAX_PEERS
		pendingPeerTimeout = PENDING_PEER_TIMEOUT
		unestablishedPeerTimeout = UNESTABLISHED_PEER_TIMEOUT
		sourceAddressValidationTriggerConcurrentHandshakes = SOURCE_ADDRESS_VALIDATION_TRIGGER_CONCURRENT_HANDSHAKES
		maxConcurrentHandshakesPerIP = MAX_CONCURRENT_HANDSHAKES_PER_IP
		maxConcurrentHandshakes = MAX_CONCURRENT_HANDSHAKES
	}()

	obfuscationKey := prng.HexString(32)

	listener, err := Listen(
		nil,
		func(string, error, common.LogFields) {},
		"127.0.0.1:0",
		false,
		0,
		obfuscationKey,
		false)
	if err != nil {
		t.Fatalf("Listen failed: %s", err)
	}
	defer listener.Close()

	serverAddress := listener.Addr().String()

	remoteAddr, err := net.ResolveUDPAddr("udp", serverAddress)
	if err != nil {
		t.Fatalf("ResolveUDPAddr failed: %s", err)
	}

	dial := func(timeout time.Duration, localAddress string) (net.Conn, error) {

		ctx, cancelFunc := context.WithTimeout(context.Background(), timeout)
		defer cancelFunc()

		packetConn, err := net.ListenPacket("udp4", localAddress)
		if err != nil {
			return nil, errors.Trace(err)
		}

		obfuscationPaddingSeed, err := prng.NewSeed()
		if err != nil {
			return nil, errors.Trace(err)
		}

		var clientHelloSeed *prng.Seed
		if isClientHelloRandomized(quicVersion) {
			clientHelloSeed, err = prng.NewSeed()
			if err != nil {
				return nil, errors.Trace(err)
			}
		}

		quicSNIAddress, _, err := net.SplitHostPort(serverAddress)
		if err != nil {
			return nil, errors.Trace(err)
		}

		return Dial(
			ctx,
			packetConn,
			remoteAddr,
			quicSNIAddress,
			quicVersion,
			clientHelloSeed,
			obfuscationKey,
			obfuscationPaddingSeed,
			nil,
			false,
			0,
			true,
			false,
			common.WrapClientSessionCache(tls.NewLRUClientSessionCache(0), "localhost"))
	}

	obfuscatedConn := listener.(*Listener).packetConn.ObfuscatedPacketConn

	flood := func(packetSize int) {
		for i := 0; i < 2*maxPeers; i++ {
			packetConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("ListenPacket failed: %s", err)
			}
			_, err = packetConn.WriteTo(prng.Bytes(packetSize), remoteAddr)
			packetConn.Close()
			if err != nil {
				t.Fatalf("WriteTo failed: %s", err)
			}
		}
	}

	// Below MIN_FIRST_PACKET_SIZE, no peer state is allocated.

	flood(1)
	time.Sleep(100 * time.Millisecond)

	if pending, responded, _, _ := getPeerCounts(listener); pending != 0 || responded != 0 {
		t.Fatalf("unexpected peer counts: %s", peerCountsString(listener))
	}

	// Full-size keyless packets reach anti-probing but get no response:
	// pending peers are evicted beyond maxPeers, none is promoted, and
	// source address validation is never required.

	flood(MAX_PRE_DISCOVERY_PACKET_SIZE)

	if !waitForPeerCounts(listener, maxPeers, 0, 0, 0) {
		t.Fatalf("unexpected peer counts: %s", peerCountsString(listener))
	}
	time.Sleep(100 * time.Millisecond)

	metrics := listener.(*Listener).GetQUICCounterMetrics()
	droppedFlows := metrics["quic_dropped_flow_count"].(int64)
	evictedFlows := metrics["quic_evicted_flow_count"].(int64)
	validations := metrics["quic_source_address_validation_count"].(int64)
	if droppedFlows != 0 || evictedFlows == 0 || validations != 0 {
		t.Fatalf("unexpected peer metrics: %d dropped, %d evicted, %d validations",
			droppedFlows, evictedFlows, validations)
	}

	// A write to a pending peer, such as a Retry, does not change its
	// state; only a quic-go connection allocation does.

	packetConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket failed: %s", err)
	}
	defer packetConn.Close()
	_, err = packetConn.WriteTo(prng.Bytes(MAX_PRE_DISCOVERY_PACKET_SIZE), remoteAddr)
	if err != nil {
		t.Fatalf("WriteTo failed: %s", err)
	}
	time.Sleep(100 * time.Millisecond)

	_, err = obfuscatedConn.WriteTo([]byte{0}, packetConn.LocalAddr())
	if err != nil {
		t.Fatalf("WriteTo failed: %s", err)
	}

	obfuscatedConn.peerModesMutex.Lock()
	_, isPending := obfuscatedConn.peers[peerPending][peerAddress(
		packetConn.LocalAddr().(*net.UDPAddr))]
	obfuscatedConn.peerModesMutex.Unlock()
	if !isPending {
		t.Fatalf("pending peer promoted by write")
	}

	// Handshakes are simulated through the admission and tracer callbacks.
	// A handshake that ends without completing returns its peer to pending.

	pendingAddress := peerAddress(packetConn.LocalAddr().(*net.UDPAddr))
	stateOf := func() peerState {
		obfuscatedConn.peerModesMutex.Lock()
		defer obfuscatedConn.peerModesMutex.Unlock()
		_, state, _ := obfuscatedConn.lookupPeer(pendingAddress)
		return state
	}

	startHandshake := func(validated bool) (*logging.ConnectionTracer, error) {
		connConfig, err := obfuscatedConn.handshakeStarted(
			&ietf_quic.Config{},
			&ietf_quic.ClientHelloInfo{RemoteAddr: packetConn.LocalAddr(), AddrVerified: validated})
		if err != nil {
			return nil, err
		}
		return connConfig.Tracer(
			context.Background(), logging.PerspectiveServer, ietf_quic.ConnectionID{}), nil
	}

	tracer, err := startHandshake(false)
	if err != nil {
		t.Fatalf("handshakeStarted failed: %s", err)
	}
	if stateOf() != peerUnestablished {
		t.Fatalf("unexpected peer state after handshake start: %d", stateOf())
	}
	tracer.ClosedConnection(nil)
	if stateOf() != peerPending {
		t.Fatalf("unexpected peer state after handshake close: %d", stateOf())
	}

	// A completed handshake establishes the peer, and the close of its last
	// connection returns the peer to pending at once. An overlapping
	// handshake keeps the peer unestablished through that close.

	tracer1, err := startHandshake(false)
	if err != nil {
		t.Fatalf("handshakeStarted failed: %s", err)
	}
	tracer1.ChoseALPN("")
	if stateOf() != peerEstablished {
		t.Fatalf("unexpected peer state after handshake completion: %d", stateOf())
	}
	tracer2, err := startHandshake(false)
	if err != nil {
		t.Fatalf("handshakeStarted failed: %s", err)
	}
	tracer1.ClosedConnection(nil)
	if stateOf() != peerUnestablished {
		t.Fatalf("unexpected peer state after overlapped close: %d", stateOf())
	}
	tracer2.ChoseALPN("")
	if stateOf() != peerEstablished {
		t.Fatalf("unexpected peer state after second completion: %d", stateOf())
	}
	tracer2.ClosedConnection(nil)
	if stateOf() != peerPending {
		t.Fatalf("unexpected peer state after last close: %d", stateOf())
	}

	// Each refused admission counts once as a limited flow.

	localIP := netip.MustParseAddr("127.0.0.1")

	listener.(*Listener).GetQUICCounterMetrics()
	obfuscatedConn.concurrentHandshakeCount.Add(2)
	if _, err := startHandshake(false); err == nil {
		t.Fatalf("unexpected admission at concurrent handshake limit")
	}
	obfuscatedConn.concurrentHandshakeCount.Add(-2)
	obfuscatedConn.peerModesMutex.Lock()
	obfuscatedConn.concurrentHandshakesByIP[localIP] = 1
	obfuscatedConn.peerModesMutex.Unlock()
	if _, err := startHandshake(true); err == nil {
		t.Fatalf("unexpected admission at per-IP handshake limit")
	}
	obfuscatedConn.peerModesMutex.Lock()
	delete(obfuscatedConn.concurrentHandshakesByIP, localIP)
	obfuscatedConn.peerModesMutex.Unlock()
	if limitedFlows := listener.(*Listener).GetQUICCounterMetrics()["quic_limited_flow_count"].(int64); limitedFlows != 2 {
		t.Fatalf("unexpected limited flows: %d", limitedFlows)
	}

	// At the per-IP limit, a validated Initial is refused before quic-go
	// allocates, and the dial fails. The in-flight handshakes are
	// simulated; the global one forces the Retry that validates the dial.

	obfuscatedConn.concurrentHandshakeCount.Add(1)
	obfuscatedConn.peerModesMutex.Lock()
	obfuscatedConn.concurrentHandshakesByIP[localIP] = 1
	obfuscatedConn.peerModesMutex.Unlock()

	_, err = dial(1*time.Second, "127.0.0.1:0")
	if err == nil {
		t.Fatalf("unexpected dial success at handshake limit")
	}

	obfuscatedConn.concurrentHandshakeCount.Add(-1)
	obfuscatedConn.peerModesMutex.Lock()
	delete(obfuscatedConn.concurrentHandshakesByIP, localIP)
	obfuscatedConn.peerModesMutex.Unlock()

	// At the concurrent handshake limit, any Initial is refused.

	obfuscatedConn.concurrentHandshakeCount.Add(2)

	_, err = dial(1*time.Second, "127.0.0.1:0")
	if err == nil {
		t.Fatalf("unexpected dial success at concurrent handshake limit")
	}

	obfuscatedConn.concurrentHandshakeCount.Add(-2)

	if !waitForPeerCounts(listener, maxPeers, 0, 0, 0) {
		t.Fatalf("unexpected peer counts: %s", peerCountsString(listener))
	}

	// A new flow at capacity evicts a pending peer; it is promoted, and
	// established once its handshake completes.

	conn1, err := dial(2*time.Second, "127.0.0.1:0")
	if err != nil {
		t.Fatalf("dial failed: %s", err)
	}

	metrics = listener.(*Listener).GetQUICCounterMetrics()
	droppedFlows = metrics["quic_dropped_flow_count"].(int64)
	evictedFlows = metrics["quic_evicted_flow_count"].(int64)
	if droppedFlows != 0 || evictedFlows == 0 {
		t.Fatalf("unexpected peer metrics: %d dropped, %d evicted", droppedFlows, evictedFlows)
	}

	if !waitForPeerCounts(listener, 0, 1, 0, 0) {
		t.Fatalf("unexpected peer counts: %s", peerCountsString(listener))
	}

	// With the handshake trigger reached, the next new flow must validate
	// its source address; the client handles the Retry. A handshake in
	// flight is simulated, as a real one completes within the dial.

	obfuscatedConn.concurrentHandshakeCount.Add(1)

	conn2, err := dial(2*time.Second, "127.0.0.1:0")
	if err != nil {
		t.Fatalf("dial failed: %s", err)
	}

	obfuscatedConn.concurrentHandshakeCount.Add(-1)

	if listener.(*Listener).GetQUICCounterMetrics()["quic_source_address_validation_count"].(int64) == 0 {
		t.Fatalf("unexpected no source address validations")
	}

	if !waitForPeerCounts(listener, 0, 2, 0, 0) {
		t.Fatalf("unexpected peer counts: %s", peerCountsString(listener))
	}

	// With only responded peers at capacity, new flows are dropped.

	flood(MAX_PRE_DISCOVERY_PACKET_SIZE)
	time.Sleep(100 * time.Millisecond)

	metrics = listener.(*Listener).GetQUICCounterMetrics()
	droppedFlows = metrics["quic_dropped_flow_count"].(int64)
	evictedFlows = metrics["quic_evicted_flow_count"].(int64)
	if droppedFlows == 0 || evictedFlows != 0 {
		t.Fatalf("unexpected peer metrics: %d dropped, %d evicted", droppedFlows, evictedFlows)
	}

	if pending, responded, _, _ := getPeerCounts(listener); pending != 0 || responded != 2 {
		t.Fatalf("unexpected peer counts: %s", peerCountsString(listener))
	}

	serverConn1, err := listener.Accept()
	if err != nil {
		t.Fatalf("Accept failed: %s", err)
	}
	serverConn2, err := listener.Accept()
	if err != nil {
		t.Fatalf("Accept failed: %s", err)
	}

	localAddress := conn1.LocalAddr().String()

	// Both maps drain after close.

	conn1.Close()
	conn2.Close()
	serverConn1.Close()
	serverConn2.Close()

	if !waitForPeerCounts(listener, 0, 0, 0, 0) {
		t.Fatalf("unexpected peer counts: %s", peerCountsString(listener))
	}

	// A redial from the same address, after its peer was reaped, is a new
	// flow.

	conn, err := dial(2*time.Second, localAddress)
	if err != nil {
		t.Fatalf("dial failed: %s", err)
	}

	serverConn, err := listener.Accept()
	if err != nil {
		t.Fatalf("Accept failed: %s", err)
	}

	if !waitForPeerCounts(listener, 0, 1, 0, 0) {
		t.Fatalf("unexpected peer counts: %s", peerCountsString(listener))
	}

	conn.Close()
	serverConn.Close()

	if !waitForPeerCounts(listener, 0, 0, 0, 0) {
		t.Fatalf("unexpected peer counts: %s", peerCountsString(listener))
	}
}

func TestQUICInitialWithoutClientHello(t *testing.T) {

	obfuscationKey := prng.HexString(32)

	listener, err := Listen(
		nil,
		func(string, error, common.LogFields) {},
		"127.0.0.1:0",
		false,
		0,
		obfuscationKey,
		false)
	if err != nil {
		t.Fatalf("Listen failed: %s", err)
	}
	defer listener.Close()

	remoteAddr, err := net.ResolveUDPAddr("udp", listener.Addr().String())
	if err != nil {
		t.Fatalf("ResolveUDPAddr failed: %s", err)
	}

	obfuscatedConn := listener.(*Listener).packetConn.ObfuscatedPacketConn

	// send writes one Initial packet and reports whether the server
	// responded and how many handshakes the peer has in flight.

	send := func(fill func(payload []byte)) (bool, int) {

		packetConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("ListenPacket failed: %s", err)
		}
		defer packetConn.Close()

		_, err = packetConn.WriteTo(makeInitialPacket(t, fill), remoteAddr)
		if err != nil {
			t.Fatalf("WriteTo failed: %s", err)
		}

		packetConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		_, _, err = packetConn.ReadFrom(make([]byte, MAX_PACKET_SIZE))
		responded := err == nil

		obfuscatedConn.peerModesMutex.Lock()
		mode, _, ok := obfuscatedConn.lookupPeer(
			peerAddress(packetConn.LocalAddr().(*net.UDPAddr)))
		var handshakes int
		if ok {
			handshakes = mode.concurrentHandshakes
		}
		obfuscatedConn.peerModesMutex.Unlock()
		if !ok {
			t.Fatalf("missing peer")
		}

		return responded, handshakes
	}

	responded, handshakes := send(func(payload []byte) {
		for i := range payload {
			payload[i] = 0x01 // PING
		}
	})
	if responded || handshakes != 0 {
		t.Fatalf("unexpected response to Initial without CRYPTO frame")
	}

	random, err := obfuscator.MakeTLSPassthroughMessage(true, obfuscationKey)
	if err != nil {
		t.Fatalf("MakeTLSPassthroughMessage failed: %s", err)
	}
	clientHello := append(
		[]byte{0x01, 0, 0, byte(2 + len(random)), 0x03, 0x03}, random...)

	responded, _ = send(func(payload []byte) {
		n := copy(payload, []byte{0x06, 0x00, byte(len(clientHello))}) // CRYPTO
		copy(payload[n:], clientHello)
	})
	if !responded {
		t.Fatalf("unexpected no response to Initial with CRYPTO frame")
	}
}

// makeInitialPacket returns a minimum size QUIC v1 Initial packet for a
// random connection ID, encrypted and header protected with the Initial
// keys of RFC 9001 section 5.2. fill writes the frames; unwritten bytes
// are PADDING.
func makeInitialPacket(t *testing.T, fill func(payload []byte)) []byte {

	// RFC 9000 section 14.1
	const minInitialPacketSize = 1200

	const packetNumberLen = 1
	const tagLen = 16

	expandLabel := func(secret []byte, label string, length int) []byte {
		info := []byte{byte(length >> 8), byte(length), byte(6 + len(label))}
		info = append(info, "tls13 "...)
		info = append(info, label...)
		info = append(info, 0)
		out := make([]byte, length)
		_, err := io.ReadFull(hkdf.Expand(sha256.New, secret, info), out)
		if err != nil {
			t.Fatalf("hkdf.Expand failed: %s", err)
		}
		return out
	}

	initialSalt := []byte{
		0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
		0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a}

	destConnID := prng.Bytes(8)
	srcConnID := prng.Bytes(8)

	clientSecret := expandLabel(
		hkdf.Extract(sha256.New, destConnID, initialSalt), "client in", 32)
	key := expandLabel(clientSecret, "quic key", 16)
	iv := expandLabel(clientSecret, "quic iv", 12)
	headerProtectionKey := expandLabel(clientSecret, "quic hp", 16)

	// Long header, fixed bit, Initial, 1 byte packet number.
	header := []byte{0xc0 | (packetNumberLen - 1), 0, 0, 0, 1}
	header = append(header, byte(len(destConnID)))
	header = append(header, destConnID...)
	header = append(header, byte(len(srcConnID)))
	header = append(header, srcConnID...)
	header = append(header, 0) // token length

	payload := make([]byte, minInitialPacketSize-len(header)-2-packetNumberLen-tagLen)
	fill(payload)

	length := packetNumberLen + len(payload) + tagLen
	header = append(header, 0x40|byte(length>>8), byte(length))
	packetNumberOffset := len(header)
	header = append(header, 0) // packet number 0

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes.NewCipher failed: %s", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("cipher.NewGCM failed: %s", err)
	}

	// With packet number 0, the nonce is the IV.
	packet := aead.Seal(append([]byte(nil), header...), iv, payload, header)

	block, err = aes.NewCipher(headerProtectionKey)
	if err != nil {
		t.Fatalf("aes.NewCipher failed: %s", err)
	}
	var mask [16]byte
	block.Encrypt(mask[:], packet[packetNumberOffset+4:packetNumberOffset+4+16])
	packet[0] ^= mask[0] & 0x0f
	packet[packetNumberOffset] ^= mask[1]

	if len(packet) != minInitialPacketSize {
		t.Fatalf("unexpected packet size: %d", len(packet))
	}

	return packet
}
