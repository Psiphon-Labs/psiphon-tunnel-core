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
	"fmt"
	"io"
	"net"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"golang.org/x/sync/errgroup"
)

func TestQUIC(t *testing.T) {
	for quicVersion := range supportedVersionNumbers {
		t.Run(fmt.Sprintf("%s", quicVersion), func(t *testing.T) {
			if isGQUIC(quicVersion) && !GQUICEnabled() {
				t.Skipf("gQUIC is not enabled")
			}
			runQUIC(t, quicVersion, GQUICEnabled(), false)
		})
		if isIETF(quicVersion) {
			t.Run(fmt.Sprintf("%s (invoke anti-probing)", quicVersion), func(t *testing.T) {
				runQUIC(t, quicVersion, GQUICEnabled(), true)
			})
		}
		if isIETF(quicVersion) {
			t.Run(fmt.Sprintf("%s (disable gQUIC)", quicVersion), func(t *testing.T) {
				runQUIC(t, quicVersion, false, false)
			})
		}
	}
}

func runQUIC(
	t *testing.T,
	quicVersion string,
	enableGQUIC bool,
	invokeAntiProbing bool) {

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

	irregularTunnelLogger := func(_ string, err error, _ common.LogFields) {
		if !invokeAntiProbing {
			t.Errorf("unexpected irregular tunnel event: %v", err)
		}
	}

	obfuscationKey := prng.HexString(32)

	listener, err := Listen(
		nil,
		irregularTunnelLogger,
		"127.0.0.1:0",
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
				true,
				nil)

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
	r := make([]runtime.StackRecord, n)
	runtime.GoroutineProfile(r)
	return r
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
