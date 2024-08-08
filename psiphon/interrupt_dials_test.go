/*
 * Copyright (c) 2017, Psiphon Inc.
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
	"context"
	"fmt"
	"net"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/parameters"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
)

func TestInterruptDials(t *testing.T) {

	resolveIP := func(_ context.Context, host string) ([]net.IP, error) {
		return []net.IP{net.ParseIP(host)}, nil
	}

	makeDialers := make(map[string]func(string) common.Dialer)

	makeDialers["TCP"] = func(string) common.Dialer {
		return NewTCPDialer(&DialConfig{ResolveIP: resolveIP})
	}

	makeDialers["SOCKS4-Proxied"] = func(mockServerAddr string) common.Dialer {
		return NewTCPDialer(
			&DialConfig{
				ResolveIP:        resolveIP,
				UpstreamProxyURL: "socks4a://" + mockServerAddr,
			})
	}

	makeDialers["SOCKS5-Proxied"] = func(mockServerAddr string) common.Dialer {
		return NewTCPDialer(
			&DialConfig{
				ResolveIP:        resolveIP,
				UpstreamProxyURL: "socks5://" + mockServerAddr,
			})
	}

	makeDialers["HTTP-CONNECT-Proxied"] = func(mockServerAddr string) common.Dialer {
		return NewTCPDialer(
			&DialConfig{
				ResolveIP:        resolveIP,
				UpstreamProxyURL: "http://" + mockServerAddr,
			})
	}

	// TODO: test upstreamproxy.ProxyAuthTransport

	params, err := parameters.NewParameters(nil)
	if err != nil {
		t.Fatalf("NewParameters failed: %s", err)
	}

	seed, err := prng.NewSeed()
	if err != nil {
		t.Fatalf("NewSeed failed: %s", err)
	}

	makeDialers["TLS"] = func(string) common.Dialer {
		// Cast CustomTLSDialer to common.Dialer.
		return func(context context.Context, network, addr string) (net.Conn, error) {
			return NewCustomTLSDialer(
				&CustomTLSConfig{
					Parameters:               params,
					Dial:                     NewTCPDialer(&DialConfig{ResolveIP: resolveIP}),
					RandomizedTLSProfileSeed: seed,
				})(context, network, addr)
		}
	}

	dialGoroutineFunctionNames := []string{"NewTCPDialer", "NewCustomTLSDialer"}

	for dialerName, makeDialer := range makeDialers {
		for _, doTimeout := range []bool{true, false} {
			t.Run(
				fmt.Sprintf("%s-timeout-%+v", dialerName, doTimeout),
				func(t *testing.T) {
					runInterruptDials(
						t,
						doTimeout,
						makeDialer,
						dialGoroutineFunctionNames)
				})
		}
	}

}

func runInterruptDials(
	t *testing.T,
	doTimeout bool,
	makeDialer func(string) common.Dialer,
	dialGoroutineFunctionNames []string) {

	t.Logf("Test timeout: %+v", doTimeout)

	noAcceptListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %s", err)
	}
	defer noAcceptListener.Close()

	noResponseListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %s", err)
	}
	defer noResponseListener.Close()

	listenerAccepted := make(chan struct{}, 1)

	noResponseListenerWaitGroup := new(sync.WaitGroup)
	noResponseListenerWaitGroup.Add(1)
	defer noResponseListenerWaitGroup.Wait()
	go func() {
		defer noResponseListenerWaitGroup.Done()
		for {
			conn, err := noResponseListener.Accept()
			if err != nil {
				return
			}
			listenerAccepted <- struct{}{}

			var b [1024]byte
			for {
				_, err := conn.Read(b[:])
				if err != nil {
					conn.Close()
					return
				}
			}
		}
	}()

	var ctx context.Context
	var cancelFunc context.CancelFunc

	timeout := 100 * time.Millisecond

	if doTimeout {
		ctx, cancelFunc = context.WithTimeout(context.Background(), timeout)
	} else {
		ctx, cancelFunc = context.WithCancel(context.Background())
	}

	addrs := []string{
		noAcceptListener.Addr().String(),
		noResponseListener.Addr().String()}

	dialTerminated := make(chan struct{}, len(addrs))

	for _, addr := range addrs {
		go func(addr string) {
			conn, err := makeDialer(addr)(ctx, "tcp", addr)
			if err == nil {
				conn.Close()
			}
			dialTerminated <- struct{}{}
		}(addr)
	}

	// Wait for noResponseListener to accept to ensure that we exercise
	// post-TCP-dial interruption in the case of TLS and proxy dialers that
	// do post-TCP-dial handshake I/O as part of their dial.

	<-listenerAccepted

	if doTimeout {
		time.Sleep(timeout)
		defer cancelFunc()
	} else {
		// No timeout, so interrupt with cancel
		cancelFunc()
	}

	startWaiting := time.Now()

	for range addrs {
		<-dialTerminated
	}

	// Test: dial interrupt must complete quickly

	interruptDuration := time.Since(startWaiting)

	if interruptDuration > 100*time.Millisecond {
		t.Fatalf("interrupt duration too long: %s", interruptDuration)
	}

	// Test: interrupted dialers must not leave goroutines running

	if findGoroutines(t, dialGoroutineFunctionNames) {
		t.Fatalf("unexpected dial goroutines")
	}
}

func findGoroutines(t *testing.T, targets []string) bool {
	n, _ := runtime.GoroutineProfile(nil)
	r := make([]runtime.StackRecord, n)
	runtime.GoroutineProfile(r)
	found := false
	for _, g := range r {
		stack := g.Stack()
		funcNames := make([]string, len(stack))
		for i := 0; i < len(stack); i++ {
			funcNames[i] = getFunctionName(stack[i])
		}
		s := strings.Join(funcNames, ", ")
		for _, target := range targets {
			if strings.Contains(s, target) {
				t.Logf("found dial goroutine: %s", s)
				found = true
			}
		}
	}
	return found
}

func getFunctionName(pc uintptr) string {
	funcName := runtime.FuncForPC(pc).Name()
	index := strings.LastIndex(funcName, "/")
	if index != -1 {
		funcName = funcName[index+1:]
	}
	return funcName
}
