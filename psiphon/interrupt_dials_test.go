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
	"testing"
	"time"

	"github.com/Psiphon-Inc/goarista/monotime"
)

func TestInterruptDials(t *testing.T) {

	makeDialers := make(map[string]func(string) Dialer)

	makeDialers["TCP"] = func(string) Dialer {
		return NewTCPDialer(&DialConfig{})
	}

	makeDialers["SOCKS4-Proxied"] = func(mockServerAddr string) Dialer {
		return NewTCPDialer(
			&DialConfig{
				UpstreamProxyUrl: "socks4a://" + mockServerAddr,
			})
	}

	makeDialers["SOCKS5-Proxied"] = func(mockServerAddr string) Dialer {
		return NewTCPDialer(
			&DialConfig{
				UpstreamProxyUrl: "socks5://" + mockServerAddr,
			})
	}

	makeDialers["HTTP-CONNECT-Proxied"] = func(mockServerAddr string) Dialer {
		return NewTCPDialer(
			&DialConfig{
				UpstreamProxyUrl: "http://" + mockServerAddr,
			})
	}

	// TODO: test upstreamproxy.ProxyAuthTransport

	makeDialers["TLS"] = func(string) Dialer {
		return NewCustomTLSDialer(
			&CustomTLSConfig{
				Dial: NewTCPDialer(&DialConfig{}),
			})
	}

	for dialerName, makeDialer := range makeDialers {
		for _, doTimeout := range []bool{true, false} {
			t.Run(
				fmt.Sprintf("%s-timeout-%+v", dialerName, doTimeout),
				func(t *testing.T) {
					runInterruptDials(t, doTimeout, makeDialer)
				})
		}
	}

}

func runInterruptDials(
	t *testing.T,
	doTimeout bool,
	makeDialer func(string) Dialer) {

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

	go func() {
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

	startGoroutines := runtime.NumGoroutine()

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

	startWaiting := monotime.Now()

	for _ = range addrs {
		<-dialTerminated
	}

	// Test: dial interrupt must complete quickly

	interruptDuration := monotime.Since(startWaiting)

	if interruptDuration > 10*time.Millisecond {
		t.Fatalf("interrupt duration too long: %s", interruptDuration)
	}

	// Test: interrupted dialers must not leave goroutines running

	endGoroutines := runtime.NumGoroutine()

	if endGoroutines > startGoroutines {
		t.Fatalf("unexpected goroutines: %d > %d", endGoroutines, startGoroutines)
	}
}
