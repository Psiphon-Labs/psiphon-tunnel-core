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
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"golang.org/x/sync/errgroup"
)

func TestQUIC(t *testing.T) {
	for negotiateQUICVersion, _ := range supportedVersionNumbers {
		t.Run(negotiateQUICVersion, func(t *testing.T) {
			runQUIC(t, negotiateQUICVersion)
		})
	}
}

func runQUIC(t *testing.T, negotiateQUICVersion string) {

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

	obfuscationKey := prng.HexString(32)

	listener, err := Listen(nil, "127.0.0.1:0", obfuscationKey)
	if err != nil {
		t.Fatalf("Listen failed: %s", err)
	}

	serverAddress := listener.Addr().String()

	testGroup, testCtx := errgroup.WithContext(context.Background())

	testGroup.Go(func() error {

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

			obfuscationPaddingSeed, err := prng.NewSeed()
			if err != nil {
				return errors.Trace(err)
			}

			conn, err := Dial(
				ctx,
				packetConn,
				remoteAddr,
				serverAddress,
				negotiateQUICVersion,
				obfuscationKey,
				obfuscationPaddingSeed)
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
}
