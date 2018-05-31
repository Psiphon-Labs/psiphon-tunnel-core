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
	"sync/atomic"
	"testing"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"golang.org/x/sync/errgroup"
)

func TestQUIC(t *testing.T) {

	clients := 10
	bytesToSend := 1 << 20

	serverReceivedBytes := int64(0)
	clientReceivedBytes := int64(0)

	hostname := "www.example.com"
	certificate, privateKey, err := common.GenerateWebServerCertificate(hostname)

	listener, err := NewListener("127.0.0.1:0", certificate, privateKey)
	if err != nil {
		t.Errorf("NewListener failed: %s", err)
	}

	serverAddr, err := net.ResolveUDPAddr("udp", listener.Addr().String())
	if err != nil {
		t.Errorf("ResolveUDPAddr failed: %s", err)
	}

	serverHost := fmt.Sprintf("%s:%d", hostname, serverAddr.Port)

	testGroup, testCtx := errgroup.WithContext(context.Background())

	testGroup.Go(func() error {

		var serverGroup errgroup.Group

		for i := 0; i < clients; i++ {

			conn, err := listener.Accept()
			if err != nil {
				return common.ContextError(err)
			}

			serverGroup.Go(func() error {
				for {
					b := make([]byte, 1024)
					n, err := conn.Read(b)
					atomic.AddInt64(&serverReceivedBytes, int64(n))
					if err == io.EOF {
						return nil
					} else if err != nil {
						return common.ContextError(err)
					}
					_, err = conn.Write(b)
					if err != nil {
						return common.ContextError(err)
					}
				}
			})
		}

		err := serverGroup.Wait()
		if err != nil {
			return common.ContextError(err)
		}

		return nil
	})

	for i := 0; i < clients; i++ {

		testGroup.Go(func() error {

			ctx, cancelFunc := context.WithTimeout(
				context.Background(), 1*time.Second)
			defer cancelFunc()

			packetConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				return common.ContextError(err)
			}

			conn, err := Dial(ctx, packetConn, serverAddr, serverHost)
			if err != nil {
				return common.ContextError(err)
			}

			// Cancel should interrupt dialing only
			cancelFunc()

			var clientGroup errgroup.Group

			clientGroup.Go(func() error {
				defer conn.Close()
				bytesRead := 0
				for bytesRead < bytesToSend {
					b := make([]byte, 1024)
					n, err := conn.Read(b)
					bytesRead += n
					atomic.AddInt64(&clientReceivedBytes, int64(n))
					if err == io.EOF {
						break
					} else if err != nil {
						return common.ContextError(err)
					}
				}
				return nil
			})

			clientGroup.Go(func() error {
				b := make([]byte, bytesToSend)
				_, err := conn.Write(b)
				if err != nil {
					return common.ContextError(err)
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
