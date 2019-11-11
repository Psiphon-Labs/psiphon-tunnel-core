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

package marionette

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	_ "net/http/pprof"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"golang.org/x/sync/errgroup"
)

func TestMarionette(t *testing.T) {

	go func() {
		fmt.Println(http.ListenAndServe("localhost:6060", nil))
	}()

	// Create a number of concurrent Marionette clients, each of which sends
	// data to the server. The server echoes back the data.

	clients := 5
	bytesToSend := 1 << 15

	serverReceivedBytes := int64(0)
	clientReceivedBytes := int64(0)

	serverAddress := "127.0.0.1"
	format := "http_simple_nonblocking"

	listener, err := Listen(serverAddress, format)
	if err != nil {
		t.Fatalf("Listen failed: %s", err)
	}

	testGroup, testCtx := errgroup.WithContext(context.Background())

	testGroup.Go(func() error {

		var serverGroup errgroup.Group

		for i := 0; i < clients; i++ {

			conn, err := listener.Accept()
			if err != nil {
				return errors.Trace(err)
			}

			serverGroup.Go(func() error {
				defer func() {
					fmt.Printf("Start server conn.Close\n")
					start := time.Now()
					conn.Close()
					fmt.Printf("Done server conn.Close: %s\n", time.Since(start))
				}()
				bytesFromClient := 0
				b := make([]byte, 1024)
				for bytesFromClient < bytesToSend {
					n, err := conn.Read(b)
					bytesFromClient += n
					atomic.AddInt64(&serverReceivedBytes, int64(n))
					if err != nil {
						fmt.Printf("Server read error: %s\n", err)
						return errors.Trace(err)
					}
					_, err = conn.Write(b[:n])
					if err != nil {
						fmt.Printf("Server write error: %s\n", err)
						return errors.Trace(err)
					}
				}
				return nil
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

			conn, err := Dial(ctx, &net.Dialer{}, format, serverAddress)
			if err != nil {
				return errors.Trace(err)
			}

			var clientGroup errgroup.Group

			clientGroup.Go(func() error {
				defer func() {
					fmt.Printf("Start client conn.Close\n")
					start := time.Now()
					conn.Close()
					fmt.Printf("Done client conn.Close: %s\n", time.Since(start))
				}()
				b := make([]byte, 1024)
				bytesRead := 0
				for bytesRead < bytesToSend {
					n, err := conn.Read(b)
					bytesRead += n
					atomic.AddInt64(&clientReceivedBytes, int64(n))
					if err == io.EOF {
						break
					} else if err != nil {
						fmt.Printf("Client read error: %s\n", err)
						return errors.Trace(err)
					}
				}
				return nil
			})

			clientGroup.Go(func() error {
				b := make([]byte, bytesToSend)
				_, err := conn.Write(b)
				if err != nil {
					fmt.Printf("Client write error: %s\n", err)
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

	fmt.Printf("Start listener.Close\n")
	start := time.Now()
	listener.Close()
	fmt.Printf("Done listener.Close: %s\n", time.Since(start))

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
}
