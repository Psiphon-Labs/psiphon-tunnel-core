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

package fragmentor

import (
	"bytes"
	"context"
	"fmt"
	"math/rand"
	"net"
	"testing"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/parameters"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	"golang.org/x/sync/errgroup"
)

func TestFragmentor(t *testing.T) {

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen failed: %s")
	}

	address := listener.Addr().String()

	data := make([]byte, 1<<18)
	rand.Read(data)

	// This test is sensitive to OS buffering and timing; the delays are
	// intended to be sufficiently long to ensure fragmented writes are read
	// before additional data is written, even when running tests with the
	// race detector.

	bytesFragmented := 1 << 15
	minWriteBytes := 1
	maxWriteBytes := 512
	minDelay := 2 * time.Millisecond
	maxDelay := 2 * time.Millisecond

	clientParameters, err := parameters.NewClientParameters(nil)
	if err != nil {
		t.Fatalf("parameters.NewClientParameters failed: %s", err)
	}
	_, err = clientParameters.Set("", false, map[string]interface{}{
		"FragmentorProbability":    1.0,
		"FragmentorLimitProtocols": protocol.TunnelProtocols{},
		"FragmentorMinTotalBytes":  bytesFragmented,
		"FragmentorMaxTotalBytes":  bytesFragmented,
		"FragmentorMinWriteBytes":  minWriteBytes,
		"FragmentorMaxWriteBytes":  maxWriteBytes,
		"FragmentorMinDelay":       minDelay,
		"FragmentorMaxDelay":       maxDelay,
	})
	if err != nil {
		t.Fatalf("ClientParameters.Set failed: %s", err)
	}

	testGroup, testCtx := errgroup.WithContext(context.Background())

	testGroup.Go(func() error {
		conn, err := listener.Accept()
		if err != nil {
			return common.ContextError(err)
		}
		defer conn.Close()
		readData := make([]byte, len(data))
		n := 0
		for n < len(data) {
			m, err := conn.Read(readData[n:])
			if err != nil {
				return common.ContextError(err)
			}
			if m > maxWriteBytes && n < bytesFragmented {
				return common.ContextError(fmt.Errorf("unexpected write size: %d, %d", m, n))
			}
			n += m
		}
		if !bytes.Equal(data, readData) {
			return common.ContextError(fmt.Errorf("data mismatch"))
		}
		return nil
	})

	testGroup.Go(func() error {
		conn, err := net.Dial("tcp", address)
		if err != nil {
			return common.ContextError(err)
		}
		config := NewUpstreamConfig(clientParameters.Get(), "")
		t.Logf("%+v", config.GetMetrics())
		conn = NewConn(
			config,
			func(message string) { t.Logf(message) },
			conn)
		defer conn.Close()
		_, err = conn.Write(data)
		if err != nil {
			return common.ContextError(err)
		}
		return nil
	})

	go func() {
		testGroup.Wait()
	}()

	<-testCtx.Done()
	listener.Close()

	err = testGroup.Wait()
	if err != nil {
		t.Errorf("goroutine failed: %s", err)
	}
}
