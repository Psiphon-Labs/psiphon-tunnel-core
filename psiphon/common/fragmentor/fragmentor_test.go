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
	"math/rand"
	"net"
	"testing"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/parameters"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	"golang.org/x/sync/errgroup"
)

func TestFragmentor(t *testing.T) {

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen failed: %s", err)
	}

	address := listener.Addr().String()

	data := make([]byte, 1<<18)
	rand.Read(data)

	// This test is sensitive to OS buffering and timing; the delays are
	// intended to be sufficiently long to ensure fragmented writes are read
	// before additional data is written, even when running tests with the
	// race detector.

	tunnelProtocol := protocol.TUNNEL_PROTOCOL_OBFUSCATED_SSH
	bytesToFragment := 1 << 15
	minWriteBytes := 1
	maxWriteBytes := 512
	minDelay := 2 * time.Millisecond
	maxDelay := 2 * time.Millisecond

	params, err := parameters.NewParameters(nil)
	if err != nil {
		t.Fatalf("parameters.NewParameters failed: %s", err)
	}
	_, err = params.Set("", 0, map[string]interface{}{
		"FragmentorProbability":              1.0,
		"FragmentorLimitProtocols":           protocol.TunnelProtocols{tunnelProtocol},
		"FragmentorMinTotalBytes":            bytesToFragment,
		"FragmentorMaxTotalBytes":            bytesToFragment,
		"FragmentorMinWriteBytes":            minWriteBytes,
		"FragmentorMaxWriteBytes":            maxWriteBytes,
		"FragmentorMinDelay":                 minDelay,
		"FragmentorMaxDelay":                 maxDelay,
		"FragmentorDownstreamProbability":    1.0,
		"FragmentorDownstreamLimitProtocols": protocol.TunnelProtocols{tunnelProtocol},
		"FragmentorDownstreamMinTotalBytes":  bytesToFragment,
		"FragmentorDownstreamMaxTotalBytes":  bytesToFragment,
		"FragmentorDownstreamMinWriteBytes":  minWriteBytes,
		"FragmentorDownstreamMaxWriteBytes":  maxWriteBytes,
		"FragmentorDownstreamMinDelay":       minDelay,
		"FragmentorDownstreamMaxDelay":       maxDelay,
	})
	if err != nil {
		t.Fatalf("parameters.Parameters.Set failed: %s", err)
	}

	testGroup, testCtx := errgroup.WithContext(context.Background())

	testGroup.Go(func() error {

		conn, err := listener.Accept()
		if err != nil {
			return errors.Trace(err)
		}
		fragConn := NewConn(
			NewDownstreamConfig(params.Get(), tunnelProtocol, nil),
			func(message string) { t.Log(message) },
			conn)
		defer fragConn.Close()

		readData := make([]byte, len(data))
		n := 0
		for n < len(data) {
			m, err := fragConn.Read(readData[n:])
			if err != nil {
				return errors.Trace(err)
			}
			if m > maxWriteBytes && n+maxWriteBytes <= bytesToFragment {
				return errors.Tracef("unexpected write size: %d, %d", m, n)
			}
			n += m
		}
		if !bytes.Equal(data, readData) {
			return errors.Tracef("data mismatch")
		}

		PRNG, err := prng.NewPRNG()
		if err != nil {
			return errors.Trace(err)
		}
		fragConn.SetReplay(PRNG)
		_, err = fragConn.Write(data)
		if err != nil {
			return errors.Trace(err)
		}
		return nil
	})

	testGroup.Go(func() error {

		conn, err := net.Dial("tcp", address)
		if err != nil {
			return errors.Trace(err)
		}
		seed, err := prng.NewSeed()
		if err != nil {
			return errors.Trace(err)
		}
		fragConn := NewConn(
			NewUpstreamConfig(params.Get(), tunnelProtocol, seed),
			func(message string) { t.Log(message) },
			conn)
		defer fragConn.Close()

		_, err = fragConn.Write(data)
		if err != nil {
			return errors.Trace(err)
		}
		t.Logf("%+v", fragConn.GetMetrics())

		readData := make([]byte, len(data))
		n := 0
		for n < len(data) {
			m, err := fragConn.Read(readData[n:])
			if err != nil {
				return errors.Trace(err)
			}
			if m > maxWriteBytes && n+maxWriteBytes <= bytesToFragment {
				return errors.Tracef("unexpected write size: %d, %d", m, n)
			}
			n += m
		}
		if !bytes.Equal(data, readData) {
			return errors.Tracef("data mismatch")
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
