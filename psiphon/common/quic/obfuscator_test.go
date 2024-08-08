//go:build !PSIPHON_DISABLE_QUIC
// +build !PSIPHON_DISABLE_QUIC

/*
 * Copyright (c) 2023, Psiphon Inc.
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
	"encoding/hex"
	"net"
	"testing"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/transforms"
	"golang.org/x/sync/errgroup"
)

func TestNonceTransformer(t *testing.T) {
	for quicVersion := range supportedVersionNumbers {
		if !isObfuscated(quicVersion) {
			continue
		}
		t.Run(quicVersion, func(t *testing.T) {
			runNonceTransformer(t, quicVersion)
		})
	}
}

func runNonceTransformer(t *testing.T, quicVersion string) {

	serverIdleTimeout = 1 * time.Second

	obfuscationKey := prng.HexString(32)

	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %s", err)
	}

	serverAddress := listener.LocalAddr().(*net.UDPAddr)

	testGroup, testCtx := errgroup.WithContext(context.Background())

	testGroup.Go(func() error {
		var serverGroup errgroup.Group

		// reads the first packet and verifies the nonce prefix
		serverGroup.Go(func() error {
			b := make([]byte, 1024)

			_, _, err := listener.ReadFrom(b)
			if err != nil {
				return errors.Trace(err)
			}

			prefix := hex.EncodeToString(b[:NONCE_SIZE])
			if prefix != "ffff00000000000000000000" {
				return errors.Tracef("unexpected prefix: %s", prefix)
			}

			return nil
		})

		err = serverGroup.Wait()
		if err != nil {
			return errors.Trace(err)
		}

		return nil
	})

	// client

	testGroup.Go(func() error {

		ctx, cancelFunc := context.WithTimeout(
			context.Background(), 1*time.Second)
		defer cancelFunc()

		packetConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			return errors.Trace(err)
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

		// Dial with nonce transformer

		Dial(
			ctx,
			packetConn,
			serverAddress,
			serverAddress.String(),
			quicVersion,
			clientHelloSeed,
			obfuscationKey,
			obfuscationPaddingSeed,
			&transforms.ObfuscatorSeedTransformerParameters{
				TransformName: "",
				TransformSeed: &prng.Seed{0},
				TransformSpec: transforms.Spec{{"^.{24}", "ffff00000000000000000000"}},
			},
			false,
			false,
			nil,
		)

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
