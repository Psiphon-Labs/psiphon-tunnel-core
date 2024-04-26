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

package dtls

import (
	"context"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
)

type dtlsSeedValue string

const valueKey = dtlsSeedValue("DTLS-seed")

// SetDTLSSeed establishes a cached common/prng seed to be used when
// randomizing DTLS Hellos.
//
// The seed is attached as a value to the input dial context, yielding the
// output context. This allows a fork of pion/dtls to fetch the seed, from a
// context, and apply randomization without having to fork many pion layers
// to pass in seeds.
//
// Both sides of a WebRTC connection may randomize their Hellos. isOffer
// allows the same seed to be used, but produce two distinct random streams.
// The client generates or replays an obfuscation secret used to derive the
// seed, and the obfuscation secret is relayed to the proxy by the Broker.
func SetDTLSSeed(
	ctx context.Context, baseSeed *prng.Seed, isOffer bool) (context.Context, error) {

	salt := "inproxy-client-DTLS-seed"
	if !isOffer {
		salt = "inproxy-proxy-DTLS-seed"
	}

	seed, err := prng.NewSaltedSeed(baseSeed, salt)
	if err != nil {
		return nil, errors.Trace(err)
	}

	seedCtx := context.WithValue(ctx, valueKey, seed)

	return seedCtx, nil
}

// SetNoDTLSSeed indicates to skip DTLS randomization for the given dial
// context.
func SetNoDTLSSeed(ctx context.Context) context.Context {
	var nilSeed *prng.Seed
	return context.WithValue(ctx, valueKey, nilSeed)
}

// GetDTLSSeed fetches a seed established by SetDTLSSeed, or nil for no seed
// as set by SetNoDTLSSeed, or returns an error if no seed is configured
// specified dial context.
func GetDTLSSeed(ctx context.Context) (*prng.Seed, error) {
	value := ctx.Value(valueKey)
	if value == nil {
		return nil, errors.TraceNew("missing seed")
	}
	return value.(*prng.Seed), nil
}
