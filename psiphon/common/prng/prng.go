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

/*

Package prng implements a seeded, unbiased PRNG that is suitable for use
cases including obfuscation, network jitter, load balancing.

Seeding is based on crypto/rand.Read and the PRNG stream is provided by
chacha20. As such, this PRNG is suitable for high volume cases such as
generating random bytes per IP packet as it avoids the syscall overhead
(context switch/spinlock) of crypto/rand.Read.

This PRNG also supports replay use cases, where its intended to reproduce the
same traffic shape or protocol attributes there were previously produced.

This PRNG is _not_ for security use cases including production cryptographic
key generation.

Limitations: there is a cycle in the PRNG stream, after roughly 2^64 * 2^38-64
bytes; and the global instance initialized in init() ignores seeding errors.

It is safe to make concurrent calls to a PRNG instance, including the global
instance, but the caller is responsible for serializing multiple calls as
required for replay.

PRNG conforms to io.Reader and math/rand.Source, with additional helper
functions.

*/
package prng

import (
	crypto_rand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"io"
	"math"
	"math/rand"
	"sync"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/crypto/Yawning/chacha20"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"golang.org/x/crypto/hkdf"
)

const (
	SEED_LENGTH = 32
)

// Seed is a PRNG seed.
type Seed [SEED_LENGTH]byte

// NewSeed creates a new PRNG seed using crypto/rand.Read.
func NewSeed() (*Seed, error) {
	seed := new(Seed)
	_, err := crypto_rand.Read(seed[:])
	if err != nil {
		return nil, errors.Trace(err)
	}
	return seed, nil
}

// NewSaltedSeed creates a new seed derived from an existing seed and a salt.
// A HKDF is applied to the seed and salt.
//
// NewSaltedSeed is intended for use cases where a single seed needs to be
// used in distinct contexts to produce independent random streams.
func NewSaltedSeed(seed *Seed, salt string) (*Seed, error) {
	saltedSeed := new(Seed)
	_, err := io.ReadFull(
		hkdf.New(sha256.New, seed[:], []byte(salt), nil), saltedSeed[:])
	if err != nil {
		return nil, errors.Trace(err)
	}
	return saltedSeed, nil
}

// PRNG is a seeded, unbiased PRNG based on chacha20.
type PRNG struct {
	rand                   *rand.Rand
	randomStreamMutex      sync.Mutex
	randomStreamSeed       *Seed
	randomStream           *chacha20.Cipher
	randomStreamUsed       uint64
	randomStreamRekeyCount uint64
}

// NewPRNG generates a seed and creates a PRNG with that seed.
func NewPRNG() (*PRNG, error) {
	seed, err := NewSeed()
	if err != nil {
		return nil, errors.Trace(err)
	}
	return NewPRNGWithSeed(seed), nil
}

// NewPRNGWithSeed initializes a new PRNG using an existing seed.
func NewPRNGWithSeed(seed *Seed) *PRNG {
	p := &PRNG{
		randomStreamSeed: seed,
	}
	p.rekey()
	p.rand = rand.New(p)
	return p
}

// NewPRNGWithSaltedSeed initializes a new PRNG using a seed derived from an
// existing seed and a salt with NewSaltedSeed.
func NewPRNGWithSaltedSeed(seed *Seed, salt string) (*PRNG, error) {
	saltedSeed, err := NewSaltedSeed(seed, salt)
	if err != nil {
		return nil, errors.Trace(err)
	}
	return NewPRNGWithSeed(saltedSeed), nil
}

// Read reads random bytes from the PRNG stream into b. Read conforms to
// io.Reader and always returns len(p), nil.
func (p *PRNG) Read(b []byte) (int, error) {

	p.randomStreamMutex.Lock()
	defer p.randomStreamMutex.Unlock()

	// Re-key before reaching the 2^38-64 chacha20 key stream limit.
	if p.randomStreamUsed+uint64(len(b)) >= uint64(1<<38-64) {
		p.rekey()
	}

	p.randomStream.KeyStream(b)

	p.randomStreamUsed += uint64(len(b))

	return len(b), nil
}

func (p *PRNG) rekey() {

	// chacha20 has a stream limit of 2^38-64. Before that limit is reached,
	// the cipher must be rekeyed. To rekey without changing the seed, we use
	// a counter for the nonce.
	//
	// Limitation: the counter wraps at 2^64, which produces a cycle in the
	// PRNG after 2^64 * 2^38-64 bytes.
	//
	// TODO: this could be extended by using all 2^96 bits of the nonce for
	// the counter; and even further by using the 24 byte XChaCha20 nonce.
	var randomKeyNonce [12]byte
	binary.BigEndian.PutUint64(randomKeyNonce[0:8], p.randomStreamRekeyCount)

	var err error
	p.randomStream, err = chacha20.NewCipher(
		p.randomStreamSeed[:], randomKeyNonce[:])
	if err != nil {
		// Functions returning random values, which may call rekey, don't
		// return an error. As of github.com/Yawning/chacha20 rev. e3b1f968,
		// the only possible errors from chacha20.NewCipher invalid key or
		// nonce size, and since we use the correct sizes, there should never
		// be an error here. So panic in this unexpected case.
		panic(errors.Trace(err))
	}

	p.randomStreamRekeyCount += 1
	p.randomStreamUsed = 0
}

// Int63 is equivilent to math/read.Int63.
func (p *PRNG) Int63() int64 {
	i := p.Uint64()
	return int64(i & (1<<63 - 1))
}

// Int63 is equivilent to math/read.Uint64.
func (p *PRNG) Uint64() uint64 {
	var b [8]byte
	p.Read(b[:])
	return binary.BigEndian.Uint64(b[:])
}

// Seed must exist in order to use a PRNG as a math/rand.Source. This call is
// not supported and ignored.
func (p *PRNG) Seed(_ int64) {
}

// FlipCoin randomly returns true or false.
func (p *PRNG) FlipCoin() bool {
	return p.rand.Int31n(2) == 1
}

// FlipWeightedCoin returns the result of a weighted
// random coin flip. If the weight is 0.5, the outcome
// is equally likely to be true or false. If the weight
// is 1.0, the outcome is always true, and if the
// weight is 0.0, the outcome is always false.
//
// Input weights > 1.0 are treated as 1.0.
func (p *PRNG) FlipWeightedCoin(weight float64) bool {
	if weight > 1.0 {
		weight = 1.0
	}
	f := float64(p.Int63()) / float64(math.MaxInt64)
	return f > 1.0-weight
}

// Intn is equivilent to math/read.Intn, except it returns 0 if n <= 0
// instead of panicking.
func (p *PRNG) Intn(n int) int {
	if n <= 0 {
		return 0
	}
	return p.rand.Intn(n)
}

// Int63n is equivilent to math/read.Int63n, except it returns 0 if n <= 0
// instead of panicking.
func (p *PRNG) Int63n(n int64) int64 {
	if n <= 0 {
		return 0
	}
	return p.rand.Int63n(n)
}

// ExpFloat64Range returns a pseudo-exponentially distributed float64 in the
// range [min, max] with the specified lambda. Numbers are selected using
// math/rand.ExpFloat64 and discarding values that exceed max.
//
// If max < min or lambda is <= 0, min is returned.
func (p *PRNG) ExpFloat64Range(min, max, lambda float64) float64 {
	if max <= min || lambda <= 0.0 {
		return min
	}
	var value float64
	for {
		value = min + (rand.ExpFloat64()/lambda)*(max-min)
		if value <= max {
			break
		}
	}
	return value
}

// Intn is equivilent to math/read.Perm.
func (p *PRNG) Perm(n int) []int {
	return p.rand.Perm(n)
}

// Range selects a random integer in [min, max].
// If min < 0, min is set to 0. If max < min, min is returned.
func (p *PRNG) Range(min, max int) int {
	if min < 0 {
		min = 0
	}
	if max < min {
		return min
	}
	n := p.Intn(max - min + 1)
	n += min
	return n
}

// Bytes returns a new slice containing length random bytes.
func (p *PRNG) Bytes(length int) []byte {
	b := make([]byte, length)
	p.Read(b)
	return b
}

// Padding selects a random padding length in the indicated
// range and returns a random byte slice of the selected length.
// If maxLength <= minLength, the padding is minLength.
func (p *PRNG) Padding(minLength, maxLength int) []byte {
	return p.Bytes(p.Range(minLength, maxLength))
}

// Period returns a random duration, within a given range.
// If max <= min, the duration is min.
func (p *PRNG) Period(min, max time.Duration) time.Duration {
	duration := p.Int63n(max.Nanoseconds() - min.Nanoseconds())
	return min + time.Duration(duration)
}

// Jitter returns n +/- the given factor.
// For example, for n = 100 and factor = 0.1, the
// return value will be in the range [90, 110].
func (p *PRNG) Jitter(n int64, factor float64) int64 {
	a := int64(math.Ceil(float64(n) * factor))
	r := p.Int63n(2*a + 1)
	return n + r - a
}

// JitterDuration invokes Jitter for time.Duration.
func (p *PRNG) JitterDuration(d time.Duration, factor float64) time.Duration {
	return time.Duration(p.Jitter(int64(d), factor))
}

// HexString returns a hex encoded random string.
// byteLength specifies the pre-encoded data length.
func (p *PRNG) HexString(byteLength int) string {
	return hex.EncodeToString(p.Bytes(byteLength))
}

// Base64String returns a base64 encoded random string.
// byteLength specifies the pre-encoded data length.
func (p *PRNG) Base64String(byteLength int) string {
	return base64.StdEncoding.EncodeToString(p.Bytes(byteLength))
}

var p *PRNG

func Read(b []byte) (int, error) {
	return p.Read(b)
}

func Int63() int64 {
	return p.Int63()
}

func Uint64() uint64 {
	return p.Uint64()
}

func FlipCoin() bool {
	return p.FlipCoin()
}

func FlipWeightedCoin(weight float64) bool {
	return p.FlipWeightedCoin(weight)
}

func Intn(n int) int {
	return p.Intn(n)
}

func Int63n(n int64) int64 {
	return p.Int63n(n)
}

func ExpFloat64Range(min, max, lambda float64) float64 {
	return p.ExpFloat64Range(min, max, lambda)
}

func Perm(n int) []int {
	return p.Perm(n)
}

func Range(min, max int) int {
	return p.Range(min, max)
}

func Bytes(length int) []byte {
	return p.Bytes(length)
}

func Padding(minLength, maxLength int) []byte {
	return p.Padding(minLength, maxLength)
}

func Period(min, max time.Duration) time.Duration {
	return p.Period(min, max)
}

func Jitter(n int64, factor float64) int64 {
	return p.Jitter(n, factor)
}

func JitterDuration(d time.Duration, factor float64) time.Duration {
	return p.JitterDuration(d, factor)
}

func HexString(byteLength int) string {
	return p.HexString(byteLength)
}

func Base64String(byteLength int) string {
	return p.Base64String(byteLength)
}

func init() {

	// Limitation: if crypto/rand.Read fails, the global PRNG will be
	// initialized with a zero-byte seed. This ensures that non-security-
	// critical use of the global PRNG can proceed.
	//
	// As of Go 1.9, with https://github.com/golang/go/issues/19274, on Linux
	// kernels v3.17+, cryto/rand.Read should now block instead of failing or
	// returning predictable bytes.
	var err error
	p, err = NewPRNG()
	if err != nil {
		p = NewPRNGWithSeed(new(Seed))
	}
}
