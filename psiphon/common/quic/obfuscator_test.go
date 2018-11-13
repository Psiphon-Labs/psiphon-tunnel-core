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
	"testing"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
)

func TestPaddingLen(t *testing.T) {

	c, err := NewObfuscatedPacketConn(nil, false, "key")
	if err != nil {
		t.Fatalf("NewObfuscatedPacketConn failed: %s", err)
	}

	for max := 0; max <= 255; max++ {

		counts := make(map[int]int)
		repeats := 200000

		for r := 0; r < repeats; r++ {
			padding, err := c.getRandomPaddingLen(max)
			if err != nil {
				t.Fatalf("getRandomPaddingLen failed: %s", err)
			}
			if padding < 0 || padding > max {
				t.Fatalf("unexpected padding: max = %d, padding = %d", max, padding)
			}
			counts[padding] += 1
		}

		expected := repeats / (max + 1)

		for i := 0; i <= max; i++ {
			if counts[i] < (expected/10)*8 {
				t.Logf("max = %d, counts = %+v", max, counts)
				t.Fatalf("unexpected low count: max = %d, i = %d, count = %d", max, i, counts[i])
			}
		}
	}
}

func Disabled_TestPaddingLenLimit(t *testing.T) {

	// This test takes up to ~2 minute to complete, so it's disabled by default.

	c, err := NewObfuscatedPacketConn(nil, false, "key")
	if err != nil {
		t.Fatalf("NewObfuscatedPacketConn failed: %s", err)
	}

	// Use large blocks to get close to the key stream limit.

	var b [2 * 1024 * 1024 * 1024]byte
	n := int64(0)

	for i := 0; i < 127; i++ {
		err := c.getRandomBytes(b[:])
		if err != nil {
			t.Fatalf("getRandomBytes failed: %s", err)
		}
		n += int64(len(b))
	}

	// Stop using large blocks 64 bytes short of the limit, 2^38-64.

	err = c.getRandomBytes(b[0 : len(b)-128])
	if err != nil {
		t.Fatalf("getRandomBytes failed: %s", err)
	}
	n += int64(len(b) - 128)

	// Invoke byte at a time across the limit boundary to ensure we
	// don't jump over the limit case.

	for i := 0; i < 192; i++ {
		err := c.getRandomBytes(b[0:1])
		if err != nil {
			t.Fatalf("getRandomBytes failed: %s", err)
		}
		n += int64(1)
	}
}

func BenchmarkPaddingLen(b *testing.B) {

	c, err := NewObfuscatedPacketConn(nil, false, "key")
	if err != nil {
		b.Fatalf("NewObfuscatedPacketConn failed: %s", err)
	}

	b.Run("getPaddingLen", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			_, _ = c.getRandomPaddingLen(n % MAX_PADDING)
		}
	})

	b.Run("SecureRandomRange", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			_, _ = common.MakeSecureRandomRange(0, n%MAX_PADDING)
		}
	})
}
