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
)

func TestPaddingLen(t *testing.T) {

	c, err := NewObfuscatedPacketConnPacketConn(nil, false, "key")
	if err != nil {
		t.Fatalf("NewObfuscatedPacketConnPacketConn failed: %s", err)
	}

	for max := 0; max <= 255; max++ {

		counts := make(map[int]int)
		repeats := 200000

		for r := 0; r < repeats; r++ {
			padding := c.getPaddingLen(max)
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
