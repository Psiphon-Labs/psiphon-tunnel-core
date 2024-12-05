/*
 * Copyright (c) 2024, Psiphon Inc.
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

package networkid

import (
	"testing"
	"time"
)

// prevent compiler optimization
var networkID string
var err error

// This test doesn't show anything very useful, as it will mostly be getting cached results
func BenchmarkGet(b *testing.B) {
	for i := 0; i < b.N; i++ {
		networkID, err = Get()
		if err != nil {
			b.Fatalf("error: %v", err)
		}
	}
}

func TestGet(t *testing.T) {
	gotNetworkID, err := Get()
	if err != nil {
		t.Errorf("error: %v", err)
		return
	}
	if gotNetworkID == "" {
		t.Error("got empty network ID")
	}

	// Call again immediately to get a cached result
	gotNetworkID, err = Get()
	if err != nil {
		t.Errorf("error: %v", err)
		return
	}
	if gotNetworkID == "" {
		t.Error("got empty network ID")
	}

	// Wait until the cached result expires, so we get another fresh value
	time.Sleep(2 * time.Second)

	gotNetworkID, err = Get()
	if err != nil {
		t.Errorf("error: %v", err)
		return
	}
	if gotNetworkID == "" {
		t.Error("got empty network ID")
	}
}
