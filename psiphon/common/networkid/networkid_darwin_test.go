//go:build darwin && !ios && cgo

/*
 * Copyright (c) 2026, Psiphon Inc.
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
	"os"
	"strings"
	"sync"
	"testing"
)

func TestConnectionTypeFromMedia(t *testing.T) {
	for media, expected := range map[int32]string{
		0x80:     "WIFI",
		0x82:     "WIFI",
		0x20:     "WIRED",
		0x22:     "WIRED",
		0x100020: "WIRED",
		0x02:     "UNKNOWN",
		0x00:     "UNKNOWN",
	} {
		if connectionTypeFromMedia(media) != expected {
			t.Errorf("media %#x: expected %s, got %s",
				media, expected, connectionTypeFromMedia(media))
		}
	}
}

func countOpenFDs(t *testing.T) int {
	t.Helper()
	dir, err := os.Open("/dev/fd")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	defer dir.Close()
	names, err := dir.Readdirnames(-1)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	return len(names)
}

// getInterfaceMedia opens a socket per call, on both the success and failure
// paths.
func TestGetInterfaceMediaClosesSocket(t *testing.T) {

	call := func() {
		getInterfaceMedia("en0")
		getInterfaceMedia("utun0")
		getInterfaceMedia("no-such-interface")
	}

	call()
	before := countOpenFDs(t)
	for i := 0; i < 1000; i++ {
		call()
	}

	// A leak shows as thousands of descriptors, so a small margin absorbs
	// unrelated activity without masking one.
	if after := countOpenFDs(t); after > before+8 {
		t.Errorf("descriptors leaked: before %d, after %d", before, after)
	}
}

// An over-long name must be truncated into ifm_name rather than overflowing it.
func TestGetInterfaceMediaLongName(t *testing.T) {
	for _, length := range []int{15, 16, 17, 64, 300} {
		if _, err := getInterfaceMedia(strings.Repeat("x", length)); err == nil {
			t.Errorf("length %d: unexpected success", length)
		}
	}
}

func TestGetConcurrent(t *testing.T) {

	skipWithoutDefaultRoute(t)

	var waitGroup sync.WaitGroup
	for i := 0; i < 10; i++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			for j := 0; j < 20; j++ {
				if _, err := Get(""); err != nil {
					t.Errorf("error: %v", err)
					return
				}
			}
		}()
	}
	waitGroup.Wait()
}
