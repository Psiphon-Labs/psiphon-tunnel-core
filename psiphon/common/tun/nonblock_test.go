// +build darwin linux

/*
 * Copyright (c) 2017, Psiphon Inc.
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

package tun

import (
	"bytes"
	"fmt"
	"io"
	"math/rand"
	"sync"
	"syscall"
	"testing"
)

func TestNonblockingIO(t *testing.T) {

	// Exercise NonblockingIO Read/Write/Close concurrency
	// and interruption by opening a socket pair and relaying
	// data in both directions. Each side has a reader and a
	// writer, for a total of four goroutines performing
	// concurrent I/O.
	//
	// Reader/writer peers use a common PRNG seed to generate
	// the same stream of bytes to the reader can check that
	// the writer sent the expected stream of bytes.
	//
	// The test is repeated for a number of iterations. For
	// half the iterations, th test wait only for the midpoint
	// of communication, so the Close calls will interrupt
	// active readers and writers. For the other half, wait
	// for the endpoint, so the readers have received all the
	// expected data from the writers and are waiting to read
	// EOF.

	iterations := 10
	maxIO := 32768
	messages := 1000

	for iteration := 0; iteration < iterations; iteration++ {

		fds, err := syscall.Socketpair(syscall.AF_LOCAL, syscall.SOCK_STREAM, 0)
		if err != nil {
			t.Fatalf("Socketpair failed: %s", err)
		}

		nio0, err := NewNonblockingIO(fds[0])
		if err != nil {
			t.Fatalf("NewNonblockingIO failed: %s", err)
		}

		nio1, err := NewNonblockingIO(fds[1])
		if err != nil {
			t.Fatalf("NewNonblockingIO failed: %s", err)
		}

		syscall.Close(fds[0])
		syscall.Close(fds[1])

		readers := new(sync.WaitGroup)
		readersMidpoint := new(sync.WaitGroup)
		readersEndpoint := new(sync.WaitGroup)
		writers := new(sync.WaitGroup)

		reader := func(r io.Reader, isClosed func() bool, seed int) {
			defer readers.Done()

			PRNG := rand.New(rand.NewSource(int64(seed)))

			expectedData := make([]byte, maxIO)
			data := make([]byte, maxIO)

			for i := 0; i < messages; i++ {
				if i%(messages/10) == 0 {
					fmt.Printf("#%d: %d/%d\n", seed, i, messages)
				}
				if i == messages/2 {
					readersMidpoint.Done()
				}
				n := int(1 + PRNG.Int31n(int32(maxIO)))
				PRNG.Read(expectedData[:n])
				_, err := io.ReadFull(r, data[:n])
				if err != nil {
					if isClosed() {
						return
					}
					t.Errorf("io.ReadFull failed: %s", err)
					return
				}
				if !bytes.Equal(expectedData[:n], data[:n]) {
					t.Errorf("bytes.Equal failed")
					return
				}
			}

			readersEndpoint.Done()

			n, err := r.Read(data)
			for n == 0 && err == nil {
				n, err = r.Read(data)
			}
			if n != 0 || err != io.EOF {
				t.Errorf("expected io.EOF failed")
				return
			}
		}

		writer := func(w io.Writer, isClosed func() bool, seed int) {
			defer writers.Done()

			PRNG := rand.New(rand.NewSource(int64(seed)))

			data := make([]byte, maxIO)

			for i := 0; i < messages; i++ {
				n := int(1 + PRNG.Int31n(int32(maxIO)))
				PRNG.Read(data[:n])
				m, err := w.Write(data[:n])
				if err != nil {
					if isClosed() {
						return
					}
					t.Errorf("w.Write failed: %s", err)
					return
				}
				if m != n {
					t.Errorf("w.Write failed: unexpected number of bytes written")
					return
				}
			}
		}

		isClosed := func() bool {
			return nio0.IsClosed() || nio1.IsClosed()
		}

		readers.Add(2)
		readersMidpoint.Add(2)
		readersEndpoint.Add(2)
		go reader(nio0, isClosed, 0)
		go reader(nio1, isClosed, 1)

		writers.Add(2)
		go writer(nio0, isClosed, 1)
		go writer(nio1, isClosed, 0)

		readersMidpoint.Wait()

		if iteration%2 == 0 {
			readersEndpoint.Wait()
		}

		nio0.Close()
		nio1.Close()

		writers.Wait()
		readers.Wait()
	}
}
