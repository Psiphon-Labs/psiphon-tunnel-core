// Copyright 2017 Sergey Frolov
// Use of this source code is governed by a LGPL-style
// license that can be found in the LICENSE file.

package bsbuffer

import (
	"bytes"
	"io"
	"io/ioutil"
	"sync"
)

// BSBuffer:
// B - Blocking - Read() calls are blocking.
// S - Safe - Supports arbitrary amount of readers and writers.
// Could be unblocked and turned into SBuffer.
type BSBuffer struct {
	mu sync.Mutex

	bufBlocked   bytes.Buffer // used before Unblock() is called
	bufUnblocked bytes.Buffer // used after Unblock() is called

	r *io.PipeReader
	w *io.PipeWriter

	unblocked  chan struct{} // closed on unblocking
	engineExit chan struct{} // after unblocking, engine will wrap up, close this and exit
	hasData    chan struct{} // never closed

	unblockOnce sync.Once
}

// Creates new BSBuffer
func NewBSBuffer() *BSBuffer {
	bsb := new(BSBuffer)

	bsb.r, bsb.w = io.Pipe()

	bsb.hasData = make(chan struct{}, 1)
	bsb.unblocked = make(chan struct{})
	bsb.engineExit = make(chan struct{})
	go bsb.engine()
	return bsb
}

// # How this is supposed to work #
// (all operations, except piped ones, are locked)
//
// before Unblock:
//    Write stores data to bufBlocked
//    engine copies data from bufBlocked, writes to pipe
//    Read reads from pipe
// after Unblock:
//    Write still writes data to bufBlocked
//    engine will copy data from bufBlocked to bufUnblocked and close `engineExit`
//    Read reads from pipe
// after engineExit is closed:
//    Write writes to bufUnblocked
//    Read reads from bufUnblocked

func (b *BSBuffer) engine() {
	for {
		select {
		case _ = <-b.hasData:
			b.mu.Lock()
			buf, _ := ioutil.ReadAll(&b.bufBlocked)
			b.mu.Unlock()
			n, _ := b.w.Write(buf) // blocking, unless Unblock was called
			select {
			case _ = <-b.unblocked:
				b.mu.Lock()
				// copy from buf whatever wasn't written to the pipe
				b.bufUnblocked.Write(buf[n:])

				// copy everything from bufBlocked to bufUnblocked
				// bufBlocked shouldn't be touched after engineExit is closed
				// and we have the Lock.
				b.bufUnblocked.Write(b.bufBlocked.Bytes())

				close(b.engineExit)
				b.mu.Unlock()
				return
			default:
			}
		}
	}
}

// Reads data from the BSBuffer, blocking until a writer arrives or the BSBuffer is unblocked.
// If the write end is closed with an error, that error is returned as err; otherwise err is EOF.
// Supports multiple concurrent goroutines and p is valid forever.
func (b *BSBuffer) Read(p []byte) (n int, err error) {
	n, err = b.r.Read(p) // blocking, unless Unblock was called
	if err != nil {
		if n != 0 {
			// There might be remaining data in underlying buffer, and we want user to
			// come back for it, so we clean the error and push data we have upwards
			err = nil
		} else {
			// Unblocked and no data in engine.
			// Operate as SafeBuffer
			b.mu.Lock()
			n, err = b.bufUnblocked.Read(p)
			b.mu.Unlock()
		}
	}
	return
}

// Non-blocking write appends the contents of p to the buffer, growing the buffer as needed.
// The return value n is the length of p; err is always nil.
// If the buffer becomes too large, Write will panic with ErrTooLarge.
// Supports multiple concurrent goroutines and p is safe for reuse right away.
func (b *BSBuffer) Write(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}

	b.mu.Lock()
	select {
	case _ = <-b.engineExit:
		n, err = b.bufUnblocked.Write(p)
		b.mu.Unlock()
	default:
		// Push data to engine and wake it up, if needed.
		n, err = b.bufBlocked.Write(p)
		select {
		case b.hasData <- struct{}{}:
		default:
		}
		b.mu.Unlock()
	}

	return
}

// Turns BSBuffer into SBuffer: Read() is no longer blocking, but still safe.
// Unblock() is safe to call multiple times.
func (b *BSBuffer) Unblock() {
	b.unblockOnce.Do(func() {
		// closing the pipes will make engine and reads non-blocking
		b.w.Close()
		b.r.Close()

		b.mu.Lock()
		close(b.unblocked)
		select {
		case b.hasData <- struct{}{}:
		default:
		}
		b.mu.Unlock()
	})
}
