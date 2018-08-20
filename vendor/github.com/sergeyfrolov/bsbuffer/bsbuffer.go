// Copyright 2017 Sergey Frolov
// Use of this source code is governed by a LGPL-style
// license that can be found in the LICENSE file.

package bsbuffer

import (
	"bytes"
	"io"
	"sync"
)

// BSBuffer:
// B - Blocking - Read() calls are blocking.
// S - Safe - Supports arbitrary amount of readers and writers.
// Could be unblocked and turned into SBuffer.
type BSBuffer struct {
	sync.Mutex
	bufIn  bytes.Buffer
	bufOut bytes.Buffer
	r      *io.PipeReader
	w      *io.PipeWriter

	hasData    chan struct{}
	engineExit chan struct{}
	unblocked  bool

	unblockOnce sync.Once
}

// Creates new BSBuffer
func NewBSBuffer() *BSBuffer {
	bsb := new(BSBuffer)

	bsb.r, bsb.w = io.Pipe()

	bsb.hasData = make(chan struct{}, 1)
	bsb.engineExit = make(chan struct{})
	go bsb.engine()
	return bsb
}

func (b *BSBuffer) engine() {
	for {
		select {
		case _ = <-b.hasData:
			b.Lock()
			b.bufOut.ReadFrom(&b.bufIn)
			_, err := b.bufOut.WriteTo(b.w)
			if b.unblocked || err != nil {
				b.r.Close()
				close(b.engineExit)
				b.Unlock()
				return
			}
			b.Unlock()
		}
	}
}

// Reads data from the BSBuffer, blocking until a writer arrives or the BSBuffer is unblocked.
// If the write end is closed with an error, that error is returned as err; otherwise err is EOF.
// Supports multiple concurrent goroutines and p is valid forever.
func (b *BSBuffer) Read(p []byte) (n int, err error) {
	n, err = b.r.Read(p)
	if err != nil {
		if n != 0 {
			// There might be remaining data in underlying buffer, and we want user to
			// come back for it, so we clean the error and push data we have upwards
			err = nil
		} else {
			// Unblocked and no data in engine.
			// Operate as SafeBuffer
			b.Lock()
			n, err = b.bufOut.Read(p)
			b.Unlock()
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
	b.Lock()
	if b.unblocked {
		// Wait for engine to exit and operate as Safe Buffer.
		_ = <-b.engineExit
		n, err = b.bufOut.Write(p)
	} else {
		// Push data to engine and wake it up, if needed.
		n, err = b.bufIn.Write(p)
		select {
		case b.hasData <- struct{}{}:
		default:
		}
	}
	b.Unlock()
	return
}

// Turns BSBuffer into SBuffer: Read() is no longer blocking, but still safe.
// Unblock() is safe to call multiple times.
func (b *BSBuffer) Unblock() {
	b.unblockOnce.Do(func() {
		b.Lock()
		b.unblocked = true
		b.w.Close()
		close(b.hasData)
		b.Unlock()
	})
}
