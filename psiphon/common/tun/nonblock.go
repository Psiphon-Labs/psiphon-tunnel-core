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
	"io"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/creack/goselect"
)

// NonblockingIO provides interruptible I/O for non-pollable
// and/or foreign file descriptors that can't use the netpoller
// available in os.OpenFile as of Go 1.9.
//
// A NonblockingIO wraps a file descriptor in an
// io.ReadWriteCloser interface. The underlying implementation
// uses select and a pipe to interrupt Read and Write calls that
// are blocked when Close is called.
//
// Read and write mutexes allow, for each operation, only one
// concurrent goroutine to call syscalls, preventing an unbounded
// number of OS threads from being created by blocked select
// syscalls.
type NonblockingIO struct {
	closed      int32
	ioFD        int
	controlFDs  [2]int
	readMutex   sync.Mutex
	readFDSet   *goselect.FDSet
	writeMutex  sync.Mutex
	writeFDSets []*goselect.FDSet
}

// NewNonblockingIO creates a new NonblockingIO with the specified
// file descriptor, which is duplicated and set to nonblocking and
// close-on-exec.
func NewNonblockingIO(ioFD int) (*NonblockingIO, error) {

	syscall.ForkLock.RLock()
	defer syscall.ForkLock.RUnlock()

	newFD, err := syscall.Dup(ioFD)
	if err != nil {
		return nil, errors.Trace(err)
	}

	init := func(fd int) error {
		syscall.CloseOnExec(fd)
		return syscall.SetNonblock(fd, true)
	}

	err = init(newFD)
	if err != nil {
		return nil, errors.Trace(err)
	}

	var controlFDs [2]int
	err = syscall.Pipe(controlFDs[:])
	if err != nil {
		return nil, errors.Trace(err)
	}

	for _, fd := range controlFDs {
		err = init(fd)
		if err != nil {
			return nil, errors.Trace(err)
		}
	}

	return &NonblockingIO{
		ioFD:       newFD,
		controlFDs: controlFDs,
		readFDSet:  new(goselect.FDSet),
		writeFDSets: []*goselect.FDSet{
			new(goselect.FDSet), new(goselect.FDSet)},
	}, nil
}

// Read implements the io.Reader interface.
func (nio *NonblockingIO) Read(p []byte) (int, error) {
	nio.readMutex.Lock()
	defer nio.readMutex.Unlock()

	if atomic.LoadInt32(&nio.closed) != 0 {
		return 0, io.EOF
	}

	for {
		nio.readFDSet.Zero()
		nio.readFDSet.Set(uintptr(nio.controlFDs[0]))
		nio.readFDSet.Set(uintptr(nio.ioFD))
		max := nio.ioFD
		if nio.controlFDs[0] > max {
			max = nio.controlFDs[0]
		}
		err := goselect.Select(max+1, nio.readFDSet, nil, nil, -1)
		if err == syscall.EINTR {
			continue
		} else if err != nil {
			return 0, errors.Trace(err)
		}
		if nio.readFDSet.IsSet(uintptr(nio.controlFDs[0])) {
			return 0, io.EOF
		}
		n, err := syscall.Read(nio.ioFD, p)
		if err != nil && err != io.EOF {
			return n, errors.Trace(err)
		}

		if n == 0 && err == nil {
			// https://godoc.org/io#Reader:
			// "Implementations of Read are discouraged from
			// returning a zero byte count with a nil error".
			continue
		}

		return n, err
	}
}

// Write implements the io.Writer interface.
func (nio *NonblockingIO) Write(p []byte) (int, error) {
	nio.writeMutex.Lock()
	defer nio.writeMutex.Unlock()

	if atomic.LoadInt32(&nio.closed) != 0 {
		return 0, errors.TraceNew("file already closed")
	}

	n := 0
	t := len(p)
	for n < t {
		nio.writeFDSets[0].Zero()
		nio.writeFDSets[0].Set(uintptr(nio.controlFDs[0]))
		nio.writeFDSets[1].Zero()
		nio.writeFDSets[1].Set(uintptr(nio.ioFD))
		max := nio.ioFD
		if nio.controlFDs[0] > max {
			max = nio.controlFDs[0]
		}
		err := goselect.Select(max+1, nio.writeFDSets[0], nio.writeFDSets[1], nil, -1)
		if err == syscall.EINTR {
			continue
		} else if err != nil {
			return 0, errors.Trace(err)
		}
		if nio.writeFDSets[0].IsSet(uintptr(nio.controlFDs[0])) {
			return 0, errors.TraceNew("file has closed")
		}
		m, err := syscall.Write(nio.ioFD, p)
		n += m
		if err != nil && err != syscall.EAGAIN && err != syscall.EWOULDBLOCK {
			return n, errors.Trace(err)
		}
		if n < t {
			p = p[m:]
		}
	}
	return n, nil
}

// IsClosed indicates whether the NonblockingIO is closed.
func (nio *NonblockingIO) IsClosed() bool {
	return atomic.LoadInt32(&nio.closed) != 0
}

// Close implements the io.Closer interface.
func (nio *NonblockingIO) Close() error {

	if !atomic.CompareAndSwapInt32(&nio.closed, 0, 1) {
		return nil
	}

	// Interrupt any Reads/Writes blocked in Select.

	var b [1]byte
	_, err := syscall.Write(nio.controlFDs[1], b[:])
	if err != nil {
		return errors.Trace(err)
	}

	// Lock to ensure concurrent Read/Writes have
	// exited and are no longer using the file
	// descriptors before closing the file descriptors.

	nio.readMutex.Lock()
	defer nio.readMutex.Unlock()
	nio.writeMutex.Lock()
	defer nio.writeMutex.Unlock()

	syscall.Close(nio.controlFDs[0])
	syscall.Close(nio.controlFDs[1])
	syscall.Close(nio.ioFD)

	return nil
}
