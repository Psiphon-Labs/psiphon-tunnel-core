/*
 * Copyright (c) 2016, Psiphon Inc.
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

// Package `rotate` provides an io.Writer interface for files that will detect when the open
// file has been rotated away (due to log rotation, or manual move/deletion) and re-open it.
// This allows the standard log.Logger to continue working as expected after log rotation
// happens (without needing to specify the `copytruncate` or equivalient options).
//
// This package is safe to use concurrently from multiple goroutines
package rotate

import (
	"os"
	"sync"
)

// RotatableFileWriter implementation that knows when the file has been rotated and re-opens it
type RotatableFileWriter struct {
	sync.Mutex
	file     *os.File
	fileInfo *os.FileInfo
	mode     os.FileMode
	name     string
}

// Close closes the underlying file
func (f *RotatableFileWriter) Close() error {
	f.Lock()
	err := f.file.Close()
	f.Unlock()

	return err
}

// reopen provides the (not exported, not concurrency safe) implementation of re-opening the file and updates the struct's fileInfo
func (f *RotatableFileWriter) reopen() error {
	if f.file != nil {
		f.file.Close()
		f.file = nil
		f.fileInfo = nil
	}

	reopened, err := os.OpenFile(f.name, os.O_WRONLY|os.O_APPEND|os.O_CREATE, f.mode)
	if err != nil {
		return err
	}

	f.file = reopened

	fileInfo, err := os.Stat(f.name)
	if err != nil {
		return err
	}

	f.fileInfo = &fileInfo

	return nil
}

// Reopen provides the concurrency safe implementation of re-opening the file, and updating the struct's fileInfo
func (f *RotatableFileWriter) Reopen() error {
	f.Lock()
	err := f.reopen()
	f.Unlock()

	return err
}

// Write implements the standard io.Writer interface, but checks whether or not the file
// has changed prior to writing. If it has, it will reopen the file first, then write
func (f *RotatableFileWriter) Write(p []byte) (int, error) {
	f.Lock()
	defer f.Unlock() // Defer unlock due to the possibility of early return

	// If a call to Write fails while attempting to re-open the file, f.fileInfo
	// could be left nil, causing subsequent writes to panic. This will attempt
	// to re-open the file handle prior to writing in that case
	if f.file == nil || f.fileInfo == nil {
		err := f.reopen()
		if err != nil {
			return 0, err
		}
	}

	currentFileInfo, err := os.Stat(f.name)
	if err != nil || !os.SameFile(*f.fileInfo, currentFileInfo) {
		err := f.reopen()
		if err != nil {
			return 0, err
		}
	}

	bytesWritten, err := f.file.Write(p)

	// If the write fails with nothing written, attempt to re-open the file and retry the write
	if bytesWritten == 0 && err != nil {
		err = f.reopen()
		if err != nil {
			return 0, err
		}

		bytesWritten, err = f.file.Write(p)
	}

	return bytesWritten, err
}

// NewRotatableFileWriter opens a file for appending and writing that can be safely rotated
func NewRotatableFileWriter(name string, mode os.FileMode) (*RotatableFileWriter, error) {
	rotatableFileWriter := RotatableFileWriter{
		file:     nil,
		name:     name,
		mode:     mode,
		fileInfo: nil,
	}

	err := rotatableFileWriter.reopen()
	if err != nil {
		return nil, err
	}

	return &rotatableFileWriter, nil
}
