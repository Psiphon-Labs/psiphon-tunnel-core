//go:build darwin || linux
// +build darwin linux

/*
 * Copyright (c) 2021, Psiphon Inc.
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
	"os"
	"syscall"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"golang.org/x/sys/unix"
)

// fileFromFD duplicates the file descriptor; sets O_CLOEXEC to avoid leaking
// to child processes; sets the mode to nonblocking; and creates a os.File
// using os.NewFile.
func fileFromFD(fd int, name string) (*os.File, error) {

	// Prevent fork between duplicating fd and setting CLOEXEC
	syscall.ForkLock.RLock()
	defer syscall.ForkLock.RUnlock()

	dupfd, err := unix.Dup(fd)
	if err != nil {
		return nil, errors.Trace(err)
	}

	// Set CLOEXEC so file descriptor not leaked to network config command
	// subprocesses.
	unix.CloseOnExec(dupfd)

	err = unix.SetNonblock(dupfd, true)
	if err != nil {
		unix.Close(dupfd)
		return nil, errors.Trace(err)
	}

	return os.NewFile(uintptr(dupfd), name), nil
}
