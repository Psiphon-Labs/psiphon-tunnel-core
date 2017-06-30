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

// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tun

import (
	"os"
	"syscall"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
)

// dupFD is essentially this function:
// https://github.com/golang/go/blob/bf0f69220255941196c684f235727fd6dc747b5c/src/net/fd_unix.go#L306
//
// dupFD duplicates the file descriptor; sets O_CLOEXEC to avoid leaking
// to child processes; and sets the mode to blocking for use with os.NewFile.
func dupFD(fd int) (newfd int, err error) {

	syscall.ForkLock.RLock()
	defer syscall.ForkLock.RUnlock()

	newfd, err = syscall.Dup(fd)
	if err != nil {
		return -1, common.ContextError(os.NewSyscallError("dup", err))
	}

	syscall.CloseOnExec(newfd)

	if err = syscall.SetNonblock(newfd, false); err != nil {
		return -1, common.ContextError(os.NewSyscallError("setnonblock", err))
	}

	return
}
