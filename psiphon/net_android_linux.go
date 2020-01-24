// +build android linux

/*
 * Copyright (c) 2020, Psiphon Inc.
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

package psiphon

import (
	"unsafe"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

func ClientBPFEnabled() bool {
	return true
}

func setSocketBPF(BPFProgramInstructions []bpf.RawInstruction, socketFD int) error {

	// Tactics parameters validation ensures BPFProgramInstructions has len >= 1.
	err := unix.SetsockoptSockFprog(
		socketFD,
		unix.SOL_SOCKET,
		unix.SO_ATTACH_FILTER,
		&unix.SockFprog{
			Len:    uint16(len(BPFProgramInstructions)),
			Filter: (*unix.SockFilter)(unsafe.Pointer(&BPFProgramInstructions[0])),
		})
	return errors.Trace(err)
}

func setAdditionalSocketOptions(_ int) {
}
