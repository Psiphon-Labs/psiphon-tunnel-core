//go:build windows
// +build windows

/*
 * Copyright (c) 2022, Psiphon Inc.
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
	"context"
	"net"
	"strconv"
	"syscall"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"golang.org/x/net/bpf"
)

func ClientBPFEnabled() bool {
	return false
}

func setSocketBPF(_ []bpf.RawInstruction, _ int) error {
	return errors.TraceNew("BPF not supported")
}

func setAdditionalSocketOptions(_ int) {
}

func makeLocalProxyListener(listenIP string, port int) (net.Listener, bool, error) {
	listenConfig := net.ListenConfig{
		Control: func(_, _ string, c syscall.RawConn) error {
			var controlErr error
			err := c.Control(func(fd uintptr) {

				if listenIP != "0.0.0.0" {
					return
				}

				// When binding to the wildcard IP address, 0.0.0.0, set
				// SO_EXCLUSIVEADDRUSE since Windows, in this case, otherwise
				// allows other programs to bind to a specific IP address
				// (e.g., 127.0.0.1) with the same port number and we'll
				// unexpectedly lose our port binding.
				//
				// SO_EXCLUSIVEADDRUSE is not necessary in the non-wildcard
				// case, as Windows will cause conflicting bind calls to
				// fail.

				// SO_EXCLUSIVEADDRUSE isn't defined in syscall. This is the
				// definition from Winsock2.h.
				SO_EXCLUSIVEADDRUSE := ^syscall.SO_REUSEADDR

				controlErr = syscall.SetsockoptInt(
					syscall.Handle(fd),
					syscall.SOL_SOCKET,
					SO_EXCLUSIVEADDRUSE,
					1)
			})
			if controlErr != nil {
				return errors.Trace(controlErr)
			}
			return errors.Trace(err)
		},
	}
	listener, err := listenConfig.Listen(
		context.Background(), "tcp", net.JoinHostPort(listenIP, strconv.Itoa(port)))
	if err != nil {
		return nil, IsAddressInUseError(err), errors.Trace(err)
	}
	return listener, false, nil
}
