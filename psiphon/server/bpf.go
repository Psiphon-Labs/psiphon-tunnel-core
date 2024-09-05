//go:build linux
// +build linux

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

package server

import (
	"context"
	"net"
	"syscall"
	"unsafe"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/parameters"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

// ServerBPFEnabled indicates if BPF functionality is enabled.
func ServerBPFEnabled() bool {
	return true
}

// newTCPListenerWithBPF creates a TCP net.Listener, optionally attaching
// the BPF program specified by the tactics parameter BPFServerTCPProgram.
func newTCPListenerWithBPF(
	support *SupportServices,
	localAddress string) (net.Listener, string, error) {

	// Limitations:
	// - BPFServerTCPProgram must be set unconditionally as neither client GeoIP
	//   nor API parameters are checked before the BPF is attached.
	// - Currently, lhe listener BPF is not reset upon tactics hot reload.

	havePBFProgram, programName, rawInstructions, err := getBPFProgram(support)
	if err != nil {
		log.WithTraceFields(
			LogFields{"error": err}).Warning("failed to get BPF program for listener")
		// If tactics is somehow misconfigured, keep running.
	}

	listenConfig := &net.ListenConfig{}

	if havePBFProgram {

		// Tactics parameters validation ensures BPFProgramInstructions has len >= 1.
		listenConfig.Control = func(network, address string, c syscall.RawConn) error {
			var setSockOptError error
			err := c.Control(func(fd uintptr) {
				setSockOptError = unix.SetsockoptSockFprog(
					int(fd),
					unix.SOL_SOCKET,
					unix.SO_ATTACH_FILTER,
					&unix.SockFprog{
						Len:    uint16(len(rawInstructions)),
						Filter: (*unix.SockFilter)(unsafe.Pointer(&rawInstructions[0])),
					})
			})
			if err == nil {
				err = setSockOptError
			}
			return errors.Trace(err)
		}
	}

	listener, err := listenConfig.Listen(context.Background(), "tcp", localAddress)

	return listener, programName, errors.Trace(err)
}

func getBPFProgram(support *SupportServices) (bool, string, []bpf.RawInstruction, error) {

	p, err := support.ServerTacticsParametersCache.Get(NewGeoIPData())
	if err != nil {
		return false, "", nil, errors.Trace(err)
	}

	if p.IsNil() {
		// No tactics are configured; BPF is disabled.
		return false, "", nil, nil
	}

	seed, err := protocol.DeriveBPFServerProgramPRNGSeed(support.Config.ObfuscatedSSHKey)
	if err != nil {
		return false, "", nil, errors.Trace(err)
	}

	PRNG := prng.NewPRNGWithSeed(seed)

	if !PRNG.FlipWeightedCoin(
		p.Float(parameters.BPFServerTCPProbability)) {
		return false, "", nil, nil
	}

	ok, name, rawInstructions := p.BPFProgram(parameters.BPFServerTCPProgram)
	return ok, name, rawInstructions, nil
}
