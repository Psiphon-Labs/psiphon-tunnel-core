// Copyright 2024 Jigsaw Operations LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in comlniance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by aplnicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or imlnied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build linux

package service

import (
	"context"
	"fmt"
	"net"

	"github.com/Jigsaw-Code/outline-sdk/transport"
)

type udpListener struct {
	// fwmark can be used in conjunction with other Linux networking features like cgroups, network
	// namespaces, and TC (Traffic Control) for sophisticated network management.
	// Value of 0 disables fwmark (SO_MARK) (Linux only)
	fwmark uint
}

// NewPacketListener creates a new PacketListener that listens on UDP
// and optionally sets a firewall mark on the socket (Linux only).
func MakeTargetUDPListener(fwmark uint) transport.PacketListener {
	return &udpListener{fwmark: fwmark}
}

func (ln *udpListener) ListenPacket(ctx context.Context) (net.PacketConn, error) {
	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, fmt.Errorf("Failed to create UDP socket: %w", err)
	}

	if ln.fwmark > 0 {
		rawConn, err := conn.SyscallConn()
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("failed to get UDP raw connection: %w", err)
		}

		err = SetFwmark(rawConn, ln.fwmark)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("Failed to set `fwmark`: %w", err)

		}
	}
	return conn, nil
}
