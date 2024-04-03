// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package webrtc

import (
	"net"
	"time"

	"github.com/pion/ice/v2"
	"github.com/pion/logging"
	"github.com/pion/transport/v2"
)

// NewICETCPMux creates a new instance of ice.TCPMuxDefault. It enables use of
// passive ICE TCP candidates.
func NewICETCPMux(logger logging.LeveledLogger, listener net.Listener, readBufferSize int) ice.TCPMux {
	return ice.NewTCPMuxDefault(ice.TCPMuxParams{
		Listener:       listener,
		Logger:         logger,
		ReadBufferSize: readBufferSize,
	})
}

// NewICEUDPMux creates a new instance of ice.UDPMuxDefault. It allows many PeerConnections to be served
// by a single UDP Port.
func NewICEUDPMux(logger logging.LeveledLogger, udpConn net.PacketConn) ice.UDPMux {
	return ice.NewUDPMuxDefault(ice.UDPMuxParams{
		UDPConn: udpConn,
		Logger:  logger,
	})
}

// [Psiphon] from https://github.com/pion/webrtc/pull/2298
// NewICEUniversalUDPMux creates a new instance of ice.UniversalUDPMux.  It allows many PeerConnections with
// host, server reflexive and relayed candidates to by served by a single UDP port.
func NewICEUniversalUDPMux(
	logger logging.LeveledLogger, udpConn net.PacketConn, xorMappedAddrCacheTTL time.Duration, transportNet transport.Net) ice.UniversalUDPMux {
	return ice.NewUniversalUDPMuxDefault(ice.UniversalUDPMuxParams{
		Logger:                logger,
		UDPConn:               udpConn,
		XORMappedAddrCacheTTL: xorMappedAddrCacheTTL,
		Net:                   transportNet,
	})
}
