// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"net"
)

// Resume imports an already established dtls connection using a specific dtls state.
//
// Deprecated: Use ResumeWithOptions instead.
func Resume(state *State, conn net.PacketConn, rAddr net.Addr, config *Config) (*Conn, error) {
	if err := state.initCipherSuite(); err != nil {
		return nil, err
	}

	if config == nil {
		return nil, errNoConfigProvided
	}

	if err := validateConfig(config); err != nil {
		return nil, err
	}

	return createConn(conn, rAddr, config, state.isClient, state)
}

// ResumeWithOptions imports an already established dtls connection using a specific dtls state.
func ResumeWithOptions(state *State, conn net.PacketConn, rAddr net.Addr, opts ...Option) (*Conn, error) {
	config, err := buildConfig(opts...)
	if err != nil {
		return nil, err
	}

	return Resume(state, conn, rAddr, config)
}
