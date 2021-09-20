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
	"net"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/fragmentor"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
)

// TacticsListener wraps a net.Listener and applies server-side implementation
// of certain tactics parameters to accepted connections. Tactics filtering is
// limited to GeoIP attributes as the client has not yet sent API parameters.
// GeoIP uses the immediate peer IP, and so TacticsListener is suitable only
// for tactics that do not require the original client GeoIP when fronted.
type TacticsListener struct {
	net.Listener
	support        *SupportServices
	tunnelProtocol string
	geoIPLookup    func(IPaddress string) GeoIPData
}

// NewTacticsListener creates a new TacticsListener.
func NewTacticsListener(
	support *SupportServices,
	listener net.Listener,
	tunnelProtocol string,
	geoIPLookup func(IPaddress string) GeoIPData) *TacticsListener {

	return &TacticsListener{
		Listener:       listener,
		support:        support,
		tunnelProtocol: tunnelProtocol,
		geoIPLookup:    geoIPLookup,
	}
}

// Accept calls the underlying listener's Accept, and then applies server-side
// tactics to new connections.
func (listener *TacticsListener) Accept() (net.Conn, error) {
	for {
		// accept may discard a successfully accepted conn. In that case, accept
		// returns nil, nil; call accept until either the conn or err is not nil.
		conn, err := listener.accept()
		if conn != nil || err != nil {
			// Don't modify error from net.Listener
			return conn, err
		}
	}
}

func (listener *TacticsListener) accept() (net.Conn, error) {

	conn, err := listener.Listener.Accept()
	if err != nil {
		// Don't modify error from net.Listener
		return nil, err
	}

	// Limitation: RemoteAddr is the immediate peer IP, which is not the original
	// client IP in the case of fronting.
	geoIPData := listener.geoIPLookup(
		common.IPAddressFromAddr(conn.RemoteAddr()))

	p, err := listener.support.ServerTacticsParametersCache.Get(geoIPData)
	if err != nil {
		conn.Close()
		return nil, errors.Trace(err)
	}

	if p.IsNil() {
		// No tactics are configured; use the accepted conn without customization.
		return conn, nil
	}

	// Server-side fragmentation may be synchronized with client-side in two ways.
	//
	// In the OSSH case, replay is always activated and it is seeded using the
	// content of the client's OSSH seed message, which is fully delivered before
	// the server sends any bytes. SetReplay is deferred until after the seed
	// message is read by obfuscator.NewServerObfuscatedSSHConn. doReplay is set
	// to true so no seed is set at this time.
	//
	// SSH lacks the initial obfuscation message, and meek and other protocols
	// transmit downstream data before the initial obfuscation message arrives.
	// For these protocols, server-side fragmentation will happen, initially,
	// with an uncoordinated coin flip, based on server-side tactics
	// configuration. For protocols with multiple underlying TCP connections,
	// such as meek, the coin flip is performed independently once per
	// TCP connection.
	//
	// The server-side replay mechanism is used to replay successful server-side
	// fragmentation for uncoordinated protocols, subject to replay configuration
	// parameters. In this case, the replay seed returned by GetReplayFragmentor
	// below is applied.

	replaySeed, doReplay := listener.support.ReplayCache.GetReplayFragmentor(
		listener.tunnelProtocol, geoIPData)

	if listener.tunnelProtocol == protocol.TUNNEL_PROTOCOL_OBFUSCATED_SSH {
		replaySeed = nil
		doReplay = true
	}

	var newSeed *prng.Seed
	if !doReplay {
		var err error
		newSeed, err = prng.NewSeed()
		if err != nil {
			log.WithTraceFields(
				LogFields{"error": err}).Warning("failed to seed fragmentor PRNG")
			return conn, nil
		}
	}

	fragmentorConfig := fragmentor.NewDownstreamConfig(
		p, listener.tunnelProtocol, newSeed)

	if fragmentorConfig.MayFragment() {
		conn = fragmentor.NewConn(
			fragmentorConfig,
			func(message string) {
				log.WithTraceFields(
					LogFields{"message": message}).Debug("Fragmentor")
			},
			conn)

		if doReplay && replaySeed != nil {
			conn.(common.FragmentorReplayAccessor).SetReplay(
				prng.NewPRNGWithSeed(replaySeed))
		}
	}

	return conn, nil
}
