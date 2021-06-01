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

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/packetman"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/parameters"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
)

func makePacketManipulatorConfig(
	support *SupportServices) (*packetman.Config, error) {

	// Packet interception is configured for any tunnel protocol port that _may_
	// use packet manipulation. A future hot reload of tactics may apply specs to
	// any of these protocols.

	var ports []int
	for tunnelProtocol, port := range support.Config.TunnelProtocolPorts {
		if protocol.TunnelProtocolMayUseServerPacketManipulation(tunnelProtocol) {
			ports = append(ports, port)
		}
	}

	selectSpecName := func(protocolPort int, clientIP net.IP) (string, interface{}) {

		specName, extraData, err := selectPacketManipulationSpec(
			support, protocolPort, clientIP)
		if err != nil {
			log.WithTraceFields(
				LogFields{"error": err}).Warning(
				"failed to get tactics for packet manipulation")
			return "", nil
		}

		return specName, extraData
	}

	specs, err := getPacketManipulationSpecs(support)
	if err != nil {
		return nil, errors.Trace(err)
	}

	return &packetman.Config{
		Logger:                    CommonLogger(log),
		SudoNetworkConfigCommands: support.Config.PacketTunnelSudoNetworkConfigCommands,
		QueueNumber:               1,
		ProtocolPorts:             ports,
		Specs:                     specs,
		SelectSpecName:            selectSpecName,
	}, nil
}

func getPacketManipulationSpecs(support *SupportServices) ([]*packetman.Spec, error) {

	// By convention, parameters.ServerPacketManipulationSpecs should be in
	// DefaultTactics, not FilteredTactics; and ServerTacticsParametersCache
	// ignores Tactics.Probability.

	p, err := support.ServerTacticsParametersCache.Get(NewGeoIPData())
	if err != nil {
		return nil, errors.Trace(err)
	}

	if p.IsNil() {
		// No tactics are configured; return an empty spec list.
		return nil, nil
	}

	paramSpecs := p.PacketManipulationSpecs(parameters.ServerPacketManipulationSpecs)

	specs := make([]*packetman.Spec, len(paramSpecs))
	for i, spec := range paramSpecs {
		packetmanSpec := packetman.Spec(*spec)
		specs[i] = &packetmanSpec
	}

	return specs, nil
}

func reloadPacketManipulationSpecs(support *SupportServices) error {

	specs, err := getPacketManipulationSpecs(support)
	if err != nil {
		return errors.Trace(err)
	}

	err = support.PacketManipulator.SetSpecs(specs)
	if err != nil {
		return errors.Trace(err)
	}

	return nil
}

func selectPacketManipulationSpec(
	support *SupportServices,
	protocolPort int,
	clientIP net.IP) (string, interface{}, error) {

	// First check for replay, then check tactics.

	// The intercepted packet source/protocol port is used to determine the
	// tunnel protocol name, which is used to lookup first replay and then
	// enabled packet manipulation specs in ServerProtocolPacketManipulations.
	//
	// This assumes that all TunnelProtocolMayUseServerPacketManipulation
	// protocols run on distinct ports, which is true when all such protocols run
	// over TCP.

	targetTunnelProtocol := ""
	for tunnelProtocol, port := range support.Config.TunnelProtocolPorts {
		if port == protocolPort && protocol.TunnelProtocolMayUseServerPacketManipulation(tunnelProtocol) {
			targetTunnelProtocol = tunnelProtocol
			break
		}
	}
	if targetTunnelProtocol == "" {
		return "", nil, errors.Tracef(
			"packet manipulation protocol port not found: %d", protocolPort)
	}

	geoIPData := support.GeoIPService.LookupIP(clientIP)

	specName, doReplay := support.ReplayCache.GetReplayPacketManipulation(
		targetTunnelProtocol, geoIPData)

	// extraData records the is_server_replay metric.
	extraData := doReplay

	if doReplay {
		return specName, extraData, nil
	}

	// GeoIP tactics filtering is applied when getting
	// ServerPacketManipulationProbability and ServerProtocolPacketManipulations.
	//
	// When there are multiple enabled specs, one is selected at random.
	//
	// Specs under the key "All" apply to all protocols. Duplicate specs per
	// entry are allowed, enabling weighted selection. If a spec appears in both
	// "All" and a specific protocol, the duplicate(s) are retained.

	p, err := support.ServerTacticsParametersCache.Get(geoIPData)
	if err != nil {
		return "", nil, errors.Trace(err)
	}

	if p.IsNil() {
		// No tactics are configured; select no spec.
		return "", extraData, nil
	}

	if !p.WeightedCoinFlip(parameters.ServerPacketManipulationProbability) {
		return "", extraData, nil
	}

	protocolSpecs := p.ProtocolPacketManipulations(
		parameters.ServerProtocolPacketManipulations)

	// TODO: cache merged per-protocol + "All" lists?
	specNames, ok := protocolSpecs[targetTunnelProtocol]
	if !ok {
		specNames = []string{}
	}

	allProtocolsSpecNames, ok := protocolSpecs[protocol.TUNNEL_PROTOCOLS_ALL]
	if ok {
		specNames = append(specNames, allProtocolsSpecNames...)
	}

	if len(specNames) < 1 {
		// Tactics contains no candidate specs for this protocol.
		return "", extraData, nil
	}

	return specNames[prng.Range(0, len(specNames)-1)], extraData, nil
}
