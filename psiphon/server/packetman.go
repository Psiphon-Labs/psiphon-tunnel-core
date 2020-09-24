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

	selectSpecName := func(protocolPort int, clientIP net.IP) string {

		specName, err := selectPacketManipulationSpec(support, protocolPort, clientIP)
		if err != nil {
			log.WithTraceFields(
				LogFields{"error": err}).Warning(
				"failed to get tactics for packet manipulation")
			return ""
		}

		return specName
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
	// DefaultTactics, not FilteredTactics; and Tactics.Probability is ignored.

	tactics, err := support.TacticsServer.GetTactics(
		true, common.GeoIPData(NewGeoIPData()), make(common.APIParameters))
	if err != nil {
		return nil, errors.Trace(err)
	}

	if tactics == nil {
		// This server isn't configured with tactics.
		return []*packetman.Spec{}, nil
	}

	clientParameters, err := parameters.NewClientParameters(nil)
	if err != nil {
		return nil, errors.Trace(err)
	}
	_, err = clientParameters.Set("", false, tactics.Parameters)
	if err != nil {
		return nil, errors.Trace(err)
	}
	p := clientParameters.Get()

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
	support *SupportServices, protocolPort int, clientIP net.IP) (string, error) {

	geoIPData := support.GeoIPService.Lookup(clientIP.String())

	tactics, err := support.TacticsServer.GetTactics(
		true, common.GeoIPData(geoIPData), make(common.APIParameters))
	if err != nil {
		return "", errors.Trace(err)
	}

	if tactics == nil {
		// This server isn't configured with tactics.
		return "", nil
	}

	if !prng.FlipWeightedCoin(tactics.Probability) {
		// Skip tactics with the configured probability.
		return "", nil
	}

	clientParameters, err := parameters.NewClientParameters(nil)
	if err != nil {
		return "", errors.Trace(err)
	}
	_, err = clientParameters.Set("", false, tactics.Parameters)
	if err != nil {
		return "", errors.Trace(err)
	}
	p := clientParameters.Get()

	// GeoIP tactics filtering is applied before getting
	// ServerPacketManipulationProbability and ServerProtocolPacketManipulations.
	//
	// The intercepted packet source/protocol port is used to determine the
	// tunnel protocol name, which is used to lookup enabled packet manipulation
	// specs in ServerProtocolPacketManipulations.
	//
	// When there are multiple enabled specs, one is selected at random.
	//
	// Specs under the key "All" apply to all protocols. Duplicate specs per
	// entry are allowed, enabling weighted selection. If a spec appears in both
	// "All" and a specific protocol, the duplicate(s) are retained.

	if !p.WeightedCoinFlip(parameters.ServerPacketManipulationProbability) {
		return "", nil
	}

	targetTunnelProtocol := ""
	for tunnelProtocol, port := range support.Config.TunnelProtocolPorts {
		if port == protocolPort {
			targetTunnelProtocol = tunnelProtocol
			break
		}
	}
	if targetTunnelProtocol == "" {
		return "", errors.Tracef(
			"packet manipulation protocol port not found: %d", protocolPort)
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
		return "", nil
	}

	return specNames[prng.Range(0, len(specNames)-1)], nil
}
