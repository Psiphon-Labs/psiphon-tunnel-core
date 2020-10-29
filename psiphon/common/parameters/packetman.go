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

package parameters

import (
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
)

// PacketManipulationSpec is a work-around to avoid the client-side code size
// impact of importing the packetman package and its dependencies.
//
// TODO: Given that packetman and its parameters are server-side only,
// rearrange tactics/parameters to reference packetman.Spec directly, but only
// in server code. This should allow reinstating the spec.Validate below.

// PacketManipulationSpec is type-compatible with
// psiphon/common.packetman.Spec.
type PacketManipulationSpec struct {
	Name        string
	PacketSpecs [][]string
}

// PacketManipulationSpecs is a list of packet manipulation specs.
type PacketManipulationSpecs []*PacketManipulationSpec

// Validate checks that each spec name is unique and that each spec compiles.
func (specs PacketManipulationSpecs) Validate() error {
	specNames := make(map[string]bool)
	for _, spec := range specs {
		if spec.Name == "" {
			return errors.TraceNew("missing spec name")
		}
		if ok, _ := specNames[spec.Name]; ok {
			return errors.Tracef("duplicate spec name: %s", spec.Name)
		}
		specNames[spec.Name] = true

		// See PacketManipulationSpec comment above.
		//
		// Note that, even with spec.Validate disabled, spec validation will still
		// be performed, by packetman.Manipulator, on startup and after tactics hot
		// reload, with equivilent outcomes for invalid specs; however, the tactics
		// load itself will not fail in this case.

		// err := spec.Validate()
		// if err != nil {
		// 	return errors.Trace(err)
		// }
	}
	return nil
}

// ProtocolPacketManipulations is a map from tunnel protocol names (or "All")
// to a list of packet manipulation spec names.
type ProtocolPacketManipulations map[string][]string

// Validate checks that tunnel protocol and spec names are valid. Duplicate
// spec names are allowed in each entry, enabling weighted selection.
func (manipulations ProtocolPacketManipulations) Validate(specs PacketManipulationSpecs) error {
	validSpecNames := make(map[string]bool)
	for _, spec := range specs {
		validSpecNames[spec.Name] = true
	}
	for tunnelProtocol, specNames := range manipulations {
		if tunnelProtocol != protocol.TUNNEL_PROTOCOLS_ALL {
			if !protocol.TunnelProtocolMayUseServerPacketManipulation(tunnelProtocol) {
				return errors.TraceNew("invalid tunnel protocol for packet manipulation")
			}
		}

		for _, specName := range specNames {
			if ok, _ := validSpecNames[specName]; !ok {
				return errors.Tracef("invalid spec name: %s", specName)
			}
		}
	}
	return nil
}
