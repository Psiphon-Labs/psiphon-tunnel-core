/*
 * Copyright (c) 2023, Psiphon Inc.
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

package inproxy

import (
	"fmt"
)

// NATMapping is a NAT mapping behavior defined in RFC 4787, section 4.1.
type NATMapping int32

const (
	NATMappingUnknown NATMapping = iota
	NATMappingEndpointIndependent
	NATMappingAddressDependent
	NATMappingAddressPortDependent
)

func (m NATMapping) String() string {
	switch m {
	case NATMappingUnknown:
		return "MappingUnknown"
	case NATMappingEndpointIndependent:
		return "MappingEndpointIndependent"
	case NATMappingAddressDependent:
		return "MappingAddressDependent"
	case NATMappingAddressPortDependent:
		return "MappingAddressPortDependent"
	}
	return ""
}

// MarshalText ensures the string representation of the value is logged in
// JSON.
func (m NATMapping) MarshalText() ([]byte, error) {
	return []byte(m.String()), nil
}

func (m NATMapping) IsValid() bool {
	return m.String() != ""
}

// NATMapping is a NAT filtering behavior defined in RFC 4787, section 5.
type NATFiltering int32

const (
	NATFilteringUnknown NATFiltering = iota
	NATFilteringEndpointIndependent
	NATFilteringAddressDependent
	NATFilteringAddressPortDependent
)

func (f NATFiltering) String() string {
	switch f {
	case NATFilteringUnknown:
		return "FilteringUnknown"
	case NATFilteringEndpointIndependent:
		return "FilteringEndpointIndependent"
	case NATFilteringAddressDependent:
		return "FilteringAddressDependent"
	case NATFilteringAddressPortDependent:
		return "FilteringAddressPortDependent"
	}
	return ""
}

// MarshalText ensures the string representation of the value is logged in
// JSON.
func (f NATFiltering) MarshalText() ([]byte, error) {
	return []byte(f.String()), nil
}

func (f NATFiltering) IsValid() bool {
	return f.String() != ""
}

// NATType specifies a network's NAT behavior and consists of a NATMapping and
// a NATFiltering component.
type NATType int32

// MakeNATType creates a new NATType.
func MakeNATType(mapping NATMapping, filtering NATFiltering) NATType {
	return (NATType(mapping) << 2) | NATType(filtering)
}

var (
	NATTypeUnknown = MakeNATType(NATMappingUnknown, NATFilteringUnknown)

	// NATTypePortMapping is a pseudo NATType, used in matching, that
	// represents the relevant NAT behavior of a port mapping (e.g., UPnP-IGD).
	NATTypePortMapping = MakeNATType(NATMappingEndpointIndependent, NATFilteringEndpointIndependent)

	// NATTypeMobileNetwork is a pseudo NATType, usied in matching, that
	// represents the assumed and relevent NAT behavior of clients on mobile
	// networks, presumed to be behind CGNAT when they report NATTypeUnknown.
	NATTypeMobileNetwork = MakeNATType(NATMappingAddressPortDependent, NATFilteringAddressPortDependent)

	// NATTypeNone and the following NATType constants are used in testing.
	// They are not entirely precise (a symmetric NAT may have a different
	// mix of mapping and filtering values). The matching logic does not use
	// specific NAT type definitions and instead considers the reported
	// mapping and filtering values.
	NATTypeNone               = MakeNATType(NATMappingEndpointIndependent, NATFilteringEndpointIndependent)
	NATTypeFullCone           = MakeNATType(NATMappingEndpointIndependent, NATFilteringEndpointIndependent)
	NATTypeRestrictedCone     = MakeNATType(NATMappingEndpointIndependent, NATFilteringAddressDependent)
	NATTypePortRestrictedCone = MakeNATType(NATMappingEndpointIndependent, NATFilteringAddressPortDependent)
	NATTypeSymmetric          = MakeNATType(NATMappingAddressPortDependent, NATFilteringAddressPortDependent)
)

// NeedsDiscovery indicates that the NATType is unknown and should be
// discovered.
func (t NATType) NeedsDiscovery() bool {
	return t == NATTypeUnknown
}

// Mapping extracts the NATMapping component of this NATType.
func (t NATType) Mapping() NATMapping {
	return NATMapping(t >> 2)
}

// Filtering extracts the NATFiltering component of this NATType.
func (t NATType) Filtering() NATFiltering {
	return NATFiltering(t & 0x3)
}

// Traversal returns the NATTraversal classification for this NATType.
func (t NATType) Traversal() NATTraversal {
	return MakeTraversal(t)
}

// Compatible indicates whether the NATType NATTraversals are compatible.
func (t NATType) Compatible(t1 NATType) bool {
	return t.Traversal().Compatible(t1.Traversal())
}

// IsPreferredMatch indicates whether the peer NATType's NATTraversal is
// preferred.
func (t NATType) IsPreferredMatch(t1 NATType) bool {
	return t.Traversal().IsPreferredMatch(t1.Traversal())
}

// ExistsPreferredMatch indicates whhether there exists a preferred match for
// the NATType's NATTraversal.
func (t NATType) ExistsPreferredMatch(unlimited, partiallyLimited, limited bool) bool {
	return t.Traversal().ExistsPreferredMatch(unlimited, partiallyLimited, limited)
}

func (t NATType) String() string {
	return fmt.Sprintf(
		"%s/%s", t.Mapping().String(), t.Filtering().String())
}

// MarshalText ensures the string representation of the value is logged in
// JSON.
func (t NATType) MarshalText() ([]byte, error) {
	return []byte(t.String()), nil
}

func (t NATType) IsValid() bool {
	return t.Mapping().IsValid() && t.Filtering().IsValid()
}

// NATTraversal classifies the NAT traversal potential for a NATType. NATTypes
// are determined to be compatible -- that is, a connection between the
// corresponding networks can be established via STUN hole punching  -- based
// on their respective NATTraversal classifications.
type NATTraversal int32

const (
	NATTraversalUnlimited NATTraversal = iota
	NATTraversalPartiallyLimited
	NATTraversalStrictlyLimited
)

// MakeTraversal returns the NATTraversal classification for the given
// NATType.
func MakeTraversal(t NATType) NATTraversal {
	mapping := t.Mapping()
	filtering := t.Filtering()
	if mapping == NATMappingEndpointIndependent {
		if filtering != NATFilteringAddressPortDependent {
			// NAT type is, e.g., none, full cone, or restricted cone.
			return NATTraversalUnlimited
		}
		// NAT type is, e.g., port restricted cone.
		return NATTraversalPartiallyLimited
	}

	// NAT type is, e.g., symmetric; or unknown -- where we assume the worst
	// case.
	return NATTraversalStrictlyLimited
}

// Compatible indicates whether the NATTraversals are compatible.
func (t NATTraversal) Compatible(t1 NATTraversal) bool {

	// See the NAT compatibility matrix here:
	// https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/-/wikis/NAT-matching#nat-compatibility

	switch t {
	case NATTraversalUnlimited:
		// t1 can be any value when t is unlimited.
		return true
	case NATTraversalPartiallyLimited:
		// t1 can be unlimited or partially limited when t is partially limited.
		return t1 != NATTraversalStrictlyLimited
	case NATTraversalStrictlyLimited:
		// t1 must be unlimited when t is limited.
		return t1 == NATTraversalUnlimited
	}
	return false
}

// IsPreferredMatch indicates whether the peer NATTraversal is a preferred
// match for this NATTraversal. A match is preferred, and so prioritized,
// when one of the two NATTraversals is more limited, but the pair is still
// compatible. This preference attempt to reserve less limited match
// candidates for those peers that need them.
func (t NATTraversal) IsPreferredMatch(t1 NATTraversal) bool {
	switch t {
	case NATTraversalUnlimited:
		// Prefer matching unlimited peers with strictly limited peers.
		// TODO: prefer matching unlimited with partially limited?
		return t1 == NATTraversalStrictlyLimited
	case NATTraversalPartiallyLimited:
		// Prefer matching partially limited peers with unlimited or other
		// partially limited peers.
		return t1 == NATTraversalUnlimited || t1 == NATTraversalPartiallyLimited
	case NATTraversalStrictlyLimited:
		// Prefer matching strictly limited peers with unlimited peers.
		return t1 == NATTraversalUnlimited
	}
	return false
}

// ExistsPreferredMatch indicates whether a preferred match exists, for this
// NATTraversal, when there are unlimited/partiallyLimited/strictlyLimited candidates
// available.
func (t NATTraversal) ExistsPreferredMatch(unlimited, partiallyLimited, strictlyLimited bool) bool {
	switch t {
	case NATTraversalUnlimited:
		return strictlyLimited
	case NATTraversalPartiallyLimited:
		return unlimited || partiallyLimited
	case NATTraversalStrictlyLimited:
		return unlimited
	}
	return false
}

// PortMappingType is a port mapping protocol supported by a network. Values
// include UPnP-IGD, NAT-PMP, and PCP.
type PortMappingType int32

const (
	PortMappingTypeNone PortMappingType = iota
	PortMappingTypeUPnP
	PortMappingTypePMP
	PortMappingTypePCP
)

func (t PortMappingType) String() string {
	switch t {
	case PortMappingTypeNone:
		return "None"
	case PortMappingTypeUPnP:
		return "UPnP-IGD"
	case PortMappingTypePMP:
		return "PMP"
	case PortMappingTypePCP:
		return "PCP"
	}
	return ""
}

// MarshalText ensures the string representation of the value is logged in
// JSON.
func (t PortMappingType) MarshalText() ([]byte, error) {
	return []byte(t.String()), nil
}

func (t PortMappingType) IsValid() bool {
	return t.String() != ""
}

// PortMappingTypes is a list of port mapping protocol supported by a
// network.
type PortMappingTypes []PortMappingType

// NeedsDiscovery indicates that the list of port mapping types is empty and
// should be discovered. If a network has no supported port mapping types,
// its list will include PortMappingTypeNone.
func (t PortMappingTypes) NeedsDiscovery() bool {
	return len(t) == 0
}

// Available indicates that at least one port mapping protocol is supported.
func (t PortMappingTypes) Available() bool {
	for _, portMappingType := range t {
		if portMappingType > PortMappingTypeNone {
			return true
		}
	}
	return false
}

func (t PortMappingTypes) IsValid() bool {
	for _, portMappingType := range t {
		if !portMappingType.IsValid() {
			return false
		}
	}
	return true
}

// ICECandidateType is an ICE candidate type: host for public addresses, port
// mapping for when a port mapping protocol was used to establish a public
// address, or server reflexive when STUN hole punching was used to create a
// public address. Peer reflexive candidates emerge during the ICE
// negotiation process and are not SDP entries.
type ICECandidateType int32

const (
	ICECandidateUnknown ICECandidateType = iota
	ICECandidateHost
	ICECandidatePortMapping
	ICECandidateServerReflexive
	ICECandidatePeerReflexive
)

func (t ICECandidateType) String() string {
	switch t {
	case ICECandidateUnknown:
		return "Unknown"
	case ICECandidateHost:
		return "Host"
	case ICECandidatePortMapping:
		return "PortMapping"
	case ICECandidateServerReflexive:
		return "ServerReflexive"
	case ICECandidatePeerReflexive:
		return "PeerReflexive"
	}
	return ""
}

// MarshalText ensures the string representation of the value is logged in
// JSON.
func (t ICECandidateType) MarshalText() ([]byte, error) {
	return []byte(t.String()), nil
}

func (t ICECandidateType) IsValid() bool {
	return t.String() != ""
}

// ICECandidateTypes is a list of ICE candidate types.
type ICECandidateTypes []ICECandidateType

func (t ICECandidateTypes) IsValid() bool {
	for _, candidateType := range t {
		if !candidateType.IsValid() {
			return false
		}
	}
	return true
}
