/*
 * Copyright (c) 2021, Psiphon Inc.
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
	"net"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/regen"
)

// FrontingSpecs is a list of domain fronting specs.
type FrontingSpecs []*FrontingSpec

// FrontingSpec specifies a domain fronting configuration, to be used with
// MeekConn and MeekModePlaintextRoundTrip. In MeekModePlaintextRoundTrip, the
// fronted origin is an arbitrary web server, not a Psiphon server. This
// MeekConn mode requires HTTPS and server certificate validation:
// VerifyServerName is required; VerifyPins is recommended. See also
// psiphon.MeekConfig and psiphon.MeekConn.
//
// FrontingSpec.Addresses supports the functionality of both
// ServerEntry.MeekFrontingAddressesRegex and
// ServerEntry.MeekFrontingAddresses: multiple candidates are supported, and
// each candidate may be a regex, or a static value (with regex syntax).
type FrontingSpec struct {

	// Optional/new fields use omitempty to minimize tactics tag churn.

	FrontingProviderID string
	Transports         protocol.FrontingTransports `json:",omitempty"`
	Addresses          []string
	DisableSNI         bool     `json:",omitempty"`
	SkipVerify         bool     `json:",omitempty"`
	VerifyServerName   string   `json:",omitempty"`
	VerifyPins         []string `json:",omitempty"`
	Host               string
}

// SelectParameters selects fronting parameters from the given FrontingSpecs,
// first selecting a spec at random. SelectParameters is similar to
// psiphon.selectFrontingParameters, which operates on server entries.
//
// The return values are:
// - Dial Address (domain or IP address)
// - Transport (e.g., protocol.FRONTING_TRANSPORT_HTTPS)
// - SNI (which may be transformed; unless it is "", which indicates omit SNI)
// - VerifyServerName (see psiphon.CustomTLSConfig)
// - VerifyPins (see psiphon.CustomTLSConfig)
// - Host (Host header value)
func (specs FrontingSpecs) SelectParameters() (
	string, string, string, string, string, []string, string, error) {

	if len(specs) == 0 {
		return "", "", "", "", "", nil, "", errors.TraceNew("missing fronting spec")
	}

	spec := specs[prng.Intn(len(specs))]

	if len(spec.Addresses) == 0 {
		return "", "", "", "", "", nil, "", errors.TraceNew("missing fronting address")
	}

	// For backwards compatibility, the transport type defaults
	// to "FRONTED-HTTPS" when the FrontingSpec specifies no transport types.
	transport := protocol.FRONTING_TRANSPORT_HTTPS
	if len(spec.Transports) > 0 {
		transport = spec.Transports[prng.Intn(len(spec.Transports))]
	}

	frontingDialAddr, err := regen.GenerateString(
		spec.Addresses[prng.Intn(len(spec.Addresses))])
	if err != nil {
		return "", "", "", "", "", nil, "", errors.Trace(err)
	}

	SNIServerName := frontingDialAddr
	if spec.DisableSNI || net.ParseIP(frontingDialAddr) != nil {
		SNIServerName = ""
	}

	// When SkipVerify is true, VerifyServerName and VerifyPins must be empty,
	// as checked in Validate. When dialing in any mode, MeekConn will set
	// CustomTLSConfig.SkipVerify to true as long as VerifyServerName is "".
	// So SkipVerify does not need to be explicitly returned.

	return spec.FrontingProviderID,
		transport,
		frontingDialAddr,
		SNIServerName,
		spec.VerifyServerName,
		spec.VerifyPins,
		spec.Host,
		nil
}

// Validate checks that the JSON values are well-formed.
func (specs FrontingSpecs) Validate(allowSkipVerify bool) error {

	// An empty FrontingSpecs is allowed as a tactics setting, but
	// SelectParameters will fail at runtime: code that uses FrontingSpecs must
	// provide some mechanism -- or check for an empty FrontingSpecs -- to
	// enable/disable features that use FrontingSpecs.

	for _, spec := range specs {
		if len(spec.FrontingProviderID) == 0 {
			return errors.TraceNew("empty fronting provider ID")
		}
		err := spec.Transports.Validate()
		if err != nil {
			return errors.Trace(err)
		}
		if len(spec.Addresses) == 0 {
			return errors.TraceNew("missing fronting addresses")
		}
		for _, addr := range spec.Addresses {
			if len(addr) == 0 {
				return errors.TraceNew("empty fronting address")
			}
		}
		if spec.SkipVerify {
			if !allowSkipVerify {
				return errors.TraceNew("invalid skip verify")
			}
			if len(spec.VerifyServerName) != 0 {
				return errors.TraceNew("unexpected verify server name")
			}
			if len(spec.VerifyPins) != 0 {
				return errors.TraceNew("unexpected verify pins")
			}
		} else {
			if len(spec.VerifyServerName) == 0 {
				return errors.TraceNew("empty verify server name")
			}
			// An empty VerifyPins is allowed.
			for _, pin := range spec.VerifyPins {
				if len(pin) == 0 {
					return errors.TraceNew("empty verify pin")
				}
			}
		}
		if len(spec.Host) == 0 {
			return errors.TraceNew("empty fronting host")
		}
	}
	return nil
}
