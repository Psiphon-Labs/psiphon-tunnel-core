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

package parameters

import (
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/inproxy"
)

// InproxyBrokerSpecsValue is a list of in-proxy broker specs.
type InproxyBrokerSpecsValue []*InproxyBrokerSpec

// InproxyBrokerSpec specifies the configuration to use to establish a secure
// connection to an in-proxy broker.
type InproxyBrokerSpec struct {
	BrokerPublicKey             string
	BrokerRootObfuscationSecret string
	BrokerFrontingSpecs         FrontingSpecs
}

// Validate checks that the in-proxy broker specs values are well-formed.
func (specs InproxyBrokerSpecsValue) Validate(checkBrokerSpecsList *InproxyBrokerSpecsValue) error {

	for _, spec := range specs {
		if _, err := inproxy.SessionPublicKeyFromString(spec.BrokerPublicKey); err != nil {
			return errors.Tracef("invalid broker public key: %w", err)
		}
		if checkBrokerSpecsList != nil {
			found := false
			for _, checkBrokerSpec := range *checkBrokerSpecsList {
				// Verify that the broker public key and root obfuscation
				// secret match an entry on the check list. The fronting
				// specs may differ and are not compared.
				if spec.BrokerPublicKey == checkBrokerSpec.BrokerPublicKey &&
					spec.BrokerRootObfuscationSecret == checkBrokerSpec.BrokerRootObfuscationSecret {
					found = true
					break
				}
			}
			if !found {
				return errors.TraceNew("unknown broker spec")
			}
		}
		if _, err := inproxy.ObfuscationSecretFromString(spec.BrokerRootObfuscationSecret); err != nil {
			return errors.Tracef("invalid broker root obfuscation secret: %w", err)
		}
		if len(spec.BrokerFrontingSpecs) == 0 {
			return errors.TraceNew("missing broker fronting spec")
		}
		// Broker fronting specs may specify SkipVerify, since the meek
		// payload has it's own transport security layer, the Noise sessions.
		// Broker fronting dials use MeekModeWrappedPlaintextRoundTrip.
		allowSkipVerify := true
		err := spec.BrokerFrontingSpecs.Validate(allowSkipVerify)
		if err != nil {
			return errors.Trace(err)
		}
	}
	return nil
}

// InproxyCompartmentIDsValue is a list of in-proxy common compartment IDs.
type InproxyCompartmentIDsValue []string

// Validate checks that the in-proxy common compartment ID values are
// well-formed.
func (IDs InproxyCompartmentIDsValue) Validate(checkCompartmentIDList *[]string) error {

	for _, ID := range IDs {
		if _, err := inproxy.IDFromString(ID); err != nil {
			return errors.Tracef("invalid compartment ID: %w", err)
		}
		if checkCompartmentIDList != nil && !common.Contains(*checkCompartmentIDList, ID) {
			return errors.TraceNew("unknown compartment ID")
		}
	}
	return nil
}

// InproxyTrafficShapingParametersValue is type-compatible with
// common/inproxy.TrafficShapingParameters.
type InproxyTrafficShapingParametersValue struct {
	MinPaddedMessages       int
	MaxPaddedMessages       int
	MinPaddingSize          int
	MaxPaddingSize          int
	MinDecoyMessages        int
	MaxDecoyMessages        int
	MinDecoySize            int
	MaxDecoySize            int
	DecoyMessageProbability float64
}

func (p *InproxyTrafficShapingParametersValue) Validate() error {
	if p.MinPaddedMessages < 0 ||
		p.MaxPaddedMessages < 0 ||
		p.MinPaddingSize < 0 ||
		p.MaxPaddingSize < 0 ||
		p.MinDecoyMessages < 0 ||
		p.MaxDecoyMessages < 0 ||
		p.MinDecoySize < 0 ||
		p.MaxDecoySize < 0 ||
		p.DecoyMessageProbability < 0.0 {
		return errors.TraceNew("invalid parameter")
	}
	return nil
}
