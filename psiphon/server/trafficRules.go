/*
 * Copyright (c) 2016, Psiphon Inc.
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
	"encoding/json"
	"io/ioutil"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
)

// TrafficRulesSet represents the various traffic rules to
// apply to Psiphon client tunnels. The Reload function supports
// hot reloading of rules data while the server is running.
//
// For a given client, the traffic rules are determined by starting
// with DefaultRules, then finding the first (if any)
// FilteredTrafficRules match and overriding the defaults with fields
// set in the selected FilteredTrafficRules.
type TrafficRulesSet struct {
	common.ReloadableFile

	// DefaultRules are the base values to use as defaults for all
	// clients.
	DefaultRules TrafficRules

	// FilteredTrafficRules is an ordered list of filter/rules pairs.
	// For each client, the first matching Filter in FilteredTrafficRules
	// determines the additional Rules that are selected and applied
	// on top of DefaultRules.
	FilteredRules []struct {
		Filter TrafficRulesFilter
		Rules  TrafficRules
	}
}

// TrafficRulesFilter defines a filter to match against client attributes.
type TrafficRulesFilter struct {

	// Protocols is a list of client tunnel protocols that must be in use
	// to match this filter. When omitted or empty, any protocol matches.
	Protocols []string

	// Regions is a list of client GeoIP countries that the client must
	// reolve to to match this filter. When omitted or empty, any client
	// region matches.
	Regions []string

	// APIProtocol specifies whether the client must use the SSH
	// API protocol (when "ssh") or the web API protocol (when "web").
	// When omitted or blank, any API protocol matches.
	APIProtocol string

	// HandshakeParameters specifies handshake API parameter names and
	// a list of values, one of which must be specified to match this
	// filter. Only scalar string API parameters may be filtered.
	HandshakeParameters map[string][]string
}

// TrafficRules specify the limits placed on client traffic.
type TrafficRules struct {

	// RateLimits specifies data transfer rate limits for the
	// client traffic.
	RateLimits RateLimits

	// IdleTCPPortForwardTimeoutMilliseconds is the timeout period
	// after which idle (no bytes flowing in either direction)
	// client TCP port forwards are preemptively closed.
	// The default, 0, is no idle timeout.
	IdleTCPPortForwardTimeoutMilliseconds *int

	// IdleUDPPortForwardTimeoutMilliseconds is the timeout period
	// after which idle (no bytes flowing in either direction)
	// client UDP port forwards are preemptively closed.
	// The default, 0, is no idle timeout.
	IdleUDPPortForwardTimeoutMilliseconds *int

	// MaxTCPPortForwardCount is the maximum number of TCP port
	// forwards each client may have open concurrently.
	// The default, 0, is no maximum.
	MaxTCPPortForwardCount *int

	// MaxUDPPortForwardCount is the maximum number of UDP port
	// forwards each client may have open concurrently.
	// The default, 0, is no maximum.
	MaxUDPPortForwardCount *int

	// AllowTCPPorts specifies a whitelist of TCP ports that
	// are permitted for port forwarding. When set, only ports
	// in the list are accessible to clients.
	AllowTCPPorts []int

	// AllowUDPPorts specifies a whitelist of UDP ports that
	// are permitted for port forwarding. When set, only ports
	// in the list are accessible to clients.
	AllowUDPPorts []int

	// DenyTCPPorts specifies a blacklist of TCP ports that
	// are not permitted for port forwarding. When set, the
	// ports in the list are inaccessible to clients.
	DenyTCPPorts []int

	// DenyUDPPorts specifies a blacklist of UDP ports that
	// are not permitted for port forwarding. When set, the
	// ports in the list are inaccessible to clients.
	DenyUDPPorts []int
}

// RateLimits is a clone of common.RateLimits with pointers
// to fields to enable distinguishing between zero values and
// omitted values in JSON serialized traffic rules.
// See common.RateLimits for field descriptions.
type RateLimits struct {
	ReadUnthrottledBytes  *int64
	ReadBytesPerSecond    *int64
	WriteUnthrottledBytes *int64
	WriteBytesPerSecond   *int64
	CloseAfterExhausted   *bool
}

// CommonRateLimits converts a RateLimits to a common.RateLimits.
func (rateLimits *RateLimits) CommonRateLimits() common.RateLimits {
	return common.RateLimits{
		ReadUnthrottledBytes:  *rateLimits.ReadUnthrottledBytes,
		ReadBytesPerSecond:    *rateLimits.ReadBytesPerSecond,
		WriteUnthrottledBytes: *rateLimits.WriteUnthrottledBytes,
		WriteBytesPerSecond:   *rateLimits.WriteBytesPerSecond,
		CloseAfterExhausted:   *rateLimits.CloseAfterExhausted,
	}
}

// NewTrafficRulesSet initializes a TrafficRulesSet with
// the rules data in the specified config file.
func NewTrafficRulesSet(filename string) (*TrafficRulesSet, error) {

	set := &TrafficRulesSet{}

	set.ReloadableFile = common.NewReloadableFile(
		filename,
		func(filename string) error {
			configJSON, err := ioutil.ReadFile(filename)
			if err != nil {
				// On error, state remains the same
				return common.ContextError(err)
			}
			err = json.Unmarshal(configJSON, &set)
			if err != nil {
				// On error, state remains the same
				// (Unmarshal first validates the provided
				//  JOSN and then populates the interface)
				return common.ContextError(err)
			}
			return nil
		})

	_, err := set.Reload()
	if err != nil {
		return nil, common.ContextError(err)
	}

	return set, nil
}

// GetTrafficRules determines the traffic rules for a client based on its attributes.
// For the return value TrafficRules, all pointer and slice fields are initialized,
// so nil checks are not required. The caller must not modify the returned TrafficRules.
func (set *TrafficRulesSet) GetTrafficRules(
	tunnelProtocol string, geoIPData GeoIPData, state handshakeState) TrafficRules {

	set.ReloadableFile.RLock()
	defer set.ReloadableFile.RUnlock()

	// Start with a copy of the DefaultRules, and then select the first
	// matches Rules from FilteredTrafficRules, taking only the explicitly
	// specified fields from that Rules.
	//
	// Notes:
	// - Scalar pointers are used in TrafficRules and RateLimits to distinguish between
	//   omitted fields (in serialized JSON) and default values. For example, if a filtered
	//   Rules specifies a field value of 0, this will override the default; but if the
	//   serialized filtered rule omits the field, the default is to be retained.
	// - We use shallow copies and slices and scalar pointers are shared between the
	//   return value TrafficRules, so callers must treat the return value as immutable.
	//   This also means that these slices and pointers can remain referenced in memory even
	//   after a hot reload.

	trafficRules := set.DefaultRules

	// Populate defaults for omitted DefaultRules fields

	if trafficRules.RateLimits.ReadUnthrottledBytes == nil {
		trafficRules.RateLimits.ReadUnthrottledBytes = new(int64)
	}

	if trafficRules.RateLimits.ReadBytesPerSecond == nil {
		trafficRules.RateLimits.ReadBytesPerSecond = new(int64)
	}

	if trafficRules.RateLimits.WriteUnthrottledBytes == nil {
		trafficRules.RateLimits.WriteUnthrottledBytes = new(int64)
	}

	if trafficRules.RateLimits.WriteBytesPerSecond == nil {
		trafficRules.RateLimits.WriteBytesPerSecond = new(int64)
	}

	if trafficRules.RateLimits.CloseAfterExhausted == nil {
		trafficRules.RateLimits.CloseAfterExhausted = new(bool)
	}

	if trafficRules.IdleTCPPortForwardTimeoutMilliseconds == nil {
		trafficRules.IdleTCPPortForwardTimeoutMilliseconds = new(int)
	}

	if trafficRules.IdleUDPPortForwardTimeoutMilliseconds == nil {
		trafficRules.IdleUDPPortForwardTimeoutMilliseconds = new(int)
	}

	if trafficRules.MaxTCPPortForwardCount == nil {
		trafficRules.MaxTCPPortForwardCount = new(int)
	}

	if trafficRules.MaxUDPPortForwardCount == nil {
		trafficRules.MaxUDPPortForwardCount = new(int)
	}

	if trafficRules.AllowTCPPorts == nil {
		trafficRules.AllowTCPPorts = make([]int, 0)
	}

	if trafficRules.AllowUDPPorts == nil {
		trafficRules.AllowUDPPorts = make([]int, 0)
	}

	if trafficRules.DenyTCPPorts == nil {
		trafficRules.DenyTCPPorts = make([]int, 0)
	}

	if trafficRules.DenyUDPPorts == nil {
		trafficRules.DenyUDPPorts = make([]int, 0)
	}

	// TODO: faster lookup?
	for _, filteredRules := range set.FilteredRules {

		if len(filteredRules.Filter.Protocols) > 0 {
			if !common.Contains(filteredRules.Filter.Protocols, tunnelProtocol) {
				continue
			}
		}

		if len(filteredRules.Filter.Regions) > 0 {
			if !common.Contains(filteredRules.Filter.Regions, geoIPData.Country) {
				continue
			}
		}

		if filteredRules.Filter.APIProtocol != "" {
			if !state.completed {
				continue
			}
			if state.apiProtocol != filteredRules.Filter.APIProtocol {
				continue
			}
		}

		if filteredRules.Filter.HandshakeParameters != nil {
			if !state.completed {
				continue
			}

			for name, values := range filteredRules.Filter.HandshakeParameters {
				clientValue, err := getStringRequestParam(state.apiParams, name)
				if err != nil || !common.Contains(values, clientValue) {
					continue
				}
			}
		}

		// This is the first match. Override defaults using provided fields from selected rules, and return result.

		if filteredRules.Rules.RateLimits.ReadUnthrottledBytes != nil {
			trafficRules.RateLimits.ReadUnthrottledBytes = filteredRules.Rules.RateLimits.ReadUnthrottledBytes
		}

		if filteredRules.Rules.RateLimits.ReadBytesPerSecond != nil {
			trafficRules.RateLimits.ReadBytesPerSecond = filteredRules.Rules.RateLimits.ReadBytesPerSecond
		}

		if filteredRules.Rules.RateLimits.WriteUnthrottledBytes != nil {
			trafficRules.RateLimits.WriteUnthrottledBytes = filteredRules.Rules.RateLimits.WriteUnthrottledBytes
		}

		if filteredRules.Rules.RateLimits.WriteBytesPerSecond != nil {
			trafficRules.RateLimits.WriteBytesPerSecond = filteredRules.Rules.RateLimits.WriteBytesPerSecond
		}

		if filteredRules.Rules.RateLimits.CloseAfterExhausted != nil {
			trafficRules.RateLimits.CloseAfterExhausted = filteredRules.Rules.RateLimits.CloseAfterExhausted
		}

		if filteredRules.Rules.IdleTCPPortForwardTimeoutMilliseconds != nil {
			trafficRules.IdleTCPPortForwardTimeoutMilliseconds = filteredRules.Rules.IdleTCPPortForwardTimeoutMilliseconds
		}

		if filteredRules.Rules.IdleUDPPortForwardTimeoutMilliseconds != nil {
			trafficRules.IdleUDPPortForwardTimeoutMilliseconds = filteredRules.Rules.IdleUDPPortForwardTimeoutMilliseconds
		}

		if filteredRules.Rules.MaxTCPPortForwardCount != nil {
			trafficRules.MaxTCPPortForwardCount = filteredRules.Rules.MaxTCPPortForwardCount
		}

		if filteredRules.Rules.MaxUDPPortForwardCount != nil {
			trafficRules.MaxUDPPortForwardCount = filteredRules.Rules.MaxUDPPortForwardCount
		}

		if filteredRules.Rules.AllowTCPPorts != nil {
			trafficRules.AllowTCPPorts = filteredRules.Rules.AllowTCPPorts
		}

		if filteredRules.Rules.AllowUDPPorts != nil {
			trafficRules.AllowUDPPorts = filteredRules.Rules.AllowUDPPorts
		}

		if filteredRules.Rules.DenyTCPPorts != nil {
			trafficRules.DenyTCPPorts = filteredRules.Rules.DenyTCPPorts
		}

		if filteredRules.Rules.DenyUDPPorts != nil {
			trafficRules.DenyUDPPorts = filteredRules.Rules.DenyUDPPorts
		}

		break
	}

	return trafficRules
}
