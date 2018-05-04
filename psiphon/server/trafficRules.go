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
	"fmt"
	"net"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
)

const (
	DEFAULT_IDLE_TCP_PORT_FORWARD_TIMEOUT_MILLISECONDS = 30000
	DEFAULT_IDLE_UDP_PORT_FORWARD_TIMEOUT_MILLISECONDS = 30000
	DEFAULT_DIAL_TCP_PORT_FORWARD_TIMEOUT_MILLISECONDS = 10000
	DEFAULT_MAX_TCP_DIALING_PORT_FORWARD_COUNT         = 64
	DEFAULT_MAX_TCP_PORT_FORWARD_COUNT                 = 512
	DEFAULT_MAX_UDP_PORT_FORWARD_COUNT                 = 32
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

	// TunnelProtocols is a list of client tunnel protocols that must be
	// in use to match this filter. When omitted or empty, any protocol
	// matches.
	TunnelProtocols []string

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

	// AuthorizedAccessTypes specifies a list of access types, at least
	// one of which the client must have presented an active authorization
	// for and which must not be revoked.
	// AuthorizedAccessTypes is ignored when AuthorizationsRevoked is true.
	AuthorizedAccessTypes []string

	// AuthorizationsRevoked indicates whether the client's authorizations
	// must have been revoked. When true, authorizations must have been
	// revoked. When omitted or false, this field is ignored.
	AuthorizationsRevoked bool
}

// TrafficRules specify the limits placed on client traffic.
type TrafficRules struct {

	// RateLimits specifies data transfer rate limits for the
	// client traffic.
	// Any RateLimits.ReadUnthrottledBytes/WriteUnthrottledBytes
	// apply only to the first tunnel in a session.
	RateLimits RateLimits

	// DialTCPPortForwardTimeoutMilliseconds is the timeout period
	// for dialing TCP port forwards. A value of 0 specifies no timeout.
	// When omitted in DefaultRules,
	// DEFAULT_TCP_PORT_FORWARD_DIAL_TIMEOUT_MILLISECONDS is used.
	DialTCPPortForwardTimeoutMilliseconds *int

	// IdleTCPPortForwardTimeoutMilliseconds is the timeout period
	// after which idle (no bytes flowing in either direction)
	// client TCP port forwards are preemptively closed.
	// A value of 0 specifies no idle timeout. When omitted in
	// DefaultRules, DEFAULT_IDLE_TCP_PORT_FORWARD_TIMEOUT_MILLISECONDS
	// is used.
	IdleTCPPortForwardTimeoutMilliseconds *int

	// IdleUDPPortForwardTimeoutMilliseconds is the timeout period
	// after which idle (no bytes flowing in either direction)
	// client UDP port forwards are preemptively closed.
	// A value of 0 specifies no idle timeout. When omitted in
	// DefaultRules, DEFAULT_IDLE_UDP_PORT_FORWARD_TIMEOUT_MILLISECONDS
	// is used.
	IdleUDPPortForwardTimeoutMilliseconds *int

	// MaxTCPDialingPortForwardCount is the maximum number of dialing
	// TCP port forwards each client may have open concurrently. When
	// persistently at the limit, new TCP port forwards are rejected.
	// A value of 0 specifies no maximum. When omitted in
	// DefaultRules, DEFAULT_MAX_TCP_DIALING_PORT_FORWARD_COUNT is used.
	MaxTCPDialingPortForwardCount *int

	// MaxTCPPortForwardCount is the maximum number of established TCP
	// port forwards each client may have open concurrently. If at the
	// limit when a new TCP port forward is established, the LRU
	// established TCP port forward is closed.
	// A value of 0 specifies no maximum. When omitted in
	// DefaultRules, DEFAULT_MAX_TCP_PORT_FORWARD_COUNT is used.
	MaxTCPPortForwardCount *int

	// MaxUDPPortForwardCount is the maximum number of UDP port
	// forwards each client may have open concurrently. If at the
	// limit when a new UDP port forward is created, the LRU
	// UDP port forward is closed.
	// A value of 0 specifies no maximum. When omitted in
	// DefaultRules, DEFAULT_MAX_UDP_PORT_FORWARD_COUNT is used.
	MaxUDPPortForwardCount *int

	// AllowTCPPorts specifies a whitelist of TCP ports that
	// are permitted for port forwarding. When set, only ports
	// in the list are accessible to clients.
	AllowTCPPorts []int

	// AllowUDPPorts specifies a whitelist of UDP ports that
	// are permitted for port forwarding. When set, only ports
	// in the list are accessible to clients.
	AllowUDPPorts []int

	// AllowSubnets specifies a list of IP address subnets for
	// which all TCP and UDP ports are allowed. This list is
	// consulted if a port is disallowed by the AllowTCPPorts
	// or AllowUDPPorts configuration. Each entry is a IP subnet
	// in CIDR notation.
	// Limitation: currently, AllowSubnets only matches port
	// forwards where the client sends an IP address. Domain
	// names aren not resolved before checking AllowSubnets.
	AllowSubnets []string
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
		func(fileContent []byte) error {
			var newSet TrafficRulesSet
			err := json.Unmarshal(fileContent, &newSet)
			if err != nil {
				return common.ContextError(err)
			}
			err = newSet.Validate()
			if err != nil {
				return common.ContextError(err)
			}
			// Modify actual traffic rules only after validation
			set.DefaultRules = newSet.DefaultRules
			set.FilteredRules = newSet.FilteredRules
			return nil
		})

	_, err := set.Reload()
	if err != nil {
		return nil, common.ContextError(err)
	}

	return set, nil
}

// Validate checks for correct input formats in a TrafficRulesSet.
func (set *TrafficRulesSet) Validate() error {

	validateTrafficRules := func(rules *TrafficRules) error {
		for _, subnet := range rules.AllowSubnets {
			_, _, err := net.ParseCIDR(subnet)
			if err != nil {
				return common.ContextError(
					fmt.Errorf("invalid subnet: %s %s", subnet, err))
			}
		}
		return nil
	}

	err := validateTrafficRules(&set.DefaultRules)
	if err != nil {
		return common.ContextError(err)
	}

	for _, filteredRule := range set.FilteredRules {

		for paramName := range filteredRule.Filter.HandshakeParameters {
			validParamName := false
			for _, paramSpec := range baseRequestParams {
				if paramSpec.name == paramName {
					validParamName = true
					break
				}
			}
			if !validParamName {
				return common.ContextError(
					fmt.Errorf("invalid parameter name: %s", paramName))
			}
		}

		err := validateTrafficRules(&filteredRule.Rules)
		if err != nil {
			return common.ContextError(err)
		}
	}

	return nil
}

// GetTrafficRules determines the traffic rules for a client based on its attributes.
// For the return value TrafficRules, all pointer and slice fields are initialized,
// so nil checks are not required. The caller must not modify the returned TrafficRules.
func (set *TrafficRulesSet) GetTrafficRules(
	isFirstTunnelInSession bool,
	tunnelProtocol string,
	geoIPData GeoIPData,
	state handshakeState) TrafficRules {

	set.ReloadableFile.RLock()
	defer set.ReloadableFile.RUnlock()

	// Start with a copy of the DefaultRules, and then select the first
	// matching Rules from FilteredTrafficRules, taking only the explicitly
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

	intPtr := func(i int) *int {
		return &i
	}

	if trafficRules.DialTCPPortForwardTimeoutMilliseconds == nil {
		trafficRules.DialTCPPortForwardTimeoutMilliseconds =
			intPtr(DEFAULT_DIAL_TCP_PORT_FORWARD_TIMEOUT_MILLISECONDS)
	}

	if trafficRules.IdleTCPPortForwardTimeoutMilliseconds == nil {
		trafficRules.IdleTCPPortForwardTimeoutMilliseconds =
			intPtr(DEFAULT_IDLE_TCP_PORT_FORWARD_TIMEOUT_MILLISECONDS)
	}

	if trafficRules.IdleUDPPortForwardTimeoutMilliseconds == nil {
		trafficRules.IdleUDPPortForwardTimeoutMilliseconds =
			intPtr(DEFAULT_IDLE_UDP_PORT_FORWARD_TIMEOUT_MILLISECONDS)
	}

	if trafficRules.MaxTCPDialingPortForwardCount == nil {
		trafficRules.MaxTCPDialingPortForwardCount =
			intPtr(DEFAULT_MAX_TCP_DIALING_PORT_FORWARD_COUNT)
	}

	if trafficRules.MaxTCPPortForwardCount == nil {
		trafficRules.MaxTCPPortForwardCount =
			intPtr(DEFAULT_MAX_TCP_PORT_FORWARD_COUNT)
	}

	if trafficRules.MaxUDPPortForwardCount == nil {
		trafficRules.MaxUDPPortForwardCount =
			intPtr(DEFAULT_MAX_UDP_PORT_FORWARD_COUNT)
	}

	if trafficRules.AllowTCPPorts == nil {
		trafficRules.AllowTCPPorts = make([]int, 0)
	}

	if trafficRules.AllowUDPPorts == nil {
		trafficRules.AllowUDPPorts = make([]int, 0)
	}

	// TODO: faster lookup?
	for _, filteredRules := range set.FilteredRules {

		log.WithContextFields(LogFields{"filter": filteredRules.Filter}).Debug("filter check")

		if len(filteredRules.Filter.TunnelProtocols) > 0 {
			if !common.Contains(filteredRules.Filter.TunnelProtocols, tunnelProtocol) {
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

			mismatch := false
			for name, values := range filteredRules.Filter.HandshakeParameters {
				clientValue, err := getStringRequestParam(state.apiParams, name)
				if err != nil || !common.Contains(values, clientValue) {
					mismatch = true
					break
				}
			}
			if mismatch {
				continue
			}
		}

		if filteredRules.Filter.AuthorizationsRevoked {
			if !state.completed {
				continue
			}

			if !state.authorizationsRevoked {
				continue
			}

		} else if len(filteredRules.Filter.AuthorizedAccessTypes) > 0 {
			if !state.completed {
				continue
			}

			if state.authorizationsRevoked {
				continue
			}

			if !common.ContainsAny(filteredRules.Filter.AuthorizedAccessTypes, state.authorizedAccessTypes) {
				continue
			}
		}

		log.WithContextFields(LogFields{"filter": filteredRules.Filter}).Debug("filter match")

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

		if filteredRules.Rules.DialTCPPortForwardTimeoutMilliseconds != nil {
			trafficRules.DialTCPPortForwardTimeoutMilliseconds = filteredRules.Rules.DialTCPPortForwardTimeoutMilliseconds
		}

		if filteredRules.Rules.IdleTCPPortForwardTimeoutMilliseconds != nil {
			trafficRules.IdleTCPPortForwardTimeoutMilliseconds = filteredRules.Rules.IdleTCPPortForwardTimeoutMilliseconds
		}

		if filteredRules.Rules.IdleUDPPortForwardTimeoutMilliseconds != nil {
			trafficRules.IdleUDPPortForwardTimeoutMilliseconds = filteredRules.Rules.IdleUDPPortForwardTimeoutMilliseconds
		}

		if filteredRules.Rules.MaxTCPDialingPortForwardCount != nil {
			trafficRules.MaxTCPDialingPortForwardCount = filteredRules.Rules.MaxTCPDialingPortForwardCount
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

		break
	}

	if !isFirstTunnelInSession {
		*trafficRules.RateLimits.ReadUnthrottledBytes = 0
		*trafficRules.RateLimits.WriteUnthrottledBytes = 0
	}

	log.WithContextFields(LogFields{"trafficRules": trafficRules}).Debug("selected traffic rules")

	return trafficRules
}
