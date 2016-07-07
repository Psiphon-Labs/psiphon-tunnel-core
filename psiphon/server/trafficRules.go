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
	"strings"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon"
)

// TrafficRulesSet represents the various traffic rules to
// apply to Psiphon client tunnels. The Reload function supports
// hot reloading of rules data while the server is running.
type TrafficRulesSet struct {
	psiphon.ReloadableFile

	// DefaultRules specifies the traffic rules to be used when no
	// regional-specific rules are set or apply to a particular
	// client.
	DefaultRules TrafficRules

	// RegionalRules specifies the traffic rules for particular client
	// regions (countries) as determined by GeoIP lookup of the client
	// IP address. The key for each regional traffic rule entry is one
	// or more space delimited ISO 3166-1 alpha-2 country codes.
	RegionalRules map[string]TrafficRules
}

// RateLimits specify the rate limits for tunneled data transfer
// between an individual client and the server.
type RateLimits struct {

	// DownstreamUnlimitedBytes specifies the number of downstream
	// bytes to transfer, approximately, before starting rate
	// limiting.
	DownstreamUnlimitedBytes int64

	// DownstreamBytesPerSecond specifies a rate limit for downstream
	// data transfer. The default, 0, is no limit.
	DownstreamBytesPerSecond int

	// UpstreamUnlimitedBytes specifies the number of upstream
	// bytes to transfer, approximately, before starting rate
	// limiting.
	UpstreamUnlimitedBytes int64

	// UpstreamBytesPerSecond specifies a rate limit for upstream
	// data transfer. The default, 0, is no limit.
	UpstreamBytesPerSecond int
}

// TrafficRules specify the limits placed on client traffic.
type TrafficRules struct {
	// DefaultLimits are the rate limits to be applied when
	// no protocol-specific rates are set.
	DefaultLimits RateLimits

	// ProtocolLimits specifies the rate limits for particular
	// tunnel protocols. The key for each rate limit entry is one
	// or more space delimited Psiphon tunnel protocol names. Valid
	// tunnel protocols includes the same list as for
	// TunnelProtocolPorts.
	ProtocolLimits map[string]RateLimits

	// IdleTCPPortForwardTimeoutMilliseconds is the timeout period
	// after which idle (no bytes flowing in either direction)
	// client TCP port forwards are preemptively closed.
	// The default, 0, is no idle timeout.
	IdleTCPPortForwardTimeoutMilliseconds int

	// IdleUDPPortForwardTimeoutMilliseconds is the timeout period
	// after which idle (no bytes flowing in either direction)
	// client UDP port forwards are preemptively closed.
	// The default, 0, is no idle timeout.
	IdleUDPPortForwardTimeoutMilliseconds int

	// MaxTCPPortForwardCount is the maximum number of TCP port
	// forwards each client may have open concurrently.
	// The default, 0, is no maximum.
	MaxTCPPortForwardCount int

	// MaxUDPPortForwardCount is the maximum number of UDP port
	// forwards each client may have open concurrently.
	// The default, 0, is no maximum.
	MaxUDPPortForwardCount int

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

// NewTrafficRulesSet initializes a TrafficRulesSet with
// the rules data in the specified config file.
func NewTrafficRulesSet(filename string) (*TrafficRulesSet, error) {

	set := &TrafficRulesSet{}

	set.ReloadableFile = psiphon.NewReloadableFile(
		"traffic rules set",
		filename,
		func(filename string) error {
			configJSON, err := ioutil.ReadFile(filename)
			if err != nil {
				// On error, state remains the same
				return psiphon.ContextError(err)
			}
			err = json.Unmarshal(configJSON, &set)
			if err != nil {
				// On error, state remains the same
				// (Unmarshal first validates the provided
				//  JOSN and then populates the interface)
				return psiphon.ContextError(err)
			}
			return nil
		})

	_, err := set.Reload()
	if err != nil {
		return nil, psiphon.ContextError(err)
	}

	return set, nil
}

// GetTrafficRules looks up the traffic rules for the specified country. If there
// are no regional TrafficRules for the country, default TrafficRules are returned.
func (set *TrafficRulesSet) GetTrafficRules(clientCountryCode string) TrafficRules {
	set.ReloadableFile.RLock()
	defer set.ReloadableFile.RUnlock()

	// TODO: faster lookup?
	for countryCodes, trafficRules := range set.RegionalRules {
		for _, countryCode := range strings.Split(countryCodes, " ") {
			if countryCode == clientCountryCode {
				return trafficRules
			}
		}
	}
	return set.DefaultRules
}

// GetRateLimits looks up the rate limits for the specified tunnel protocol.
// If there are no specific RateLimits for the protocol, default RateLimits are
// returned.
func (rules *TrafficRules) GetRateLimits(clientTunnelProtocol string) RateLimits {

	// TODO: faster lookup?
	for tunnelProtocols, rateLimits := range rules.ProtocolLimits {
		for _, tunnelProtocol := range strings.Split(tunnelProtocols, " ") {
			if tunnelProtocol == clientTunnelProtocol {
				return rateLimits
			}
		}
	}
	return rules.DefaultLimits
}
