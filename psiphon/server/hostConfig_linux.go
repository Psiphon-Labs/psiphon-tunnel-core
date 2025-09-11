/*
 * Copyright (c) 2025, Psiphon Inc.
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
	"fmt"
	"strings"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	"golang.org/x/sys/unix"
)

func addHostConfig(config *Config) error {

	// Disable Transparent Huge Pages; huge pages can result in false
	// positives in "low free memory" checks performed by load limiting
	// scripts which inspect host/server process memory usage, further
	// resulting in improper SIGTSTP signals.

	err := unix.Prctl(unix.PR_SET_THP_DISABLE, 1, 0, 0, 0)
	if err != nil {
		return errors.Trace(err)
	}

	// Programmatically configure iptables rules to allow and apply rate
	// limits to tunnel protocol ports.

	err = configureIptablesAcceptRateLimitChain(config, true)
	if err != nil {
		return errors.Trace(err)
	}

	return nil
}

func removeHostConfig(config *Config) error {

	err := configureIptablesAcceptRateLimitChain(config, false)
	if err != nil {
		return errors.Trace(err)
	}

	return nil
}

func configureIptablesAcceptRateLimitChain(config *Config, add bool) error {

	// Adapted from:
	// https://github.com/Psiphon-Inc/psiphon-automation/blob/8fce7c72/Automation/psi_ops_install.py#L936

	// The chain is assumed to be created by the host (iptables -N); the host
	// is also responsible any default DROP rule and for jumping to the
	// specified chain.

	chainName := config.IptablesAcceptRateLimitChainName

	if chainName == "" {
		return nil
	}

	for _, c := range chainName {
		if !(c == '_' || c == '-' || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
			return errors.TraceNew("invalid chain name")
		}
	}

	// Direct protocols in which the original client IP directly connects to the Psiphon server will
	// use the "recent" rule, which limits connections by client IP. Fronted and other indirect
	// protocols where many clients can arrive from a few intermediate IPs use a simple frequency
	// rate limit; this rule is also used for direct meek protocols, since one client tunnel can
	// consist of many TCP connections, with meek resiliency.
	//
	// Custom rate limits may be set, per tunnel protocol, in IptablesAcceptRateLimitTunnelProtocolRateLimits.
	// When no custom rate is set, or if IptablesAcceptRateLimitTunnelProtocolRateLimits contains zero
	// values, default values are used.
	//
	// For the [2]int value in IptablesAcceptRateLimitTunnelProtocolRateLimits:
	// - In the "recent" rule case, value[0] specifies --seconds N and value[1] specifies --hitcount N.
	// - In the other case, value[0] specifies --limit N/sec and value[1] is ignored.

	inproxyAcceptRateLimitRules := func(networkProtocol string, portNumber int, rateLimit [2]int) ([]string, error) {
		if rateLimit[0] == 0 {
			rateLimit[0] = 1000
		}
		return []string{
			fmt.Sprintf("-A %s -p %s -m state --state NEW -m %s --dport %d -m limit --limit %d/sec -j ACCEPT",
				chainName, networkProtocol, networkProtocol, portNumber, rateLimit[0]),
		}, nil
	}

	meekAcceptRateLimitRules := func(portNumber int, rateLimit [2]int) ([]string, error) {
		if rateLimit[0] == 0 {
			rateLimit[0] = 1000
		}
		return []string{
			fmt.Sprintf("-A %s -p tcp -m state --state NEW -m tcp --dport %d -m limit --limit %d/sec -j ACCEPT",
				chainName, portNumber, rateLimit[0]),
		}, nil
	}

	refractionNetworkingRateLimitRules := meekAcceptRateLimitRules

	directAcceptRateLimitRules := func(networkProtocol string, portNumber int, rateLimit [2]int) ([]string, error) {
		if rateLimit[0] == 0 {
			rateLimit[0] = 60
		}
		if rateLimit[1] == 0 {
			rateLimit[1] = 3
		}
		name := fmt.Sprintf("LIMIT-%s-%d", networkProtocol, portNumber)
		return []string{
			fmt.Sprintf("-A %s -p %s -m state --state NEW -m %s --dport %d -m recent --set --name %s",
				chainName, networkProtocol, networkProtocol, portNumber, name),
			fmt.Sprintf("-A %s -p %s -m state --state NEW -m %s --dport %d -m recent --update --name %s --seconds %d --hitcount %d -j DROP",
				chainName, networkProtocol, networkProtocol, portNumber, name, rateLimit[0], rateLimit[1]),
			fmt.Sprintf("-A %s -p %s -m state --state NEW -m %s --dport %d -j ACCEPT",
				chainName, networkProtocol, networkProtocol, portNumber),
		}, nil
	}

	rules := []string{fmt.Sprintf("-F %s", chainName)}

	if add {

		for tunnelProtocol, portNumber := range config.TunnelProtocolPorts {

			rateLimit := config.IptablesAcceptRateLimitTunnelProtocolRateLimits[tunnelProtocol]
			var protocolRules []string
			var err error

			if protocol.TunnelProtocolUsesInproxy(tunnelProtocol) {

				networkProtocol := "tcp"
				if !protocol.TunnelProtocolUsesTCP(tunnelProtocol) {
					networkProtocol = "udp"
				}
				protocolRules, err = inproxyAcceptRateLimitRules(networkProtocol, portNumber, rateLimit)
				if err != nil {
					return errors.Trace(err)
				}

			} else if protocol.TunnelProtocolUsesMeek(tunnelProtocol) {

				// Assumes all FRONTED-MEEK is HTTPS over TCP between the edge
				// and Psiphon server.
				if protocol.TunnelProtocolUsesFrontedMeekNonHTTPS(tunnelProtocol) {
					continue
				}

				protocolRules, err = meekAcceptRateLimitRules(portNumber, rateLimit)
				if err != nil {
					return errors.Trace(err)
				}

			} else if protocol.TunnelProtocolUsesRefractionNetworking(tunnelProtocol) {

				protocolRules, err = refractionNetworkingRateLimitRules(portNumber, rateLimit)
				if err != nil {
					return errors.Trace(err)
				}

			} else {

				networkProtocol := "tcp"
				if !protocol.TunnelProtocolUsesTCP(tunnelProtocol) {
					networkProtocol = "udp"
				}
				protocolRules, err = directAcceptRateLimitRules(networkProtocol, portNumber, rateLimit)
				if err != nil {
					return errors.Trace(err)
				}
			}

			rules = append(rules, protocolRules...)
		}

		rules = append(rules, fmt.Sprintf("-A %s -j RETURN", chainName))
	}

	for _, rule := range rules {

		// While the config values IptablesAcceptRateLimitChainName and
		// IptablesAcceptRateLimitTunnelProtocolRateLimits are considered
		// trusted inputs, the risk of command injection is mitigated by
		// input validation and common.RunNetworkConfigCommand using
		// exec.Command and not invoking a shell.
		//
		// The command will be logged at log level debug.

		err := common.RunNetworkConfigCommand(
			CommonLogger(log),
			config.PacketTunnelSudoNetworkConfigCommands,
			"iptables",
			strings.Split(rule, " ")...)
		if err != nil {
			return errors.Trace(err)
		}
	}

	return nil
}
