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
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
)

// TunnelProtocolPortLists is a map from tunnel protocol names (or "All") to a
// list of port number ranges.
type TunnelProtocolPortLists map[string]*common.PortList

// Validate checks that tunnel protocol names are valid.
func (lists TunnelProtocolPortLists) Validate() error {
	for tunnelProtocol, _ := range lists {
		if tunnelProtocol != protocol.TUNNEL_PROTOCOLS_ALL &&
			!common.Contains(protocol.SupportedTunnelProtocols, tunnelProtocol) {
			return errors.TraceNew("invalid tunnel protocol for port list")
		}
	}
	return nil
}
