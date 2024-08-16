/*
 * Copyright (c) 2024, Psiphon Inc.
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

package psiphon

import (
	"sync/atomic"
)

var allowOverlappingPersonalCompartmentIDs int32

func GetAllowOverlappingPersonalCompartmentIDs() bool {
	return atomic.LoadInt32(&allowOverlappingPersonalCompartmentIDs) == 1
}

// SetAllowOverlappingPersonalCompartmentIDs configures whether to allow
// overlapping personal compartment IDs in InproxyProxyPersonalCompartmentIDs
// and InproxyClientPersonalCompartmentIDs. Overlapping IDs are not allowed
// in order to prevent a client matching its own proxy.
// SetAllowOverlappingPersonalCompartmentIDs is for end-to-end testing on a
// single host, and should be used only for testing purposes.
func SetAllowOverlappingPersonalCompartmentIDs(allow bool) {
	value := int32(0)
	if allow {
		value = 1
	}
	atomic.StoreInt32(&allowOverlappingPersonalCompartmentIDs, value)
}

var allowBogonWebRTCConnections int32

func GetAllowBogonWebRTCConnections() bool {
	return atomic.LoadInt32(&allowBogonWebRTCConnections) == 1
}

// SetAllowBogonWebRTCConnections configures whether to allow bogon ICE
// candidates in WebRTC session descriptions. This included loopback and
// private network candidates. By default, bogon addresses are exclude as
// they are not expected to be useful and may expose private network
// information. SetAllowBogonWebRTCConnections is for end-to-end testing on a
// single host, and should be used only for testing purposes.
func SetAllowBogonWebRTCConnections(allow bool) {
	value := int32(0)
	if allow {
		value = 1
	}
	atomic.StoreInt32(&allowBogonWebRTCConnections, value)
}
