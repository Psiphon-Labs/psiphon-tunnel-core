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
	"sync/atomic"
)

var allowCommonASNMatching int32

func GetAllowCommonASNMatching() bool {
	return atomic.LoadInt32(&allowCommonASNMatching) == 1
}

// SetAllowCommonASNMatching configures whether to allow matching proxies and
// clients with the same GeoIP country and ASN. This matching is always
// permitted for matching personal compartment IDs, but for common
// compartment IDs, these matches are not allowed as they are not expected to
// be useful. SetAllowCommonASNMatching is for end-to-end testing on a single
// host, and should be used only for testing purposes.
func SetAllowCommonASNMatching(allow bool) {
	value := int32(0)
	if allow {
		value = 1
	}
	atomic.StoreInt32(&allowCommonASNMatching, value)
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
