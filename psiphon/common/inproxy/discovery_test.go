//go:build PSIPHON_ENABLE_INPROXY

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
	"context"
	"sync/atomic"
	"testing"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/internal/testutils"
)

func TestNATDiscovery(t *testing.T) {

	// TODO: run local STUN and port mapping servers to test against, along
	// with iptables rules to simulate NAT conditions

	stunServerAddress := "stun.nextcloud.com:443"

	var setNATTypeCallCount,
		setPortMappingTypesCallCount,
		stunServerAddressSucceededCallCount,
		stunServerAddressFailedCallCount int32

	coordinator := &testWebRTCDialCoordinator{
		stunServerAddress:        stunServerAddress,
		stunServerAddressRFC5780: stunServerAddress,

		setNATType: func(NATType) {
			atomic.AddInt32(&setNATTypeCallCount, 1)
		},

		setPortMappingTypes: func(PortMappingTypes) {
			atomic.AddInt32(&setPortMappingTypesCallCount, 1)
		},

		stunServerAddressSucceeded: func(RFC5780 bool, address string) {
			atomic.AddInt32(&stunServerAddressSucceededCallCount, 1)
			if address != stunServerAddress {
				t.Errorf("unexpected STUN server address")
			}
		},

		stunServerAddressFailed: func(RFC5780 bool, address string) {
			atomic.AddInt32(&stunServerAddressFailedCallCount, 1)
			if address != stunServerAddress {
				t.Errorf("unexpected STUN server address")
			}
		},
	}

	checkCallCounts := func(a, b, c, d int32) {
		callCount := atomic.LoadInt32(&setNATTypeCallCount)
		if callCount != a {
			t.Errorf(
				"unexpected setNATType call count: %d",
				callCount)
		}

		callCount = atomic.LoadInt32(&setPortMappingTypesCallCount)
		if callCount != b {
			t.Errorf(
				"unexpected setPortMappingTypes call count: %d",
				callCount)
		}

		callCount = atomic.LoadInt32(&stunServerAddressSucceededCallCount)
		if callCount != c {
			t.Errorf(
				"unexpected stunServerAddressSucceeded call count: %d",
				callCount)
		}

		callCount = atomic.LoadInt32(&stunServerAddressFailedCallCount)
		if callCount != d {
			t.Errorf(
				"unexpected stunServerAddressFailedCallCount call count: %d",
				callCount)
		}
	}

	config := &NATDiscoverConfig{
		Logger:                testutils.NewTestLogger(),
		WebRTCDialCoordinator: coordinator,
	}

	// Should do STUN only

	coordinator.disablePortMapping = true

	NATDiscover(context.Background(), config)

	checkCallCounts(1, 0, 1, 0)

	// Should do port mapping only

	coordinator.disableSTUN = true
	coordinator.disablePortMapping = false

	NATDiscover(context.Background(), config)

	checkCallCounts(1, 1, 1, 0)

	// Should skip both and use values cached in WebRTCDialCoordinator

	coordinator.disableSTUN = false
	coordinator.disablePortMapping = false

	NATDiscover(context.Background(), config)

	checkCallCounts(1, 1, 1, 0)

	t.Logf("NAT Type: %s", coordinator.NATType())
	t.Logf("Port Mapping Types: %s", coordinator.PortMappingTypes())
}
