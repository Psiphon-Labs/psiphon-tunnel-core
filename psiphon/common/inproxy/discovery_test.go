//go:build !PSIPHON_DISABLE_INPROXY

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
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/internal/testutils"
)

func TestNATDiscovery(t *testing.T) {
	// Since this test can fail due to external network conditions, retry.
	var err error
	for try := 0; try < 2; try++ {
		err = runTestNATDiscovery()
		if err == nil {
			return
		}
	}
	t.Error(err.Error())
}

func runTestNATDiscovery() error {

	// TODO: run local STUN and port mapping servers to test against, along
	// with iptables rules to simulate NAT conditions

	stunServerAddress := "stun.voipgate.com:3478"

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
			if address == stunServerAddress {
				atomic.AddInt32(&stunServerAddressSucceededCallCount, 1)
			}
		},

		stunServerAddressFailed: func(RFC5780 bool, address string) {
			if address == stunServerAddress {
				atomic.AddInt32(&stunServerAddressFailedCallCount, 1)
			}
		},
	}

	checkCallCounts := func(a, b, c, d int32) error {
		callCount := atomic.LoadInt32(&setNATTypeCallCount)
		if callCount != a {
			return errors.Tracef(
				"unexpected setNATType call count: %d",
				callCount)
		}

		callCount = atomic.LoadInt32(&setPortMappingTypesCallCount)
		if callCount != b {
			return errors.Tracef(
				"unexpected setPortMappingTypes call count: %d",
				callCount)
		}

		callCount = atomic.LoadInt32(&stunServerAddressSucceededCallCount)
		if callCount != c {
			return errors.Tracef(
				"unexpected stunServerAddressSucceeded call count: %d",
				callCount)
		}

		callCount = atomic.LoadInt32(&stunServerAddressFailedCallCount)
		if callCount != d {
			return errors.Tracef(
				"unexpected stunServerAddressFailedCallCount call count: %d",
				callCount)
		}

		return nil
	}

	config := &NATDiscoverConfig{
		Logger:                testutils.NewTestLogger(),
		WebRTCDialCoordinator: coordinator,
	}

	// Should do STUN only

	coordinator.disablePortMapping = true

	NATDiscover(context.Background(), config)

	err := checkCallCounts(1, 0, 1, 0)
	if err != nil {
		return errors.Trace(err)
	}

	// Should do port mapping only

	coordinator.disableSTUN = true
	coordinator.disablePortMapping = false

	NATDiscover(context.Background(), config)

	err = checkCallCounts(1, 1, 1, 0)
	if err != nil {
		return errors.Trace(err)
	}

	// Should skip both and use values cached in WebRTCDialCoordinator

	coordinator.disableSTUN = false
	coordinator.disablePortMapping = false

	NATDiscover(context.Background(), config)

	err = checkCallCounts(1, 1, 1, 0)
	if err != nil {
		return errors.Trace(err)
	}

	fmt.Printf("NAT Type: %s\n", coordinator.NATType())
	fmt.Printf("Port Mapping Types: %s\n", coordinator.PortMappingTypes())

	return nil
}
