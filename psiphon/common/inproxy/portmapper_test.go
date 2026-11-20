//go:build !PSIPHON_DISABLE_INPROXY

/*
 * Copyright (c) 2026, Psiphon Inc.
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
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/portmapper"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/internal/testutils"
)

// TestPortMapperSignalsFailedAttempt checks that a port mapping attempt
// which ends without a port mapping is signaled, so that a dial awaiting the
// port mapping can proceed without waiting for its timeout.
func TestPortMapperSignalsFailedAttempt(t *testing.T) {

	// With no gateway, the port mapping attempt fails without any network
	// operations.
	probe := &PortMappingProbe{
		client: portmapper.NewClient(portmapper.Config{
			GatewayLookupFunc: func() (gw, myIP netip.Addr, ok bool) {
				return netip.Addr{}, netip.Addr{}, false
			},
		}),
	}

	p, err := newPortMapper(testutils.NewTestLogger(), probe, 12345)
	if err != nil {
		t.Fatalf("newPortMapper failed: %v", err)
	}
	defer p.close()

	p.start()

	select {
	case address := <-p.portMappingExternalAddress():
		t.Fatalf("unexpected port mapping: %s", address)
	case <-p.portMappingAttemptFailed():
	case <-time.After(5 * time.Second):
		t.Fatal("failed port mapping attempt not signaled")
	}
}

func TestVerifiedPortMappingTypes(t *testing.T) {

	publicAddress := netip.MustParseAddr("123.123.123.123")
	privateAddress := netip.MustParseAddr("192.168.1.1")
	reservedAddress := netip.MustParseAddr("198.18.0.1")

	for _, test := range []struct {
		description  string
		verification portmapper.Verification
		expected     PortMappingTypes
	}{
		{
			"granting type is first",
			portmapper.Verification{
				UPnP:     portmapper.ServiceSeen,
				PMP:      portmapper.ServiceGranted,
				PCP:      portmapper.ServiceSeen,
				External: publicAddress,
			},
			PortMappingTypes{
				PortMappingTypePMP, PortMappingTypeUPnP, PortMappingTypePCP},
		},
		{
			"refusing type is omitted",
			portmapper.Verification{
				UPnP:     portmapper.ServiceGranted,
				PMP:      portmapper.ServiceRefused,
				External: publicAddress,
			},
			PortMappingTypes{PortMappingTypeUPnP},
		},
		{
			"no types when not granted",
			portmapper.Verification{
				UPnP: portmapper.ServiceRefused,
				PCP:  portmapper.ServiceSeen,
			},
			PortMappingTypes{},
		},
		{
			"no types when external address is private",
			portmapper.Verification{
				UPnP:     portmapper.ServiceGranted,
				PMP:      portmapper.ServiceSeen,
				External: privateAddress,
			},
			PortMappingTypes{},
		},
		{
			"no types when external address is reserved",
			portmapper.Verification{
				PCP:      portmapper.ServiceGranted,
				External: reservedAddress,
			},
			PortMappingTypes{},
		},
	} {
		t.Run(test.description, func(t *testing.T) {
			types := verifiedPortMappingTypes(test.verification)
			if !reflect.DeepEqual(types, test.expected) {
				t.Fatalf("unexpected types: %v, expected %v", types, test.expected)
			}
		})
	}
}

// TestPortMapperDeliver checks that a port mapping with an external address
// that is not usable is signaled as a failed attempt and not delivered: a
// delivered port mapping ends the await for ICE candidate gathering.
func TestPortMapperDeliver(t *testing.T) {

	for _, test := range []struct {
		description string
		address     string
		delivered   bool
	}{
		{"public address", "123.123.123.123:1234", true},
		{"private address", "192.168.1.1:1234", false},
		{"shared address space", "100.64.0.1:1234", false},
	} {
		t.Run(test.description, func(t *testing.T) {

			p := &portMapper{
				portMappingAddress: make(chan string, 1),
				portMappingFailed:  make(chan struct{}),
				portMappingLogger:  func(string, ...any) {},
			}

			p.deliver(netip.MustParseAddrPort(test.address))

			select {
			case address := <-p.portMappingExternalAddress():
				if !test.delivered || address != test.address {
					t.Fatalf("unexpected port mapping: %s", address)
				}
			case <-p.portMappingAttemptFailed():
				if test.delivered {
					t.Fatal("unexpected failed port mapping attempt")
				}
			default:
				t.Fatal("no port mapping and no failed attempt")
			}
		})
	}
}
