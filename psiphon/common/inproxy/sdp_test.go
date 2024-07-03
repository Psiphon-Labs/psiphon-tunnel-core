//go:build PSIPHON_ENABLE_INPROXY

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

package inproxy

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
)

func TestProcessSDP(t *testing.T) {
	err := runTestProcessSDP()
	if err != nil {
		t.Errorf(errors.Trace(err).Error())
	}
}

func runTestProcessSDP() error {

	config := &webRTCConfig{
		Logger: newTestLogger(),
		WebRTCDialCoordinator: &testWebRTCDialCoordinator{
			disableSTUN:        true,
			disablePortMapping: true,
		},
	}

	// Create a valid, base SDP, including private network (bogon) candidates.

	SetAllowBogonWebRTCConnections(true)
	defer SetAllowBogonWebRTCConnections(false)

	conn, webRTCSDP, metrics, err := newWebRTCConnWithOffer(
		context.Background(), config)
	if err != nil {
		return errors.Trace(err)
	}
	defer conn.Close()

	SDP := []byte(webRTCSDP.SDP)

	// Test disallow IPv6

	if metrics.hasIPv6 {
		preparedSDP, metrics, err := prepareSDPAddresses(
			SDP, true, "", true)
		if err != nil {
			return errors.Trace(err)
		}

		found := false
		for _, reason := range metrics.filteredICECandidates {
			if strings.Contains(reason, "disabled IPv6") {
				found = true
				break
			}
		}
		if !found {
			return errors.TraceNew("unexpected filteredICECandidates")
		}

		if len(preparedSDP) >= len(SDP) {
			return errors.TraceNew("unexpected SDP length")
		}
	}

	// Test filter unexpected GeoIP

	// This IP must not be a bogon; this address is not dialed.
	testIP := "1.1.1.1"
	expectedGeoIP := common.GeoIPData{Country: "AA", ASN: "1"}
	lookupGeoIP := func(IP string) common.GeoIPData {
		if IP == testIP {
			return common.GeoIPData{Country: "BB", ASN: "2"}
		}
		return expectedGeoIP
	}

	// Add the testIP as a port mapping candidate.
	preparedSDP, metrics, err := prepareSDPAddresses(
		SDP, true, net.JoinHostPort(testIP, "80"), false)
	if err != nil {
		return errors.Trace(err)
	}

	filteredSDP, metrics, err := filterSDPAddresses(
		preparedSDP, true, lookupGeoIP, expectedGeoIP)
	if err != nil {
		return errors.Trace(err)
	}

	found := false
	for _, reason := range metrics.filteredICECandidates {
		if strings.Contains(reason, "unexpected GeoIP") {
			found = true
			break
		}
	}
	if !found {
		return errors.TraceNew("unexpected filteredICECandidates")
	}

	if len(filteredSDP) >= len(preparedSDP) {
		return errors.TraceNew("unexpected SDP length")
	}

	// Test filter bogons

	SetAllowBogonWebRTCConnections(false)

	// Allow no candidates (errorOnNoCandidates = false)
	filteredSDP, metrics, err = filterSDPAddresses(
		SDP, false, nil, common.GeoIPData{})
	if err != nil {
		return errors.Trace(err)
	}

	found = false
	for _, reason := range metrics.filteredICECandidates {
		if strings.Contains(reason, "bogon") {
			found = true
			break
		}
	}
	if !found {
		return errors.TraceNew("unexpected filteredICECandidates")
	}

	if len(filteredSDP) >= len(preparedSDP) {
		return errors.TraceNew("unexpected SDP length")
	}

	return nil
}
