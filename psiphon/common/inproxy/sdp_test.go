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
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/internal/testutils"
)

func TestProcessSDP(t *testing.T) {
	err := runTestProcessSDP()
	if err != nil {
		t.Error(errors.Trace(err).Error())
	}
}

func runTestProcessSDP() error {

	config := &webRTCConfig{
		Logger: testutils.NewTestLogger(),
		WebRTCDialCoordinator: &testWebRTCDialCoordinator{
			disableSTUN:        true,
			disablePortMapping: true,
		},
	}

	hasPersonalCompartmentIDs := false
	errorOnNoCandidates := true
	disableIPv6Candidates := false
	allowPrivateIPAddressCandidates := false
	filterPrivateIPAddressCandidates := false

	// Create a valid, base SDP, including private network (bogon) candidates.

	SetAllowBogonWebRTCConnections(true)
	defer SetAllowBogonWebRTCConnections(false)

	conn, webRTCSDP, metrics, err := newWebRTCConnForOffer(
		context.Background(), config, hasPersonalCompartmentIDs)
	if err != nil {
		return errors.Trace(err)
	}
	defer conn.Close()

	SDP := []byte(webRTCSDP.SDP)

	// Test disallow IPv6

	disableIPv6Candidates = true

	if metrics.hasIPv6 {
		preparedSDP, metrics, err := prepareSDPAddresses(
			SDP,
			errorOnNoCandidates,
			"",
			disableIPv6Candidates,
			allowPrivateIPAddressCandidates)
		if err != nil {
			return errors.Trace(err)
		}

		found := false
		for _, reason := range metrics.filteredICECandidates {
			if strings.Contains(reason, "disabled") {
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

	disableIPv6Candidates = false

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
		SDP,
		errorOnNoCandidates,
		net.JoinHostPort(testIP, "80"),
		disableIPv6Candidates,
		allowPrivateIPAddressCandidates)
	if err != nil {
		return errors.Trace(err)
	}

	filteredSDP, metrics, err := filterSDPAddresses(
		preparedSDP,
		errorOnNoCandidates,
		lookupGeoIP,
		expectedGeoIP,
		allowPrivateIPAddressCandidates,
		filterPrivateIPAddressCandidates)
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

	// Allow no candidates
	errorOnNoCandidates = false

	filteredSDP, metrics, err = filterSDPAddresses(
		SDP,
		errorOnNoCandidates,
		nil,
		common.GeoIPData{},
		allowPrivateIPAddressCandidates,
		filterPrivateIPAddressCandidates)
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

	if len(filteredSDP) >= len(SDP) {
		return errors.TraceNew("unexpected SDP length")
	}

	errorOnNoCandidates = true

	// Test private IP addresses

	SetAllowBogonWebRTCConnections(false)

	hasPersonalCompartmentIDs = true
	allowPrivateIPAddressCandidates = true
	filterPrivateIPAddressCandidates = true

	conn, webRTCSDP, metrics, err = newWebRTCConnForOffer(
		context.Background(), config, hasPersonalCompartmentIDs)
	if err != nil {
		return errors.Trace(err)
	}
	defer conn.Close()

	SDP = []byte(webRTCSDP.SDP)

	hasPrivateIP := metrics.hasPrivateIP

	if !hasPrivateIP {
		// Test may run on host without RFC 1918/4193 private IP address
		fmt.Printf("No private IP address\n")
	}

	// Filter should retain any private IP address(es)
	filteredSDP, metrics, err = filterSDPAddresses(
		SDP,
		errorOnNoCandidates,
		nil,
		common.GeoIPData{},
		allowPrivateIPAddressCandidates,
		filterPrivateIPAddressCandidates)
	if err != nil {
		return errors.Trace(err)
	}

	if hasPrivateIP != metrics.hasPrivateIP {
		return errors.TraceNew("unexpected metrics.hasPrivateIP")
	}

	if len(filteredSDP) != len(SDP) {
		return errors.TraceNew("unexpected SDP length")
	}

	return nil
}
