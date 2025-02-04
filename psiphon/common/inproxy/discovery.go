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
	"sync"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
)

const (
	discoverNATTimeout          = 10 * time.Second
	discoverNATRoundTripTimeout = 2 * time.Second
)

// NATDiscoverConfig specifies the configuration for a NATDiscover run.
type NATDiscoverConfig struct {

	// Logger is used to log events.
	Logger common.Logger

	// WebRTCDialCoordinator specifies specific STUN and discovery and
	// settings, and receives discovery results.
	WebRTCDialCoordinator WebRTCDialCoordinator

	// SkipPortMapping indicates whether to skip port mapping type discovery,
	// as clients do since they will gather the same stats during the WebRTC
	// offer preparation.
	SkipPortMapping bool
}

// NATDiscover runs NAT type and port mapping type discovery operations.
//
// Successfuly results are delivered to NATDiscoverConfig.WebRTCDialCoordinator
// callbacks, SetNATType and SetPortMappingTypes, which should cache results
// associated with the current network, by network ID.
//
// NAT discovery will invoke WebRTCDialCoordinator callbacks
// STUNServerAddressSucceeded and STUNServerAddressFailed, which may be used
// to mark or unmark STUN servers for replay.
func NATDiscover(
	ctx context.Context,
	config *NATDiscoverConfig) {

	// Run discovery until the specified timeout, or ctx is done. NAT and port
	// mapping discovery are run concurrently.

	discoverCtx, cancelFunc := context.WithTimeout(
		ctx, common.ValueOrDefault(
			config.WebRTCDialCoordinator.DiscoverNATTimeout(), discoverNATTimeout))
	defer cancelFunc()

	discoveryWaitGroup := new(sync.WaitGroup)

	if config.WebRTCDialCoordinator.NATType().NeedsDiscovery() &&
		!config.WebRTCDialCoordinator.DisableSTUN() {

		discoveryWaitGroup.Add(1)
		go func() {
			defer discoveryWaitGroup.Done()

			natType, err := discoverNATType(discoverCtx, config)

			if err == nil {
				// Deliver the result. The WebRTCDialCoordinator provider may cache
				// this result, associated wih the current networkID.
				config.WebRTCDialCoordinator.SetNATType(natType)
			}

			config.Logger.WithTraceFields(common.LogFields{
				"nat_type": natType,
				"error":    err,
			}).Info("NAT type discovery")

		}()
	}

	if !config.SkipPortMapping &&
		config.WebRTCDialCoordinator.PortMappingTypes().NeedsDiscovery() &&
		!config.WebRTCDialCoordinator.DisablePortMapping() {

		discoveryWaitGroup.Add(1)
		go func() {
			defer discoveryWaitGroup.Done()

			portMappingTypes, portMapperProbe, err := discoverPortMappingTypes(
				discoverCtx, config.Logger)

			if err == nil {
				// Deliver the results. The WebRTCDialCoordinator provider
				// should cache this data, associated wih the current networkID.
				config.WebRTCDialCoordinator.SetPortMappingTypes(portMappingTypes)
				config.WebRTCDialCoordinator.SetPortMappingProbe(portMapperProbe)
			}

			config.Logger.WithTraceFields(common.LogFields{
				"port_mapping_types": portMappingTypes,
				"error":              err,
			}).Info("Port mapping type discovery")

		}()
	}

	discoveryWaitGroup.Wait()
}

func discoverNATType(
	ctx context.Context,
	config *NATDiscoverConfig) (NATType, error) {

	RFC5780 := true
	stunServerAddress := config.WebRTCDialCoordinator.STUNServerAddress(RFC5780)

	if stunServerAddress == "" {
		return NATTypeUnknown, errors.TraceNew("no RFC5780 STUN server")
	}

	serverAddress, err := config.WebRTCDialCoordinator.ResolveAddress(
		ctx, "ip", stunServerAddress)
	if err != nil {
		return NATTypeUnknown, errors.Trace(err)
	}

	// The STUN server will observe proxy IP addresses. Enumeration is
	// mitigated by using various public STUN servers, including Psiphon STUN
	// servers for proxies in non-censored regions. Proxies are also more
	// ephemeral than Psiphon servers.

	// Limitation: RFC5780, "4.1. Source Port Selection" recommends using the
	// same source port for NAT discovery _and_ subsequent NAT traveral
	// applications, such as WebRTC ICE. It's stated that the discovered NAT
	// type may only be valid for the particular tested port.
	//
	// We don't do this at this time, as we don't want to incur the full
	// RFC5780 discovery overhead for every WebRTC dial, and expect that, in
	// most typical cases, the network NAT type applies to all ports.
	// Furthermore, the UDP conn that owns the tested port may need to be
	// closed to interrupt discovery.

	// We run the filtering test before the mapping test, and each test uses a
	// distinct source port; using the same source port may result in NAT
	// state from one test confusing the other test. See also,
	// https://github.com/jselbie/stunserver/issues/18:
	//
	//  > running both the behavior test and the filtering test at the
	//  > same time can cause an incorrect filtering type to be detected.
	//  > If the filtering is actually "address dependent", the scan will
	//  > report it as "endpoint independent".
	//  >
	//  > The cause appears to be the order in which the tests are being
	//  > performed, currently "behavior" tests followed by "filtering"
	//  > tests. The network traffic from the behavior tests having been run
	//  > causes the router to allow filtering test responses back through
	//  > that would not have otherwise been allowed... The behavior tests
	//  > send traffic to the secondary IP of the STUN server, so the
	//  > filtering tests are allowed to get responses back from that
	//  > secondary IP.
	//  >
	//  > The fix is likely some combination of ...re-order the tests...
	//  > or use the a different port for the filtering test.
	//
	// TODO: RFC5780, "4.5 Combining and Ordering Tests", suggests that the
	// individual test steps within filtering and mapping could be combined,
	// and certain tests may be run concurrently, with the goal of reducing
	// the total elapsed test time. However, "care must be taken when
	// combining and parallelizing tests, due to the sensitivity of certain
	// tests to prior state on the NAT and because some NAT devices have an
	// upper limit on how quickly bindings will be allocated."
	//
	// For now, we stick with a conservative arrangement of tests. Note that,
	// in practise, the discoverNATMapping completes much faster
	// discoverNATFiltering, and so there's a limited gain from running these
	// two top-level tests concurrently.

	mappingConn, err := config.WebRTCDialCoordinator.UDPListen(ctx)
	if err != nil {
		return NATTypeUnknown, errors.Trace(err)
	}
	defer mappingConn.Close()

	filteringConn, err := config.WebRTCDialCoordinator.UDPListen(ctx)
	if err != nil {
		return NATTypeUnknown, errors.Trace(err)
	}
	defer filteringConn.Close()

	type result struct {
		NATType NATType
		err     error
	}
	resultChannel := make(chan result, 1)

	go func() {

		filtering, err := discoverNATFiltering(ctx, filteringConn, serverAddress)
		if err != nil {
			resultChannel <- result{err: errors.Trace(err)}
			return
		}

		mapping, err := discoverNATMapping(ctx, mappingConn, serverAddress)
		if err != nil {
			resultChannel <- result{err: errors.Trace(err)}
			return
		}

		resultChannel <- result{NATType: MakeNATType(mapping, filtering)}
	}()

	var r result
	select {
	case r = <-resultChannel:
	case <-ctx.Done():

		// Interrupt and await the goroutine
		mappingConn.Close()
		filteringConn.Close()
		<-resultChannel

		// Don't call STUNServerAddressFailed, since ctx.Done may be due to an
		// early dial cancel.
		return NATTypeUnknown, errors.Trace(ctx.Err())
	}

	if r.err != nil {

		config.WebRTCDialCoordinator.STUNServerAddressFailed(RFC5780, stunServerAddress)

		return NATTypeUnknown, errors.Trace(err)
	}

	config.WebRTCDialCoordinator.STUNServerAddressSucceeded(RFC5780, stunServerAddress)

	return r.NATType, nil
}

func discoverPortMappingTypes(
	ctx context.Context,
	logger common.Logger) (PortMappingTypes, *PortMappingProbe, error) {

	portMappingTypes, portMapperProbe, err := probePortMapping(ctx, logger)
	if err != nil {
		return nil, nil, errors.Trace(err)
	}

	return portMappingTypes, portMapperProbe, nil
}
