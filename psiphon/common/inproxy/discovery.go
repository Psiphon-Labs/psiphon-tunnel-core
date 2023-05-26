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
	"net"
	"sync"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/pion/stun"
)

const (
	discoverNATTimeout          = 10 * time.Second
	discoverNATRoundTripTimeout = 2 * time.Second
)

// NATDiscoverConfig specifies the configuration for a NATDiscover run.
type NATDiscoverConfig struct {

	// Logger is used to log events.
	Logger common.Logger

	// DialParameters specifies specific STUN and discovery and
	// settings, and receives discovery results.
	DialParameters DialParameters

	// SkipPortMapping indicates whether to skip port mapping type discovery,
	// as clients do since they will gather the same stats during the WebRTC
	// offer preparation.
	SkipPortMapping bool
}

// NATDiscover runs NAT type and port mapping type discovery operations.
//
// Successfuly results are delivered to NATDiscoverConfig.DialParameters
// callbacks, SetNATType and SetPortMappingTypes, which should cache results
// associated with the current network, by network ID.
//
// NAT discovery will invoke DialParameter callbacks
// STUNServerAddressSucceeded and STUNServerAddressFailed, which may be used
// to mark or unmark STUN servers for replay.
func NATDiscover(
	ctx context.Context,
	config *NATDiscoverConfig) {

	// Run discovery until the specified timeout, or ctx is done. NAT and port
	// mapping discovery are run concurrently.

	discoverCtx, cancelFunc := context.WithTimeout(
		ctx, common.ValueOrDefault(config.DialParameters.DiscoverNATTimeout(), discoverNATTimeout))
	defer cancelFunc()

	discoveryWaitGroup := new(sync.WaitGroup)

	if config.DialParameters.NATType().NeedsDiscovery() &&
		!config.DialParameters.DisableSTUN() {

		discoveryWaitGroup.Add(1)
		go func() {
			defer discoveryWaitGroup.Done()

			natType, err := discoverNATType(discoverCtx, config)

			if err == nil {
				// Deliver the result. The DialParameters provider may cache
				// this result, associated wih the current networkID.
				config.DialParameters.SetNATType(natType)
			}

			config.Logger.WithTraceFields(common.LogFields{
				"nat_type": natType.String(),
				"error":    err,
			}).Info("NAT type discovery")

		}()
	}

	if !config.SkipPortMapping &&
		config.DialParameters.PortMappingTypes().NeedsDiscovery() &&
		!config.DialParameters.DisablePortMapping() {

		discoveryWaitGroup.Add(1)
		go func() {
			defer discoveryWaitGroup.Done()

			portMappingTypes, err := discoverPortMappingTypes(
				discoverCtx, config.Logger)

			if err == nil {
				// Deliver the result. The DialParameters provider may cache
				// this result, associated wih the current networkID.
				config.DialParameters.SetPortMappingTypes(portMappingTypes)
			}

			config.Logger.WithTraceFields(common.LogFields{
				"port_mapping_types": portMappingTypes.String(),
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
	stunServerAddress := config.DialParameters.STUNServerAddress(RFC5780)

	if stunServerAddress == "" {
		return NATTypeUnknown, errors.TraceNew("no RFC5780 STUN server")
	}

	serverAddress, err := config.DialParameters.ResolveAddress(
		ctx, stunServerAddress)
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

	mappingConn, err := config.DialParameters.UDPListen()
	if err != nil {
		return NATTypeUnknown, errors.Trace(err)
	}
	defer mappingConn.Close()

	filteringConn, err := config.DialParameters.UDPListen()
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
		return
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

		config.DialParameters.STUNServerAddressFailed(RFC5780, stunServerAddress)

		return NATTypeUnknown, errors.Trace(err)
	}

	config.DialParameters.STUNServerAddressSucceeded(RFC5780, stunServerAddress)

	return r.NATType, nil
}

// discoverNATMapping and discoverNATFiltering are modifications of:
// https://github.com/pion/stun/blob/b321a45be43b07685c639943aaa28e6841517799/cmd/stun-nat-behaviour/main.go

// https://github.com/pion/stun/blob/b321a45be43b07685c639943aaa28e6841517799/LICENSE.md:
/*
Copyright 2018 Pion LLC

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

// RFC5780: 4.3.  Determining NAT Mapping Behavior
func discoverNATMapping(
	ctx context.Context,
	conn net.PacketConn,
	serverAddress string) (NATMapping, error) {

	// Test I: Regular binding request

	request := stun.MustBuild(stun.TransactionID, stun.BindingRequest)

	response, _, err := doSTUNRoundTrip(request, conn, serverAddress)
	if err != nil {
		return NATMappingUnknown, errors.Trace(err)
	}
	responseFields := parseSTUNMessage(response)
	if responseFields.xorAddr == nil || responseFields.otherAddr == nil {
		return NATMappingUnknown, errors.TraceNew("NAT discovery not supported")
	}
	if responseFields.xorAddr.String() == conn.LocalAddr().String() {
		return NATMappingEndpointIndependent, nil
	}

	otherAddress := responseFields.otherAddr

	// Test II: Send binding request to the other address but primary port

	_, serverPort, err := net.SplitHostPort(serverAddress)
	if err != nil {
		return NATMappingUnknown, errors.Trace(err)
	}

	address := net.JoinHostPort(otherAddress.IP.String(), serverPort)
	response2, _, err := doSTUNRoundTrip(request, conn, address)
	if err != nil {
		return NATMappingUnknown, errors.Trace(err)
	}
	response2Fields := parseSTUNMessage(response2)
	if response2Fields.xorAddr.String() == responseFields.xorAddr.String() {
		return NATMappingEndpointIndependent, nil
	}

	// Test III: Send binding request to the other address and port

	response3, _, err := doSTUNRoundTrip(request, conn, otherAddress.String())
	if err != nil {
		return NATMappingUnknown, errors.Trace(err)
	}
	response3Fields := parseSTUNMessage(response3)
	if response3Fields.xorAddr.String() == response2Fields.xorAddr.String() {
		return NATMappingAddressDependent, nil
	} else {
		return NATMappingAddressPortDependent, nil
	}

	return NATMappingUnknown, nil
}

// RFC5780: 4.4.  Determining NAT Filtering Behavior
func discoverNATFiltering(
	ctx context.Context,
	conn net.PacketConn,
	serverAddress string) (NATFiltering, error) {

	// Test I: Regular binding request

	request := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
	response, _, err := doSTUNRoundTrip(request, conn, serverAddress)
	if err != nil {
		return NATFilteringUnknown, errors.Trace(err)
	}
	responseFields := parseSTUNMessage(response)
	if responseFields.xorAddr == nil || responseFields.otherAddr == nil {
		return NATFilteringUnknown, errors.TraceNew("NAT discovery not supported")
	}

	// Test II: Request to change both IP and port

	request = stun.MustBuild(stun.TransactionID, stun.BindingRequest)
	request.Add(stun.AttrChangeRequest, []byte{0x00, 0x00, 0x00, 0x06})

	response, responseTimeout, err := doSTUNRoundTrip(request, conn, serverAddress)
	if err == nil {
		return NATFilteringEndpointIndependent, nil
	} else if !responseTimeout {
		return NATFilteringUnknown, errors.Trace(err)
	}

	// Test III: Request to change port only

	request = stun.MustBuild(stun.TransactionID, stun.BindingRequest)
	request.Add(stun.AttrChangeRequest, []byte{0x00, 0x00, 0x00, 0x02})

	response, responseTimeout, err = doSTUNRoundTrip(request, conn, serverAddress)
	if err == nil {
		return NATFilteringAddressDependent, nil
	} else if !responseTimeout {
		return NATFilteringUnknown, errors.Trace(err)
	}

	return NATFilteringAddressPortDependent, nil
}

func parseSTUNMessage(message *stun.Message) (ret struct {
	xorAddr    *stun.XORMappedAddress
	otherAddr  *stun.OtherAddress
	respOrigin *stun.ResponseOrigin
	mappedAddr *stun.MappedAddress
	software   *stun.Software
},
) {
	ret.mappedAddr = &stun.MappedAddress{}
	ret.xorAddr = &stun.XORMappedAddress{}
	ret.respOrigin = &stun.ResponseOrigin{}
	ret.otherAddr = &stun.OtherAddress{}
	ret.software = &stun.Software{}
	if ret.xorAddr.GetFrom(message) != nil {
		ret.xorAddr = nil
	}
	if ret.otherAddr.GetFrom(message) != nil {
		ret.otherAddr = nil
	}
	if ret.respOrigin.GetFrom(message) != nil {
		ret.respOrigin = nil
	}
	if ret.mappedAddr.GetFrom(message) != nil {
		ret.mappedAddr = nil
	}
	if ret.software.GetFrom(message) != nil {
		ret.software = nil
	}
	return ret
}

// doSTUNRoundTrip returns nil, true, nil on timeout reading a response.
func doSTUNRoundTrip(
	request *stun.Message,
	conn net.PacketConn,
	remoteAddress string) (*stun.Message, bool, error) {

	remoteAddr, err := net.ResolveUDPAddr("udp", remoteAddress)
	if err != nil {
		return nil, false, errors.Trace(err)
	}

	_ = request.NewTransactionID()
	_, err = conn.WriteTo(request.Raw, remoteAddr)
	if err != nil {
		return nil, false, errors.Trace(err)
	}

	conn.SetReadDeadline(time.Now().Add(discoverNATRoundTripTimeout))

	var buffer [1500]byte
	n, _, err := conn.ReadFrom(buffer[:])
	if err != nil {
		if e, ok := err.(net.Error); ok && e.Timeout() {
			return nil, true, errors.Trace(err)
		}
		return nil, false, errors.Trace(err)
	}

	response := new(stun.Message)
	response.Raw = buffer[:n]
	err = response.Decode()
	if err != nil {
		return nil, false, errors.Trace(err)
	}

	return response, false, nil
}

func discoverPortMappingTypes(
	ctx context.Context,
	logger common.Logger) (PortMappingTypes, error) {

	portMappingTypes, err := probePortMapping(ctx, logger)
	if err != nil {
		return nil, errors.Trace(err)
	}

	return portMappingTypes, nil
}
