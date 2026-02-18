//go:build !PSIPHON_DISABLE_INPROXY

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
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/pion/stun"
)

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

	// Verify that otherAddress, specified by STUN server, is a valid public
	// IP before sending a packet to it. This prevents the STUN server
	// (or injected response) from redirecting the flow to an internal network.

	if common.IsBogon(otherAddress.IP) {
		return NATMappingUnknown, errors.TraceNew("OTHER-ADDRESS is bogon")
	}

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
	}
	return NATMappingAddressPortDependent, nil
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

	_, responseTimeout, err := doSTUNRoundTrip(request, conn, serverAddress)
	if err == nil {
		return NATFilteringEndpointIndependent, nil
	} else if !responseTimeout {
		return NATFilteringUnknown, errors.Trace(err)
	}

	// Test III: Request to change port only

	request = stun.MustBuild(stun.TransactionID, stun.BindingRequest)
	request.Add(stun.AttrChangeRequest, []byte{0x00, 0x00, 0x00, 0x02})

	_, responseTimeout, err = doSTUNRoundTrip(request, conn, serverAddress)
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

	err = conn.SetReadDeadline(time.Now().Add(discoverNATRoundTripTimeout))
	if err != nil {
		return nil, false, errors.Trace(err)
	}

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

	// Verify that the response packet has the expected transaction ID, to
	// partially mitigate against phony injected responses.

	if response.TransactionID != request.TransactionID {
		return nil, false, errors.TraceNew(
			"unexpected response transaction ID")
	}

	return response, false, nil
}
