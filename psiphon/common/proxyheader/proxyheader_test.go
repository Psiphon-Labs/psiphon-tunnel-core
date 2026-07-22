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

package proxyheader

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	proxyproto "github.com/pires/go-proxyproto"
)

func TestProxyProtocolHeaderVerification(t *testing.T) {

	err := runTestProxyProtocolHeaderVerification()
	if err != nil {
		t.Fatal(err.Error())
	}
}

func runTestProxyProtocolHeaderVerification() error {

	keyID := make([]byte, ProxyProtocolHeaderKeyIDSize)
	binary.BigEndian.PutUint32(keyID, 1)
	key := prng.Bytes(ProxyProtocolHeaderMACKeySize)

	incorrectKeyID := make([]byte, ProxyProtocolHeaderKeyIDSize)
	binary.BigEndian.PutUint32(incorrectKeyID, 2)
	incorrectKey := prng.Bytes(ProxyProtocolHeaderMACKeySize)

	sourceIP := net.ParseIP("127.0.0.1")
	destinationIP := net.ParseIP("127.0.0.2")
	destinationPort := 443

	// Test: check offset of final TLV and MAC

	wireHeader, err := MakeProxyProtocolHeader(
		keyID, key, sourceIP, destinationIP, destinationPort)
	if err != nil {
		return errors.Trace(err)
	}

	header, err := proxyproto.Read(
		bufio.NewReader(bytes.NewReader(wireHeader)))
	if err != nil {
		return errors.Trace(err)
	}

	tlvs, err := header.TLVs()
	if err != nil {
		return errors.Trace(err)
	}

	if len(tlvs) != 1 {
		return errors.TraceNew("unexpected TLV count")
	}

	if tlvs[0].Type != proxyProtocolHeaderMACTLVType ||
		len(tlvs[0].Value) != proxyProtocolHeaderMACTLVSize {
		return errors.TraceNew("unexpected TLV")
	}

	if !bytes.Equal(
		wireHeader[len(wireHeader)-proxyProtocolHeaderMACTLVSize:],
		tlvs[0].Value) {
		return errors.TraceNew("unexpected TLV offset")
	}

	// Test: successful verification

	wireHeader, err = MakeProxyProtocolHeader(
		keyID, key, sourceIP, destinationIP, destinationPort)
	if err != nil {
		return errors.Trace(err)
	}

	timestamp,
		headerSourceIP,
		headerDestinationIP,
		headerDestinationPort,
		err :=
		VerifyProxyProtocolHeader(keyID, key, wireHeader)
	if err != nil {
		return errors.Trace(err)
	}

	if time.Now().Sub(timestamp).Abs() > 5*time.Second ||
		headerSourceIP.String() != sourceIP.String() ||
		headerDestinationIP.String() != destinationIP.String() ||
		headerDestinationPort != destinationPort {
		return errors.TraceNew("unexpected output")
	}

	// Test: wrong key ID

	_, _, _, _, err =
		VerifyProxyProtocolHeader(incorrectKeyID, key, wireHeader)
	if err == nil {
		return errors.TraceNew("unexpected success")
	}

	// Test: wrong key

	_, _, _, _, err =
		VerifyProxyProtocolHeader(keyID, incorrectKey, wireHeader)
	if err == nil {
		return errors.TraceNew("unexpected success")
	}

	// Test: invalid MAC

	wireHeader[16] ^= 0xff // Flip source IPv4 field bits

	_, _, _, _, err =
		VerifyProxyProtocolHeader(keyID, key, wireHeader)
	if err == nil {
		return errors.TraceNew("unexpected success")
	}

	// Note: AddOrReplaceProxyProtocolHeader is exercised in server_test.

	return nil
}

func TestProxyProtocolHeaderMixedAddressFamilies(t *testing.T) {

	keyID := make([]byte, ProxyProtocolHeaderKeyIDSize)
	key := prng.Bytes(ProxyProtocolHeaderMACKeySize)
	destinationPort := 443

	tests := []struct {
		name          string
		sourceIP      net.IP
		destinationIP net.IP
	}{
		{
			name:          "IPv4 source and IPv6 destination",
			sourceIP:      net.ParseIP("192.0.2.1"),
			destinationIP: net.ParseIP("2001:db8::1"),
		},
		{
			name:          "IPv6 source and IPv4 destination",
			sourceIP:      net.ParseIP("2001:db8::1"),
			destinationIP: net.ParseIP("192.0.2.1"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			wireHeader, err := MakeProxyProtocolHeader(
				keyID,
				key,
				test.sourceIP,
				test.destinationIP,
				destinationPort)
			if err != nil {
				t.Fatal(err.Error())
			}

			_, sourceIP, destinationIP, port, err :=
				VerifyProxyProtocolHeader(keyID, key, wireHeader)
			if err != nil {
				t.Fatal(err.Error())
			}
			if !sourceIP.Equal(test.sourceIP) ||
				!destinationIP.Equal(test.destinationIP) ||
				port != destinationPort {

				t.Fatalf(
					"unexpected addresses: source %s, destination %s:%d",
					sourceIP,
					destinationIP,
					port)
			}
		})
	}
}
