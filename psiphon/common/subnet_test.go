/*
 * Copyright (c) 2016, Psiphon Inc.
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

package common

import (
	"encoding/binary"
	"io/ioutil"
	"math/rand"
	"net"
	"testing"
)

func TestSubnetLookup(t *testing.T) {
	CIDRs := []string{
		"192.168.0.0/16",
		"10.0.0.0/8",
		"172.16.0.0/12",
		"100.64.0.0/10"}

	routes := []byte("192.168.0.0\t255.255.0.0\n10.0.0.0\t255.0.0.0\n" +
		"172.16.0.0\t255.240.0.0\n100.64.0.0\t255.192.0.0\n")

	var subnetLookup SubnetLookup

	t.Run("new subnet lookup", func(t *testing.T) {

		var err error
		subnetLookup, err = NewSubnetLookup(CIDRs)
		if err != nil {
			t.Fatalf("NewSubnetLookup failed: %s", err)
		}
	})

	var subnetLookupRoutes SubnetLookup

	t.Run("new subnet lookup (routes case)", func(t *testing.T) {

		var err error
		subnetLookupRoutes, err = NewSubnetLookupFromRoutes(routes)
		if err != nil {
			t.Fatalf("NewSubnetLookupFromRoutes failed: %s", err)
		}
	})

	if subnetLookup == nil || subnetLookupRoutes == nil {
		t.Fatalf("new subnet list failed")
	}

	testCases := []struct {
		description    string
		ipAddress      net.IP
		expectedResult bool
	}{
		{"IP address in subnet", net.ParseIP("172.17.3.2"), true},
		{"IP address not in subnet", net.ParseIP("169.254.1.1"), false},
		{"IP address not in subnet (prefix case)", net.ParseIP("172.15.3.2"), false},
	}

	for _, testCase := range testCases {
		t.Run(testCase.description, func(t *testing.T) {

			result := subnetLookup.ContainsIPAddress(testCase.ipAddress)
			if result != testCase.expectedResult {
				t.Fatalf(
					"ContainsIPAddress returned %+v expected %+v",
					result, testCase.expectedResult)
			}

			result = subnetLookupRoutes.ContainsIPAddress(testCase.ipAddress)
			if result != testCase.expectedResult {
				t.Fatalf(
					"ContainsIPAddress (routes case) returned %+v expected %+v",
					result, testCase.expectedResult)
			}
		})
	}
}

func BenchmarkSubnetLookup(b *testing.B) {

	var subnetLookup SubnetLookup

	b.Run("load routes file", func(b *testing.B) {

		routesData, err := ioutil.ReadFile("test_routes.dat")
		if err != nil {
			b.Skipf("can't load test routes file: %s", err)
		}

		for n := 0; n < b.N; n++ {
			subnetLookup, err = NewSubnetLookupFromRoutes(routesData)
			if err != nil {
				b.Fatalf("NewSubnetLookup failed: %s", err)
			}
		}
	})

	if subnetLookup == nil {
		b.Skipf("no test routes file")
	}

	b.Run("lookup random IP address", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			ip := make([]byte, 4)
			binary.BigEndian.PutUint32(ip, rand.Uint32())
			_ = subnetLookup.ContainsIPAddress(net.IP(ip))
		}
	})
}
