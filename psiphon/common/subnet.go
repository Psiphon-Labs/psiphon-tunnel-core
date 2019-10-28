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
	"bufio"
	"bytes"
	"encoding/binary"
	"net"
	"sort"
	"strings"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
)

// SubnetLookup provides an efficient lookup for individual
// IPv4 addresses within a list of subnets.
type SubnetLookup []net.IPNet

// NewSubnetLookup creates a SubnetLookup from a list of
// subnet CIDRs.
func NewSubnetLookup(CIDRs []string) (SubnetLookup, error) {

	subnets := make([]net.IPNet, len(CIDRs))

	for i, CIDR := range CIDRs {
		_, network, err := net.ParseCIDR(CIDR)
		if err != nil {
			return nil, errors.Trace(err)
		}
		subnets[i] = *network
	}

	lookup := SubnetLookup(subnets)
	sort.Sort(lookup)

	return lookup, nil
}

// NewSubnetLookupFromRoutes creates a SubnetLookup from text routes
// data. The input format is expected to be text lines where each line
// is, e.g., "1.2.3.0\t255.255.255.0\n"
func NewSubnetLookupFromRoutes(routesData []byte) (SubnetLookup, error) {

	// Parse text routes data
	var subnets []net.IPNet
	scanner := bufio.NewScanner(bytes.NewReader(routesData))
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		s := strings.Split(scanner.Text(), "\t")
		if len(s) != 2 {
			continue
		}

		ip := parseIPv4(s[0])
		mask := parseIPv4Mask(s[1])
		if ip == nil || mask == nil {
			continue
		}

		subnets = append(subnets, net.IPNet{IP: ip.Mask(mask), Mask: mask})
	}
	if len(subnets) == 0 {
		return nil, errors.TraceNew("Routes data contains no networks")
	}

	lookup := SubnetLookup(subnets)
	sort.Sort(lookup)

	return lookup, nil
}

func parseIPv4(s string) net.IP {
	ip := net.ParseIP(s)
	if ip == nil {
		return nil
	}
	return ip.To4()
}

func parseIPv4Mask(s string) net.IPMask {
	ip := parseIPv4(s)
	if ip == nil {
		return nil
	}
	mask := net.IPMask(ip)
	if bits, size := mask.Size(); bits == 0 || size == 0 {
		return nil
	}
	return mask
}

// Len implements Sort.Interface
func (lookup SubnetLookup) Len() int {
	return len(lookup)
}

// Swap implements Sort.Interface
func (lookup SubnetLookup) Swap(i, j int) {
	lookup[i], lookup[j] = lookup[j], lookup[i]
}

// Less implements Sort.Interface
func (lookup SubnetLookup) Less(i, j int) bool {
	return binary.BigEndian.Uint32(lookup[i].IP) < binary.BigEndian.Uint32(lookup[j].IP)
}

// ContainsIPAddress performs a binary search on the sorted subnet
// list to find a network containing the candidate IP address.
func (lookup SubnetLookup) ContainsIPAddress(addr net.IP) bool {

	// Search criteria
	//
	// The following conditions are satisfied when address_IP is in the network:
	// 1. address_IP ^ network_mask == network_IP ^ network_mask
	// 2. address_IP >= network_IP.
	// We are also assuming that network ranges do not overlap.
	//
	// For an ascending array of networks, the sort.Search returns the smallest
	// index idx for which condition network_IP > address_IP is satisfied, so we
	// are checking whether or not adrress_IP belongs to the network[idx-1].

	// Edge conditions check
	//
	// idx == 0 means that address_IP is lesser than the first (smallest) network_IP
	// thus never satisfies search condition 2.
	// idx == array_length means that address_IP is larger than the last (largest)
	// network_IP so we need to check the last element for condition 1.

	ipv4 := addr.To4()
	if ipv4 == nil {
		return false
	}
	addrValue := binary.BigEndian.Uint32(ipv4)
	index := sort.Search(len(lookup), func(i int) bool {
		networkValue := binary.BigEndian.Uint32(lookup[i].IP)
		return networkValue > addrValue
	})
	return index > 0 && lookup[index-1].IP.Equal(addr.Mask(lookup[index-1].Mask))
}
