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

package tun

import (
	"net"
	"slices"
	"strings"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
)

// Client addresses are assigned from all of privateSubnetIPv4. When the host
// also routes a more specific subnet of privateSubnetIPv4 through another
// interface, such as a private network, replies to a client assigned an
// address in that subnet follow the more specific route and never reach the
// tun device. The client stays connected but receives no downstream packets.
//
// To avoid this, the server excludes such subnets from address assignment.
// Excluded subnets are the configured ServerConfig.ExcludedIPv4Subnets plus,
// where supported, subnets discovered from the host's routes and interface
// addresses. ServerConfig.DisableHostSubnetDiscovery turns discovery off.
//
// Only IPv4 subnets are excluded. Client IPv6 addresses are in
// privateSubnetIPv6, a randomly chosen unique local prefix that host
// networks aren't expected to use. Each index maps to one IPv4 and one
// IPv6 address, so excluding an index also excludes its IPv6 address.
//
// Discovery runs once, at startup. Server network configuration is expected
// to be static: the server should start after the host's interfaces and
// routes are configured, and be restarted after host network changes.
// Subnets added later are not excluded until then; list known subnets in
// ExcludedIPv4Subnets to exclude them regardless.

// minAvailableAddresses is the number of assignable client addresses below
// which the excluded subnets are logged as a warning. Each client session
// holds one address until it expires (see SessionIdleExpirySeconds), and a
// server has far fewer sessions than this.
const minAvailableAddresses = 1 << 20

// indexRange is an inclusive range of session indexes.
type indexRange struct {
	first, last int32
}

// excludedIndexes is a sorted list of non-overlapping session index ranges
// which must not be assigned. subnets lists the excluded subnets, for
// logging.
type excludedIndexes struct {
	ranges  []indexRange
	subnets []string
}

// newExcludedIndexes maps subnets to session index ranges. Subnets outside
// privateSubnetIPv4, and subnets not more specific than privateSubnetIPv4,
// such as the tun device's own route or a default route, are ignored.
func newExcludedIndexes(subnets []*net.IPNet) *excludedIndexes {

	privatePrefixLength, _ := privateSubnetIPv4.Mask.Size()

	var ranges []indexRange
	var included []*net.IPNet

	for _, subnet := range subnets {
		if subnet == nil {
			continue
		}
		IP := subnet.IP.To4()
		prefixLength, bits := subnet.Mask.Size()
		if IP == nil || bits != 32 || prefixLength <= privatePrefixLength {
			continue
		}
		if !privateSubnetIPv4.Contains(IP) {
			continue
		}
		network := IP.Mask(subnet.Mask)
		first := int32(network[1])<<16 | int32(network[2])<<8 | int32(network[3])
		last := first + int32(1)<<(32-prefixLength) - 1
		ranges = append(ranges, indexRange{first: first, last: last})
		included = append(included, &net.IPNet{IP: network, Mask: subnet.Mask})
	}

	// For logging, list each subnet once, omitting subnets covered by
	// another listed subnet, such as host addresses within their prefix.
	var names []string
	for i, subnet := range included {
		prefixLength, _ := subnet.Mask.Size()
		covered := false
		for j, other := range included {
			otherPrefixLength, _ := other.Mask.Size()
			if i != j && other.Contains(subnet.IP) &&
				(otherPrefixLength < prefixLength ||
					(otherPrefixLength == prefixLength && j < i)) {
				covered = true
				break
			}
		}
		if !covered {
			names = append(names, subnet.String())
		}
	}

	slices.SortFunc(ranges, func(a, b indexRange) int {
		return int(a.first - b.first)
	})

	merged := ranges[:0]
	for _, r := range ranges {
		if n := len(merged); n > 0 && r.first <= merged[n-1].last+1 {
			merged[n-1].last = max(merged[n-1].last, r.last)
			continue
		}
		merged = append(merged, r)
	}

	slices.Sort(names)

	return &excludedIndexes{ranges: merged, subnets: names}
}

// lastExcluded returns the last index of the excluded range containing
// index, if any.
func (e *excludedIndexes) lastExcluded(index int32) (int32, bool) {
	if e == nil {
		return 0, false
	}
	i, found := slices.BinarySearchFunc(e.ranges, index, func(r indexRange, index int32) int {
		switch {
		case r.last < index:
			return -1
		case r.first > index:
			return 1
		}
		return 0
	})
	if !found {
		return 0, false
	}
	return e.ranges[i].last, true
}

// firstAssignableIndex and lastAssignableIndex bound the indexes that
// allocateIndex may assign; see allocateIndex for the reserved indexes.
const (
	firstAssignableIndex = 3
	lastAssignableIndex  = 0x00FFFFFE
)

// assignableRange returns the part of r that allocateIndex may assign, and
// false if there is none.
func assignableRange(r indexRange) (indexRange, bool) {
	r.first = max(r.first, firstAssignableIndex)
	r.last = min(r.last, lastAssignableIndex)
	return r, r.first <= r.last
}

// available returns the number of indexes that allocateIndex may assign,
// less the excluded indexes.
func (e *excludedIndexes) available() int {
	n := lastAssignableIndex - firstAssignableIndex + 1
	if e == nil {
		return n
	}
	for _, r := range e.ranges {
		if r, ok := assignableRange(r); ok {
			n -= int(r.last-r.first) + 1
		}
	}
	return n
}

// randomIndex returns an index chosen uniformly at random from the indexes
// that allocateIndex may assign, less the excluded indexes. allocateIndex
// starts its search there.
//
// Choosing from all indexes instead would, whenever the choice fell in an
// excluded range, continue the search from the end of that range. With
// most indexes excluded, most searches would then start at the same few
// indexes, sessions would collect there, and each new search would step
// through all of them, until searches ran out of tries.
//
// This costs two passes over the excluded ranges, which are few.
func (e *excludedIndexes) randomIndex() int32 {
	n := e.available()
	if n <= 0 {
		return firstAssignableIndex
	}
	return e.nthAvailable(prng.Intn(n))
}

// nthAvailable returns the nth index, counting from 0, that allocateIndex
// may assign and that isn't excluded. n must be less than available().
func (e *excludedIndexes) nthAvailable(n int) int32 {
	index := int32(firstAssignableIndex + n)
	if e == nil {
		return index
	}
	// Ranges are sorted and don't overlap, so each one that starts at or
	// before index shifts index past it.
	for _, r := range e.ranges {
		r, ok := assignableRange(r)
		if !ok {
			continue
		}
		if r.first > index {
			break
		}
		index += r.last - r.first + 1
	}
	return index
}

func (e *excludedIndexes) contains(index int32) bool {
	_, ok := e.lastExcluded(index)
	return ok
}

func (e *excludedIndexes) String() string {
	if e == nil {
		return ""
	}
	return strings.Join(e.subnets, ",")
}

// ValidateExcludedIPv4Subnet returns an error if subnet can't be used in
// ServerConfig.ExcludedIPv4Subnets: it must be an IPv4 subnet within, and
// more specific than, privateSubnetIPv4, and must not contain the server
// tun device address.
func ValidateExcludedIPv4Subnet(subnet *net.IPNet) error {
	privatePrefixLength, _ := privateSubnetIPv4.Mask.Size()
	prefixLength, bits := subnet.Mask.Size()
	if subnet.IP.To4() == nil || bits != 32 {
		return errors.Tracef("not an IPv4 subnet: %s", subnet)
	}
	if !privateSubnetIPv4.Contains(subnet.IP) ||
		prefixLength <= privatePrefixLength {
		return errors.Tracef(
			"not a smaller subnet within %s: %s", privateSubnetIPv4, subnet)
	}
	serverIP, _, _ := net.ParseCIDR(serverIPv4AddressCIDR)
	if subnet.Contains(serverIP) {
		return errors.Tracef(
			"contains the server tun device address %s: %s", serverIP, subnet)
	}
	return nil
}

// makeExcludedIndexes returns the excluded indexes for
// config.ExcludedIPv4Subnets and, unless config.DisableHostSubnetDiscovery
// is set, the host subnets discovered by getHostIPv4Subnets, and logs the
// excluded subnets.
func makeExcludedIndexes(
	config *ServerConfig, tunDeviceName string) (*excludedIndexes, error) {

	subnets := append([]*net.IPNet(nil), config.ExcludedIPv4Subnets...)

	if !config.DisableHostSubnetDiscovery {
		hostSubnets, err := getHostIPv4Subnets(tunDeviceName)
		if err != nil {
			return nil, errors.Trace(err)
		}
		subnets = append(subnets, hostSubnets...)
	}

	excluded := newExcludedIndexes(subnets)

	availableAddresses := excluded.available()
	logger := config.Logger.WithTraceFields(
		common.LogFields{
			"excludedSubnets":     excluded.String(),
			"availableAddresses":  availableAddresses,
			"hostSubnetDiscovery": !config.DisableHostSubnetDiscovery,
		})
	if availableAddresses < minAvailableAddresses {
		logger.Warning("packet tunnel excluded subnets leave few client addresses")
	} else {
		logger.Info("packet tunnel excluded subnets")
	}

	// The server tun device address, 10.0.0.1, is fixed, so it can't be
	// excluded. When a host subnet contains it, for example when it's the
	// host's default gateway, the host treats 10.0.0.1 as its own address:
	// packets addressed to it stay on the host instead of reaching that
	// subnet. The server logs a warning and continues: a private network
	// with its gateway at 10.0.0.1 is a common default with some providers,
	// and stopping would take down all of the server's protocols. Avoid this
	// host configuration, for example by using a private network outside of
	// privateSubnetIPv4.
	//
	// The transparent DNS address, 10.0.0.2, needs no such check: the server
	// rewrites packets to and from it before they reach the host.
	serverIP, _, _ := net.ParseCIDR(serverIPv4AddressCIDR)
	serverIPv4 := serverIP.To4()
	serverIndex := int32(serverIPv4[1])<<16 | int32(serverIPv4[2])<<8 | int32(serverIPv4[3])
	if excluded.contains(serverIndex) {
		config.Logger.WithTraceFields(
			common.LogFields{
				"excludedSubnets":        excluded.String(),
				"serverTunDeviceAddress": serverIP.String(),
			}).Warning(
			"packet tunnel server tun device address conflicts with host subnet")
	}

	return excluded, nil
}
