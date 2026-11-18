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
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/monotime"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/internal/testutils"
)

func mustParseSubnets(t *testing.T, cidrs ...string) []*net.IPNet {
	var subnets []*net.IPNet
	for _, cidr := range cidrs {
		_, subnet, err := net.ParseCIDR(cidr)
		if err != nil {
			t.Fatalf("ParseCIDR(%s): %v", cidr, err)
		}
		subnets = append(subnets, subnet)
	}
	return subnets
}

func index(IP string) int32 {
	ip := net.ParseIP(IP).To4()
	return int32(ip[1])<<16 | int32(ip[2])<<8 | int32(ip[3])
}

// allAssignable is the number of indexes allocateIndex may assign when
// nothing is excluded: 3 to 0x00FFFFFE.
const allAssignable = 0x00FFFFFE - 3 + 1

func TestExclusionsExcludedIndexes(t *testing.T) {

	type check struct {
		IP       string
		excluded bool
		last     string
	}

	testCases := []struct {
		name      string
		subnets   []string
		want      string
		available int
		checks    []check
	}{
		{
			// Two /16s on other interfaces, plus a host address within one.
			name:      "two /16 subnets",
			subnets:   []string{"10.20.0.0/16", "10.40.0.0/16", "10.20.30.40/16"},
			want:      "10.20.0.0/16,10.40.0.0/16",
			available: allAssignable - 2*65536,
			checks: []check{
				{"10.19.255.255", false, ""},
				{"10.20.0.0", true, "10.20.255.255"},
				{"10.20.30.40", true, "10.20.255.255"},
				{"10.21.0.0", false, ""},
				{"10.40.5.6", true, "10.40.255.255"},
			},
		},
		{
			// A /31 to the gateway, plus the gateway as a /32.
			name:      "gateway /31",
			subnets:   []string{"10.30.4.6/31", "10.30.4.6/32"},
			want:      "10.30.4.6/31",
			available: allAssignable - 2,
			checks: []check{
				{"10.30.4.5", false, ""},
				{"10.30.4.6", true, "10.30.4.7"},
				{"10.30.4.7", true, "10.30.4.7"},
				{"10.30.4.8", false, ""},
			},
		},
		{
			// Host subnet contains the server tun device address 10.0.0.1.
			name:      "tun address in host subnet",
			subnets:   []string{"10.0.0.0/23", "10.0.0.1/32"},
			want:      "10.0.0.0/23",
			available: allAssignable - 509,
			checks: []check{
				{"10.0.0.1", true, "10.0.1.255"},
				{"10.0.2.0", false, ""},
			},
		},
		{
			// Not more specific than 10.0.0.0/8, or outside it.
			name: "ignored",
			subnets: []string{
				"10.0.0.0/8", "0.0.0.0/0", "8.0.0.0/6", "192.168.1.0/24",
				"172.16.0.0/12", "fd19:ca83:e6d5:1c44::/64"},
			want:      "",
			available: allAssignable,
			checks: []check{
				{"10.0.0.3", false, ""},
				{"10.255.255.254", false, ""},
			},
		},
		{
			// Overlapping and adjacent subnets merge into one range.
			name:      "merged",
			subnets:   []string{"10.2.0.0/16", "10.1.2.0/24", "10.1.0.0/16"},
			want:      "10.1.0.0/16,10.2.0.0/16",
			available: allAssignable - 2*65536,
			checks: []check{
				{"10.0.255.255", false, ""},
				{"10.1.0.0", true, "10.2.255.255"},
				{"10.2.255.255", true, "10.2.255.255"},
				{"10.3.0.0", false, ""},
			},
		},
		{
			// Repeated subnets, and host addresses, are listed once, in
			// address order.
			name: "repeated",
			subnets: []string{
				"10.5.0.0/16", "10.5.1.2/32", "10.5.0.0/16", "10.5.1.2/32",
				"10.4.0.1/32", "10.4.0.1/32"},
			want:      "10.4.0.1/32,10.5.0.0/16",
			available: allAssignable - 65536 - 1,
			checks: []check{
				{"10.4.0.1", true, "10.4.0.1"},
				{"10.5.1.2", true, "10.5.255.255"},
			},
		},
		{
			// Half of 10.0.0.0/8.
			name:      "half of 10.0.0.0/8",
			subnets:   []string{"10.128.0.0/9"},
			want:      "10.128.0.0/9",
			available: allAssignable - (1<<23 - 1),
			checks: []check{
				{"10.127.255.255", false, ""},
				{"10.128.0.0", true, "10.255.255.255"},
			},
		},
		{
			// Only 10.240.0.0/12 left, fewer than minAvailableAddresses.
			name: "only a /12 available",
			subnets: []string{
				"10.0.0.0/9", "10.128.0.0/10", "10.192.0.0/11", "10.224.0.0/12"},
			want:      "10.0.0.0/9,10.128.0.0/10,10.192.0.0/11,10.224.0.0/12",
			available: 1<<20 - 1,
			checks: []check{
				{"10.239.255.255", true, "10.239.255.255"},
				{"10.240.0.0", false, ""},
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			excluded := newExcludedIndexes(mustParseSubnets(t, testCase.subnets...))
			if excluded.String() != testCase.want {
				t.Errorf("subnets: got %q, want %q", excluded.String(), testCase.want)
			}
			if excluded.available() != testCase.available {
				t.Errorf("available: got %d, want %d",
					excluded.available(), testCase.available)
			}
			for _, c := range testCase.checks {
				last, ok := excluded.lastExcluded(index(c.IP))
				if ok != c.excluded {
					t.Errorf("%s: excluded %v, want %v", c.IP, ok, c.excluded)
					continue
				}
				if ok && last != index(c.last) {
					t.Errorf("%s: last %d, want %d (%s)", c.IP, last, index(c.last), c.last)
				}
			}
		})
	}

	var nilExcluded *excludedIndexes
	if nilExcluded.contains(index("10.1.2.3")) {
		t.Errorf("nil excludedIndexes contains an index")
	}
	if nilExcluded.available() != allAssignable {
		t.Errorf("nil excludedIndexes available: got %d", nilExcluded.available())
	}
}

func newTestAllocationServer(t *testing.T, excludedSubnets ...string) *Server {
	return &Server{
		config:          &ServerConfig{Logger: testutils.NewTestLogger()},
		excludedIndexes: newExcludedIndexes(mustParseSubnets(t, excludedSubnets...)),
	}
}

func allocateTestSession(t *testing.T, server *Server, i int) *session {
	s := &session{
		sessionID: fmt.Sprintf("session-%d", i),
		workers:   new(sync.WaitGroup),
	}
	s.lastActivity.Store(int64(monotime.Now()))
	if err := server.allocateIndex(s); err != nil {
		t.Fatalf("allocateIndex %d: %v", i, err)
	}
	return s
}

func TestExclusionsAllocateIndexSkipsExcludedSubnets(t *testing.T) {

	// Assigned addresses must be outside the excluded subnets, including
	// adjacent /16s and a subnet containing the reserved addresses, and
	// must not be reserved.
	excludedSubnets := []string{"10.20.0.0/16", "10.21.0.0/16", "10.40.0.0/16", "10.0.0.0/23"}
	server := newTestAllocationServer(t, excludedSubnets...)
	excluded := mustParseSubnets(t, excludedSubnets...)

	// About 3/256 of random indexes fall in the excluded /16s, so this
	// would assign dozens of excluded addresses without exclusions.
	for i := 0; i < 3000; i++ {
		s := allocateTestSession(t, server, i)
		for _, subnet := range excluded {
			if subnet.Contains(s.assignedIPv4Address) {
				t.Fatalf("assigned %s in excluded subnet %s", s.assignedIPv4Address, subnet)
			}
		}
		if s.index <= 2 || s.index >= 0x00FFFFFF {
			t.Fatalf("assigned reserved index %d", s.index)
		}
	}
}

func TestExclusionsAllocateIndexMostlyExcluded(t *testing.T) {

	// Only 10.200.1.0/24 remains. Allocation must find it from any starting
	// point, including wrapping past the end of the index space.
	server := newTestAllocationServer(t, mostlyExcludedSubnets...)

	_, free, _ := net.ParseCIDR("10.200.1.0/24")

	for i := 0; i < 200; i++ {
		s := allocateTestSession(t, server, i)
		if !free.Contains(s.assignedIPv4Address) {
			t.Fatalf("assigned %s outside %s", s.assignedIPv4Address, free)
		}
	}
}

// mostlyExcludedSubnets leaves only 10.200.1.0/24 available.
var mostlyExcludedSubnets = []string{
	"10.0.0.0/9", "10.128.0.0/10", "10.192.0.0/13",
	"10.200.0.0/24", "10.200.2.0/23", "10.200.4.0/22", "10.200.8.0/21",
	"10.200.16.0/20", "10.200.32.0/19", "10.200.64.0/18", "10.200.128.0/17",
	"10.201.0.0/16", "10.202.0.0/15", "10.204.0.0/14", "10.208.0.0/12",
	"10.224.0.0/11"}

func TestExclusionsNthAvailable(t *testing.T) {

	var nilExcluded *excludedIndexes
	if got := nilExcluded.nthAvailable(0); got != 3 {
		t.Errorf("nil: first: got %d", got)
	}
	if got := nilExcluded.nthAvailable(allAssignable - 1); got != 0x00FFFFFE {
		t.Errorf("nil: last: got %d", got)
	}

	// Every available index, in order, and nothing else.
	excluded := newExcludedIndexes(mustParseSubnets(t, mostlyExcludedSubnets...))
	if excluded.available() != 256 {
		t.Fatalf("available: got %d", excluded.available())
	}
	for n := 0; n < 256; n++ {
		if got, want := excluded.nthAvailable(n), index("10.200.1.0")+int32(n); got != want {
			t.Fatalf("nthAvailable(%d): got %d, want %d", n, got, want)
		}
	}

	// Ranges at both ends, and one that includes the reserved indexes 0-2.
	excluded = newExcludedIndexes(mustParseSubnets(t,
		"10.0.0.0/23", "10.20.0.0/16", "10.21.0.0/16", "10.255.255.0/24"))
	n := excluded.available()
	checks := []struct {
		n    int
		want string
	}{
		{0, "10.0.2.0"},
		{int(index("10.19.255.255") - index("10.0.2.0")), "10.19.255.255"},
		{int(index("10.19.255.255")-index("10.0.2.0")) + 1, "10.22.0.0"},
		{n - 1, "10.255.254.255"},
	}
	for _, c := range checks {
		if got := excluded.nthAvailable(c.n); got != index(c.want) {
			t.Errorf("nthAvailable(%d): got %d, want %s", c.n, got, c.want)
		}
	}
}

func TestExclusionsRandomIndexUniform(t *testing.T) {

	// Each of the 256 available indexes is expected 400 times; the
	// standard deviation is about 20. A bound of 125, over 6 standard
	// deviations, fails about once in 10 million runs across all 256.
	excluded := newExcludedIndexes(mustParseSubnets(t, mostlyExcludedSubnets...))
	counts := make(map[int32]int)
	for i := 0; i < 256*400; i++ {
		index := excluded.randomIndex()
		if excluded.contains(index) || index < 3 || index > 0x00FFFFFE {
			t.Fatalf("randomIndex returned %d", index)
		}
		counts[index]++
	}
	if len(counts) != 256 {
		t.Fatalf("randomIndex returned %d distinct indexes, want 256", len(counts))
	}
	for index, count := range counts {
		if count < 275 || count > 525 {
			t.Errorf("index %d returned %d times, want about 400", index, count)
		}
	}
}

func TestExclusionsAllocateIndexSpreadsSessions(t *testing.T) {

	// Only 10.240.0.0/12 is available. A search start chosen from all
	// indexes falls in the excluded range 15 times in 16, continuing from
	// 10.240.0.0, so sessions would collect at the start of the available
	// range. Spread evenly, about 8 of 2000 sessions fall in its first
	// 4096 addresses.
	server := newTestAllocationServer(t,
		"10.0.0.0/9", "10.128.0.0/10", "10.192.0.0/11", "10.224.0.0/12")

	first := index("10.240.0.0")
	atStart := 0
	for i := 0; i < 2000; i++ {
		s := allocateTestSession(t, server, i)
		if s.index < first {
			t.Fatalf("assigned excluded index %d", s.index)
		}
		if s.index < first+4096 {
			atStart++
		}
	}
	if atStart > 100 {
		t.Errorf("%d of 2000 sessions in the first 4096 addresses", atStart)
	}
}

func TestExclusionsAllocateIndexFull(t *testing.T) {

	// Only 10.200.1.0/24 remains. All 256 indexes are assigned once, and
	// then allocation fails, after one pass over the available indexes
	// instead of after allocateIndexMaxTries.
	server := newTestAllocationServer(t, mostlyExcludedSubnets...)
	excluded := server.excludedIndexes

	wantMaxTries := 2 * (256 + len(excluded.ranges) + 4)
	if got := excluded.maxAllocateTries(); got != wantMaxTries {
		t.Fatalf("maxAllocateTries: got %d, want %d", got, wantMaxTries)
	}

	sessions := make(map[int32]*session)
	for i := 0; i < 256; i++ {
		s := allocateTestSession(t, server, i)
		if sessions[s.index] != nil {
			t.Fatalf("index %d assigned twice", s.index)
		}
		sessions[s.index] = s
	}

	s := &session{sessionID: "session-full", workers: new(sync.WaitGroup)}
	s.lastActivity.Store(int64(monotime.Now()))
	if err := server.allocateIndex(s); err == nil {
		t.Fatalf("allocateIndex: no error with all indexes assigned")
	}

	// An expired session's index is reaped and assigned again.
	expiredIndex := index("10.200.1.77")
	sessions[expiredIndex].lastActivity.Store(
		int64(monotime.Now().Add(-2 * server.sessionIdleExpiry())))
	if err := server.allocateIndex(s); err != nil {
		t.Fatalf("allocateIndex: with an expired session: %v", err)
	}
	if s.index != expiredIndex {
		t.Errorf("allocateIndex: got index %d, want %d", s.index, expiredIndex)
	}

	// With nothing available, allocation fails without searching.
	server = newTestAllocationServer(t, "10.0.0.0/9", "10.128.0.0/9")
	if server.excludedIndexes.available() != 0 {
		t.Fatalf("available: got %d", server.excludedIndexes.available())
	}
	if err := server.allocateIndex(s); err == nil {
		t.Fatalf("allocateIndex: no error with nothing available")
	}

	// Without exclusions, the limit is unchanged.
	var nilExcluded *excludedIndexes
	if got := nilExcluded.maxAllocateTries(); got != allocateIndexMaxTries {
		t.Errorf("nil: maxAllocateTries: got %d", got)
	}
	if got := newExcludedIndexes(nil).maxAllocateTries(); got != allocateIndexMaxTries {
		t.Errorf("none: maxAllocateTries: got %d", got)
	}
}

func TestExclusionsLoggedSubnets(t *testing.T) {

	// Many host routes are listed up to maxLoggedExcludedSubnets.
	var cidrs []string
	for i := 0; i < 1000; i++ {
		cidrs = append(cidrs, fmt.Sprintf("10.1.%d.%d/32", i/256, i%256))
		cidrs = append(cidrs, fmt.Sprintf("10.1.%d.%d/32", i/256, i%256))
	}
	excluded := newExcludedIndexes(mustParseSubnets(t, cidrs...))
	if len(excluded.subnets) != maxLoggedExcludedSubnets {
		t.Errorf("listed %d subnets", len(excluded.subnets))
	}
	if excluded.subnets[0] != "10.1.0.0/32" || excluded.subnets[1] != "10.1.0.1/32" {
		t.Errorf("listed %v", excluded.subnets[:2])
	}
	want := fmt.Sprintf(" (%d more)", 1000-maxLoggedExcludedSubnets)
	if !strings.HasSuffix(excluded.String(), want) {
		t.Errorf("String: got %q, want suffix %q", excluded.String(), want)
	}
	if excluded.available() != allAssignable-1000 {
		t.Errorf("available: got %d", excluded.available())
	}

	// A subnet covering all of them is listed alone.
	excluded = newExcludedIndexes(mustParseSubnets(t, append(cidrs, "10.1.0.0/16")...))
	if excluded.String() != "10.1.0.0/16" {
		t.Errorf("String: got %q", excluded.String())
	}
}

func TestExclusionsNewServerExcludedIndexes(t *testing.T) {

	logger := testutils.NewTestLogger()

	// A host subnet containing 10.0.0.1, which can't be configured, is
	// logged as a warning, not an error, and is still excluded.
	excluded, err := newServerExcludedIndexes(
		logger,
		mustParseSubnets(t, "10.20.0.0/16"),
		mustParseSubnets(t, "10.0.0.0/24"),
		true)
	if err != nil {
		t.Fatalf("newServerExcludedIndexes: %v", err)
	}
	if !excluded.contains(index("10.0.0.200")) || !excluded.contains(index("10.20.1.1")) {
		t.Errorf("newServerExcludedIndexes: subnets not excluded")
	}

	// A host route equal to 10.0.0.0/8 is logged as a warning, not an
	// error, and excludes nothing.
	excluded, err = newServerExcludedIndexes(
		logger, nil, mustParseSubnets(t, "10.0.0.0/8"), true)
	if err != nil {
		t.Fatalf("newServerExcludedIndexes: %v", err)
	}
	if excluded.available() != allAssignable {
		t.Errorf("newServerExcludedIndexes: available: got %d", excluded.available())
	}

	// Fewer than minAvailableAddresses is an error, whether the subnets
	// are configured or discovered.
	enough := []string{"10.0.0.0/9", "10.128.0.0/10", "10.192.0.0/11", "10.240.0.0/12"}
	tooFew := []string{"10.0.0.0/9", "10.128.0.0/10", "10.192.0.0/11", "10.224.0.0/12"}
	if newExcludedIndexes(mustParseSubnets(t, enough...)).available() != minAvailableAddresses {
		t.Fatalf("enough: not exactly minAvailableAddresses")
	}
	if _, err := newServerExcludedIndexes(
		logger, nil, mustParseSubnets(t, enough...), true); err != nil {
		t.Errorf("newServerExcludedIndexes: enough: %v", err)
	}
	if _, err := newServerExcludedIndexes(
		logger, nil, mustParseSubnets(t, tooFew...), true); err == nil {
		t.Errorf("newServerExcludedIndexes: too few discovered: no error")
	}
	if _, err := newServerExcludedIndexes(
		logger, mustParseSubnets(t, tooFew...), nil, false); err == nil {
		t.Errorf("newServerExcludedIndexes: too few configured: no error")
	}
	if _, err := newServerExcludedIndexes(
		logger, mustParseSubnets(t, "10.0.0.0/9"),
		mustParseSubnets(t, "10.128.0.0/10", "10.192.0.0/11", "10.224.0.0/12"),
		true); err == nil {
		t.Errorf("newServerExcludedIndexes: too few combined: no error")
	}
}

func TestExclusionsMakeExcludedIndexes(t *testing.T) {

	// On Linux, "lo" stands in for the tun device, so host subnet discovery
	// runs too; the test host is not expected to have a subnet that
	// contains 10.0.0.1, or to leave fewer than minAvailableAddresses.
	makeWith := func(subnets ...string) (*excludedIndexes, error) {
		config := &ServerConfig{
			Logger:              testutils.NewTestLogger(),
			ExcludedIPv4Subnets: mustParseSubnets(t, subnets...),
		}
		return makeExcludedIndexes(config, "lo")
	}

	excluded, err := makeWith("10.20.0.0/16")
	if err != nil {
		t.Fatalf("makeExcludedIndexes: %v", err)
	}
	if !excluded.contains(index("10.20.1.1")) {
		t.Errorf("makeExcludedIndexes: 10.20.0.0/16 not excluded")
	}

	// Configured subnets are validated.
	for _, invalid := range []string{"10.0.0.0/24", "10.0.0.0/8", "192.168.1.0/24"} {
		if _, err := makeWith(invalid); err == nil {
			t.Errorf("makeExcludedIndexes: %s: no error", invalid)
		}
	}
}

func TestExclusionsContainsPrivateSubnetIPv4(t *testing.T) {

	for _, cidr := range []string{"10.0.0.0/8", "10.1.2.3/8"} {
		if !containsPrivateSubnetIPv4(mustParseSubnets(t, "10.1.0.0/16", cidr)) {
			t.Errorf("%s: not found", cidr)
		}
	}
	for _, cidr := range []string{"10.0.0.0/9", "0.0.0.0/0", "8.0.0.0/6", "11.0.0.0/8", "fd19:ca83:e6d5:1c44::/8"} {
		if containsPrivateSubnetIPv4(mustParseSubnets(t, cidr)) {
			t.Errorf("%s: found", cidr)
		}
	}
	if containsPrivateSubnetIPv4([]*net.IPNet{nil}) {
		t.Errorf("nil: found")
	}
}

func TestExclusionsValidateExcludedIPv4Subnet(t *testing.T) {

	for _, valid := range []string{"10.20.0.0/16", "10.30.4.6/31", "10.0.1.0/24"} {
		if err := ValidateExcludedIPv4Subnet(mustParseSubnets(t, valid)[0]); err != nil {
			t.Errorf("%s: %v", valid, err)
		}
	}

	invalid := []string{
		"10.0.0.0/8",               // not more specific than 10.0.0.0/8
		"0.0.0.0/0",                // not within 10.0.0.0/8
		"192.168.1.0/24",           // not within 10.0.0.0/8
		"10.0.0.0/24",              // contains the server tun device address
		"10.0.0.1/32",              // the server tun device address
		"fd19:ca83:e6d5:1c44::/64", // not IPv4
		"::ffff:10.1.0.0/112",      // IPv4 in IPv6 notation
	}
	for _, s := range invalid {
		if err := ValidateExcludedIPv4Subnet(mustParseSubnets(t, s)[0]); err == nil {
			t.Errorf("%s: no error", s)
		}
	}
}
