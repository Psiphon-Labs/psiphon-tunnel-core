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
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
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

// interfaceAddress returns an interface address with its prefix length, such as
// 10.20.30.40/16, keeping the host bits that ParseCIDR would clear.
func interfaceAddress(IP string, prefixLength int) *net.IPNet {
	return &net.IPNet{
		IP: net.ParseIP(IP).To4(), Mask: net.CIDRMask(prefixLength, 32)}
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
		addresses []*net.IPNet
		want      string
		available int
		checks    []check
	}{
		{
			// Two /16s on other interfaces, plus an interface address with
			// host bits set, within one.
			name:      "two /16 subnets",
			subnets:   []string{"10.20.0.0/16", "10.40.0.0/16"},
			addresses: []*net.IPNet{interfaceAddress("10.20.30.40", 16)},
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
			// Not more specific than 10.0.0.0/8, or outside it, IPv4 in IPv6
			// notation, or nil.
			name: "ignored",
			subnets: []string{
				"10.0.0.0/8", "0.0.0.0/0", "8.0.0.0/6", "192.168.1.0/24",
				"172.16.0.0/12", "fd19:ca83:e6d5:1c44::/64", "::ffff:10.1.0.0/112"},
			addresses: []*net.IPNet{nil},
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
			// Repeated subnets are listed once, and subnets inside a listed
			// subnet are left out, in address order.
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
			excluded := newExcludedIndexes(append(
				mustParseSubnets(t, testCase.subnets...), testCase.addresses...))
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

	// This is a basic check of the result. The random start is checked by
	// TestExclusionsAllocateIndexSpreadsSessions, and skipping an excluded
	// range during the search by TestExclusionsAllocateIndexFull.
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

	// Only 10.200.1.0/24 remains, and every assignment must be inside it.
	// TestExclusionsAllocateIndexFull covers wrapping past the end of the
	// index space.
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

	// A range clipped entirely out by the reserved indexes, such as a host
	// gateway at 10.0.0.1, shifts nothing.
	if got := newExcludedIndexes(mustParseSubnets(t, "10.0.0.1/32")).nthAvailable(0); got != 3 {
		t.Errorf("10.0.0.1/32 excluded: nthAvailable(0): got %d, want 3", got)
	}
}

func TestExclusionsRandomIndexUniform(t *testing.T) {

	// Each of the 256 available indexes is expected 400 times; the standard
	// deviation is about 20. A bound of 125, over 6 standard deviations,
	// fails about once in 10 million runs across all 256.
	excluded := newExcludedIndexes(mustParseSubnets(t, mostlyExcludedSubnets...))
	counts := make(map[int32]int)
	for i := 0; i < 256*400; i++ {
		random := excluded.randomIndex()
		if excluded.contains(random) || random < 3 || random > 0x00FFFFFE {
			t.Fatalf("randomIndex returned %d", random)
		}
		counts[random]++
	}
	if len(counts) != 256 {
		t.Fatalf("randomIndex returned %d distinct indexes, want 256", len(counts))
	}
	for i, count := range counts {
		if count < 275 || count > 525 {
			t.Errorf("index %d returned %d times, want about 400", i, count)
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

func TestExclusionsAllocateIndexEdges(t *testing.T) {

	// Only the first or the last addresses remain. Each is assigned once,
	// and then allocation fails: the search wraps past the end of the
	// address space without assigning the reserved indexes 0-2, for the
	// network address, 10.0.0.1 and 10.0.0.2, or 0x00FFFFFF, the broadcast
	// address.
	for _, testCase := range []struct {
		free      string
		available int
	}{
		{"10.0.0.0/30", 1},
		{"10.255.255.0/24", 255},
	} {
		server := newTestAllocationServer(t, excludeAllBut(t, testCase.free)...)
		for i := 0; i < testCase.available; i++ {
			s := allocateTestSession(t, server, i)
			if s.index < 3 || s.index > 0x00FFFFFE {
				t.Fatalf("%s: assigned reserved index %d", testCase.free, s.index)
			}
		}
		s := &session{sessionID: "session-full", workers: new(sync.WaitGroup)}
		s.lastActivity.Store(int64(monotime.Now()))
		if err := server.allocateIndex(s); err == nil {
			t.Fatalf("%s: allocateIndex: assigned index %d with all assigned",
				testCase.free, s.index)
		}
	}
}

func TestExclusionsAllocateIndexWrap(t *testing.T) {

	// Only 10.0.0.3, the first assignable index, and 10.255.255.0/24
	// remain, and the /24 is all assigned. A search that starts in the /24
	// must wrap past the end of the address space to the first assignable
	// index. The random start is in the /24 in 255 of 256 runs, so 20 runs
	// miss a wrong wrap target with a probability of about 10^-48.
	server := newTestAllocationServer(t, excludeAllBut(t, "10.0.0.3/32", "10.255.255.0/24")...)
	for assigned := index("10.255.255.0"); assigned <= lastAssignableIndex; assigned++ {
		s := &session{sessionID: fmt.Sprintf("assigned-%d", assigned), workers: new(sync.WaitGroup)}
		s.lastActivity.Store(int64(monotime.Now()))
		server.indexToSession.Store(assigned, s)
	}
	for i := 0; i < 20; i++ {
		s := allocateTestSession(t, server, i)
		if s.index != firstAssignableIndex {
			t.Fatalf("allocateIndex: got index %d, want %d", s.index, firstAssignableIndex)
		}
		server.indexToSession.Delete(s.index)
		server.sessionIDToIndex.Delete(s.sessionID)
	}
}

func TestExclusionsAllocateIndexFull(t *testing.T) {

	// Only 10.200.1.0/24 remains. The try limit is about two passes over
	// the available indexes instead of allocateIndexMaxTries. All 256
	// indexes are assigned once, and then allocation fails.
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
	err := server.allocateIndex(s)
	if err == nil || !strings.Contains(err.Error(), "no assignable index") {
		t.Fatalf("allocateIndex: nothing available: got %v", err)
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
		t.Fatalf("listed %d subnets", len(excluded.subnets))
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

// excludeAllBut returns the subnets that cover privateSubnetIPv4 except for
// the free subnets, in address order.
func excludeAllBut(t *testing.T, free ...string) []string {
	freeSubnets := mustParseSubnets(t, free...)
	var cover func(subnet *net.IPNet) []string
	cover = func(subnet *net.IPNet) []string {
		prefixLength, _ := subnet.Mask.Size()
		overlaps := false
		for _, freeSubnet := range freeSubnets {
			freePrefixLength, _ := freeSubnet.Mask.Size()
			if freeSubnet.Contains(subnet.IP) && freePrefixLength <= prefixLength {
				return nil
			}
			if subnet.Contains(freeSubnet.IP) {
				overlaps = true
			}
		}
		if !overlaps {
			return []string{subnet.String()}
		}
		mask := net.CIDRMask(prefixLength+1, 32)
		upper := make(net.IP, 4)
		copy(upper, subnet.IP.To4())
		upper[(prefixLength)/8] |= 0x80 >> (prefixLength % 8)
		return append(
			cover(&net.IPNet{IP: subnet.IP.To4(), Mask: mask}),
			cover(&net.IPNet{IP: upper, Mask: mask})...)
	}
	return cover(privateSubnetIPv4)
}

// recordingLogger records log lines, so that tests can check the level,
// message and fields of each.
type recordingLogger struct {
	mutex   sync.Mutex
	entries []logEntry
}

type logEntry struct {
	level   string
	message string
	fields  common.LogFields
}

func (logger *recordingLogger) WithTrace() common.LogTrace {
	return &recordingTrace{logger: logger}
}

func (logger *recordingLogger) WithTraceFields(fields common.LogFields) common.LogTrace {
	return &recordingTrace{logger: logger, fields: fields}
}

func (logger *recordingLogger) LogMetric(_ string, _ common.LogFields) {
}

func (logger *recordingLogger) IsLogLevelDebug() bool {
	return false
}

type recordingTrace struct {
	logger *recordingLogger
	fields common.LogFields
}

func (trace *recordingTrace) log(level string, args ...interface{}) {
	trace.logger.mutex.Lock()
	defer trace.logger.mutex.Unlock()
	trace.logger.entries = append(trace.logger.entries,
		logEntry{level: level, message: fmt.Sprint(args...), fields: trace.fields})
}

func (trace *recordingTrace) Debug(args ...interface{})   { trace.log("debug", args...) }
func (trace *recordingTrace) Info(args ...interface{})    { trace.log("info", args...) }
func (trace *recordingTrace) Warning(args ...interface{}) { trace.log("warning", args...) }
func (trace *recordingTrace) Error(args ...interface{})   { trace.log("error", args...) }

func TestExclusionsNewServerExcludedIndexes(t *testing.T) {

	summary := func(level string, excludedSubnets string, available int, discovery bool) logEntry {
		message := "packet tunnel excluded subnets"
		if level == "warning" {
			message = "packet tunnel excluded subnets leave few client addresses"
		}
		return logEntry{
			level:   level,
			message: message,
			fields: common.LogFields{
				"excludedSubnets":     excludedSubnets,
				"availableAddresses":  available,
				"hostSubnetDiscovery": discovery,
			},
		}
	}

	privateSubnetWarning := logEntry{
		level:   "warning",
		message: "packet tunnel private subnet is also routed through another interface",
		fields:  common.LogFields{"privateSubnet": "10.0.0.0/8"},
	}

	serverAddressWarning := logEntry{
		level:   "warning",
		message: "packet tunnel server tun device address conflicts with host subnet",
		fields: common.LogFields{
			"excludedSubnets":        "10.0.0.0/24",
			"serverTunDeviceAddress": "10.0.0.1",
		},
	}

	// enough leaves exactly minAvailableAddresses: 10.0.0.0/12 has 2^20 - 3
	// assignable indexes, and 10.255.255.252/30 adds 3. tooFew leaves one
	// fewer. Neither excludes 10.0.0.1.
	enough := excludeAllBut(t, "10.0.0.0/12", "10.255.255.252/30")
	tooFew := excludeAllBut(t, "10.0.0.0/12", "10.255.255.252/31")
	enoughString := strings.Join(enough, ",")
	tooFewString := strings.Join(tooFew, ",")

	testCases := []struct {
		name       string
		configured []string
		discovered []string
		discovery  bool
		available  int
		want       []logEntry
	}{
		{
			name:      "nothing excluded",
			discovery: true,
			available: allAssignable,
			want:      []logEntry{summary("info", "", allAssignable, true)},
		},
		{
			name:       "exactly minAvailableAddresses",
			discovered: enough,
			discovery:  true,
			available:  minAvailableAddresses,
			want: []logEntry{
				summary("info", enoughString, minAvailableAddresses, true)},
		},
		{
			name:       "too few, configured",
			configured: tooFew,
			available:  minAvailableAddresses - 1,
			want: []logEntry{
				summary("warning", tooFewString, minAvailableAddresses-1, false)},
		},
		{
			name:       "too few, discovered",
			discovered: tooFew,
			discovery:  true,
			available:  minAvailableAddresses - 1,
			want: []logEntry{
				summary("warning", tooFewString, minAvailableAddresses-1, true)},
		},
		{
			name:       "too few, combined",
			configured: tooFew[:1],
			discovered: tooFew[1:],
			discovery:  true,
			available:  minAvailableAddresses - 1,
			want: []logEntry{
				summary("warning", tooFewString, minAvailableAddresses-1, true)},
		},
		{
			// The server still starts with nothing left; allocateIndex fails
			// each session. See TestExclusionsAllocateIndexFull.
			name:       "nothing left",
			discovered: []string{"10.0.0.0/9", "10.128.0.0/9"},
			discovery:  true,
			available:  0,
			want: []logEntry{
				{
					level:   "warning",
					message: "packet tunnel server tun device address conflicts with host subnet",
					fields: common.LogFields{
						"excludedSubnets":        "10.0.0.0/9,10.128.0.0/9",
						"serverTunDeviceAddress": "10.0.0.1",
					},
				},
				summary("warning", "10.0.0.0/9,10.128.0.0/9", 0, true),
			},
		},
		{
			// A host route equal to 10.0.0.0/8 excludes nothing.
			name:       "host 10.0.0.0/8",
			discovered: []string{"10.0.0.0/8"},
			discovery:  true,
			available:  allAssignable,
			want: []logEntry{
				privateSubnetWarning,
				summary("info", "", allAssignable, true),
			},
		},
		{
			// A host subnet containing 10.0.0.1, which can't be configured,
			// is still excluded.
			name:       "host subnet containing 10.0.0.1",
			configured: []string{"10.20.0.0/16"},
			discovered: []string{"10.0.0.0/24"},
			discovery:  true,
			available:  allAssignable - 65536 - 253,
			want: []logEntry{
				{
					level:   "warning",
					message: serverAddressWarning.message,
					fields: common.LogFields{
						"excludedSubnets":        "10.0.0.0/24,10.20.0.0/16",
						"serverTunDeviceAddress": "10.0.0.1",
					},
				},
				summary("info", "10.0.0.0/24,10.20.0.0/16", allAssignable-65536-253, true),
			},
		},
		{
			name:       "host subnet containing 10.0.0.1 only",
			discovered: []string{"10.0.0.0/24"},
			discovery:  true,
			available:  allAssignable - 253,
			want: []logEntry{
				serverAddressWarning,
				summary("info", "10.0.0.0/24", allAssignable-253, true),
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			logger := &recordingLogger{}
			excluded := newServerExcludedIndexes(
				logger,
				mustParseSubnets(t, testCase.configured...),
				mustParseSubnets(t, testCase.discovered...),
				testCase.discovery)
			if excluded.available() != testCase.available {
				t.Errorf("available: got %d, want %d",
					excluded.available(), testCase.available)
			}
			if !reflect.DeepEqual(logger.entries, testCase.want) {
				t.Errorf("logs:\n got %+v\nwant %+v", logger.entries, testCase.want)
			}
		})
	}
}

func TestExclusionsMakeExcludedIndexes(t *testing.T) {

	// Discovery is off, so that this test doesn't read the host's routes;
	// see exclusions_linux_test.go.
	makeWith := func(subnets ...*net.IPNet) (*excludedIndexes, error) {
		config := &ServerConfig{
			Logger:                     testutils.NewTestLogger(),
			ExcludedIPv4Subnets:        subnets,
			DisableHostSubnetDiscovery: true,
		}
		return makeExcludedIndexes(config, "tun-does-not-exist")
	}

	excluded, err := makeWith(mustParseSubnets(t, "10.20.0.0/16")...)
	if err != nil {
		t.Fatalf("makeExcludedIndexes: %v", err)
	}
	if !excluded.contains(index("10.20.1.1")) {
		t.Errorf("makeExcludedIndexes: 10.20.0.0/16 not excluded")
	}

}

func TestExclusionsNewServerValidatesSubnets(t *testing.T) {

	// NewServer rejects invalid configured subnets before NewServerDevice,
	// so it returns the ValidateExcludedIPv4Subnet error rather than a
	// device error. Without root, or on platforms without packet tunnel
	// support, NewServerDevice would fail with a different error.
	for _, testCase := range []struct {
		subnet *net.IPNet
		want   string
	}{
		{mustParseSubnets(t, "10.0.0.0/24")[0], "contains the server tun device address"},
		{mustParseSubnets(t, "10.0.0.0/8")[0], "not a smaller subnet"},
		{mustParseSubnets(t, "192.168.1.0/24")[0], "not a smaller subnet"},
		{nil, "missing subnet"},
	} {
		config := &ServerConfig{
			Logger:                     testutils.NewTestLogger(),
			ExcludedIPv4Subnets:        []*net.IPNet{testCase.subnet},
			DisableHostSubnetDiscovery: true,
		}
		_, err := NewServer(config)
		if err == nil || !strings.Contains(err.Error(), testCase.want) {
			t.Errorf("NewServer: %s: got %v, want %q", testCase.subnet, err, testCase.want)
		}
	}
}

func TestExclusionsContainsPrivateSubnetIPv4(t *testing.T) {

	// An interface address with its prefix, as discovery returns it, has
	// host bits set, which ParseCIDR would clear.
	for _, subnet := range []*net.IPNet{
		mustParseSubnets(t, "10.0.0.0/8")[0],
		interfaceAddress("10.1.2.3", 8),
	} {
		if !containsPrivateSubnetIPv4([]*net.IPNet{mustParseSubnets(t, "10.1.0.0/16")[0], subnet}) {
			t.Errorf("%s: not found", subnet)
		}
	}
	for _, cidr := range []string{"10.0.0.0/9", "0.0.0.0/0", "8.0.0.0/6", "11.0.0.0/8", "fd19:ca83:e6d5:1c44::/64"} {
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
	if err := ValidateExcludedIPv4Subnet(nil); err == nil {
		t.Errorf("nil: no error")
	}
}
