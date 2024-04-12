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

package discovery

import (
	"math/rand"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/server/psinet"
)

// Not safe for concurrent use.
type testClock struct {
	now    time.Time
	update chan time.Time

	sync.RWMutex
}

func NewTestClock(now time.Time) testClock {
	return testClock{
		now:    now,
		update: make(chan time.Time),
	}
}

func (clk *testClock) Now() time.Time {
	clk.RWMutex.RLock()
	defer clk.RWMutex.RUnlock()
	return clk.now
}

func (clk *testClock) Until(t time.Time) time.Duration {
	clk.RWMutex.RLock()
	defer clk.RWMutex.RUnlock()
	return t.Sub(clk.now)

}

func (clk *testClock) After(d time.Duration) <-chan time.Time {
	t := clk.NewTimer(d)
	return t.C()
}

func (clk *testClock) SetNow(now time.Time) {
	clk.RWMutex.Lock()
	clk.now = now
	clk.RWMutex.Unlock()
	select {
	case clk.update <- now:
	default:
	}
}

// Not safe for concurrent use.
func (clk *testClock) NewTimer(d time.Duration) timer {

	clk.RWMutex.RLock()
	start := clk.now
	clk.RWMutex.RUnlock()

	c := make(chan time.Time)
	if d == 0 {
		close(c)
	} else {
		go func() {
			for {
				now := <-clk.update
				if now.Sub(start) >= d {
					close(c)
					break
				}
			}
		}()
	}

	return &testTimer{
		c: c,
	}
}

type testTimer struct {
	c <-chan time.Time
}

func (t *testTimer) C() <-chan time.Time {
	return t.c
}

func (t *testTimer) Stop() bool {
	return true
}

func (t *testTimer) Reset(d time.Duration) bool {
	return false
}

type check struct {
	t      time.Time // time check is performed
	ips    []string  // server IP addresses expected to be discoverable
	subset int       // if non-zero, then expect a subset of ips of this size to be discovered
}

type discoveryTest struct {
	name                 string
	newDiscoveryStrategy func(clk clock) (DiscoveryStrategy, error)
	servers              []*psinet.DiscoveryServer
	checks               []check
}

func runDiscoveryTest(tt *discoveryTest, now time.Time) error {

	if len(tt.servers) == 0 {
		return errors.TraceNew("test requires >=1 discovery servers")
	}

	clk := NewTestClock(now)

	strategy, err := tt.newDiscoveryStrategy(&clk)
	if err != nil {
		return errors.Trace(err)
	}

	discovery := makeDiscovery(&clk, tt.servers, strategy)

	discovery.Start()

	for _, check := range tt.checks {
		time.Sleep(1 * time.Second) // let async code complete
		clk.SetNow(check.t)
		time.Sleep(1 * time.Second) // let async code complete
		discovered := discovery.SelectServers(net.IP{})
		discoveredIPs := make([]string, len(discovered))
		for i := range discovered {
			serverEntry, err := protocol.DecodeServerEntry(discovered[i].EncodedServerEntry, "", "")
			if err != nil {
				return errors.Trace(err)
			}
			discoveredIPs[i] = serverEntry.IpAddress
		}

		matches := 0
		for _, ip := range check.ips {
			if common.Contains(discoveredIPs, ip) {
				matches++
			}
		}

		expectedMatches := len(check.ips)
		if check.subset != 0 {
			expectedMatches = check.subset
		}

		if expectedMatches != matches {
			return errors.Tracef("expected %d of %s to be discovered at %s but discovered servers are %s", expectedMatches, check.ips, check.t, discoveredIPs)
		}
	}

	discovery.Stop()

	return nil
}

func TestDiscoveryTestClock(t *testing.T) {

	now := time.Now()

	serverIPs, err := nRandomIPs(4)
	if err != nil {
		t.Fatalf("nRandomIPs failed %s", err)
	}

	server1 := newDiscoveryServer(
		serverIPs[0].String(),
		[]time.Time{
			now.Add(-1 * time.Second).UTC(),
			now.Add(2 * time.Second).UTC(),
		})
	server2 := newDiscoveryServer(
		serverIPs[1].String(),
		[]time.Time{
			now.Add(3 * time.Second).UTC(),
			now.Add(5 * time.Second).UTC(),
		})
	server3 := newDiscoveryServer(
		serverIPs[2].String(),
		[]time.Time{
			now.Add(5 * time.Second).UTC(),
			now.Add(7 * time.Second).UTC(),
		})
	server4 := newDiscoveryServer(
		serverIPs[3].String(),
		[]time.Time{
			now.Add(5 * time.Second).UTC(),
			now.Add(7 * time.Second).UTC(),
		})

	tests := []discoveryTest{
		{
			name: "classic",
			newDiscoveryStrategy: func(clk clock) (DiscoveryStrategy, error) {
				return newClassicDiscovery("discoveryValueHMACKey", clk)
			},
			servers: []*psinet.DiscoveryServer{
				server1,
				server2,
				server3,
				server4,
			},
			checks: []check{
				{
					t:   now.Add(1 * time.Second),
					ips: []string{server1.IPAddress},
				},
				// discovery end date is noninclusive
				{
					t:   now.Add(2 * time.Second),
					ips: []string{},
				},
				// discovery start date is inclusive
				{
					t:   now.Add(3 * time.Second),
					ips: []string{server2.IPAddress},
				},
				{
					t:   now.Add(4 * time.Second),
					ips: []string{server2.IPAddress},
				},
				{
					t:      now.Add(6 * time.Second),
					ips:    []string{server3.IPAddress, server4.IPAddress},
					subset: 1,
				},
				{
					t:   now.Add(8 * time.Second),
					ips: []string{},
				},
			},
		},
		{
			name: "consistent",
			newDiscoveryStrategy: func(clk clock) (DiscoveryStrategy, error) {
				return newConsistentHashingDiscovery(clk)
			},
			servers: []*psinet.DiscoveryServer{
				server1,
				server2,
				server3,
				server4,
			},
			checks: []check{
				{
					t:   now.Add(1 * time.Second),
					ips: []string{server1.IPAddress},
				},
				// discovery end date is noninclusive
				{
					t:   now.Add(2 * time.Second),
					ips: []string{},
				},
				// discovery start date is inclusive
				{
					t:   now.Add(3 * time.Second),
					ips: []string{server2.IPAddress},
				},
				{
					t:   now.Add(4 * time.Second),
					ips: []string{server2.IPAddress},
				},
				{
					t:      now.Add(6 * time.Second),
					ips:    []string{server3.IPAddress, server4.IPAddress},
					subset: 1,
				},
				{
					t:   now.Add(8 * time.Second),
					ips: []string{},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			err := runDiscoveryTest(&tt, now)
			if err != nil {
				t.Fatalf("runDiscoveryTest failed: %v", err)
			}
		})
	}
}

func newDiscoveryServer(IPAddress string, discoveryDateRange []time.Time) *psinet.DiscoveryServer {

	encoded, err := protocol.EncodeServerEntry(
		&protocol.ServerEntry{
			IpAddress: IPAddress,
		},
	)
	if err != nil {
		panic(err)
	}

	return &psinet.DiscoveryServer{
		EncodedServerEntry: encoded,
		DiscoveryDateRange: discoveryDateRange,
		IPAddress:          IPAddress,
	}
}

// randomIP returns a random IP address.
func randomIP() (net.IP, error) {

	r := make([]byte, 4)
	_, err := rand.Read(r)
	if err != nil {
		return nil, errors.Trace(err)
	}

	return r, nil
}

// nRandomIPs returns numIPs unique random IPs.
func nRandomIPs(numIPs int) ([]net.IP, error) {

	ips := make([]net.IP, numIPs)
	ipsSeen := make(map[string]struct{})

	for i := 0; i < numIPs; i++ {

		for {

			ip, err := randomIP()
			if err != nil {
				return nil, errors.Trace(err)
			}

			if _, ok := ipsSeen[ip.String()]; ok {
				continue
			}

			ipsSeen[ip.String()] = struct{}{}
			ips[i] = ip

			break
		}
	}

	return ips, nil
}
