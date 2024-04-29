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

// Package discovery implements the Psiphon discovery algorithms.
package discovery

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/server/psinet"
)

// clock is an interface of functions required by discovery that exist in
// the time package in the Go standard library, which enables using
// implementations in tests that do not rely on the monotonic clock or wall
// clock.
type clock interface {
	Now() time.Time
	Until(t time.Time) time.Duration
	After(d time.Duration) <-chan time.Time
	NewTimer(d time.Duration) timer
}

// realClock implements clock using the time package in the Go standard library.
type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

func (realClock) Until(t time.Time) time.Duration { return time.Until(t) }

func (realClock) After(d time.Duration) <-chan time.Time { return time.After(d) }

func (realClock) NewTimer(d time.Duration) timer { return &realTimer{t: time.NewTimer(d)} }

// timer is an interface matching what Timer in the time package provides in
// the Go standard library, which enables using implementations in tests that
// do not rely on the monotonic clock or wall clock.
type timer interface {
	C() <-chan time.Time
	Stop() bool
	Reset(d time.Duration) bool
}

// realTimer implements timer using the time package in the Go standard library.
type realTimer struct {
	t *time.Timer
}

func (t *realTimer) C() <-chan time.Time {
	return t.t.C
}

func (t *realTimer) Stop() bool {
	return t.t.Stop()
}

func (t *realTimer) Reset(d time.Duration) bool {
	return t.t.Reset(d)
}

// DiscoveryStrategy represents a discovery algorithm that selects server
// entries to be "discovered" by a client. Implementations must be safe for
// concurrent usage.
type DiscoveryStrategy interface {
	// selectServers selects discovery servers to give out to the client based
	// on its IP address and, possibly, other strategies that are internal to
	// the discovery strategy implementation.
	selectServers(clientIP net.IP) []*psinet.DiscoveryServer
	// serversChanged is called with the set of currently discoverable servers
	// whever that set changes. The discovery strategy implementation must
	// replace its set of discoverable servers with these servers.
	serversChanged(servers []*psinet.DiscoveryServer)
}

// Discovery is the combination of a discovery strategy with a set of discovery
// servers. It's safe for concurrent usage.
type Discovery struct {
	clk        clock
	all        []*psinet.DiscoveryServer
	strategy   DiscoveryStrategy
	cancelFunc context.CancelFunc
	wg         *sync.WaitGroup
}

// MakeDiscovery creates a new Discovery instance, which uses the specified
// strategy with the given discovery servers.
func MakeDiscovery(
	servers []*psinet.DiscoveryServer,
	strategy DiscoveryStrategy) *Discovery {

	return makeDiscovery(realClock{}, servers, strategy)
}

func makeDiscovery(
	clk clock,
	servers []*psinet.DiscoveryServer,
	strategy DiscoveryStrategy) *Discovery {

	d := Discovery{
		clk:      clk,
		all:      servers,
		strategy: strategy,
		wg:       new(sync.WaitGroup),
	}

	return &d
}

// Start starts discovery. Servers are discoverable when the current time
// falls within their discovery date range, i.e. DiscoveryDateRange[0] <=
// clk.Now() < DiscoveryDateRange[1].
func (d *Discovery) Start() {

	current, nextUpdate := discoverableServers(d.all, d.clk)

	d.strategy.serversChanged(current)

	ctx, cancelFunc := context.WithCancel(context.Background())
	d.cancelFunc = cancelFunc
	d.wg.Add(1)

	// Update the set of discovery servers used by the chosen discovery
	// algorithm, and therefore discoverable with SelectServers, everytime a
	// server enters, or exits, its discovery date range.
	go func() {
		for ctx.Err() == nil {
			// Wait until the next time a server enters, or exits, its
			// discovery date range.
			//
			// Warning: NewTimer uses the monotonic clock but discovery uses
			// the wall clock. If there is wall clock drift, then it is
			// possible that the wall clock surpasses nextUpdate or, more
			// generally, by the wall clock time the set of discoverable
			// servers should change before the timer fires. This scenario is
			// not handled. One solution would be to periodically check if set
			// of discoverable servers has changed in conjunction with using a
			// timer.
			t := d.clk.NewTimer(d.clk.Until(nextUpdate))

			select {
			case <-t.C():
			case <-ctx.Done():
				t.Stop()
				continue
			}
			t.Stop()

			// Note: servers with a discovery date range in the past are not
			// removed from d.all in case the wall clock has drifted;
			// otherwise, we risk removing them prematurely.
			servers, nextUpdate := discoverableServers(d.all, d.clk)

			// Update the set of discoverable servers.
			d.strategy.serversChanged(servers)

			if nextUpdate == (time.Time{}) {
				// The discovery date range of all candidate discovery servers
				// are in the past. No more serversChanged calls will be made
				// to DiscoveryStrategy.
				//
				// Warning: at this point if the wall clock has drifted but
				// will correct itself in the future such that the set of
				// discoverable servers changes, then serversChanged will
				// not be called on the discovery strategies with the new set
				// of discoverable servers. One workaround for this scenario
				// would be to periodically check if set of discoverable
				// servers has changed after this point and restart this loop
				// if they have.
				break
			}
		}
		d.wg.Done()
	}()
}

// Stop stops discovery and cleans up underlying resources. Stop should be
// invoked as soon as Discovery is no longer needed. Discovery should not be
// used after this because the set of discoverable servers will no longer be
// updated, so it may contain servers that are no longer discoverable and
// exclude servers that are.
func (d *Discovery) Stop() {
	d.cancelFunc()
	d.wg.Wait()
}

// SelectServers selects new server entries to be "discovered" by the client,
// using the client's IP address as the input into the configured discovery
// algorithm.
func (d *Discovery) SelectServers(clientIP net.IP) []*psinet.DiscoveryServer {
	return d.strategy.selectServers(clientIP)
}

// discoverableServers returns all servers in discoveryServers that are currently
// eligible for discovery along with the next time that a server in
// discoveryServers will enter, or exit, its discovery date range.
func discoverableServers(
	discoveryServers []*psinet.DiscoveryServer,
	clk clock) (discoverableServers []*psinet.DiscoveryServer, nextUpdate time.Time) {

	now := clk.Now().UTC()
	discoverableServers = make([]*psinet.DiscoveryServer, 0)

	var nextServerAdd time.Time
	var nextServerRemove time.Time

	for _, server := range discoveryServers {
		if len(server.DiscoveryDateRange) == 2 {
			if now.Before(server.DiscoveryDateRange[0]) {
				// Next server that will enter its discovery date range.
				if nextServerAdd == (time.Time{}) || server.DiscoveryDateRange[0].Before(nextServerAdd) {
					nextServerAdd = server.DiscoveryDateRange[0]
				}
			} else if now.Before(server.DiscoveryDateRange[1]) {
				discoverableServers = append(discoverableServers, server)

				// Next server that will exit its discovery date range.
				if nextServerRemove == (time.Time{}) || server.DiscoveryDateRange[1].Before(nextServerRemove) {
					nextServerRemove = server.DiscoveryDateRange[1]
				}
			}
		}
	}

	// The next time the set of servers eligible for discovery changes is
	// whichever occurs first: the next time a server enters its discovery
	// discovery date range or the next time a server exits its discovery
	// date range.
	nextUpdate = nextServerAdd
	if nextServerAdd == (time.Time{}) ||
		(nextServerRemove.Before(nextServerAdd) && nextServerRemove != (time.Time{})) {
		nextUpdate = nextServerRemove
	}

	return discoverableServers, nextUpdate
}
