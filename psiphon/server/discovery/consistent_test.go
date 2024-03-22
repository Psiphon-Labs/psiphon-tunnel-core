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
	"strconv"
	"testing"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/server/psinet"
)

func TestConsistentHashingDiscovery(t *testing.T) {

	serverIPs, err := nRandomIPs(100)
	if err != nil {
		t.Fatalf("nRandomIPs failed %s", err)
	}

	servers := make([]*psinet.DiscoveryServer, len(serverIPs))
	for i := 0; i < len(servers); i++ {
		servers[i] = newDiscoveryServer(strconv.Itoa(i), []time.Time{{}, time.Now().Add(1 * time.Hour)})
	}

	c, err := NewConsistentHashingDiscovery()
	if err != nil {
		t.Fatalf("newConsistentHashingDiscovery failed %s", err)
	}
	c.serversChanged(servers)

	// For a single IP address value, only one server in a set of discovery
	// servers should be discoverable.

	discoveredServers := make(map[string]bool)

	clientIP, err := randomIP()
	if err != nil {
		t.Fatalf("randomIP failed %s", err)
	}

	for i := 0; i < 1000; i++ {
		for _, server := range c.selectServers(clientIP) {
			discoveredServers[server.EncodedServerEntry] = true
		}
	}

	if len(discoveredServers) != 1 {
		t.Fatalf("expected to discover 1 server but discovered %d", len(discoveredServers))
	}
}
