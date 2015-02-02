/*
 * Copyright (c) 2015, Psiphon Inc.
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

package transferstats

import (
	"encoding/json"
	"sync"
)

// TODO: Stats for a server are only removed when they are sent in a status
// update to that server. So if there's an unexpected disconnect from serverA
// and then a reconnect to serverB, the stats for serverA will never get sent
// (unless there's later a reconnect to serverA). That means the stats for
// serverA will never get deleted and the memory won't get freed. This is only
// a small amount of memory (< 1KB, probably), but we should still probably add
// some kind of stale-stats cleanup.

// Per-host/domain stats.
// Note that the bytes we're counting are the ones going into the tunnel, so do
// not include transport overhead.
type hostStats struct {
	numBytesSent     int64
	numBytesReceived int64
}

func newHostStats() *hostStats {
	return &hostStats{}
}

// serverStats holds per-server stats.
type serverStats struct {
	hostnameToStats map[string]*hostStats
}

func newServerStats() *serverStats {
	return &serverStats{
		hostnameToStats: make(map[string]*hostStats),
	}
}

// allStats is the root object that holds stats for all servers and all hosts,
// as well as the mutex to access them.
var allStats = struct {
	statsMutex      sync.RWMutex
	serverIDtoStats map[string]*serverStats
}{serverIDtoStats: make(map[string]*serverStats)}

// statsUpdate contains new stats counts to be aggregated.
type statsUpdate struct {
	serverID         string
	hostname         string
	numBytesSent     int64
	numBytesReceived int64
}

// recordStats makes sure the given stats update is added to the global
// collection. Guaranteed to not block.
// Callers of this function should assume that it "takes control" of the
// statsUpdate object.
func recordStat(stat *statsUpdate) {
	allStats.statsMutex.Lock()
	defer allStats.statsMutex.Unlock()

	if stat.hostname == "" {
		stat.hostname = "(OTHER)"
	}

	storedServerStats := allStats.serverIDtoStats[stat.serverID]
	if storedServerStats == nil {
		storedServerStats = newServerStats()
		allStats.serverIDtoStats[stat.serverID] = storedServerStats
	}

	storedHostStats := storedServerStats.hostnameToStats[stat.hostname]
	if storedHostStats == nil {
		storedHostStats = newHostStats()
		storedServerStats.hostnameToStats[stat.hostname] = storedHostStats
	}

	storedHostStats.numBytesSent += stat.numBytesSent
	storedHostStats.numBytesReceived += stat.numBytesReceived

	//fmt.Println("server:", stat.serverID, "host:", stat.hostname, "sent:", storedHostStats.numBytesSent, "received:", storedHostStats.numBytesReceived)
}

// Implement the json.Marshaler interface
func (ss serverStats) MarshalJSON() ([]byte, error) {
	out := make(map[string]interface{})

	hostBytes := make(map[string]int64)
	bytesTransferred := int64(0)

	for hostname, hostStats := range ss.hostnameToStats {
		totalBytes := hostStats.numBytesReceived + hostStats.numBytesSent
		bytesTransferred += totalBytes
		hostBytes[hostname] = totalBytes
	}

	out["bytes_transferred"] = bytesTransferred
	out["host_bytes"] = hostBytes

	// We're not using these fields, but the server requires them
	out["page_views"] = make([]string, 0)
	out["https_requests"] = make([]string, 0)

	return json.Marshal(out)
}

// GetForServer returns the json-able stats package for the given server.
// If there are no stats, nil will be returned.
func GetForServer(serverID string) (payload *serverStats) {
	allStats.statsMutex.Lock()
	defer allStats.statsMutex.Unlock()

	payload = allStats.serverIDtoStats[serverID]
	delete(allStats.serverIDtoStats, serverID)
	return
}

// PutBack re-adds a set of server stats to the collection.
func PutBack(serverID string, ss *serverStats) {
	for hostname, hoststats := range ss.hostnameToStats {
		recordStat(
			&statsUpdate{
				serverID:         serverID,
				hostname:         hostname,
				numBytesSent:     hoststats.numBytesSent,
				numBytesReceived: hoststats.numBytesReceived,
			})
	}
}
