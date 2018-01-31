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

// AccumulatedStats holds the Psiphon Server API status request data for a
// given server. To accommodate status requests that may fail, and be retried,
// the TakeOutStatsForServer/PutBackStatsForServer procedure allows the requester
// to check out stats for reporting and merge back stats for a later retry.
type AccumulatedStats struct {
	hostnameToStats map[string]*hostStats
}

// GetStatsForStatusRequest summarizes AccumulatedStats data as
// required for the Psiphon Server API status request.
func (stats AccumulatedStats) GetStatsForStatusRequest() map[string]int64 {

	hostBytes := make(map[string]int64)

	for hostname, hostStats := range stats.hostnameToStats {
		totalBytes := hostStats.numBytesReceived + hostStats.numBytesSent
		hostBytes[hostname] = totalBytes
	}

	return hostBytes
}

// serverStats holds per-server stats.
// accumulatedStats data is payload for the Psiphon status request
// which is accessed via TakeOut/PutBack.
// recentBytes data is for tunnel monitoring which is accessed via
// ReportRecentBytesTransferredForServer.
type serverStats struct {
	accumulatedStats    *AccumulatedStats
	recentBytesSent     int64
	recentBytesReceived int64
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
// collection. recentBytes are not adjusted when isPutBack is true,
// as recentBytes aren't subject to TakeOut/PutBack.
func recordStat(stat *statsUpdate, isRecordingHostBytes, isPutBack bool) {
	allStats.statsMutex.Lock()
	defer allStats.statsMutex.Unlock()

	storedServerStats := allStats.serverIDtoStats[stat.serverID]
	if storedServerStats == nil {
		storedServerStats = &serverStats{
			accumulatedStats: &AccumulatedStats{
				hostnameToStats: make(map[string]*hostStats)}}
		allStats.serverIDtoStats[stat.serverID] = storedServerStats
	}

	if isRecordingHostBytes {

		if stat.hostname == "" {
			stat.hostname = "(OTHER)"
		}

		storedHostStats := storedServerStats.accumulatedStats.hostnameToStats[stat.hostname]
		if storedHostStats == nil {
			storedHostStats = &hostStats{}
			storedServerStats.accumulatedStats.hostnameToStats[stat.hostname] = storedHostStats
		}

		storedHostStats.numBytesSent += stat.numBytesSent
		storedHostStats.numBytesReceived += stat.numBytesReceived
	}

	if !isPutBack {
		storedServerStats.recentBytesSent += stat.numBytesSent
		storedServerStats.recentBytesReceived += stat.numBytesReceived
	}
}

// ReportRecentBytesTransferredForServer returns bytes sent and received since
// the last call to ReportRecentBytesTransferredForServer. The accumulated sent
// and received are reset to 0 by this call.
func ReportRecentBytesTransferredForServer(serverID string) (sent, received int64) {
	allStats.statsMutex.Lock()
	defer allStats.statsMutex.Unlock()

	stats := allStats.serverIDtoStats[serverID]

	if stats == nil {
		return
	}

	sent = stats.recentBytesSent
	received = stats.recentBytesReceived

	stats.recentBytesSent = 0
	stats.recentBytesReceived = 0

	return
}

// TakeOutStatsForServer borrows the AccumulatedStats for the specified
// server. When we fail to report these stats, resubmit them with
// PutBackStatsForServer. Stats will continue to be accumulated between
// TakeOut and PutBack calls. The recentBytes values are unaffected by
// TakeOut/PutBack. Returns empty stats if the serverID is not found.
func TakeOutStatsForServer(serverID string) (accumulatedStats *AccumulatedStats) {
	allStats.statsMutex.Lock()
	defer allStats.statsMutex.Unlock()

	newAccumulatedStats := &AccumulatedStats{
		hostnameToStats: make(map[string]*hostStats)}

	// Note: for an existing serverStats, only the accumulatedStats is
	// affected; the recentBytes fields are not changed.
	serverStats := allStats.serverIDtoStats[serverID]
	if serverStats != nil {
		accumulatedStats = serverStats.accumulatedStats
		serverStats.accumulatedStats = newAccumulatedStats
	} else {
		accumulatedStats = newAccumulatedStats
	}
	return
}

// PutBackStatsForServer re-adds a set of server stats to the collection.
func PutBackStatsForServer(serverID string, accumulatedStats *AccumulatedStats) {
	for hostname, hoststats := range accumulatedStats.hostnameToStats {
		recordStat(
			&statsUpdate{
				serverID:         serverID,
				hostname:         hostname,
				numBytesSent:     hoststats.numBytesSent,
				numBytesReceived: hoststats.numBytesReceived,
			},
			// We can set isRecordingHostBytes to true, regardless of whether there
			// are any regexes, since there will be no host bytes to put back if they
			// are not being recorded.
			true,
			true)
	}
}
