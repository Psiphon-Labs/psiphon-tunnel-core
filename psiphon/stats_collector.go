/*
 * Copyright (c) 2014, Psiphon Inc.
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

package psiphon

import (
	"encoding/base64"
	"encoding/json"
	"sync"
	"time"
)

// TODO: Stats for a server are only removed when they are sent in a status
// update to that server. So if there's an unexpected disconnect from serverA
// and then a reconnect to serverB, the stats for serverA will never get sent
// (unless there's later a reconnect to serverA). That means the stats for
// serverA will never get deleted and the memory won't get freed. This is only
// a small amount of memory (< 1KB, probably), but we should still probably add
// some kind of stale-stats cleanup.

// TODO: What size should this be?
var _CHANNEL_CAPACITY = 20

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
// as well as the mutex to access them, the channel to update them, etc.
var allStats struct {
	serverIDtoStats    map[string]*serverStats
	statsMutex         sync.RWMutex
	stopSignal         chan struct{}
	statsChan          chan []statsUpdate
	processorWaitGroup sync.WaitGroup
}

// Start initializes and begins stats collection. Must be called once, when the
// application starts.
func Stats_Start() {
	if allStats.stopSignal != nil {
		return
	}

	allStats.serverIDtoStats = make(map[string]*serverStats)
	allStats.stopSignal = make(chan struct{})
	allStats.statsChan = make(chan []statsUpdate, _CHANNEL_CAPACITY)

	allStats.processorWaitGroup.Add(1)
	go processStats()
}

// Stop ends stats collection. Must be called once, before the application
// terminates.
func Stats_Stop() {
	if allStats.stopSignal != nil {
		close(allStats.stopSignal)
		allStats.processorWaitGroup.Wait()
		allStats.stopSignal = nil
	}
}

// Instances of statsUpdate will be sent through the connection-to-collector
// channel.
type statsUpdate struct {
	serverID         string
	hostname         string
	numBytesSent     int64
	numBytesReceived int64
}

// recordStats makes sure the given stats update is added to the global collection.
// Guaranteed to not block.
func recordStat(newStat statsUpdate) {
	statSlice := []statsUpdate{newStat}
	// Priority: Don't block connections when updating stats. We can't just
	// write to the statsChan, since that will block if it's full. We could
	// launch a goroutine for each update, but that seems like  unnecessary
	// overhead. So we'll try to write to the channel, and launch a goro if it
	// fails.
	select {
	case allStats.statsChan <- statSlice:
	default:
		go func() {
			allStats.statsChan <- statSlice
		}()
	}
}

// processStats is a goro started by Start() and runs until Stop(). It collects
// stats provided by StatsConn.
func processStats() {
	defer allStats.processorWaitGroup.Done()

	for {
		select {
		case statSlice := <-allStats.statsChan:
			allStats.statsMutex.Lock()

			for _, stat := range statSlice {
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

			allStats.statsMutex.Unlock()

		default:
			// Note that we only checking the stopSignal in the default case. This is
			// because we don't want the statsChan to fill and block the connections
			// sending to it. The connections have their own signals, so they will
			// stop themselves, we will drain the channel, and then we will stop.
			select {
			case <-allStats.stopSignal:
				return
			default:
			}
		}
	}
}

// NextSendPeriod returns the amount of time that should be waited before the
// next time stats are sent.
func NextSendPeriod() (duration time.Duration) {
	defaultStatsSendDuration := 5 * 60 * 1000 // 5 minutes in millis

	// We include a random component to make the stats send less fingerprintable.
	jitter, err := MakeSecureRandomInt(defaultStatsSendDuration)

	// In case of error we're just going to use zero jitter.
	if err != nil {
		Notice(NOTICE_ALERT, "stats.NextSendPeriod: MakeSecureRandomInt failed")
	}

	duration = time.Duration(defaultStatsSendDuration+jitter) * time.Millisecond
	return
}

// Implement the json.Marshaler interface
func (ss serverStats) MarshalJSON() ([]byte, error) {
	out := make(map[string]interface{})

	var padding []byte
	paddingSize, err := MakeSecureRandomInt(256)
	// In case of randomness fail, we're going to proceed with zero padding.
	// TODO: Is this okay?
	if err != nil {
		Notice(NOTICE_ALERT, "stats.serverStats.MarshalJSON: MakeSecureRandomInt failed")
		padding = make([]byte, 0)
	} else {
		padding, err = MakeSecureRandomBytes(paddingSize)
		if err != nil {
			Notice(NOTICE_ALERT, "stats.serverStats.MarshalJSON: MakeSecureRandomBytes failed")
			padding = make([]byte, 0)
		}
	}

	hostBytes := make(map[string]int64)
	bytesTransferred := int64(0)

	for hostname, hostStats := range ss.hostnameToStats {
		totalBytes := hostStats.numBytesReceived + hostStats.numBytesSent
		bytesTransferred += totalBytes
		hostBytes[hostname] = totalBytes
	}

	out["bytes_transferred"] = bytesTransferred
	out["host_bytes"] = hostBytes

	// Print the notice before adding the padding, since it's not interesting
	noticeJSON, _ := json.Marshal(out)
	Notice(NOTICE_INFO, "sending stats: %s %s", noticeJSON, err)

	out["padding"] = base64.StdEncoding.EncodeToString(padding)

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
	statSlice := make([]statsUpdate, 0, len(ss.hostnameToStats))
	for hostname, hoststats := range ss.hostnameToStats {
		statSlice = append(statSlice, statsUpdate{
			serverID:         serverID,
			hostname:         hostname,
			numBytesSent:     hoststats.numBytesSent,
			numBytesReceived: hoststats.numBytesReceived,
		})
	}

	allStats.statsChan <- statSlice
}
