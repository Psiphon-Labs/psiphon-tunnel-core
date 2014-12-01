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

package stats

import (
	"fmt"
	"sync"
)

// TODO: What size should this be?
var _CHANNEL_CAPACITY = 20

type hostnameStats struct {
	numBytesSent     int64
	numBytesReceived int64
}

func newHostnameStats() *hostnameStats {
	return &hostnameStats{}
}

// serverStats holds per-server stats.
// Note that the bytes we're counting are the ones going into the tunnel, so do
// not include transport overhead.
type serverStats struct {
	hostnameToStats map[string]*hostnameStats
}

func newServerStats() *serverStats {
	return &serverStats{
		hostnameToStats: make(map[string]*hostnameStats),
	}
}

var allStats struct {
	serverIDtoStats map[string]*serverStats
	statsMutex      sync.RWMutex
	stopSignal      chan struct{}
	statsChan       chan statsUpdate
}

// Start initializes and begins stats collection. Must be called once, when the
// application starts.
func Start() {
	if allStats.stopSignal != nil {
		return
	}

	allStats.serverIDtoStats = make(map[string]*serverStats)
	allStats.stopSignal = make(chan struct{})
	allStats.statsChan = make(chan statsUpdate, _CHANNEL_CAPACITY)

	go processStats()
}

// Stop ends stats collection. Must be called once, before the application terminates.
func Stop() {
	if allStats.stopSignal != nil {
		close(allStats.stopSignal)
		allStats.stopSignal = nil
	}
}

type statsUpdate struct {
	serverID         string
	hostname         string
	numBytesSent     int
	numBytesReceived int
}

func recordStat(newStat statsUpdate) {
	go func() {
		allStats.statsChan <- newStat
	}()
}

func processStats() {
	for {
		select {
		case stat := <-allStats.statsChan:
			if stat.hostname == "" {
				stat.hostname = "(OTHER)"
			}

			allStats.statsMutex.Lock()

			storedServerStats := allStats.serverIDtoStats[stat.serverID]
			if storedServerStats == nil {
				storedServerStats = newServerStats()
				allStats.serverIDtoStats[stat.serverID] = storedServerStats
			}

			storedHostnameStats := storedServerStats.hostnameToStats[stat.hostname]
			if storedHostnameStats == nil {
				storedHostnameStats = newHostnameStats()
				storedServerStats.hostnameToStats[stat.hostname] = storedHostnameStats
			}

			storedHostnameStats.numBytesSent += int64(stat.numBytesSent)
			storedHostnameStats.numBytesReceived += int64(stat.numBytesReceived)

			fmt.Println(stat.hostname, storedHostnameStats.numBytesSent, storedHostnameStats.numBytesReceived)

			allStats.statsMutex.Unlock()

		default:
			// Note that we only checking the stopSignal in the default case. This is
			// because we don't want the statsChan to fill and block the connections
			// sending to it. The connections have their own signals, so they will
			// stop themselves, we will drain the channel, and then we will stop.
			select {
			case <-allStats.stopSignal:
				fmt.Println("stats processor stopping")
				return
			default:
			}
		}
	}
}
