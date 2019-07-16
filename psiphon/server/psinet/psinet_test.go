/*
 * Copyright (c) 2017, Psiphon Inc.
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

package psinet

import (
	"strconv"
	"testing"
	"time"
)

func TestDiscoveryBuckets(t *testing.T) {

	checkBuckets := func(buckets [][]*DiscoveryServer, expectedServerEntries [][]int) {
		if len(buckets) != len(expectedServerEntries) {
			t.Errorf(
				"unexpected bucket count: got %d expected %d",
				len(buckets), len(expectedServerEntries))
			return
		}
		for i := 0; i < len(buckets); i++ {
			if len(buckets[i]) != len(expectedServerEntries[i]) {
				t.Errorf(
					"unexpected bucket %d size: got %d expected %d",
					i, len(buckets[i]), len(expectedServerEntries[i]))
				return
			}
			for j := 0; j < len(buckets[i]); j++ {
				expectedServerEntry := strconv.Itoa(expectedServerEntries[i][j])
				if buckets[i][j].EncodedServerEntry != expectedServerEntry {
					t.Errorf(
						"unexpected bucket %d item %d: got %s expected %s",
						i, j, buckets[i][j].EncodedServerEntry, expectedServerEntry)
					return
				}
			}
		}
	}

	// Partition test cases from:
	// http://stackoverflow.com/questions/2659900/python-slicing-a-list-into-n-nearly-equal-length-partitions

	servers := make([]*DiscoveryServer, 0)
	for i := 0; i < 105; i++ {
		servers = append(servers, &DiscoveryServer{EncodedServerEntry: strconv.Itoa(i)})
	}

	t.Run("5 servers, 5 buckets", func(t *testing.T) {
		checkBuckets(
			bucketizeServerList(servers[0:5], 5),
			[][]int{{0}, {1}, {2}, {3}, {4}})
	})

	t.Run("5 servers, 2 buckets", func(t *testing.T) {
		checkBuckets(
			bucketizeServerList(servers[0:5], 2),
			[][]int{{0, 1, 2}, {3, 4}})
	})

	t.Run("5 servers, 3 buckets", func(t *testing.T) {
		checkBuckets(
			bucketizeServerList(servers[0:5], 3),
			[][]int{{0, 1}, {2}, {3, 4}})
	})

	t.Run("105 servers, 10 buckets", func(t *testing.T) {
		checkBuckets(
			bucketizeServerList(servers, 10),
			[][]int{
				{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
				{11, 12, 13, 14, 15, 16, 17, 18, 19, 20},
				{21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31},
				{32, 33, 34, 35, 36, 37, 38, 39, 40, 41},
				{42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52},
				{53, 54, 55, 56, 57, 58, 59, 60, 61, 62},
				{63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73},
				{74, 75, 76, 77, 78, 79, 80, 81, 82, 83},
				{84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94},
				{95, 96, 97, 98, 99, 100, 101, 102, 103, 104},
			})
	})

	t.Run("repeatedly discover with fixed IP address", func(t *testing.T) {

		// For a IP address values, only one bucket should be used; with enough
		// iterations, all and only the items in a single bucket should be discovered.

		discoveredServers := make(map[string]bool)

		// discoveryValue is derived from the client's IP address and indexes the bucket;
		// a value of 0 always maps to the first bucket.
		discoveryValue := 0

		for i := 0; i < 1000; i++ {
			for _, server := range selectServers(servers, i*int(time.Hour/time.Second), discoveryValue) {
				discoveredServers[server.EncodedServerEntry] = true
			}
		}

		bucketCount := calculateBucketCount(len(servers))

		buckets := bucketizeServerList(servers, bucketCount)

		if len(buckets[0]) != len(discoveredServers) {
			t.Errorf(
				"unexpected discovered server count: got %d expected %d",
				len(discoveredServers), len(buckets[0]))
			return
		}

		for _, bucketServer := range buckets[0] {
			if _, ok := discoveredServers[bucketServer.EncodedServerEntry]; !ok {
				t.Errorf("unexpected missing discovery server: %s", bucketServer.EncodedServerEntry)
				return
			}
		}
	})

}
