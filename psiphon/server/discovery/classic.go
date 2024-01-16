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
	"crypto/hmac"
	"crypto/sha256"
	"math"
	"net"
	"sync"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/server/psinet"
)

type classicDiscovery struct {
	clk                   clock
	buckets               [][]*psinet.DiscoveryServer
	discoveryValueHMACKey string

	sync.RWMutex
}

func NewClassicDiscovery(discoveryValueHMACKey string, clk clock) (*classicDiscovery, error) {
	return &classicDiscovery{
		clk:                   clk,
		discoveryValueHMACKey: discoveryValueHMACKey,
	}, nil
}

func (c *classicDiscovery) serversChanged(servers []*psinet.DiscoveryServer) {

	var buckets [][]*psinet.DiscoveryServer
	if len(servers) != 0 {
		// Divide servers into buckets. The bucket count is chosen such that the number
		// of buckets and the number of items in each bucket are close (using sqrt).
		// IP address selects the bucket, time selects the item in the bucket.
		bucketCount := calculateBucketCount(len(servers))
		buckets = bucketizeServerList(servers, bucketCount)
	}
	c.RWMutex.Lock()
	c.buckets = buckets
	c.RWMutex.Unlock()
}

func calculateDiscoveryValue(discoveryValueHMACKey string, ipAddress net.IP) int {
	// From: psi_ops_discovery.calculate_ip_address_strategy_value:
	//     # Mix bits from all octets of the client IP address to determine the
	//     # bucket. An HMAC is used to prevent pre-calculation of buckets for IPs.
	//     return ord(hmac.new(HMAC_KEY, ip_address, hashlib.sha256).digest()[0])
	// TODO: use 3-octet algorithm?
	hash := hmac.New(sha256.New, []byte(discoveryValueHMACKey))
	hash.Write([]byte(ipAddress.String()))
	return int(hash.Sum(nil)[0])
}

func (c *classicDiscovery) selectServers(clientIP net.IP) []*psinet.DiscoveryServer {
	discoveryValue := calculateDiscoveryValue(c.discoveryValueHMACKey, clientIP)
	return c.discoverServers(discoveryValue)
}

// discoverServers selects new encoded server entries to be "discovered" by
// the client, using the discoveryValue -- a function of the client's IP
// address -- as the input into the discovery algorithm.
func (c *classicDiscovery) discoverServers(discoveryValue int) []*psinet.DiscoveryServer {

	discoveryDate := c.clk.Now().UTC()

	c.RWMutex.RLock()
	buckets := c.buckets
	c.RWMutex.RUnlock()

	if len(buckets) == 0 {
		return nil
	}

	timeInSeconds := int(discoveryDate.Unix())
	servers := selectServers(buckets, timeInSeconds, discoveryValue)

	return servers
}

// Combine client IP address and time-of-day strategies to give out different
// discovery servers to different clients. The aim is to achieve defense against
// enumerability. We also want to achieve a degree of load balancing clients
// and these strategies are expected to have reasonably random distribution,
// even for a cluster of users coming from the same network.
//
// We only select one server: multiple results makes enumeration easier; the
// strategies have a built-in load balancing effect; and date range discoverability
// means a client will actually learn more servers later even if they happen to
// always pick the same result at this point.
//
// This is a blended strategy: as long as there are enough servers to pick from,
// both aspects determine which server is selected. IP address is given the
// priority: if there are only a couple of servers, for example, IP address alone
// determines the outcome.
func selectServers(
	buckets [][]*psinet.DiscoveryServer, timeInSeconds, discoveryValue int) []*psinet.DiscoveryServer {

	TIME_GRANULARITY := 3600

	// Time truncated to an hour
	timeStrategyValue := timeInSeconds / TIME_GRANULARITY

	// NOTE: this code assumes that the range of possible timeStrategyValues
	// and discoveryValues are sufficient to index to all bucket items.

	if len(buckets) == 0 {
		return nil
	}

	bucket := buckets[discoveryValue%len(buckets)]

	if len(bucket) == 0 {
		return nil
	}

	// TODO: consider checking that server is in its discover window
	server := bucket[timeStrategyValue%len(bucket)]

	serverList := make([]*psinet.DiscoveryServer, 1)
	serverList[0] = server

	return serverList
}

// Number of buckets such that first strategy picks among about the same number
// of choices as the second strategy. Gives an edge to the "outer" strategy.
func calculateBucketCount(length int) int {
	return int(math.Ceil(math.Sqrt(float64(length))))
}

// bucketizeServerList creates nearly equal sized slices of the input list.
func bucketizeServerList(servers []*psinet.DiscoveryServer, bucketCount int) [][]*psinet.DiscoveryServer {

	// This code creates the same partitions as legacy servers:
	// https://github.com/Psiphon-Inc/psiphon-automation/blob/685f91a85bcdb33a75a200d936eadcb0686eadd7/Automation/psi_ops_discovery.py
	//
	// Both use the same algorithm from:
	// http://stackoverflow.com/questions/2659900/python-slicing-a-list-into-n-nearly-equal-length-partitions

	buckets := make([][]*psinet.DiscoveryServer, bucketCount)

	division := float64(len(servers)) / float64(bucketCount)

	for i := 0; i < bucketCount; i++ {
		start := int((division * float64(i)) + 0.5)
		end := int((division * (float64(i) + 1)) + 0.5)
		buckets[i] = servers[start:end]
	}

	return buckets
}
