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

package psiphon

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Psiphon-Inc/goarista/monotime"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
)

// SplitTunnelClassifier determines whether a network destination
// should be accessed through a tunnel or accessed directly.
//
// The classifier uses tables of IP address data, routes data,
// to determine if a given IP is to be tunneled or not. If presented
// with a hostname, the classifier performs a tunneled (uncensored)
// DNS request to first determine the IP address for that hostname;
// then a classification is made based on the IP address.
//
// Classification results (both the hostname resolution and the
// following IP address classification) are cached for the duration
// of the DNS record TTL.
//
// Classification is by geographical region (country code). When the
// split tunnel feature is configured to be on, and if the IP
// address is within the user's region, it may be accessed untunneled.
// Otherwise, the IP address must be accessed through a tunnel. The
// user's current region is revealed to a Tunnel via the Psiphon server
// API handshake.
//
// When a Tunnel has a blank region (e.g., when DisableApi is set and
// the tunnel registers without performing a handshake) then no routes
// data is set and all IP addresses are classified as requiring tunneling.
//
// Split tunnel is made on a best effort basis. After the classifier is
// started, but before routes data is available for the given region,
// all IP addresses will be classified as requiring tunneling.
//
// Routes data is fetched asynchronously after Start() is called. Routes
// data is cached in the data store so it need not be downloaded in full
// when fresh data is in the cache.
type SplitTunnelClassifier struct {
	mutex                    sync.RWMutex
	fetchRoutesUrlFormat     string
	routesSignaturePublicKey string
	dnsServerAddress         string
	dnsTunneler              Tunneler
	fetchRoutesWaitGroup     *sync.WaitGroup
	isRoutesSet              bool
	cache                    map[string]*classification
	routes                   networkList
}

type classification struct {
	isUntunneled bool
	expiry       monotime.Time
}

func NewSplitTunnelClassifier(config *Config, tunneler Tunneler) *SplitTunnelClassifier {
	return &SplitTunnelClassifier{
		fetchRoutesUrlFormat:     config.SplitTunnelRoutesUrlFormat,
		routesSignaturePublicKey: config.SplitTunnelRoutesSignaturePublicKey,
		dnsServerAddress:         config.SplitTunnelDnsServer,
		dnsTunneler:              tunneler,
		fetchRoutesWaitGroup:     new(sync.WaitGroup),
		isRoutesSet:              false,
		cache:                    make(map[string]*classification),
	}
}

// Start resets the state of the classifier. In the default state,
// all IP addresses are classified as requiring tunneling. With
// sufficient configuration and region info, this function starts
// a goroutine to asynchronously fetch and install the routes data.
func (classifier *SplitTunnelClassifier) Start(fetchRoutesTunnel *Tunnel) {

	classifier.mutex.Lock()
	defer classifier.mutex.Unlock()

	classifier.isRoutesSet = false

	if classifier.dnsServerAddress == "" ||
		classifier.routesSignaturePublicKey == "" ||
		classifier.fetchRoutesUrlFormat == "" {
		// Split tunnel capability is not configured
		return
	}

	if fetchRoutesTunnel.serverContext == nil {
		// Tunnel has no serverContext
		return
	}

	if fetchRoutesTunnel.serverContext.clientRegion == "" {
		// Split tunnel region is unknown
		return
	}

	classifier.fetchRoutesWaitGroup.Add(1)
	go classifier.setRoutes(fetchRoutesTunnel)
}

// Shutdown waits until the background setRoutes() goroutine is finished.
// There is no explicit shutdown signal sent to setRoutes() -- instead
// we assume that in an overall shutdown situation, the tunnel used for
// network access in setRoutes() is closed and network events won't delay
// the completion of the goroutine.
func (classifier *SplitTunnelClassifier) Shutdown() {
	classifier.mutex.Lock()
	defer classifier.mutex.Unlock()

	if classifier.fetchRoutesWaitGroup != nil {
		classifier.fetchRoutesWaitGroup.Wait()
		classifier.fetchRoutesWaitGroup = nil
		classifier.isRoutesSet = false
	}
}

// IsUntunneled takes a destination hostname or IP address and determines
// if it should be accessed through a tunnel. When a hostname is presented, it
// is first resolved to an IP address which can be matched against the routes data.
// Multiple goroutines may invoke RequiresTunnel simultaneously. Multi-reader
// locks are used in the implementation to enable concurrent access, with no locks
// held during network access.
func (classifier *SplitTunnelClassifier) IsUntunneled(targetAddress string) bool {

	if !classifier.hasRoutes() {
		return false
	}

	classifier.mutex.RLock()
	cachedClassification, ok := classifier.cache[targetAddress]
	classifier.mutex.RUnlock()
	if ok && cachedClassification.expiry.After(monotime.Now()) {
		return cachedClassification.isUntunneled
	}

	ipAddr, ttl, err := tunneledLookupIP(
		classifier.dnsServerAddress, classifier.dnsTunneler, targetAddress)
	if err != nil {
		NoticeAlert("failed to resolve address for split tunnel classification: %s", err)
		return false
	}
	expiry := monotime.Now().Add(ttl)

	isUntunneled := classifier.ipAddressInRoutes(ipAddr)

	// TODO: garbage collect expired items from cache?

	classifier.mutex.Lock()
	classifier.cache[targetAddress] = &classification{isUntunneled, expiry}
	classifier.mutex.Unlock()

	if isUntunneled {
		NoticeUntunneled(targetAddress)
	}

	return isUntunneled
}

// setRoutes is a background routine that fetches routes data and installs it,
// which sets the isRoutesSet flag, indicating that IP addresses may now be classified.
func (classifier *SplitTunnelClassifier) setRoutes(tunnel *Tunnel) {
	defer classifier.fetchRoutesWaitGroup.Done()

	// Note: a possible optimization is to install cached routes
	// before making the request. That would ensure some split
	// tunneling for the duration of the request.

	routesData, err := classifier.getRoutes(tunnel)
	if err != nil {
		NoticeAlert("failed to get split tunnel routes: %s", err)
		return
	}

	err = classifier.installRoutes(routesData)
	if err != nil {
		NoticeAlert("failed to install split tunnel routes: %s", err)
		return
	}

	NoticeSplitTunnelRegion(tunnel.serverContext.clientRegion)
}

// getRoutes makes a web request to download fresh routes data for the
// given region, as indicated by the tunnel. It uses web caching, If-None-Match/ETag,
// to save downloading known routes data repeatedly. If the web request
// fails and cached routes data is present, that cached data is returned.
func (classifier *SplitTunnelClassifier) getRoutes(tunnel *Tunnel) (routesData []byte, err error) {

	url := fmt.Sprintf(classifier.fetchRoutesUrlFormat, tunnel.serverContext.clientRegion)
	request, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, common.ContextError(err)
	}

	etag, err := GetSplitTunnelRoutesETag(tunnel.serverContext.clientRegion)
	if err != nil {
		return nil, common.ContextError(err)
	}
	if etag != "" {
		request.Header.Add("If-None-Match", etag)
	}

	tunneledDialer := func(_, addr string) (conn net.Conn, err error) {
		return tunnel.sshClient.Dial("tcp", addr)
	}
	transport := &http.Transport{
		Dial: tunneledDialer,
		ResponseHeaderTimeout: time.Duration(*tunnel.config.FetchRoutesTimeoutSeconds) * time.Second,
	}
	httpClient := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(*tunnel.config.FetchRoutesTimeoutSeconds) * time.Second,
	}

	// At this time, the largest uncompressed routes data set is ~1MB. For now,
	// the processing pipeline is done all in-memory.

	useCachedRoutes := false

	response, err := httpClient.Do(request)

	if err == nil &&
		(response.StatusCode != http.StatusOK && response.StatusCode != http.StatusNotModified) {
		response.Body.Close()
		err = fmt.Errorf("unexpected response status code: %d", response.StatusCode)
	}
	if err != nil {
		NoticeAlert("failed to request split tunnel routes package: %s", common.ContextError(err))
		useCachedRoutes = true
	}

	if !useCachedRoutes {
		defer response.Body.Close()
		if response.StatusCode == http.StatusNotModified {
			useCachedRoutes = true
		}
	}

	var routesDataPackage []byte
	if !useCachedRoutes {
		routesDataPackage, err = ioutil.ReadAll(response.Body)
		if err != nil {
			NoticeAlert("failed to download split tunnel routes package: %s", common.ContextError(err))
			useCachedRoutes = true
		}
	}

	var encodedRoutesData string
	if !useCachedRoutes {
		encodedRoutesData, err = ReadAuthenticatedDataPackage(
			routesDataPackage, classifier.routesSignaturePublicKey)
		if err != nil {
			NoticeAlert("failed to read split tunnel routes package: %s", common.ContextError(err))
			useCachedRoutes = true
		}
	}

	var compressedRoutesData []byte
	if !useCachedRoutes {
		compressedRoutesData, err = base64.StdEncoding.DecodeString(encodedRoutesData)
		if err != nil {
			NoticeAlert("failed to decode split tunnel routes: %s", common.ContextError(err))
			useCachedRoutes = true
		}
	}

	if !useCachedRoutes {
		zlibReader, err := zlib.NewReader(bytes.NewReader(compressedRoutesData))
		if err == nil {
			routesData, err = ioutil.ReadAll(zlibReader)
			zlibReader.Close()
		}
		if err != nil {
			NoticeAlert("failed to decompress split tunnel routes: %s", common.ContextError(err))
			useCachedRoutes = true
		}
	}

	if !useCachedRoutes {
		etag := response.Header.Get("ETag")
		if etag != "" {
			err := SetSplitTunnelRoutes(tunnel.serverContext.clientRegion, etag, routesData)
			if err != nil {
				NoticeAlert("failed to cache split tunnel routes: %s", common.ContextError(err))
				// Proceed with fetched data, even when we can't cache it
			}
		}
	}

	if useCachedRoutes {
		routesData, err = GetSplitTunnelRoutesData(tunnel.serverContext.clientRegion)
		if err != nil {
			return nil, common.ContextError(err)
		}
		if routesData == nil {
			return nil, common.ContextError(errors.New("no cached routes"))
		}
	}

	return routesData, nil
}

// hasRoutes checks if the classifier has routes installed.
func (classifier *SplitTunnelClassifier) hasRoutes() bool {
	classifier.mutex.RLock()
	defer classifier.mutex.RUnlock()

	return classifier.isRoutesSet
}

// installRoutes parses the raw routes data and creates data structures
// for fast in-memory classification.
func (classifier *SplitTunnelClassifier) installRoutes(routesData []byte) (err error) {
	classifier.mutex.Lock()
	defer classifier.mutex.Unlock()

	classifier.routes, err = NewNetworkList(routesData)
	if err != nil {
		return common.ContextError(err)
	}

	classifier.isRoutesSet = true

	return nil
}

// ipAddressInRoutes searches for a split tunnel candidate IP address in the routes data.
func (classifier *SplitTunnelClassifier) ipAddressInRoutes(ipAddr net.IP) bool {
	classifier.mutex.RLock()
	defer classifier.mutex.RUnlock()

	return classifier.routes.ContainsIpAddress(ipAddr)
}

// networkList is a sorted list of network ranges. It's used to
// lookup candidate IP addresses for split tunnel classification.
// networkList implements Sort.Interface.
type networkList []net.IPNet

// NewNetworkList parses text routes data and produces a networkList
// for fast ContainsIpAddress lookup.
// The input format is expected to be text lines where each line
// is, e.g., "1.2.3.0\t255.255.255.0\n"
func NewNetworkList(routesData []byte) (networkList, error) {

	// Parse text routes data
	var list networkList
	scanner := bufio.NewScanner(bytes.NewReader(routesData))
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		s := strings.Split(scanner.Text(), "\t")
		if len(s) != 2 {
			continue
		}

		ip := parseIPv4(s[0])
		mask := parseIPv4Mask(s[1])
		if ip == nil || mask == nil {
			continue
		}

		list = append(list, net.IPNet{IP: ip.Mask(mask), Mask: mask})
	}
	if len(list) == 0 {
		return nil, common.ContextError(errors.New("Routes data contains no networks"))
	}

	// Sort data for fast lookup
	sort.Sort(list)

	return list, nil
}

func parseIPv4(s string) net.IP {
	ip := net.ParseIP(s)
	if ip == nil {
		return nil
	}
	return ip.To4()
}

func parseIPv4Mask(s string) net.IPMask {
	ip := parseIPv4(s)
	if ip == nil {
		return nil
	}
	mask := net.IPMask(ip)
	if bits, size := mask.Size(); bits == 0 || size == 0 {
		return nil
	}
	return mask
}

// Len implementes Sort.Interface
func (list networkList) Len() int {
	return len(list)
}

// Swap implementes Sort.Interface
func (list networkList) Swap(i, j int) {
	list[i], list[j] = list[j], list[i]
}

// Less implementes Sort.Interface
func (list networkList) Less(i, j int) bool {
	return binary.BigEndian.Uint32(list[i].IP) < binary.BigEndian.Uint32(list[j].IP)
}

// ContainsIpAddress performs a binary search on the networkList to
// find a network containing the candidate IP address.
func (list networkList) ContainsIpAddress(addr net.IP) bool {

	// Search criteria
	//
	// The following conditions are satisfied when address_IP is in the network:
	// 1. address_IP ^ network_mask == network_IP ^ network_mask
	// 2. address_IP >= network_IP.
	// We are also assuming that network ranges do not overlap.
	//
	// For an ascending array of networks, the sort.Search returns the smallest
	// index idx for which condition network_IP > address_IP is satisfied, so we
	// are checking whether or not adrress_IP belongs to the network[idx-1].

	// Edge conditions check
	//
	// idx == 0 means that address_IP is  lesser than the first (smallest) network_IP
	// thus never satisfies search condition 2.
	// idx == array_length means that address_IP is larger than the last (largest)
	// network_IP so we need to check the last element for condition 1.

	addrValue := binary.BigEndian.Uint32(addr.To4())
	index := sort.Search(len(list), func(i int) bool {
		networkValue := binary.BigEndian.Uint32(list[i].IP)
		return networkValue > addrValue
	})
	return index > 0 && list[index-1].IP.Equal(addr.Mask(list[index-1].Mask))
}

// tunneledLookupIP resolves a split tunnel candidate hostname with a tunneled
// DNS request.
func tunneledLookupIP(
	dnsServerAddress string, dnsTunneler Tunneler, host string) (addr net.IP, ttl time.Duration, err error) {

	ipAddr := net.ParseIP(host)
	if ipAddr != nil {
		// maxDuration from golang.org/src/time/time.go
		return ipAddr, time.Duration(1<<63 - 1), nil
	}

	// dnsServerAddress must be an IP address
	ipAddr = net.ParseIP(dnsServerAddress)
	if ipAddr == nil {
		return nil, 0, common.ContextError(errors.New("invalid IP address"))
	}

	// Dial's alwaysTunnel is set to true to ensure this connection
	// is tunneled (also ensures this code path isn't circular).
	// Assumes tunnel dialer conn configures timeouts and interruptibility.

	conn, err := dnsTunneler.Dial(fmt.Sprintf(
		"%s:%d", dnsServerAddress, DNS_PORT), true, nil)
	if err != nil {
		return nil, 0, common.ContextError(err)
	}

	ipAddrs, ttls, err := ResolveIP(host, conn)
	if err != nil {
		return nil, 0, common.ContextError(err)
	}
	if len(ipAddrs) < 1 {
		return nil, 0, common.ContextError(errors.New("no IP address"))
	}

	return ipAddrs[0], ttls[0], nil
}
