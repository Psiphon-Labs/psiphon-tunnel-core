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
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/parameters"
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
	mutex                sync.RWMutex
	clientParameters     *parameters.ClientParameters
	userAgent            string
	dnsTunneler          Tunneler
	fetchRoutesWaitGroup *sync.WaitGroup
	isRoutesSet          bool
	cache                map[string]*classification
	routes               common.SubnetLookup
}

type classification struct {
	isUntunneled bool
	expiry       time.Time
}

func NewSplitTunnelClassifier(config *Config, tunneler Tunneler) *SplitTunnelClassifier {
	return &SplitTunnelClassifier{
		clientParameters:     config.clientParameters,
		userAgent:            MakePsiphonUserAgent(config),
		dnsTunneler:          tunneler,
		fetchRoutesWaitGroup: new(sync.WaitGroup),
		isRoutesSet:          false,
		cache:                make(map[string]*classification),
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

	p := classifier.clientParameters.Get()
	dnsServerAddress := p.String(parameters.SplitTunnelDNSServer)
	routesSignaturePublicKey := p.String(parameters.SplitTunnelRoutesSignaturePublicKey)
	fetchRoutesUrlFormat := p.String(parameters.SplitTunnelRoutesURLFormat)

	if dnsServerAddress == "" ||
		routesSignaturePublicKey == "" ||
		fetchRoutesUrlFormat == "" {
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

	dnsServerAddress := classifier.clientParameters.Get().String(
		parameters.SplitTunnelDNSServer)
	if dnsServerAddress == "" {
		// Split tunnel has been disabled.
		return false
	}

	classifier.mutex.RLock()
	cachedClassification, ok := classifier.cache[targetAddress]
	classifier.mutex.RUnlock()
	if ok && cachedClassification.expiry.After(time.Now()) {
		return cachedClassification.isUntunneled
	}

	ipAddr, ttl, err := tunneledLookupIP(
		dnsServerAddress, classifier.dnsTunneler, targetAddress)
	if err != nil {
		NoticeWarning("failed to resolve address for split tunnel classification: %s", err)
		return false
	}
	expiry := time.Now().Add(ttl)

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
		NoticeWarning("failed to get split tunnel routes: %s", err)
		return
	}

	err = classifier.installRoutes(routesData)
	if err != nil {
		NoticeWarning("failed to install split tunnel routes: %s", err)
		return
	}

	NoticeSplitTunnelRegion(tunnel.serverContext.clientRegion)
}

// getRoutes makes a web request to download fresh routes data for the
// given region, as indicated by the tunnel. It uses web caching, If-None-Match/ETag,
// to save downloading known routes data repeatedly. If the web request
// fails and cached routes data is present, that cached data is returned.
func (classifier *SplitTunnelClassifier) getRoutes(tunnel *Tunnel) (routesData []byte, err error) {

	p := classifier.clientParameters.Get()
	routesSignaturePublicKey := p.String(parameters.SplitTunnelRoutesSignaturePublicKey)
	fetchRoutesUrlFormat := p.String(parameters.SplitTunnelRoutesURLFormat)
	fetchTimeout := p.Duration(parameters.FetchSplitTunnelRoutesTimeout)
	p.Close()

	url := fmt.Sprintf(fetchRoutesUrlFormat, tunnel.serverContext.clientRegion)
	request, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, errors.Trace(err)
	}

	request.Header.Set("User-Agent", classifier.userAgent)

	etag, err := GetSplitTunnelRoutesETag(tunnel.serverContext.clientRegion)
	if err != nil {
		return nil, errors.Trace(err)
	}
	if etag != "" {
		request.Header.Add("If-None-Match", etag)
	}

	tunneledDialer := func(_, addr string) (conn net.Conn, err error) {
		return tunnel.sshClient.Dial("tcp", addr)
	}
	transport := &http.Transport{
		Dial:                  tunneledDialer,
		ResponseHeaderTimeout: fetchTimeout,
	}
	httpClient := &http.Client{
		Transport: transport,
		Timeout:   fetchTimeout,
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
		NoticeWarning("failed to request split tunnel routes package: %s", errors.Trace(err))
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
			NoticeWarning("failed to download split tunnel routes package: %s", errors.Trace(err))
			useCachedRoutes = true
		}
	}

	var encodedRoutesData string
	if !useCachedRoutes {
		encodedRoutesData, err = common.ReadAuthenticatedDataPackage(
			routesDataPackage, false, routesSignaturePublicKey)
		if err != nil {
			NoticeWarning("failed to read split tunnel routes package: %s", errors.Trace(err))
			useCachedRoutes = true
		}
	}

	var compressedRoutesData []byte
	if !useCachedRoutes {
		compressedRoutesData, err = base64.StdEncoding.DecodeString(encodedRoutesData)
		if err != nil {
			NoticeWarning("failed to decode split tunnel routes: %s", errors.Trace(err))
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
			NoticeWarning("failed to decompress split tunnel routes: %s", errors.Trace(err))
			useCachedRoutes = true
		}
	}

	if !useCachedRoutes {
		etag := response.Header.Get("ETag")
		if etag != "" {
			err := SetSplitTunnelRoutes(tunnel.serverContext.clientRegion, etag, routesData)
			if err != nil {
				NoticeWarning("failed to cache split tunnel routes: %s", errors.Trace(err))
				// Proceed with fetched data, even when we can't cache it
			}
		}
	}

	if useCachedRoutes {
		routesData, err = GetSplitTunnelRoutesData(tunnel.serverContext.clientRegion)
		if err != nil {
			return nil, errors.Trace(err)
		}
		if routesData == nil {
			return nil, errors.TraceNew("no cached routes")
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

	classifier.routes, err = common.NewSubnetLookupFromRoutes(routesData)
	if err != nil {
		return errors.Trace(err)
	}

	classifier.isRoutesSet = true

	return nil
}

// ipAddressInRoutes searches for a split tunnel candidate IP address in the routes data.
func (classifier *SplitTunnelClassifier) ipAddressInRoutes(ipAddr net.IP) bool {
	classifier.mutex.RLock()
	defer classifier.mutex.RUnlock()

	return classifier.routes.ContainsIPAddress(ipAddr)
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
		return nil, 0, errors.TraceNew("invalid IP address")
	}

	// Dial's alwaysTunnel is set to true to ensure this connection
	// is tunneled (also ensures this code path isn't circular).
	// Assumes tunnel dialer conn configures timeouts and interruptibility.

	conn, err := dnsTunneler.Dial(fmt.Sprintf(
		"%s:%d", dnsServerAddress, DNS_PORT), true, nil)
	if err != nil {
		return nil, 0, errors.Trace(err)
	}

	ipAddrs, ttls, err := ResolveIP(host, conn)
	if err != nil {
		return nil, 0, errors.Trace(err)
	}
	if len(ipAddrs) < 1 {
		return nil, 0, errors.TraceNew("no IP address")
	}

	return ipAddrs[0], ttls[0], nil
}
