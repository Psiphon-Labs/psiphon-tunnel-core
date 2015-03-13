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
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"sync"
	"time"
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
}

type classification struct {
	isUntunneled bool
	expiry       time.Time
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

	if fetchRoutesTunnel.session.clientRegion == "" {
		// Split tunnel region is unknown
		return
	}

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
	if ok && cachedClassification.expiry.After(time.Now()) {
		return cachedClassification.isUntunneled
	}

	ipAddr, ttl, err := tunneledLookupIP(
		classifier.dnsServerAddress, classifier.dnsTunneler, targetAddress)
	if err != nil {
		NoticeAlert("failed to resolve address for split tunnel classification: %s", err)
		return false
	}
	expiry := time.Now().Add(ttl)

	isUntunneled := classifier.ipAddressInRoutes(ipAddr)

	// TODO: garbage collect expired items from cache?

	classifier.mutex.Lock()
	classifier.cache[targetAddress] = &classification{isUntunneled, expiry}
	classifier.mutex.Unlock()

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
}

// getRoutes makes a web request to download fresh routes data for the
// given region, as indicated by the tunnel. It uses web caching, If-None-Match/ETag,
// to save downloading known routes data repeatedly. If the web request
// fails and cached routes data is present, that cached data is returned.
func (classifier *SplitTunnelClassifier) getRoutes(tunnel *Tunnel) (routesData []byte, err error) {

	url := fmt.Sprintf(classifier.fetchRoutesUrlFormat, tunnel.session.clientRegion)
	request, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, ContextError(err)
	}

	etag, err := GetSplitTunnelRoutesETag(tunnel.session.clientRegion)
	if err != nil {
		return nil, ContextError(err)
	}
	if etag != "" {
		request.Header.Add("If-None-Match", etag)
	}

	tunneledDialer := func(_, addr string) (conn net.Conn, err error) {
		return tunnel.sshClient.Dial("tcp", addr)
	}
	transport := &http.Transport{
		Dial: tunneledDialer,
		ResponseHeaderTimeout: FETCH_ROUTES_TIMEOUT,
	}
	httpClient := &http.Client{
		Transport: transport,
		Timeout:   FETCH_ROUTES_TIMEOUT,
	}

	// At this time, the largest uncompressed routes data set is ~1MB. For now,
	// the processing pipeline is done all in-memory.

	useCachedRoutes := false

	response, err := httpClient.Do(request)
	if err != nil {
		NoticeAlert("failed to request split tunnel routes package: %s", ContextError(err))
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
			NoticeAlert("failed to download split tunnel routes package: %s", ContextError(err))
			useCachedRoutes = true
		}
	}

	var encodedRoutesData string
	if !useCachedRoutes {
		encodedRoutesData, err = ReadAuthenticatedDataPackage(
			routesDataPackage, classifier.routesSignaturePublicKey)
		if err != nil {
			NoticeAlert("failed to read split tunnel routes package: %s", ContextError(err))
			useCachedRoutes = true
		}
	}

	var compressedRoutesData []byte
	if !useCachedRoutes {
		routesData, err = base64.StdEncoding.DecodeString(encodedRoutesData)
		if err != nil {
			NoticeAlert("failed to decode split tunnel routes: %s", ContextError(err))
			useCachedRoutes = true
		}
	}

	if !useCachedRoutes {
		bytesReader := bytes.NewReader(compressedRoutesData)
		zlibReader, err := zlib.NewReader(bytesReader)
		if err == nil {
			routesData, err = ioutil.ReadAll(zlibReader)
			zlibReader.Close()
		}
		if err != nil {
			NoticeAlert("failed to decompress split tunnel routes: %s", ContextError(err))
			useCachedRoutes = true
		}
	}

	if !useCachedRoutes {
		etag := response.Header.Get("ETag")
		if etag != "" {
			err := SetSplitTunnelRoutes(tunnel.session.clientRegion, etag, routesData)
			if err != nil {
				NoticeAlert("failed to cache split tunnel routes: %s", ContextError(err))
				// Proceed with fetched data, even when we can't cache it
			}
		}
	}

	if useCachedRoutes {
		routesData, err = GetSplitTunnelRoutesData(tunnel.session.clientRegion)
		if err != nil {
			return nil, ContextError(err)
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

	// ***TODO***: implementation

	classifier.isRoutesSet = true

	return nil
}

// ipAddressInRoutes searches for a split tunnel candidate IP address in the routes data.
func (classifier *SplitTunnelClassifier) ipAddressInRoutes(ipAddr net.IP) bool {
	classifier.mutex.RLock()
	defer classifier.mutex.RUnlock()

	// ***TODO***: implementation

	return false
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
		return nil, 0, ContextError(errors.New("invalid IP address"))
	}

	// Dial's alwaysTunnel is set to true to ensure this connection
	// is tunneled (also ensures this code path isn't circular).
	// Assumes tunnel dialer conn configures timeouts and interruptibility.

	conn, err := dnsTunneler.Dial(dnsServerAddress, true, nil)
	if err != nil {
		return nil, 0, ContextError(err)
	}

	ipAddrs, ttls, err := ResolveIP(host, conn)
	if err != nil {
		return nil, 0, ContextError(err)
	}
	if len(ipAddrs) < 1 {
		return nil, 0, ContextError(errors.New("no IP address"))
	}

	return ipAddrs[0], ttls[0], nil
}
