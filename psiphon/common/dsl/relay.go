/*
 * Copyright (c) 2025, Psiphon Inc.
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

package dsl

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/protocol"
	lrucache "github.com/cognusion/go-cache-lru"
	"github.com/fxamacker/cbor/v2"
)

const (
	defaultMaxHttpConns        = 100
	defaultMaxHttpIdleConns    = 10
	defaultHttpIdleConnTimeout = 120 * time.Second
	defaultRequestTimeout      = 30 * time.Second
	defaultRequestRetryCount   = 1

	defaultServerEntryCacheTTL     = 24 * time.Hour
	defaultServerEntryCacheMaxSize = 250000

	defaultOSLFileSpecCacheTTL     = 24 * time.Hour
	defaultOSLFileSpecCacheMaxSize = 250000
)

// RelayConfig specifies the configuration for a Relay.
//
// The CACertificates and HostCertificate/Key parameters are used for mutually
// authenticated TLS between the Relay and the DSL backend. The HostID value
// is sent to the DSL backend for logging, and should be populated with the
// HostID in psiphond.config.
type RelayConfig struct {
	Logger common.Logger

	CACertificatesFilename  string
	HostCertificateFilename string
	HostKeyFilename         string

	GetServiceAddress func(
		clientGeoIPData common.GeoIPData) (string, error)

	HostID string

	// APIParameterValidator is a callback that validates base API metrics.
	APIParameterValidator common.APIParameterValidator

	// APIParameterValidator is a callback that formats base API metrics.
	APIParameterLogFieldFormatter common.APIParameterLogFieldFormatter
}

// Relay is an intermediary between a DSL client and the DSL backend which
// provides circumvention and blocking resistance. Relays include in-proxy
// brokers, and Psiphon servers. See the "Relay API layer" comment section is
// in api.go for more details.
//
// The Relay maintains a pool of persistent HTTP connections for making
// requests.
//
// The Relay supports transparent caching of server entries, where
// GetServerEntriesRequest requests may be fully or partially served out of
// the local cache.
type Relay struct {
	config *RelayConfig

	caCertificatesFile  common.ReloadableFile
	hostCertificateFile common.ReloadableFile
	hostKeyFile         common.ReloadableFile

	mutex                   sync.Mutex
	tlsSessionCache         tls.ClientSessionCache
	tlsConfig               *tls.Config
	httpClient              *http.Client
	requestTimeout          time.Duration
	requestRetryCount       int
	serverEntryCache        *lrucache.Cache
	serverEntryCacheTTL     time.Duration
	serverEntryCacheMaxSize int
	oslFileSpecCache        *lrucache.Cache
	oslFileSpecCacheTTL     time.Duration
	oslFileSpecCacheMaxSize int

	getServerEntriesBufferPool sync.Pool
	getOSLFileSpecsBufferPool  sync.Pool
}

// NewRelay creates a new Relay.
func NewRelay(config *RelayConfig) (*Relay, error) {

	relay := &Relay{
		config: config,

		caCertificatesFile:  common.NewReloadableFile(config.CACertificatesFilename, false, nil),
		hostCertificateFile: common.NewReloadableFile(config.HostCertificateFilename, false, nil),
		hostKeyFile:         common.NewReloadableFile(config.HostKeyFilename, false, nil),

		tlsSessionCache: tls.NewLRUClientSessionCache(0),
	}

	_, err := relay.Reload()
	if err != nil {
		return nil, errors.Trace(err)
	}

	relay.SetRequestParameters(
		defaultMaxHttpConns,
		defaultMaxHttpIdleConns,
		defaultHttpIdleConnTimeout,
		defaultRequestTimeout,
		defaultRequestRetryCount)

	relay.SetCacheParameters(
		defaultServerEntryCacheTTL,
		defaultServerEntryCacheMaxSize,
		defaultOSLFileSpecCacheTTL,
		defaultOSLFileSpecCacheMaxSize)

	relay.getServerEntriesBufferPool.New = func() any { return []*SourcedServerEntry{} }
	relay.getOSLFileSpecsBufferPool.New = func() any { return []OSLFileSpec{} }

	return relay, nil
}

// Reload reloads the TLS configuration when the file contents have changed.
//
// Reload implements the  common.Reloader interface.
func (r *Relay) Reload() (bool, error) {

	// The common.ReloadableFile.reloadAction callback not used; instead,
	// ReloadableFiles are used to check for changed file contents. When any
	// file has changed, all TLS configuration files are reloaded and the TLS
	// configuration is reinitialized.

	reloadedAny := false

	reloaded, err := r.caCertificatesFile.Reload()
	if err != nil {
		return false, errors.Trace(err)
	}
	reloadedAny = reloadedAny || reloaded

	reloaded, err = r.hostCertificateFile.Reload()
	if err != nil {
		return false, errors.Trace(err)
	}
	reloadedAny = reloadedAny || reloaded

	reloaded, err = r.hostKeyFile.Reload()
	if err != nil {
		return false, errors.Trace(err)
	}
	reloadedAny = reloadedAny || reloaded

	if !reloadedAny {
		return false, nil
	}

	caCertsPEM, err := os.ReadFile(r.config.CACertificatesFilename)
	if err != nil {
		return false, errors.Trace(err)
	}

	caCertificates := x509.NewCertPool()
	if !caCertificates.AppendCertsFromPEM(caCertsPEM) {
		return false, errors.TraceNew("AppendCertsFromPEM failed")
	}

	hostCertificate, err := tls.LoadX509KeyPair(
		r.config.HostCertificateFilename,
		r.config.HostKeyFilename)
	if err != nil {
		return false, errors.Trace(err)
	}

	r.mutex.Lock()
	defer r.mutex.Unlock()

	r.tlsSessionCache = tls.NewLRUClientSessionCache(0)

	r.tlsConfig = &tls.Config{
		RootCAs:      caCertificates,
		Certificates: []tls.Certificate{hostCertificate},

		ClientSessionCache: r.tlsSessionCache,
	}

	if r.httpClient != nil {

		// Replace the http.Client if it exists. See the comment in
		// SetRequestParameters regarding in-flight requests and idle timeout
		// limitations.

		httpTransport := r.httpClient.Transport.(*http.Transport)

		r.httpClient = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig:     r.tlsConfig,
				ForceAttemptHTTP2:   true,
				MaxConnsPerHost:     httpTransport.MaxConnsPerHost,
				MaxIdleConns:        httpTransport.MaxIdleConns,
				MaxIdleConnsPerHost: httpTransport.MaxIdleConnsPerHost,
				IdleConnTimeout:     httpTransport.IdleConnTimeout,
			},
		}
	}

	return true, nil
}

// WillReload implements the common.Reloader interface.
func (r *Relay) WillReload() bool {
	return true
}

// ReloadLogDescription implements the common.Reloader interface.
func (r *Relay) ReloadLogDescription() string {
	return "DSL Relay TLS configuration"
}

// SetRequestParameters updates the HTTP request parameters used for upstream
// requests.
func (r *Relay) SetRequestParameters(
	maxHttpConns int,
	maxHttpIdleConns int,
	httpIdleConnTimeout time.Duration,
	requestTimeout time.Duration,
	requestRetryCount int) {

	r.mutex.Lock()
	defer r.mutex.Unlock()

	r.requestTimeout = requestTimeout
	r.requestRetryCount = requestRetryCount

	// The http.Client client is replaced when the net/http configuration has
	// changed. Any in-flight requests using the previous http.Client will
	// continue until complete and eventually the previous http.Client will
	// be garbage collected.
	//
	// TODO: don't retain the previous http.Client for as long as
	// http.Transport.IdleConnTimeout.

	var httpTransport *http.Transport
	if r.httpClient != nil {
		httpTransport = r.httpClient.Transport.(*http.Transport)
	}

	if r.httpClient == nil ||
		httpTransport.MaxConnsPerHost != maxHttpConns ||
		httpTransport.MaxIdleConns != maxHttpIdleConns ||
		httpTransport.IdleConnTimeout != httpIdleConnTimeout {

		r.httpClient = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig:     r.tlsConfig,
				ForceAttemptHTTP2:   true,
				MaxConnsPerHost:     maxHttpConns,
				MaxIdleConns:        maxHttpIdleConns,
				MaxIdleConnsPerHost: maxHttpIdleConns,
				IdleConnTimeout:     httpIdleConnTimeout,
			},
		}
	}
}

// SetCacheParameters updates the parameters used for transparent server
// entry caching. When the parameters change, any existing cache is flushed
// and replaced.
func (r *Relay) SetCacheParameters(
	serverEntryCacheTTL time.Duration,
	serverEntryCacheMaxSize int,
	oslFileSpecCacheTTL time.Duration,
	oslFileSpecCacheMaxSize int) {

	r.mutex.Lock()
	defer r.mutex.Unlock()

	if r.serverEntryCache == nil ||
		r.serverEntryCacheTTL != serverEntryCacheTTL ||
		r.serverEntryCacheMaxSize != serverEntryCacheMaxSize {

		if r.serverEntryCache != nil {
			r.serverEntryCache.Flush()
		}

		r.serverEntryCacheTTL = serverEntryCacheTTL
		r.serverEntryCacheMaxSize = serverEntryCacheMaxSize

		if r.serverEntryCacheTTL > 0 {

			r.serverEntryCache = lrucache.NewWithLRU(
				r.serverEntryCacheTTL,
				1*time.Minute,
				r.serverEntryCacheMaxSize)

		} else {

			r.serverEntryCache = nil
		}
	}

	if r.oslFileSpecCache == nil ||
		r.oslFileSpecCacheTTL != oslFileSpecCacheTTL ||
		r.oslFileSpecCacheMaxSize != oslFileSpecCacheMaxSize {

		if r.oslFileSpecCache != nil {
			r.oslFileSpecCache.Flush()
		}

		r.oslFileSpecCacheTTL = oslFileSpecCacheTTL
		r.oslFileSpecCacheMaxSize = oslFileSpecCacheMaxSize

		if r.oslFileSpecCacheTTL > 0 {

			r.oslFileSpecCache = lrucache.NewWithLRU(
				r.oslFileSpecCacheTTL,
				1*time.Minute,
				r.oslFileSpecCacheMaxSize)

		} else {

			r.oslFileSpecCache = nil
		}
	}
}

// HandleRequest relays a DSL request.
//
// If an extendTimeout callback is specified, it will be called with the
// expected maximum request timeout, including retries; this callback may be
// used to customize the response timeout for a transport handler.
//
// Set isClientTunneled when the relay uses a connected Psiphon tunnel.
//
// In the case of an error, the caller must log the error and send
// dsl.GenericErrorResponse to the client. This generic error response
// ensures that the client receives a DSL response and doesn't consider the
// DSL FetcherRoundTripper to have failed.
func (r *Relay) HandleRequest(
	ctx context.Context,
	extendTimeout func(time.Duration),
	clientIP string,
	clientGeoIPData common.GeoIPData,
	isClientTunneled bool,
	cborRelayedRequest []byte) ([]byte, error) {

	r.mutex.Lock()
	httpClient := r.httpClient
	requestTimeout := r.requestTimeout
	requestRetryCount := r.requestRetryCount
	r.mutex.Unlock()

	if extendTimeout != nil {
		extendTimeout(requestTimeout * time.Duration(requestRetryCount))
	}

	if httpClient == nil {
		return nil, errors.TraceNew("missing http client")
	}

	if len(cborRelayedRequest) > MaxRelayPayloadSize {
		return nil, errors.Tracef(
			"request size %d exceeds limit %d",
			len(cborRelayedRequest), MaxRelayPayloadSize)
	}

	var relayedRequest RelayedRequest
	err := cbor.Unmarshal(cborRelayedRequest, &relayedRequest)
	if err != nil {
		return nil, errors.Trace(err)
	}

	if relayedRequest.Version != requestVersion {
		return nil, errors.Tracef(
			"unexpected request version %d", relayedRequest.Version)
	}

	path, ok := requestTypeToHTTPPath[relayedRequest.RequestType]
	if !ok {
		return nil, errors.Tracef(
			"unknown request type %d", relayedRequest.RequestType)
	}

	// Transparent caching:
	//
	// For requestTypeGetServerEntries, peek at the RelayedResponse.Response
	// and extract server entries and add to the local cache, keyed by server
	// entry tag.
	//
	// Peek at RelayedRequest.Request, and if all requested server entries are
	// in the cache, serve the request entirely from the local cache.
	//
	// The backend DSL may enforce a limited time interval in which certain
	// server entries can be discovered. This cache doesn't bypass this,
	// since DiscoveryServerEntries isn't cached and always passed through to
	// the DSL backend. Clients must discover the large, random server entry
	// tags via DiscoveryServerEntries within the designated time interval;
	// then clients may download the server entries via GetServerEntries at
	// any time, and this may be cached.
	//
	// Limitation: this cache ignores server entry version and may serve a
	// version that's older that the latest within the cache TTL.
	//
	// - Server entry version changes are assumed to be rare.
	//
	// - The cache will be updated with a new version as soon as
	//   cacheGetServerEntriesResponse sees it.
	//
	// - Use a reasonable TTL such as 24h; cache entry TTLs aren't extended on
	//   hits, so any old version will eventually be removed.
	//
	// - A more complicated scheme is possible: also peek at
	//   DiscoverServerEntriesResponses and, for each tag/version pair, if
	//   the tag is in the cache and the cached entry is an old version,
	//   delete from the cache. This would require unpacking each server entry.
	//
	// Similarly, for requestTypeGetOSLFileSpecs, peek at the
	// RelayedResponse.Response and extract OSL file specs and add to the
	// local cache, keyed by OSL ID; and peek at RelayedRequest.Request, and
	// if all requested OSL file specs are in the cache, serve the request
	// entirely from the local cache.

	var response []byte
	cachedResponse := false

	var serveCachedResponse func([]byte, common.GeoIPData) ([]byte, error)
	var updateCache func([]byte, []byte) error

	switch relayedRequest.RequestType {
	case requestTypeGetServerEntries:
		serveCachedResponse = r.getCachedGetServerEntriesResponse
		updateCache = r.cacheGetServerEntriesResponse
	case requestTypeGetOSLFileSpecs:
		serveCachedResponse = r.getCachedGetOSLFileSpecsResponse
		updateCache = r.cacheGetOSLFileSpecsResponse
	}

	if serveCachedResponse != nil {
		var err error
		response, err = serveCachedResponse(
			relayedRequest.Request, clientGeoIPData)
		if err != nil {
			r.config.Logger.WithTraceFields(common.LogFields{
				"error": err.Error(),
			}).Warning("DSL: serve cached response failed")
			// Proceed with relaying request, even if the failure was due to
			// an error in DecodePackedAPIParameters or APIParameterValidator.
			// This allows the DSL backend to make the authoritative decision
			// and also log all failure cases.
		}
		cachedResponse = err == nil && response != nil
	}

	for i := 0; !cachedResponse; i++ {

		requestCtx := ctx
		if requestTimeout > 0 {
			var requestCancelFunc context.CancelFunc
			requestCtx, requestCancelFunc = context.WithTimeout(ctx, requestTimeout)
			defer requestCancelFunc()
		}

		serviceAddress, err := r.config.GetServiceAddress(clientGeoIPData)
		if err != nil {
			return nil, errors.Trace(err)
		}

		url := fmt.Sprintf("https://%s%s", serviceAddress, path)

		httpRequest, err := http.NewRequestWithContext(
			requestCtx, "POST", url, bytes.NewBuffer(relayedRequest.Request))
		if err != nil {
			return nil, errors.Trace(err)
		}

		// Attach the client IP and GeoIPData. The raw IP may be used, by the
		// DSL backend, in server entry selection logic; the GeoIP data is
		// for stats, and may also be used in server entry selection logic.
		// Sending preresolved GeoIP data saves the DSL backend from needing
		// its own GeoIP resolver, and ensures, for a given client a
		// consistent GeoIP view between the Psiphon server and the DSL backend.

		jsonGeoIPData, err := json.Marshal(clientGeoIPData)
		if err != nil {
			return nil, errors.Trace(err)
		}
		httpRequest.Header.Set(PsiphonClientIPHeader, clientIP)
		httpRequest.Header.Set(PsiphonClientGeoIPDataHeader, string(jsonGeoIPData))
		if isClientTunneled {
			httpRequest.Header.Set(PsiphonClientTunneledHeader, "true")
		} else {
			httpRequest.Header.Set(PsiphonClientTunneledHeader, "false")
		}
		httpRequest.Header.Set(PsiphonHostIDHeader, r.config.HostID)

		startTime := time.Now()
		httpResponse, err := httpClient.Do(httpRequest)
		duration := time.Since(startTime)

		if err == nil && httpResponse.StatusCode != http.StatusOK {
			httpResponse.Body.Close()
			err = errors.Tracef("unexpected response code: %d", httpResponse.StatusCode)
		}

		if err == nil {
			response, err = io.ReadAll(httpResponse.Body)
			httpResponse.Body.Close()
		}

		if err == nil {

			if updateCache != nil {
				err := updateCache(
					relayedRequest.Request, response)
				if err != nil {
					r.config.Logger.WithTraceFields(common.LogFields{
						"error": err.Error(),
					}).Warning("DSL: update cache failed")
					// Proceed with relaying response
				}
			}

			break
		}

		r.config.Logger.WithTraceFields(common.LogFields{
			"duration": duration.String(),
			"error":    err.Error(),
		}).Warning("DSL: service request attempt failed")

		// Retry on network errors.
		if i < requestRetryCount && ctx.Err() == nil {
			continue
		}

		return nil, errors.Tracef("all attempts failed")
	}

	// Compress GetServerEntriesResponse responses.
	//
	// The CBOR-encoded SourcedServerEntry/protocol.PackedServerEntryFields
	// items in GetServerEntriesResponse benefit from compression due to
	// repeating server entry values. Only this response is compressed, as
	// other responses almost completely consist of non-repeating random
	// values.
	//
	// Compression is only added at the relay->client hop, to avoid additonal
	// CPU load on the DSL backend, and avoid relays having to always
	// decompress the backend response in cacheGetServerEntriesResponse.

	compression := common.CompressionNone
	if relayedRequest.RequestType == requestTypeGetServerEntries {
		compression = common.CompressionZlib
	}

	compressedResponse, err := common.Compress(compression, response)
	if err != nil {
		return nil, errors.Trace(err)
	}

	cborRelayedResponse, err := protocol.CBOREncoding.Marshal(
		&RelayedResponse{
			Compression: compression,
			Response:    compressedResponse,
		})
	if err != nil {
		return nil, errors.Trace(err)
	}

	if len(cborRelayedResponse) > MaxRelayPayloadSize {
		return nil, errors.Tracef(
			"response size %d exceeds limit %d",
			len(cborRelayedResponse), MaxRelayPayloadSize)
	}

	return cborRelayedResponse, nil
}

func (r *Relay) cacheGetServerEntriesResponse(
	cborRequest []byte,
	cborResponse []byte) error {

	r.mutex.Lock()
	cache := r.serverEntryCache
	r.mutex.Unlock()

	if cache == nil {
		// Caching is disabled
		return nil
	}

	var request GetServerEntriesRequest
	err := cbor.Unmarshal(cborRequest, &request)
	if err != nil {
		return errors.Trace(err)
	}

	var response GetServerEntriesResponse
	err = cbor.Unmarshal(cborResponse, &response)
	if err != nil {
		return errors.Trace(err)
	}

	if len(request.ServerEntryTags) != len(response.SourcedServerEntries) {
		return errors.TraceNew("unexpected entry count mismatch")
	}

	for i, serverEntryTag := range request.ServerEntryTags {

		if response.SourcedServerEntries[i] != nil {

			// This will update any existing cached copy of the server entry for
			// this tag, in case the server entry version is new. This also
			// extends the cache TTL, since the server entry is fresh.

			cache.Set(
				string(serverEntryTag),
				response.SourcedServerEntries[i],
				lrucache.DefaultExpiration)

		} else {

			// In this case, the DSL backend is indicating that the server
			// entry for the requested tag no longer exists, perhaps due to
			// server pruning since the DiscoverServerEntries request. This
			// is an edge case since DiscoverServerEntries won't return
			// invalid tags and so the "nil" value/state isn't cached.

			cache.Delete(string(serverEntryTag))
		}
	}

	return nil
}

func (r *Relay) getCachedGetServerEntriesResponse(
	cborRequest []byte,
	clientGeoIPData common.GeoIPData) ([]byte, error) {

	r.mutex.Lock()
	cache := r.serverEntryCache
	r.mutex.Unlock()

	if cache == nil {
		// Caching is disabled
		return nil, nil
	}

	var request GetServerEntriesRequest
	err := cbor.Unmarshal(cborRequest, &request)
	if err != nil {
		return nil, errors.Trace(err)
	}

	// Since we anticipate that most server entries will be cached, allocate
	// response slices optimistically. Use buffer pools to mitigate GC churn.
	//
	// TODO: check for sufficient cache entries before allocating these
	// response slices? Would doubling the cache lookups use less resources
	// than unused allocations?

	buffer := r.getServerEntriesBufferPool.Get().([]*SourcedServerEntry)
	size := len(request.ServerEntryTags)
	if cap(buffer) < size {
		buffer = make([]*SourcedServerEntry, size)
	} else {
		buffer = buffer[:size]
	}
	defer func() {
		clear(buffer)
		r.getServerEntriesBufferPool.Put(buffer)
	}()

	var response GetServerEntriesResponse
	response.SourcedServerEntries = buffer

	for i, serverEntryTag := range request.ServerEntryTags {
		cacheEntry, ok := cache.Get(string(serverEntryTag))
		if !ok {

			// The request can't be served from the cache, as some server
			// entry tags aren't present. Fall back to a full request to the
			// DSL backend.
			//
			// As a potential future enhancement, consider partially serving
			// from the cache, after making a DSL request for just the
			// unknown server entries?
			return nil, nil
		}

		// The cached entry's TTL is not extended on a hit.

		response.SourcedServerEntries[i] = cacheEntry.(*SourcedServerEntry)
	}

	cborResponse, err := protocol.CBOREncoding.Marshal(&response)
	if err != nil {
		return nil, errors.Trace(err)
	}

	// Log the request event. Since this request is served from the relay
	// cache, the DSL backend will not see the request and log the event
	// itself. This log should match the DSL log format and can be shipped to
	// the same log aggregator.

	baseParams, err := protocol.DecodePackedAPIParameters(request.BaseAPIParameters)
	if err != nil {
		return nil, errors.Trace(err)
	}

	err = r.config.APIParameterValidator(baseParams)
	if err != nil {
		return nil, errors.Trace(err)
	}

	logFields := r.config.APIParameterLogFieldFormatter("", clientGeoIPData, baseParams)
	logFields["server_entry_tag_count"] = len(response.SourcedServerEntries)
	r.config.Logger.LogMetric("dsl_relay_get_server_entries", logFields)

	return cborResponse, nil
}

func (r *Relay) cacheGetOSLFileSpecsResponse(
	cborRequest []byte,
	cborResponse []byte) error {

	r.mutex.Lock()
	cache := r.oslFileSpecCache
	r.mutex.Unlock()

	if cache == nil {
		// Caching is disabled
		return nil
	}

	var request GetOSLFileSpecsRequest
	err := cbor.Unmarshal(cborRequest, &request)
	if err != nil {
		return errors.Trace(err)
	}

	var response GetOSLFileSpecsResponse
	err = cbor.Unmarshal(cborResponse, &response)
	if err != nil {
		return errors.Trace(err)
	}

	if len(request.OSLIDs) != len(response.OSLFileSpecs) {
		return errors.TraceNew("unexpected spec count mismatch")
	}

	for i, oslID := range request.OSLIDs {

		if response.OSLFileSpecs[i] != nil {

			// This will extend the cache TTL for existing entries.

			cache.Set(
				string(oslID),
				response.OSLFileSpecs[i],
				lrucache.DefaultExpiration)

		} else {

			// In this case, the DSL backend is indicating that the OSL file
			// spec is not longer active or available for distribution.

			cache.Delete(string(oslID))
		}
	}

	return nil
}

func (r *Relay) getCachedGetOSLFileSpecsResponse(
	cborRequest []byte,
	clientGeoIPData common.GeoIPData) ([]byte, error) {

	r.mutex.Lock()
	cache := r.oslFileSpecCache
	r.mutex.Unlock()

	if cache == nil {
		// Caching is disabled
		return nil, nil
	}

	var request GetOSLFileSpecsRequest
	err := cbor.Unmarshal(cborRequest, &request)
	if err != nil {
		return nil, errors.Trace(err)
	}

	// This logic mirrors getCachedGetServerEntriesResponse. See the comments
	// in that function.

	buffer := r.getOSLFileSpecsBufferPool.Get().([]OSLFileSpec)
	size := len(request.OSLIDs)
	if cap(buffer) < size {
		buffer = make([]OSLFileSpec, size)
	} else {
		buffer = buffer[:size]
	}
	defer func() {
		clear(buffer)
		r.getOSLFileSpecsBufferPool.Put(buffer)
	}()

	var response GetOSLFileSpecsResponse
	response.OSLFileSpecs = buffer

	for i, oslID := range request.OSLIDs {
		cacheEntry, ok := cache.Get(string(oslID))
		if !ok {
			return nil, nil
		}

		response.OSLFileSpecs[i] = cacheEntry.(OSLFileSpec)
	}

	cborResponse, err := protocol.CBOREncoding.Marshal(&response)
	if err != nil {
		return nil, errors.Trace(err)
	}

	baseParams, err := protocol.DecodePackedAPIParameters(request.BaseAPIParameters)
	if err != nil {
		return nil, errors.Trace(err)
	}

	err = r.config.APIParameterValidator(baseParams)
	if err != nil {
		return nil, errors.Trace(err)
	}

	logFields := r.config.APIParameterLogFieldFormatter("", clientGeoIPData, baseParams)
	logFields["osl_id_count"] = len(response.OSLFileSpecs)
	r.config.Logger.LogMetric("dsl_relay_get_osl_file_specs", logFields)

	return cborResponse, nil
}

var relayGenericErrorResponse []byte

func init() {

	// Pre-marshal a generic, non-revealing error code to return on any
	// upstream failure.
	cborErrorResponse, err := protocol.CBOREncoding.Marshal(
		&RelayedResponse{
			Error: 1,
		})
	if err != nil {
		panic(err.Error())
	}

	relayGenericErrorResponse = cborErrorResponse
}

func GetRelayGenericErrorResponse() []byte {
	return relayGenericErrorResponse
}
