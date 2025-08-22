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
	defaultMaxHttpIdleConns    = 100
	defaultHttpIdleConnTimeout = 120 * time.Second
	defaultRequestTimeout      = 30 * time.Second
	defaultRequestRetryCount   = 2

	defaultServerEntryCacheTTL     = 24 * time.Hour
	defaultServerEntryCacheMaxSize = 100000
)

// RelayConfig specifies the configuration for a Relay.
//
// The CACertificates and HostCertificate parameters are used for mutually
// authenticated TLS between the Relay and the DSL backend. The HostID value
// is sent to the DSL backend for logging, and should be populated with the
// HostID in psiphond.config.
type RelayConfig struct {
	Logger common.Logger

	CACertificates  []*x509.Certificate
	HostCertificate *tls.Certificate

	DynamicServerListServiceURL string

	HostID string
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
	config        *RelayConfig
	tlsConfig     *tls.Config
	errorResponse []byte

	mutex                      sync.Mutex
	httpClient                 *http.Client
	requestTimeout             time.Duration
	requestRetryCount          int
	serverEntryCache           *lrucache.Cache
	serverEntryCacheDefaultTTL time.Duration
	serverEntryCacheMaxSize    int
}

// NewRelay creates a new Relay.
func NewRelay(config *RelayConfig) (*Relay, error) {

	certPool := x509.NewCertPool()
	for _, cert := range config.CACertificates {
		certPool.AddCert(cert)
	}

	tlsConfig := &tls.Config{
		RootCAs:      certPool,
		Certificates: []tls.Certificate{*config.HostCertificate},
	}

	// Pre-marshal a generic, non-revealing error code to return on any
	// upstream failure.
	cborErrorResponse, err := protocol.CBOREncoding.Marshal(
		&RelayedResponse{
			Error: 1,
		})
	if err != nil {
		return nil, errors.Trace(err)
	}

	relay := &Relay{
		config:        config,
		tlsConfig:     tlsConfig,
		errorResponse: cborErrorResponse,
	}

	relay.SetRequestParameters(
		defaultMaxHttpConns,
		defaultMaxHttpIdleConns,
		defaultHttpIdleConnTimeout,
		defaultRequestTimeout,
		defaultRequestRetryCount)

	relay.SetCacheParameters(
		defaultServerEntryCacheTTL,
		defaultServerEntryCacheMaxSize)

	return relay, nil
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
	// TODO: don't retain the previous http.Client as long as
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
	defaultTTL time.Duration,
	maxSize int) {

	r.mutex.Lock()
	defer r.mutex.Unlock()

	if r.serverEntryCache == nil ||
		r.serverEntryCacheDefaultTTL != defaultTTL ||
		r.serverEntryCacheMaxSize != maxSize {

		if r.serverEntryCache != nil {
			r.serverEntryCache.Flush()
		}

		r.serverEntryCacheDefaultTTL = defaultTTL
		r.serverEntryCacheMaxSize = maxSize

		r.serverEntryCache = lrucache.NewWithLRU(
			r.serverEntryCacheDefaultTTL,
			1*time.Minute,
			r.serverEntryCacheMaxSize)
	}
}

// HandleRequest relays a DSL request.
//
// On request failure, HandleRequest logs to the provided logger. There's
// always a response to be relayed back to the client.
func (r *Relay) HandleRequest(
	ctx context.Context,
	clientIP string,
	clientGeoIPData common.GeoIPData,
	cborRelayedRequest []byte) []byte {

	response, err := r.handleRequest(
		ctx,
		clientIP,
		clientGeoIPData,
		cborRelayedRequest)
	if err != nil {
		r.config.Logger.WithTraceFields(common.LogFields{
			"error": err.Error(),
		}).Warning("DSL: handle request failed")

		return r.errorResponse
	}

	return response
}

func (r *Relay) handleRequest(
	ctx context.Context,
	clientIP string,
	clientGeoIPData common.GeoIPData,
	cborRelayedRequest []byte) ([]byte, error) {

	r.mutex.Lock()
	httpClient := r.httpClient
	requestTimeout := r.requestTimeout
	requestRetryCount := r.requestRetryCount
	r.mutex.Unlock()

	if httpClient == nil {
		return nil, errors.TraceNew("missing http client")
	}

	if len(cborRelayedRequest) > MaxRelayPayloadSize {
		return nil, errors.Tracef(
			"request size %d exceeds limit %d",
			len(cborRelayedRequest), MaxRelayPayloadSize)
	}

	var relayedRequest *RelayedRequest
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

	// TODO: implement transparent server entry caching.
	//
	// For requestTypeGetServerEntries, peek at the RelayedResponse.Response
	// and extract server entries and add to the local cache, keyed by server
	// entry tag. When the server entry has a specific TTL, use that as the
	// cache TTL, otherwise using serverEntryCacheDefaultTTL.
	//
	// Peek at RelayedRequest.Request, and if all requested server entries are
	// in the cache, serve the request entirely from the local cache.
	// Consider also modifying requests to only fetch server entries that are
	// not cached.
	//
	// Also handle for changes to server entry version.

	requestCtx := ctx
	if requestTimeout > 0 {
		var requestCancelFunc context.CancelFunc
		requestCtx, requestCancelFunc = context.WithTimeout(ctx, requestTimeout)
		defer requestCancelFunc()
	}

	url := fmt.Sprintf("https://%s%s", r.config.DynamicServerListServiceURL, path)

	for i := 0; ; i++ {

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
		httpRequest.Header.Set(PsiphonHostIDHeader, r.config.HostID)

		startTime := time.Now()
		httpResponse, err := r.httpClient.Do(httpRequest)
		duration := time.Since(startTime)

		if err == nil && httpResponse.StatusCode != http.StatusOK {
			httpResponse.Body.Close()
			err = errors.Tracef("unexpected response code: %d", httpResponse.StatusCode)
		}

		var response []byte
		if err == nil {
			response, err = io.ReadAll(httpResponse.Body)
			httpResponse.Body.Close()
		}

		if err != nil {

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

		cborRelayedResponse, err := protocol.CBOREncoding.Marshal(
			&RelayedResponse{
				Response: response,
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
}
