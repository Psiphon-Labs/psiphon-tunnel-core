/*
 * Copyright (c) 2020, Psiphon Inc.
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

package server

import (
	"fmt"
	"sync"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/parameters"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/tactics"
	"github.com/golang/groupcache/lru"
)

const (
	TACTICS_CACHE_MAX_ENTRIES = 10000
)

// ServerTacticsParametersCache is a cache of filtered server-side tactics,
// intended to speed-up frequent tactics lookups.
//
// Presently, the cache is targeted at pre-handshake lookups which are both
// the most time critical and have a low tactic cardinality, as only GeoIP
// filter inputs are available.
//
// There is no TTL for cache entries as the cached filtered tactics remain
// valid until the tactics config changes; Flush must be called on tactics
// config hot reloads.
type ServerTacticsParametersCache struct {
	support             *SupportServices
	mutex               sync.Mutex
	tacticsCache        *lru.Cache
	parameterReferences map[string]*parameterReference
	metrics             *serverTacticsParametersCacheMetrics
}

type parameterReference struct {
	params         *parameters.Parameters
	referenceCount int
}

type serverTacticsParametersCacheMetrics struct {
	MaxCacheEntries        int64
	MaxParameterReferences int64
	CacheHitCount          int64
	CacheMissCount         int64
}

// NewServerTacticsParametersCache creates a new ServerTacticsParametersCache.
func NewServerTacticsParametersCache(
	support *SupportServices) *ServerTacticsParametersCache {

	cache := &ServerTacticsParametersCache{
		support:             support,
		tacticsCache:        lru.New(TACTICS_CACHE_MAX_ENTRIES),
		parameterReferences: make(map[string]*parameterReference),
		metrics:             &serverTacticsParametersCacheMetrics{},
	}

	cache.tacticsCache.OnEvicted = cache.onEvicted

	return cache
}

// GetMetrics returns a snapshop of current ServerTacticsParametersCache event
// counters and resets all counters to zero.
func (c *ServerTacticsParametersCache) GetMetrics() LogFields {

	c.mutex.Lock()
	defer c.mutex.Unlock()

	logFields := LogFields{
		"server_tactics_max_cache_entries":        c.metrics.MaxCacheEntries,
		"server_tactics_max_parameter_references": c.metrics.MaxParameterReferences,
		"server_tactics_cache_hit_count":          c.metrics.CacheHitCount,
		"server_tactics_cache_miss_count":         c.metrics.CacheMissCount,
	}

	c.metrics = &serverTacticsParametersCacheMetrics{}

	return logFields
}

// Get returns server-side tactics parameters for the specified GeoIP scope.
// Get is designed to be called before the API handshake and does not filter
// by API parameters. IsNil guards must be used when accessing the returned
// ParametersAccessor.
func (c *ServerTacticsParametersCache) Get(
	geoIPData GeoIPData) (parameters.ParametersAccessor, error) {

	c.mutex.Lock()
	defer c.mutex.Unlock()

	nilAccessor := parameters.MakeNilParametersAccessor()

	key := c.makeKey(geoIPData)

	// Check for cached result.

	if tag, ok := c.tacticsCache.Get(key); ok {
		paramRef, ok := c.parameterReferences[tag.(string)]
		if !ok {
			return nilAccessor, errors.TraceNew("missing parameters")
		}

		c.metrics.CacheHitCount += 1

		// The returned accessor is read-only, and paramRef.params is never
		// modified, so the return value is safe of concurrent use and may be
		// references both while the entry remains in the cache or after it is
		// evicted.

		return paramRef.params.Get(), nil
	}

	c.metrics.CacheMissCount += 1

	// Construct parameters from tactics.

	tactics, tag, err := c.support.TacticsServer.GetTacticsWithTag(
		true, common.GeoIPData(geoIPData), make(common.APIParameters))
	if err != nil {
		return nilAccessor, errors.Trace(err)
	}

	if tactics == nil {
		// This server isn't configured with tactics.
		return nilAccessor, nil
	}

	// Tactics.Probability is ignored for server-side tactics.

	params, err := parameters.NewParameters(nil)
	if err != nil {
		return nilAccessor, errors.Trace(err)
	}
	_, err = params.Set("", false, tactics.Parameters)
	if err != nil {
		return nilAccessor, errors.Trace(err)
	}

	// Update the cache.
	//
	// Two optimizations are used to limit the memory size of the cache:
	//
	// 1. The scope of the GeoIP data cache key is limited to the fields --
	// Country/ISP/ASN/City -- that are present in tactics filters. E.g., if only
	// Country appears in filters, then the key will omit IS, ASN, and City.
	//
	// 2. Two maps are maintained: GeoIP-key -> tactics-tag; and tactics-tag ->
	// parameters. For N keys with the same filtered parameters, the mapped value
	// overhead is N tags and 1 larger parameters data structure.
	//
	// If the cache is full, the LRU entry will be ejected.

	// Update the parameterRefence _before_ calling Add: if Add happens to evict
	// the last other entry referencing the same parameters, this order avoids an
	// unnecessary delete/re-add.

	paramRef, ok := c.parameterReferences[tag]
	if !ok {
		c.parameterReferences[tag] = &parameterReference{
			params:         params,
			referenceCount: 1,
		}
	} else {
		paramRef.referenceCount += 1
	}
	c.tacticsCache.Add(key, tag)

	cacheSize := int64(c.tacticsCache.Len())
	if cacheSize > c.metrics.MaxCacheEntries {
		c.metrics.MaxCacheEntries = cacheSize
	}

	paramRefsSize := int64(len(c.parameterReferences))
	if paramRefsSize > c.metrics.MaxParameterReferences {
		c.metrics.MaxParameterReferences = paramRefsSize
	}

	return params.Get(), nil
}

func (c *ServerTacticsParametersCache) Flush() {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	// onEvicted will clear c.parameterReferences.

	c.tacticsCache.Clear()
}

func (c *ServerTacticsParametersCache) onEvicted(
	key lru.Key, value interface{}) {

	// Cleanup unreferenced parameterReferences. Assumes mutex is held by Get,
	// which calls Add, which may call onEvicted.

	tag := value.(string)

	paramRef, ok := c.parameterReferences[tag]
	if !ok {
		return
	}

	paramRef.referenceCount -= 1
	if paramRef.referenceCount == 0 {
		delete(c.parameterReferences, tag)
	}
}

func (c *ServerTacticsParametersCache) makeKey(geoIPData GeoIPData) string {

	scope := c.support.TacticsServer.GetFilterGeoIPScope(
		common.GeoIPData(geoIPData))

	var region, ISP, ASN, city string

	if scope&tactics.GeoIPScopeRegion != 0 {
		region = geoIPData.Country
	}
	if scope&tactics.GeoIPScopeISP != 0 {
		ISP = geoIPData.ISP
	}
	if scope&tactics.GeoIPScopeASN != 0 {
		ASN = geoIPData.ASN
	}
	if scope&tactics.GeoIPScopeCity != 0 {
		city = geoIPData.City
	}

	return fmt.Sprintf("%s-%s-%s-%s", region, ISP, ASN, city)
}
