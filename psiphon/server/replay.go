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
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/errors"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/parameters"
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	lrucache "github.com/cognusion/go-cache-lru"
)

const (
	REPLAY_CACHE_MAX_ENTRIES      = 100000
	REPLAY_CACHE_CLEANUP_INTERVAL = 1 * time.Minute
)

// ReplayCache is a cache of recently used and successful network obfuscation
// parameters that may be replayed -- reused -- for subsequent tunnel
// connections.
//
// Server-side replay is analogous to client-side replay, with one key
// difference: server-side replay can be applied across multiple clients in
// the same GeoIP scope.
//
// Replay is enabled with tactics, and tactics determine the tunnel quality
// targets for establishing and clearing replay parameters.
//
// ReplayCache has a maximum capacity with an LRU strategy to cap memory
// overhead.
type ReplayCache struct {
	support    *SupportServices
	cacheMutex sync.Mutex
	cache      *lrucache.Cache
	metrics    *replayCacheMetrics
}

type replayCacheMetrics struct {
	MaxCacheEntries    int64
	SetReplayCount     int64
	GetReplayHitCount  int64
	GetReplayMissCount int64
	FailedReplayCount  int64
	DeleteReplayCount  int64
}

type replayParameters struct {
	replayPacketManipulation   bool
	packetManipulationSpecName string
	replayFragmentor           bool
	fragmentorSeed             *prng.Seed
	failedCount                int
}

// NewReplayCache creates a new ReplayCache.
func NewReplayCache(support *SupportServices) *ReplayCache {
	return &ReplayCache{
		support: support,
		cache: lrucache.NewWithLRU(
			0, REPLAY_CACHE_CLEANUP_INTERVAL, REPLAY_CACHE_MAX_ENTRIES),
		metrics: &replayCacheMetrics{},
	}
}

// Flush clears all entries in the ReplayCache. Flush should be called when
// tactics hot reload and change to clear any cached replay parameters that
// may be based on stale tactics.
func (r *ReplayCache) Flush() {

	r.cacheMutex.Lock()
	defer r.cacheMutex.Unlock()

	r.cache.Flush()
}

// GetMetrics returns a snapshop of current ReplayCache event counters and
// resets all counters to zero.
func (r *ReplayCache) GetMetrics() LogFields {

	r.cacheMutex.Lock()
	defer r.cacheMutex.Unlock()

	logFields := LogFields{
		"replay_max_cache_entries":     r.metrics.MaxCacheEntries,
		"replay_set_replay_count":      r.metrics.SetReplayCount,
		"replay_get_replay_hit_count":  r.metrics.GetReplayHitCount,
		"replay_get_replay_miss_count": r.metrics.GetReplayMissCount,
		"replay_failed_replay_count":   r.metrics.FailedReplayCount,
		"replay_delete_replay_count":   r.metrics.DeleteReplayCount,
	}

	r.metrics = &replayCacheMetrics{}

	return logFields
}

// GetReplayTargetDuration returns the tactics replay target tunnel duration
// for the specified GeoIP data. Tunnels which are active for the specified
// duration are candidates for setting or extending replay parameters. Wait
// for the returned wait duration before evaluating the tunnel duration. Once
// this target is met, call SetReplayParameters, which will check additional
// targets and conditionally set replay parameters.
func (r *ReplayCache) GetReplayTargetDuration(
	geoIPData GeoIPData) (bool, time.Duration, time.Duration) {

	p, err := r.support.ServerTacticsParametersCache.Get(geoIPData)
	if err != nil {
		log.WithTraceFields(LogFields{"error": errors.Trace(err)}).Warning(
			"ServerTacticsParametersCache.Get failed")
		return false, 0, 0
	}

	if p.IsNil() {
		// No tactics are configured; replay is disabled.
		return false, 0, 0
	}

	if !p.Bool(parameters.ServerReplayUnknownGeoIP) &&
		geoIPData.Country == GEOIP_UNKNOWN_VALUE &&
		geoIPData.ISP == GEOIP_UNKNOWN_VALUE {
		// Unless configured otherwise, skip replay for unknown GeoIP, since clients
		// may not have equivilent network conditions.
		return false, 0, 0
	}

	TTL := p.Duration(parameters.ServerReplayTTL)

	if TTL == 0 {
		// Server replay is disabled when TTL is 0.
		return false, 0, 0
	}

	return true,
		p.Duration(parameters.ServerReplayTargetWaitDuration),
		p.Duration(parameters.ServerReplayTargetTunnelDuration)
}

// SetReplayParameters sets replay parameters, packetManipulationSpecName and
// fragmentorSeed, for the specified tunnel protocol and GeoIP scope.
// Once set, replay parameters are active for a tactics-configurable TTL.
//
// The specified tunneledBytesUp/Down must meet tactics replay bytes
// transferred targets. SetReplayParameters should be called only after first
// calling ReplayTargetDuration and ensuring the tunnel meets the active
// tunnel duration target. When cached replay parameters exist, their TTL is
// extended and any failure counts are reset to zero.
//
// SetReplayParameters must be called only once per tunnel. Extending replay
// parameters TTL should only be done only immediately after a successful
// tunnel dial and target achievement, as this is the part of a tunnel
// lifecycle at highest risk of blocking.
//
// The value pointed to by fragmentorSeed must not be mutated after calling
// SetReplayParameters.
func (r *ReplayCache) SetReplayParameters(
	tunnelProtocol string,
	geoIPData GeoIPData,
	packetManipulationSpecName string,
	fragmentorSeed *prng.Seed,
	tunneledBytesUp int64,
	tunneledBytesDown int64) {

	p, err := r.support.ServerTacticsParametersCache.Get(geoIPData)
	if err != nil {
		log.WithTraceFields(LogFields{"error": errors.Trace(err)}).Warning(
			"ServerTacticsParametersCache.Get failed")
		return
	}

	if p.IsNil() {
		// No tactics are configured; replay is disabled.
		return
	}

	TTL := p.Duration(parameters.ServerReplayTTL)

	if TTL == 0 {
		return
	}

	targetUpstreamBytes := p.Int(parameters.ServerReplayTargetUpstreamBytes)
	targetDownstreamBytes := p.Int(parameters.ServerReplayTargetDownstreamBytes)

	if tunneledBytesUp < int64(targetUpstreamBytes) {
		return
	}
	if tunneledBytesDown < int64(targetDownstreamBytes) {
		return
	}

	key := r.makeKey(tunnelProtocol, geoIPData)

	value := &replayParameters{}

	if p.Bool(parameters.ServerReplayPacketManipulation) {
		value.replayPacketManipulation = true
		value.packetManipulationSpecName = packetManipulationSpecName
	}

	if p.Bool(parameters.ServerReplayFragmentor) {
		value.replayFragmentor = (fragmentorSeed != nil)
		value.fragmentorSeed = fragmentorSeed
	}

	r.cacheMutex.Lock()
	defer r.cacheMutex.Unlock()

	r.cache.Add(key, value, TTL)

	// go-cache-lru is typically safe for concurrent access but explicit
	// synchronization is required when accessing Items. Items may include
	// entries that are expired but not yet purged.
	cacheSize := int64(len(r.cache.Items()))

	if cacheSize > r.metrics.MaxCacheEntries {
		r.metrics.MaxCacheEntries = cacheSize
	}
	r.metrics.SetReplayCount += 1
}

// GetReplayPacketManipulation returns an active replay packet manipulation
// spec for the specified tunnel protocol and GeoIP scope.
//
// While Flush should be called to clear parameters based on stale tactics,
// it's still possible for GetReplayPacketManipulation to return a spec name
// that's no longer in the current list of known specs.
func (r *ReplayCache) GetReplayPacketManipulation(
	tunnelProtocol string,
	geoIPData GeoIPData) (string, bool) {

	r.cacheMutex.Lock()
	defer r.cacheMutex.Unlock()

	parameters, ok := r.getReplayParameters(
		tunnelProtocol, geoIPData)
	if !ok {
		return "", false
	}

	if !parameters.replayPacketManipulation {
		return "", false
	}

	return parameters.packetManipulationSpecName, true
}

// GetReplayFragmentor returns an active replay fragmentor seed for the
// specified tunnel protocol and GeoIP scope.
func (r *ReplayCache) GetReplayFragmentor(
	tunnelProtocol string,
	geoIPData GeoIPData) (*prng.Seed, bool) {

	r.cacheMutex.Lock()
	defer r.cacheMutex.Unlock()

	parameters, ok := r.getReplayParameters(
		tunnelProtocol, geoIPData)
	if !ok {
		return nil, false
	}

	if !parameters.replayFragmentor {
		return nil, false
	}

	return parameters.fragmentorSeed, true
}

func (r *ReplayCache) getReplayParameters(
	tunnelProtocol string,
	geoIPData GeoIPData) (*replayParameters, bool) {

	key := r.makeKey(tunnelProtocol, geoIPData)

	value, ok := r.cache.Get(key)

	if !ok {
		r.metrics.GetReplayMissCount += 1
		return nil, false
	}

	r.metrics.GetReplayHitCount += 1

	parameters, ok := value.(*replayParameters)

	return parameters, ok
}

// FailedReplayParameters increments the count of tunnels which failed to
// complete any liveness test and API handshake after using replay parameters.
// Once a failure threshold is reached, cached replay parameters are cleared.
// Call this function for tunnels which meet the failure criteria.
func (r *ReplayCache) FailedReplayParameters(
	tunnelProtocol string,
	geoIPData GeoIPData,
	packetManipulationSpecName string,
	fragmentorSeed *prng.Seed) {

	p, err := r.support.ServerTacticsParametersCache.Get(geoIPData)
	if err != nil {
		log.WithTraceFields(LogFields{"error": errors.Trace(err)}).Warning(
			"ServerTacticsParametersCache.Get failed")
		return
	}

	thresholdFailedCount := p.Int(parameters.ServerReplayFailedCountThreshold)

	key := r.makeKey(tunnelProtocol, geoIPData)

	r.cacheMutex.Lock()
	defer r.cacheMutex.Unlock()

	parameters, ok := r.getReplayParameters(tunnelProtocol, geoIPData)
	if !ok {
		return
	}

	// Do not count the failure if the replay values for the tunnel protocol and
	// GeoIP scope are now different; these parameters now reflect a newer,
	// successful tunnel.

	if (parameters.replayPacketManipulation &&
		parameters.packetManipulationSpecName != packetManipulationSpecName) ||
		(parameters.replayFragmentor &&
			(fragmentorSeed == nil ||
				*parameters.fragmentorSeed != *fragmentorSeed)) {
		return
	}

	parameters.failedCount += 1
	r.metrics.FailedReplayCount += 1

	if thresholdFailedCount == 0 {
		// No failure limit; the entry will not be deleted.
		return
	}

	if parameters.failedCount >= thresholdFailedCount {
		r.cache.Delete(key)
		r.metrics.DeleteReplayCount += 1
	}
}

func (r *ReplayCache) makeKey(
	tunnelProtocol string, geoIPData GeoIPData) string {
	return fmt.Sprintf(
		"%s-%s-%s",
		tunnelProtocol, geoIPData.Country, geoIPData.ISP)
}
