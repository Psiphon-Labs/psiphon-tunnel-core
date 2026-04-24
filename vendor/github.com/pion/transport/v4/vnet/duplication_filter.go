// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package vnet

import (
	"errors"
	"math"
	"math/rand"
	"sync"
	"time"
)

const (
	defaultDuplicationBurstMultiplier = 10.0
	duplicationBucketSize             = time.Millisecond
)

var (
	// errInvalidDuplicationProbability indicates the configured duplication probability is outside [0, 1].
	errInvalidDuplicationProbability = errors.New("duplication probability must be between 0 and 1 inclusive")
	// errInvalidDuplicationBurstProbability indicates the configured burst probability is outside [0, 1].
	errInvalidDuplicationBurstProbability = errors.New("duplication burst probability must be between 0 and 1 inclusive")
	// errInvalidDuplicationBurstMultiplier indicates the configured burst multiplier is invalid.
	errInvalidDuplicationBurstMultiplier = errors.New("duplication burst multiplier must be at least 1")
	// errInvalidDuplicationDelayRange indicates the configured delay range is invalid.
	errInvalidDuplicationDelayRange = errors.New("duplication delay range must satisfy 0 <= min <= max")
	// errInvalidDuplicationBurstDuration indicates the burst duration is invalid.
	errInvalidDuplicationBurstDuration = errors.New("duplication burst duration must be non-negative")
	// errInvalidDuplicationRouter indicates a nil router was provided when constructing the filter.
	errInvalidDuplicationRouter = errors.New("duplication filter requires a non-nil router reference")
)

type duplicationConfig struct {
	prob            float64
	burstStartProb  float64
	burstDuration   time.Duration
	burstMultiplier float64
	minExtraDelay   time.Duration
	maxExtraDelay   time.Duration
	seed            *int64
}

// DuplicationOption configures a DuplicationFilter.
type DuplicationOption func(*duplicationConfig) error

// WithDuplicationProbability sets the base duplication probability.
func WithDuplicationProbability(prob float64) DuplicationOption {
	return func(cfg *duplicationConfig) error {
		if prob < 0 || prob > 1 {
			return errInvalidDuplicationProbability
		}

		cfg.prob = prob

		return nil
	}
}

// WithDuplicationBurstProbability sets the probability that a burst window starts. Bursts are
// triggered probabilistically per packet when outside a burst window, creating time-based
// windows of elevated duplication. For deterministic burst cadences, seed the filter and
// control the burst timing externally.
func WithDuplicationBurstProbability(prob float64) DuplicationOption {
	return func(cfg *duplicationConfig) error {
		if prob < 0 || prob > 1 {
			return errInvalidDuplicationBurstProbability
		}

		cfg.burstStartProb = prob

		return nil
	}
}

// WithDuplicationBurstDuration configures how long burst mode stays active once triggered.
func WithDuplicationBurstDuration(duration time.Duration) DuplicationOption {
	return func(cfg *duplicationConfig) error {
		if duration < 0 {
			return errInvalidDuplicationBurstDuration
		}

		cfg.burstDuration = duration

		return nil
	}
}

// WithDuplicationBurstMultiplier adjusts how aggressively probability increases during a burst window.
func WithDuplicationBurstMultiplier(multiplier float64) DuplicationOption {
	return func(cfg *duplicationConfig) error {
		if multiplier < 1 {
			return errInvalidDuplicationBurstMultiplier
		}

		cfg.burstMultiplier = multiplier

		return nil
	}
}

// WithDuplicationExtraDelay sets the range for additional delay applied to duplicates. The
// selected delay is uniform across the inclusive range [minDelay, maxDelay].
func WithDuplicationExtraDelay(minDelay, maxDelay time.Duration) DuplicationOption {
	return func(cfg *duplicationConfig) error {
		if minDelay < 0 || maxDelay < 0 || maxDelay < minDelay {
			return errInvalidDuplicationDelayRange
		}

		cfg.minExtraDelay = minDelay
		cfg.maxExtraDelay = maxDelay

		return nil
	}
}

// WithDuplicationImmediate is a convenience that configures duplicates to be delivered
// without any extra delay (equivalent to WithDuplicationExtraDelay(0, 0)).
func WithDuplicationImmediate() DuplicationOption {
	return WithDuplicationExtraDelay(0, 0)
}

// WithDuplicationSeed sets the random seed used by the duplication filter.
func WithDuplicationSeed(seed int64) DuplicationOption {
	return func(cfg *duplicationConfig) error {
		cfg.seed = new(int64)
		*cfg.seed = seed

		return nil
	}
}

// DuplicationFilter duplicates chunks that traverse a router according to the supplied configuration.
// When chaining with other filters, register duplication ahead of loss or latency filters to better
// emulate how duplicates typically occur before drop or jitter on real networks.
//
// Note: Call Close() to cancel pending delayed duplicates and prevent goroutine leaks when
// shutting down. Routers do not automatically close registered duplication filters so applications
// should wire Close() into their lifecycle (e.g., along with Router.Stop()). The filter is safe
// for concurrent use by multiple goroutines.
//
// Note: Duplicates re-enter the router and may be reordered relative to the original if other
// filters add jitter. Configure minExtraDelay appropriately to maintain ordering guarantees.
type DuplicationFilter struct {
	router   *Router
	cfg      duplicationConfig
	mu       sync.Mutex
	rng      *rand.Rand
	burstEnd time.Time
	now      func() time.Time
	timers   map[*time.Timer]struct{}
	closed   bool
	// bucketed scheduling to reduce timer churn
	buckets map[int64]*dupBucket // key: fireAt in UnixNano aligned to duplicationBucketSize
}

type dupBucket struct {
	timer  *time.Timer
	chunks []Chunk
}

// NewDuplicationFilter constructs a new DuplicationFilter bound to the provided router.
func NewDuplicationFilter(router *Router, opts ...DuplicationOption) (*DuplicationFilter, error) {
	if router == nil {
		return nil, errInvalidDuplicationRouter
	}

	cfg := duplicationConfig{burstMultiplier: defaultDuplicationBurstMultiplier}

	for _, opt := range opts {
		if opt == nil {
			continue
		}
		if err := opt(&cfg); err != nil {
			return nil, err
		}
	}

	if err := validateDuplicationConfig(&cfg); err != nil {
		return nil, err
	}

	rng := newRNG(cfg.seed)

	return &DuplicationFilter{
		router:  router,
		cfg:     cfg,
		rng:     rng,
		now:     time.Now,
		timers:  make(map[*time.Timer]struct{}),
		buckets: make(map[int64]*dupBucket),
	}, nil
}

// ChunkFilter returns a ChunkFilter that can be registered with Router.AddChunkFilter.
func (f *DuplicationFilter) ChunkFilter() ChunkFilter {
	return func(c Chunk) bool {
		if chunkIsDuplicate(c) {
			return true
		}

		delay, shouldDup := f.shouldDuplicate()
		if shouldDup {
			clone := c.Clone()
			f.scheduleDuplicate(clone, delay)
		}

		return true
	}
}

func (f *DuplicationFilter) shouldDuplicate() (time.Duration, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.closed {
		return 0, false
	}

	now := f.now()
	probability := f.cfg.prob

	if f.cfg.burstDuration > 0 && f.cfg.burstStartProb > 0 {
		if now.After(f.burstEnd) {
			if f.rng.Float64() < f.cfg.burstStartProb {
				f.burstEnd = now.Add(f.cfg.burstDuration)
			}
		}

		if now.Before(f.burstEnd) {
			probability = math.Min(1.0, probability*f.cfg.burstMultiplier)
		}
	}

	if f.rng.Float64() >= probability {
		return 0, false
	}

	// compute delay: uniform distribution over [min, max].
	delay := f.cfg.minExtraDelay
	if f.cfg.maxExtraDelay > f.cfg.minExtraDelay {
		extra := f.cfg.maxExtraDelay - f.cfg.minExtraDelay
		delay += time.Duration(f.rng.Int63n(int64(extra) + 1))
	}

	return delay, true
}

func (f *DuplicationFilter) scheduleDuplicate(dup Chunk, delay time.Duration) {
	markChunkDuplicate(dup)

	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()

		return
	}

	// bucketed scheduling, we group duplicates into fixed windows.
	// this is to avoid creating a timer for each duplication.
	now := f.now()
	deadline := now.Add(delay)
	bucketN := int64(duplicationBucketSize)
	deadlineN := deadline.UnixNano()
	// we round up to the next bucket boundary to avoid early delivery
	fireAtN := ((deadlineN + bucketN - 1) / bucketN) * bucketN

	bucket, ok := f.buckets[fireAtN]
	if !ok {
		fireAt := time.Unix(0, fireAtN)
		wait := max(fireAt.Sub(now), 0)
		bucket = &dupBucket{}
		bucket.timer = time.AfterFunc(wait, func() {
			f.onBucketFired(fireAtN)
		})
		f.buckets[fireAtN] = bucket
		f.timers[bucket.timer] = struct{}{}
	}

	bucket.chunks = append(bucket.chunks, dup)
	f.mu.Unlock()
}

func (f *DuplicationFilter) onBucketFired(key int64) {
	f.mu.Lock()
	if f.closed {
		if bucket, ok := f.buckets[key]; ok {
			delete(f.timers, bucket.timer)
			delete(f.buckets, key)
		}
		f.mu.Unlock()

		return
	}

	bucket, ok := f.buckets[key]
	if ok {
		delete(f.timers, bucket.timer)
		delete(f.buckets, key)
	}
	chunks := bucket.chunks
	f.mu.Unlock()

	for i := 0; i < len(chunks); i++ {
		f.router.push(chunks[i])
	}
}

// Close cancels all pending duplicate deliveries and prevents future duplications.
func (f *DuplicationFilter) Close() error {
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()

		return nil
	}

	f.closed = true
	timers := make([]*time.Timer, 0, len(f.timers))
	for timer := range f.timers {
		timers = append(timers, timer)
	}
	f.mu.Unlock()

	for _, timer := range timers {
		timer.Stop()
	}

	return nil
}

func validateDuplicationConfig(cfg *duplicationConfig) error {
	if cfg.prob < 0 || cfg.prob > 1 {
		return errInvalidDuplicationProbability
	}
	if cfg.burstStartProb < 0 || cfg.burstStartProb > 1 {
		return errInvalidDuplicationBurstProbability
	}
	if cfg.burstMultiplier < 1 {
		return errInvalidDuplicationBurstMultiplier
	}
	if cfg.burstDuration < 0 {
		return errInvalidDuplicationBurstDuration
	}
	if cfg.minExtraDelay < 0 || cfg.maxExtraDelay < 0 || cfg.maxExtraDelay < cfg.minExtraDelay {
		return errInvalidDuplicationDelayRange
	}

	return nil
}

func chunkIsDuplicate(c Chunk) bool {
	type duplicateChecker interface {
		isDuplicate() bool
	}

	// a small cheat for test 100% test cov :)
	if checker, ok := c.(duplicateChecker); ok && checker.isDuplicate() {
		return true
	}

	return false
}

func markChunkDuplicate(c Chunk) {
	type duplicateMarker interface {
		markDuplicate()
	}

	if marker, ok := c.(duplicateMarker); ok {
		marker.markDuplicate()
	}
}
