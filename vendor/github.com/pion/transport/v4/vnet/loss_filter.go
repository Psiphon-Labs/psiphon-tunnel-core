// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package vnet

import (
	"errors"
	"math/rand"
	"sync"
	"time"
)

// Static errors for better error handling.
var (
	ErrInvalidChance           = errors.New("chance must be between 0 and 100 inclusive")
	ErrInvalidShuffleBlockSize = errors.New("shuffleBlockSize must be greater than 0")
)

type LossFilterHandler interface {
	shouldDrop() bool
	setLossRate(chance int, resetImmediately bool)
}

// LossFilter is a wrapper around NICs, that drops some of the packets passed to
// onInboundChunk.
type LossFilter struct {
	NIC
	LossFilterHandler
}

// lossFilterConfig holds the configuration for creating a LossFilter.
type lossFilterConfig struct {
	nic              NIC
	chance           int
	handler          LossFilterHandler
	shuffleBlockSize int
	seed             *int64
}

// LossFilterOption represents a configuration option for LossFilter creation.
type LossFilterOption func(cfg *lossFilterConfig) error

// WithLossHandler sets a custom loss handler for the LossFilter.
// This option takes precedence over WithShuffleLossHandler if both are provided.
func WithLossHandler(handler LossFilterHandler) LossFilterOption {
	return func(cfg *lossFilterConfig) error {
		cfg.handler = handler

		return nil
	}
}

// WithShuffleLossHandler configures the LossFilter to use deterministic shuffle-based packet loss
// with the specified block size. When set, for every blockSize packets, it guarantees that the
// number of packets dropped equals round(blockSize * chance / 100), where chance is a percentage (0-100).
func WithShuffleLossHandler(blockSize int) LossFilterOption {
	return func(cfg *lossFilterConfig) error {
		if blockSize < 1 {
			return ErrInvalidShuffleBlockSize
		}
		cfg.shuffleBlockSize = blockSize

		return nil
	}
}

// WithLossSeed sets the random seed used by the loss filter for deterministic behavior.
// When a seed is provided (including seed==0), both random loss and shuffle-based loss will
// produce reproducible results.
// If no seed is provided (nil), the filter uses time-based seeding for non-deterministic behavior.
func WithLossSeed(seed int64) LossFilterOption {
	return func(cfg *lossFilterConfig) error {
		cfg.seed = new(int64)
		*cfg.seed = seed

		return nil
	}
}

// lossHandle drops packets with configurable behavior: random or deterministic shuffle-based.
// When shuffleBlockSize is 0, it uses pure random dropping.
// When shuffleBlockSize > 0, it uses deterministic shuffle-based dropping for better distribution.
type lossHandle struct {
	// percentage (0-100) - used in random mode, stored for consistency in shuffle mode
	chance int
	mutex  sync.RWMutex
	// seeded random number generator
	rng *rand.Rand

	// Shuffle mode fields (only used when shuffleBlockSize > 0)
	shuffleBlockSize int
	blockIdx         int
	shuffledBlock    []bool
	// current number of drops per block (calculated from chance percentage)
	currentDrops int
	pendingDrops int
}

// calculateDropsPerBlock calculates the number of packets to drop per block based on percentage chance.
// Uses rounding: (chance * blockSize + 50) / 100.
func calculateDropsPerBlock(chancePercent int, blockSize int) int {
	return (chancePercent*blockSize + 50) / 100
}

// newRNG creates a new random number generator. If seed is nil, uses time-based seeding.
// A seed of 0 is treated as a valid deterministic seed (not time-based).
func newRNG(seed *int64) *rand.Rand {
	if seed == nil {
		// nolint:gosec // weak rand is intended
		return rand.New(rand.NewSource(time.Now().UnixNano()))
	}
	// nolint:gosec // weak rand is intended
	return rand.New(rand.NewSource(*seed))
}

// newRandomLossHandle creates a new lossHandle for random packet dropping.
func newRandomLossHandle(chance int, rng *rand.Rand) *lossHandle {
	return &lossHandle{
		chance:           chance,
		shuffleBlockSize: 0, // 0 means random mode
		rng:              rng,
	}
}

// newShuffleLossHandle creates a new lossHandle for shuffle-based packet loss.
func newShuffleLossHandle(chance, shuffleBlockSize int, rng *rand.Rand) *lossHandle {
	dropsPerBlock := calculateDropsPerBlock(chance, shuffleBlockSize)
	handler := &lossHandle{
		chance:           chance,
		shuffleBlockSize: shuffleBlockSize,
		shuffledBlock:    make([]bool, shuffleBlockSize),
		currentDrops:     dropsPerBlock,
		pendingDrops:     dropsPerBlock,
		rng:              rng,
	}

	for i := 0; i < handler.currentDrops; i++ {
		handler.shuffledBlock[i] = true
	}

	handler.shuffleBlock()

	return handler
}

func (r *lossHandle) shouldDrop() bool {
	if r.shuffleBlockSize > 0 {
		return r.shouldDropShuffle()
	}

	r.mutex.Lock()
	chance := r.chance
	result := r.rng.Intn(100) < chance
	r.mutex.Unlock()

	return result
}

func (r *lossHandle) shouldDropShuffle() bool {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if r.blockIdx == len(r.shuffledBlock) {
		r.shuffleBlock()
	}

	res := r.shuffledBlock[r.blockIdx]
	r.blockIdx++

	return res
}

func (r *lossHandle) setLossRate(chance int, resetImmediately bool) {
	if r.shuffleBlockSize > 0 {
		r.setLossRateShuffle(chance, resetImmediately)
	} else {
		r.mutex.Lock()
		defer r.mutex.Unlock()
		r.chance = chance
	}
}

func (r *lossHandle) setLossRateShuffle(chance int, resetImmediately bool) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	r.chance = chance // store percentage for consistency
	r.pendingDrops = calculateDropsPerBlock(chance, r.shuffleBlockSize)

	if resetImmediately {
		r.shuffleBlock()
	}
}

// shuffleBlock shuffles the current block using the RNG.
// This method must be called while holding mutex to ensure thread-safe RNG access.
func (r *lossHandle) shuffleBlock() {
	// Update shuffled block to match pending drops count
	for idx := 0; idx < len(r.shuffledBlock); idx++ {
		switch {
		case r.pendingDrops == r.currentDrops:
			goto shuffleComplete
		case r.pendingDrops > r.currentDrops && !r.shuffledBlock[idx]:
			r.shuffledBlock[idx] = true
			r.currentDrops++
		case r.pendingDrops < r.currentDrops && r.shuffledBlock[idx]:
			r.shuffledBlock[idx] = false
			r.currentDrops--
		}
	}

shuffleComplete:
	r.rng.Shuffle(len(r.shuffledBlock), func(i, j int) {
		r.shuffledBlock[i], r.shuffledBlock[j] = r.shuffledBlock[j], r.shuffledBlock[i]
	})
	r.blockIdx = 0
}

// NewLossFilter creates a new LossFilter that drops every packet with a
// probability of chance/100. You can provide custom options to override the
// default behavior. This follows the Pion options pattern for extensibility.
//
// Option precedence: If WithLossHandler is provided, it takes precedence and any
// WithShuffleLossHandler option will be ignored.
func NewLossFilter(nic NIC, chance int, options ...LossFilterOption) (*LossFilter, error) {
	if !validateChance(chance) {
		return nil, ErrInvalidChance
	}

	// Initialize config with defaults
	cfg := &lossFilterConfig{
		nic:              nic,
		chance:           chance,
		shuffleBlockSize: 0, // 0 means random mode
	}

	for _, option := range options {
		if option == nil {
			continue
		}
		if err := option(cfg); err != nil {
			return nil, err
		}
	}

	// Create handler based on config
	// Precedence: WithLossHandler > WithShuffleLossHandler > default random handler
	var lossHandler LossFilterHandler

	switch {
	case cfg.handler != nil:
		// Use provided handler (WithLossHandler takes precedence over WithShuffleLossHandler)
		cfg.handler.setLossRate(cfg.chance, false)
		lossHandler = cfg.handler
	case cfg.shuffleBlockSize > 0:
		// Create shuffle handler with seed from config if available
		lossHandler = newShuffleLossHandle(cfg.chance, cfg.shuffleBlockSize, newRNG(cfg.seed))
	default:
		// Random mode - create handler with seed from config if available
		lossHandler = newRandomLossHandle(cfg.chance, newRNG(cfg.seed))
	}

	lossFilter := &LossFilter{
		NIC:               nic,
		LossFilterHandler: lossHandler,
	}

	return lossFilter, nil
}

func (f *LossFilter) onInboundChunk(c Chunk) {
	if f.LossFilterHandler.shouldDrop() {
		return
	}

	f.NIC.onInboundChunk(c)
}

// SetLossRate sets the loss rate for the loss filter.
// The chance parameter is an integer out of 100.
// The resetImmediately parameter is a boolean that indicates whether to reset the loss rate immediately.
// If resetImmediately is true, the loss rate will be reset immediately.
// If resetImmediately is false, the loss rate will be reset after the next shuffle for shuffle-based handlers.
// Note that for random loss handlers (when shuffleBlockSize is 0), the loss rate will be reset immediately
// regardless of the resetImmediately parameter.
func (f *LossFilter) SetLossRate(chance int, resetImmediately bool) error {
	if !validateChance(chance) {
		return ErrInvalidChance
	}

	f.LossFilterHandler.setLossRate(chance, resetImmediately)

	return nil
}

func validateChance(chance int) bool {
	return chance >= 0 && chance <= 100
}
