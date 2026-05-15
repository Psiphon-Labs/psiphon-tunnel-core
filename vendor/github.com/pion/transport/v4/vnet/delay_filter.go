// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package vnet

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

// ErrInvalidDelay indicates an invalid (negative) delay duration was provided.
var ErrInvalidDelay = errors.New("delay must be non-negative")

type delayFilterConfig struct {
	delay time.Duration
}

// DelayFilterOption configures DelayFilter creation.
type DelayFilterOption func(*delayFilterConfig) error

// WithDelay sets the initial delay applied by the filter.
func WithDelay(delay time.Duration) DelayFilterOption {
	return func(cfg *delayFilterConfig) error {
		if delay < 0 {
			return ErrInvalidDelay
		}
		cfg.delay = delay

		return nil
	}
}

// DelayFilter delays inbound packets by the given delay. Automatically starts
// processing when created and runs until Close() is called.
type DelayFilter struct {
	NIC
	delay atomic.Int64 // atomic field - stores time.Duration as int64
	push  chan struct{}
	queue *chunkQueue
	done  chan struct{}
	wg    sync.WaitGroup
}

type timedChunk struct {
	Chunk
	deadline time.Time
}

// NewDelayFilter creates and starts a new DelayFilter with the given NIC and options.
func NewDelayFilter(nic NIC, opts ...DelayFilterOption) (*DelayFilter, error) {
	cfg := delayFilterConfig{}

	for _, opt := range opts {
		if opt == nil {
			continue
		}
		if err := opt(&cfg); err != nil {
			return nil, err
		}
	}

	delayFilter := &DelayFilter{
		NIC:   nic,
		push:  make(chan struct{}),
		queue: newChunkQueue(0, 0),
		done:  make(chan struct{}),
	}

	delayFilter.delay.Store(int64(cfg.delay))

	// Start processing automatically
	delayFilter.wg.Add(1)
	go delayFilter.run()

	return delayFilter, nil
}

// SetDelay atomically updates the delay.
func (f *DelayFilter) SetDelay(newDelay time.Duration) {
	f.delay.Store(int64(newDelay))
}

func (f *DelayFilter) getDelay() time.Duration {
	return time.Duration(f.delay.Load())
}

func (f *DelayFilter) onInboundChunk(c Chunk) {
	f.queue.push(timedChunk{
		Chunk:    c,
		deadline: time.Now().Add(f.getDelay()),
	})
	f.push <- struct{}{}
}

// run processes the delayed packets queue until Close() is called.
func (f *DelayFilter) run() {
	defer f.wg.Done()

	timer := time.NewTimer(0)
	defer timer.Stop()

	for {
		select {
		case <-f.done:
			f.drainRemainingPackets()

			return

		case <-f.push:
			f.updateTimerForNextPacket(timer)

		case now := <-timer.C:
			f.processReadyPackets(now)
			f.scheduleNextPacketTimer(timer)
		}
	}
}

// drainRemainingPackets sends all remaining packets immediately during shutdown.
func (f *DelayFilter) drainRemainingPackets() {
	for {
		next, ok := f.queue.pop()
		if !ok {
			break
		}
		if chunk, ok := next.(timedChunk); ok {
			f.NIC.onInboundChunk(chunk.Chunk)
		}
	}
}

// updateTimerForNextPacket updates the timer when a new packet arrives.
func (f *DelayFilter) updateTimerForNextPacket(timer *time.Timer) {
	next := f.queue.peek()
	if next != nil {
		if chunk, ok := next.(timedChunk); ok {
			if !timer.Stop() {
				<-timer.C
			}
			timer.Reset(time.Until(chunk.deadline))
		}
	}
}

// processReadyPackets processes all packets that are ready to be sent.
func (f *DelayFilter) processReadyPackets(now time.Time) {
	for {
		next := f.queue.peek()
		if next == nil {
			break
		}
		if chunk, ok := next.(timedChunk); ok && !chunk.deadline.After(now) {
			_, _ = f.queue.pop() // We already have the item from peek()
			f.NIC.onInboundChunk(chunk.Chunk)
		} else {
			break
		}
	}
}

// scheduleNextPacketTimer schedules the timer for the next packet to be processed.
func (f *DelayFilter) scheduleNextPacketTimer(timer *time.Timer) {
	next := f.queue.peek()
	if next == nil {
		timer.Reset(time.Minute) // Long timeout when queue is empty
	} else if chunk, ok := next.(timedChunk); ok {
		timer.Reset(time.Until(chunk.deadline))
	}
}

// Run is provided for backward compatibility. The DelayFilter now starts
// automatically when created, so this method is a no-op.
func (f *DelayFilter) Run(_ context.Context) {
	// DelayFilter now starts automatically in NewDelayFilter, so this is a no-op
}

// Close stops the DelayFilter and waits for graceful shutdown.
func (f *DelayFilter) Close() error {
	close(f.done)
	f.wg.Wait()

	return nil
}
