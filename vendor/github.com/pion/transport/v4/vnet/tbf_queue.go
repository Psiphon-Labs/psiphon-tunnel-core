// SPDX-FileCopyrightText: 2025 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package vnet

import (
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"
)

var _ Discipline = (*TBFQueue)(nil)

type TBFQueue struct {
	limiter     *rate.Limiter
	chunks      []Chunk
	maxSize     atomic.Int64
	currentSize int
}

// NewTBFQueue creates a new Token Bucket Filter queue with initial rate r in
// bit per second, burst size b in bytes and queue size s in bytes.
func NewTBFQueue(r int, b int, s int64) *TBFQueue {
	q := &TBFQueue{
		limiter:     rate.NewLimiter(rate.Limit(r), b*8),
		chunks:      []Chunk{},
		maxSize:     atomic.Int64{},
		currentSize: 0,
	}
	q.maxSize.Store(s)

	return q
}

// SetRate updates the rate to r bit per second.
func (t *TBFQueue) SetRate(r int) {
	t.limiter.SetLimit(rate.Limit(r))
}

// SetBurst updates the max burst size to b bytes.
func (t *TBFQueue) SetBurst(b int) {
	t.limiter.SetBurst(b * 8)
}

func (t *TBFQueue) SetSize(s int64) {
	t.maxSize.Store(s)
}

// empty implements discipline.
func (t *TBFQueue) empty() bool {
	return len(t.chunks) == 0
}

// next implements discipline.
func (t *TBFQueue) next() time.Time {
	if t.empty() {
		return time.Time{}
	}
	now := time.Now()
	if t.limiter.TokensAt(now) > 8*float64(len(t.chunks[0].UserData())) {
		return now
	}
	res := t.limiter.ReserveN(now, 8*len(t.chunks[0].UserData()))
	delay := res.Delay()
	res.Cancel()

	return now.Add(delay)
}

// pop implements discipline.
func (t *TBFQueue) pop() (chunk Chunk) {
	if t.empty() {
		return nil
	}
	if !t.limiter.AllowN(time.Now(), 8*len(t.chunks[0].UserData())) {
		return nil
	}
	chunk, t.chunks = t.chunks[0], t.chunks[1:]
	t.currentSize -= len(chunk.UserData())

	return chunk
}

// push implements discipline.
func (t *TBFQueue) push(chunk Chunk) {
	maxSize := int(t.maxSize.Load())
	if t.currentSize+len(chunk.UserData()) > maxSize {
		// drop chunk because queue is full
		return
	}
	t.currentSize += len(chunk.UserData())
	t.chunks = append(t.chunks, chunk)
}
