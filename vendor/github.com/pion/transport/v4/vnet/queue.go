// SPDX-FileCopyrightText: 2025 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package vnet

import (
	"sync"
	"time"
)

type Discipline interface {
	push(Chunk)
	pop() Chunk
	empty() bool
	next() time.Time
}

type Queue struct {
	NIC
	data    Discipline
	chunkCh chan Chunk
	closed  bool
	close   chan struct{}
	wg      sync.WaitGroup
	lock    sync.Mutex
}

func NewQueue(n NIC, d Discipline) (*Queue, error) {
	q := &Queue{
		NIC:     n,
		data:    d,
		chunkCh: make(chan Chunk),
		closed:  false,
		close:   make(chan struct{}),
		wg:      sync.WaitGroup{},
		lock:    sync.Mutex{},
	}
	q.wg.Add(1)
	go q.run()

	return q, nil
}

func (q *Queue) onInboundChunk(c Chunk) {
	select {
	case q.chunkCh <- c:
	case <-q.close:

		return
	}
}

func (q *Queue) run() {
	defer q.wg.Done()
	for {
		if !q.schedule() {
			return
		}
	}
}

func (q *Queue) schedule() bool {
	q.lock.Lock()
	if q.closed {
		q.lock.Unlock()

		return false
	}
	q.lock.Unlock()

	var timer <-chan time.Time

	if !q.data.empty() {
		next := q.data.next()
		timer = time.After(time.Until(next))
	}

	select {
	case chunk := <-q.chunkCh:
		q.data.push(chunk)
	case <-timer:
		chunk := q.data.pop()
		if chunk != nil {
			q.NIC.onInboundChunk(chunk)
		}
	case <-q.close:
		return false
	}

	return true
}

func (q *Queue) Close() error {
	defer q.wg.Wait()
	q.lock.Lock()
	defer q.lock.Unlock()
	if q.closed {
		return nil
	}
	q.closed = true
	close(q.close)

	return nil
}
