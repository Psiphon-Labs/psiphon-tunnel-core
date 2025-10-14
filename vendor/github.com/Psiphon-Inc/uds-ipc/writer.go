/*
Copyright 2025 Psiphon Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package udsipc

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

var (
	ErrBackpressure      = errors.New("backpressure detected")
	ErrNoConsumer        = errors.New("no consumer")
	ErrBufferFull        = errors.New("send buffer full")
	ErrNotConnected      = errors.New("not connected")
	ErrInvalidTimeout    = errors.New("timeout must be positive")
	ErrInvalidBufferSize = errors.New("invalid buffer size")
)

// Pre-allocated joined errors for hot path error conditions to reduce allocations.
var (
	errNoConsumerNotConnected = errors.Join(ErrNoConsumer, ErrNotConnected)
)

// lengthPrefixPool pools byte slices for length prefix decoding to reduce allocations.
// nolint: gochecknoglobals // Pools are package-global for efficiency.
var lengthPrefixPool = sync.Pool{
	New: func() any {
		b := make([]byte, 0, binary.MaxVarintLen64)
		return &b
	},
}

// vectoredBufferPool pools net.Buffers slices to reduce allocations.
// nolint: gochecknoglobals // Pools are package-global for efficiency.
var vectoredBufferPool = sync.Pool{
	New: func() any {
		buffers := make(net.Buffers, 2) //nolint: mnd // We always only need 2 (length, data).
		return &buffers
	},
}

// Writer writes varint length prefixed byte slices
// to a Unix Domain Socket (UDS) with a small internal buffer,
// backpressure detection, and lost consumer detection.
// If the consumer is unavailable for long enough that the buffer
// fills, new messages will be discarded (instead of blocking).
// nolint: govet
type Writer struct {
	onError          ErrorCallback
	send             chan []byte
	conn             net.Conn
	socketPath       string
	shutdownStart    chan struct{} // Signals running→stopping transition.
	shutdownComplete chan struct{} // Signals stopping→stopped gracefully.
	shutdownForced   chan struct{} // Signals stopping→stopped forcefully.
	sentCount        uint64        // Successfully sent to consumer.
	droppedCount     uint64        // Dropped due to queue full.
	failedCount      uint64        // Failed due to connection issues.
	writeTimeout     time.Duration
	dialTimeout      time.Duration
	maxBackoff       time.Duration
	wg               sync.WaitGroup
	closeOnce        sync.Once
	writeBufferSize  uint32 // Size of kernel write buffer (SO_SNDBUF).
}

// NewWriter creates a pointer to a newly initialized Writer.
func NewWriter(socketPath string, opts ...WriterOption) (*Writer, error) {
	if socketPath == "" {
		return nil, fmt.Errorf("%w: empty path", ErrInvalidSocketPath)
	}

	if len(socketPath) > MaxSocketPathLength() {
		return nil, fmt.Errorf("%w: socket path too long: %s", ErrInvalidSocketPath, socketPath)
	}

	// nolint: mnd // Default values.
	w := &Writer{
		writeTimeout:     time.Second,
		dialTimeout:      time.Second,
		maxBackoff:       10 * time.Second,
		socketPath:       socketPath,
		writeBufferSize:  256 * 1024, // 256KB.
		send:             make(chan []byte, 10_000),
		shutdownStart:    make(chan struct{}),
		shutdownComplete: make(chan struct{}),
		shutdownForced:   make(chan struct{}),
	}

	for _, opt := range opts {
		if err := opt(w); err != nil {
			return nil, fmt.Errorf("error applying option: %w", err)
		}
	}

	return w, nil
}

// WriteMessage queues a message for sending, dropping messages and returning
// ErrBufferFull when the queue is full (instead of blocking).
// Callers MUST NOT modify the data slice after calling WriteMessage. The slice
// will be retained for potential retries on write failure. If the caller needs
// to reuse or modify the slice, they must pass a copy.
func (w *Writer) WriteMessage(data []byte) error {
	if len(data) < 1 {
		return nil
	}

	select {
	case w.send <- data:
		// Queued successfully.
	default:
		// Queue full - message dropped.
		atomic.AddUint64(&w.droppedCount, 1)
		return ErrBufferFull
	}

	return nil
}

// GetMetrics returns current counter values and queue depth.
func (w *Writer) GetMetrics() (uint64, uint64, uint64, int) {
	return atomic.LoadUint64(&w.sentCount),
		atomic.LoadUint64(&w.droppedCount),
		atomic.LoadUint64(&w.failedCount),
		len(w.send)
}

// GetSocketPath returns the socket path being used.
func (w *Writer) GetSocketPath() string {
	return w.socketPath
}

// Start begins the sender loop.
func (w *Writer) Start() {
	w.wg.Add(1)
	go w.run()
}

// Stop attempts to shut down gracefully until it either finishes
// draining all writes, or the passed context is cancelled or expires.
// Subsequent calls return nil.
func (w *Writer) Stop(ctx context.Context) error {
	var err error

	w.closeOnce.Do(func() {
		close(w.shutdownStart) // Signal run() to begin shutdown

		// Wait for either graceful completion or context cancellation/expiration
		select {
		case <-w.shutdownComplete: // Clean shutdown - all buffered messages drained
		case <-ctx.Done(): // Forced shutdown - context cancelled or expired
			close(w.shutdownForced) // Force run() to exit drain phase immediately
			err = fmt.Errorf("graceful shutdown timeout, forcing unclean shutdown: %w", ctx.Err())
		}

		// Always wait for goroutine cleanup regardless of how we exited the select
		w.wg.Wait()

		// Close connection after goroutine cleanup
		if w.conn != nil {
			if closeErr := w.conn.Close(); closeErr != nil && err == nil {
				err = fmt.Errorf("failed to close connection: %w", closeErr)
			}
		}
	})

	return err
}

// writeLengthPrefixedData writes length-prefixed data to the socket.
func (w *Writer) writeLengthPrefixedData(data []byte) error {
	if w.conn == nil {
		return errNoConsumerNotConnected
	}

	lengthPrefixBuf, _ := lengthPrefixPool.Get().(*[]byte)
	*lengthPrefixBuf = (*lengthPrefixBuf)[:0]                     // Clear previous data.
	*lengthPrefixBuf = (*lengthPrefixBuf)[:binary.MaxVarintLen64] // Ensure sufficient length for PutUvarint.
	defer lengthPrefixPool.Put(lengthPrefixBuf)

	lengthPrefixSize := binary.PutUvarint(*lengthPrefixBuf, uint64(len(data)))

	// Use vectored I/O to write prefix + data in single syscall.
	buffersPtr, _ := vectoredBufferPool.Get().(*net.Buffers)
	defer vectoredBufferPool.Put(buffersPtr)

	buffers := *buffersPtr
	buffers[0] = (*lengthPrefixBuf)[:lengthPrefixSize]
	buffers[1] = data

	deadline := time.Now().Add(w.writeTimeout)
	if err := w.conn.SetWriteDeadline(deadline); err != nil {
		return errors.Join(ErrNoConsumer, err)
	}

	if _, err := buffers.WriteTo(w.conn); err != nil {
		return w.classifyWriteError(err)
	}

	return nil
}

// classifyWriteError categorizes write errors.
// Timeouts while writing return a backpressure error.
// All other errors are classified as having no consumer.
func (w *Writer) classifyWriteError(err error) error {
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return errors.Join(ErrBackpressure, err)
	}

	return errors.Join(ErrNoConsumer, err)
}

// run is the main sender loop.
func (w *Writer) run() {
	defer w.wg.Done()

	// Signal graceful shutdown completion
	defer close(w.shutdownComplete)

	// Phase 1: Normal operations.
	retryMsg := w.processMessages()

	// Phase 2: Graceful drain of remaining buffered messages.
	w.drainQueuedWrites(retryMsg)
}

// processMessages handles normal operation including connection management and message processing.
// Returns any pending retry message that should be attempted during drain phase.
// nolint: gocognit
func (w *Writer) processMessages() []byte {
	backoff := time.Second

	var retryMsgOnReconnect []byte

	for {
		// Make sure we're connected.
		if w.conn == nil { // nolint: nestif
			if err := w.connect(); err != nil {
				if w.onError != nil {
					w.onError(err, "failed to connect")
				}
				select {
				case <-time.After(backoff):
					backoff = min(backoff*2, w.maxBackoff) //nolint: mnd // Exponential backoff.
					continue
				case <-w.shutdownStart:
					return retryMsgOnReconnect // Move to draining buffered writes phase.
				}
			}

			// Reset the timeout to 1 second, which could be larger than
			// the expected minimum, but strikes a balance between fast
			// reconnections and hammering a dead endpoint repeatedly.
			backoff = time.Second

			// If we've previously failed to write a message, it will be stored
			// in retryMsgOnReconnect and a write should be immediately attempted
			// with this message upon successful reconnect. Subsequent failures
			// should continue to trigger reconnections (since failing to
			// reconnect repeatedly will eventually hit the maximum backoff time
			// and result in a different error pathway.
			if retryMsgOnReconnect != nil {
				if err := w.sendRetryMessage(retryMsgOnReconnect, "write failure after reconnect"); err != nil {
					w.closeConn()
					continue
				}

				retryMsgOnReconnect = nil
			}
		}

		// Process messages.
		select {
		case data := <-w.send:
			if err := w.writeLengthPrefixedData(data); err != nil {
				atomic.AddUint64(&w.failedCount, 1)
				if w.onError != nil {
					w.onError(err, "write failure")
				}

				w.closeConn()

				// Buffer the failed message for retry on reconnect.
				// Note: We rely on the WriteMessage API contract that callers
				// do not modify the slice after passing it to WriteMessage.
				retryMsgOnReconnect = data
			} else {
				atomic.AddUint64(&w.sentCount, 1)
			}
		case <-w.shutdownStart:
			return retryMsgOnReconnect // Move to draining buffered writes phase.
		}
	}
}

// sendRetryMessage attempts to send a buffered retry message, updating metrics accordingly.
// Returns error if write failed. Caller is responsible for connection management.
func (w *Writer) sendRetryMessage(data []byte, context string) error {
	if err := w.writeLengthPrefixedData(data); err != nil {
		atomic.AddUint64(&w.failedCount, 1)
		if w.onError != nil {
			w.onError(err, context)
		}

		return err
	}

	atomic.AddUint64(&w.sentCount, 1)
	return nil
}

// drainQueuedWrites handles graceful shutdown by draining remaining buffered messages.
func (w *Writer) drainQueuedWrites(retryMsgOnReconnect []byte) {
	// If there's a pending retry message from normal operation, attempt to send it first.
	if retryMsgOnReconnect != nil {
		if err := w.sendRetryMessage(
			retryMsgOnReconnect, "write failure during drain (retry message)",
		); err != nil {
			w.closeConn()
		}
	}

	for {
		select {
		case data := <-w.send:
			// Continue processing buffered messages during drain.
			if err := w.writeLengthPrefixedData(data); err != nil {
				atomic.AddUint64(&w.failedCount, 1)
				if w.onError != nil {
					w.onError(err, "write failure during drain")
				}
				w.closeConn()
			} else {
				atomic.AddUint64(&w.sentCount, 1)
			}
		case <-w.shutdownForced:
			// Forced shutdown - exit immediately without draining more.
			return
		default:
			// No more messages to drain - clean shutdown complete.
			if len(w.send) == 0 {
				return
			}

			// While there is a small risk this code could create a short busy loop condition
			// in the case where data is in the buffered channel but not yet available to be
			// selected, no explicit sleep or yield is needed since in Go 1.14+ the scheduler
			// can preempt busy loops itself when needed.
		}
	}
}

// connect establishes connection to the socket.
func (w *Writer) connect() error {
	conn, err := net.DialTimeout("unix", w.socketPath, w.dialTimeout) //nolint: noctx
	if err != nil {
		return fmt.Errorf("failed to dial socket: %s: %w", w.socketPath, err)
	}

	if w.writeBufferSize > 0 {
		if unixConn, ok := conn.(*net.UnixConn); ok {
			// Increase write buffer to reduce kernel allocation overhead.
			// Don't fail connection for buffer optimization errors,
			// this could happen in restricted environments.
			_ = unixConn.SetWriteBuffer(int(w.writeBufferSize))
		}
	}

	w.conn = conn
	return nil
}

// closeConn closes current connection.
func (w *Writer) closeConn() {
	if w.conn != nil {
		_ = w.conn.Close()
		w.conn = nil
	}
}
