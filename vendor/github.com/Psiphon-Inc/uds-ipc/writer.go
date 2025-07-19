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
	onError         ErrorCallback
	send            chan []byte
	conn            net.Conn
	socketPath      string
	done            chan struct{}
	sentCount       uint64 // Successfully sent to consumer.
	droppedCount    uint64 // Dropped due to queue full.
	failedCount     uint64 // Failed due to connection issues.
	writeTimeout    time.Duration
	dialTimeout     time.Duration
	maxBackoff      time.Duration
	wg              sync.WaitGroup
	closeOnce       sync.Once
	writeBufferSize uint32 // Size of kernel write buffer (SO_SNDBUF).
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
		writeTimeout:    time.Second,
		dialTimeout:     time.Second,
		maxBackoff:      10 * time.Second,
		socketPath:      socketPath,
		writeBufferSize: 256 * 1024, // 256KB.
		send:            make(chan []byte, 10_000),
		done:            make(chan struct{}),
	}

	for _, opt := range opts {
		if err := opt(w); err != nil {
			return nil, fmt.Errorf("error applying option: %w", err)
		}
	}

	return w, nil
}

// WriteMessage queues a message for sending, dropping messages when the queue is full (instead of blocking).
func (w *Writer) WriteMessage(data []byte) {
	if len(data) < 1 {
		return
	}

	select {
	case w.send <- data:
		// Queued successfully.
	default:
		// Queue full - message dropped.
		atomic.AddUint64(&w.droppedCount, 1)
	}
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

// Stop shuts down gracefully. Subsequent calls return nil.
func (w *Writer) Stop() error {
	var err error
	w.closeOnce.Do(func() {
		close(w.done)
		w.wg.Wait()

		if w.conn != nil {
			if err = w.conn.Close(); err != nil {
				err = fmt.Errorf("failed to close connection: %w", err)
			}
		}
	})

	return err
}

// writeLengthPrefixedData writes length-prefixed data to the socket with a single retry.
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

	// Retry once before falling back to close+reconnect.
	if _, err := buffers.WriteTo(w.conn); err != nil {
		deadline = time.Now().Add(w.writeTimeout)
		if deadlineErr := w.conn.SetWriteDeadline(deadline); deadlineErr != nil {
			return w.classifyWriteError(errors.Join(err, deadlineErr))
		}

		if _, retryErr := buffers.WriteTo(w.conn); retryErr != nil {
			return w.classifyWriteError(errors.Join(err, retryErr))
		}
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
// nolint: gocognit
func (w *Writer) run() {
	defer w.wg.Done()
	backoff := time.Second

	for {
		// Make sure we're connected.
		if w.conn == nil {
			if err := w.connect(); err != nil {
				if w.onError != nil {
					w.onError(err, "failed to connect")
				}
				select {
				case <-time.After(backoff):
					backoff = min(backoff*2, w.maxBackoff) //nolint: mnd // Exponential backoff.
					continue
				case <-w.done:
					return
				}
			}

			// Reset the timeout to 1 second, which could be larger than
			// the expected minimum, but strikes a balance between fast
			// reconnections and hammering a dead endpoint repeatedly.
			backoff = time.Second
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
			} else {
				atomic.AddUint64(&w.sentCount, 1)
			}
		case <-w.done:
			return
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
