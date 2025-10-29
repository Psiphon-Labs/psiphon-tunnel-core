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
	"errors"
	"time"
)

// WriterOption is the functional option type for Writer.
type WriterOption func(r *Writer) error

// WithMaxBufferedWrites sets the number of messages that can be buffered while there
// is no receiver on the other end of the socket before messages are dropped.
// Default is 10,000.
func WithMaxBufferedWrites(size uint32) WriterOption {
	return func(w *Writer) error {
		w.send = make(chan []byte, size)
		return nil
	}
}

// WithWriteTimeout sets the timeout for individual write operations.
// If a write takes longer than this duration, it will be considered a timeout error.
// Default varies by writer configuration.
func WithWriteTimeout(timeout time.Duration) WriterOption {
	return func(w *Writer) error {
		if timeout <= 0 {
			return errors.Join(ErrInvalidTimeout, errors.New("write deadline must be > 0"))
		}

		w.writeTimeout = timeout
		return nil
	}
}

// WithDialTimeout sets the timeout for establishing new connections.
// If connection establishment takes longer than this duration, it will fail.
// Default varies by writer configuration.
func WithDialTimeout(timeout time.Duration) WriterOption {
	return func(w *Writer) error {
		if timeout <= 0 {
			return errors.Join(ErrInvalidTimeout, errors.New("dial timeout must be > 0"))
		}

		w.dialTimeout = timeout
		return nil
	}
}

// WithMaxBackoff sets the maximum backoff duration for connection retry attempts.
// The writer uses exponential backoff starting from 1 second up to this maximum.
// Default varies by writer configuration.
func WithMaxBackoff(maxBackoff time.Duration) WriterOption {
	return func(w *Writer) error {
		if maxBackoff <= 0 {
			return errors.Join(ErrInvalidTimeout, errors.New("maximum backoff must be > 0"))
		}
		w.maxBackoff = maxBackoff
		return nil
	}
}

// WithWriterErrorCallback sets the callback function for writer error notifications.
// The callback receives detailed error information with context strings describing
// where the error occurred (e.g., "failed to connect", "write failure").
// If nil, errors are not reported to the application.
func WithWriterErrorCallback(callback ErrorCallback) WriterOption {
	return func(w *Writer) error {
		w.onError = callback
		return nil
	}
}

// WithWriteBufferSize sets the kernel write buffer size (SO_SNDBUF).
// Larger buffers can improve performance by reducing kernel memory allocation overhead.
// Set to 0 to disable buffer size optimization and use system defaults.
// Default is 256KB.
func WithWriteBufferSize(size uint32) WriterOption {
	return func(w *Writer) error {
		w.writeBufferSize = size
		return nil
	}
}
