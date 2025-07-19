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

// ReaderOption is the functional option type for Reader.
type ReaderOption func(r *Reader) error

// WithMaxMessageSize sets the maximum size for incoming messages.
// Messages larger than this size will be rejected and cause the connection to close.
// Default is 10MB.
func WithMaxMessageSize(size uint64) ReaderOption {
	return func(r *Reader) error {
		r.maxMessageSize = size
		return nil
	}
}

// WithInactivityTimeout sets the timeout for connection inactivity.
// If no message is received within this duration, the connection will timeout and close.
// This timeout slides forward with each received message.
// Default is 10 seconds.
func WithInactivityTimeout(timeout time.Duration) ReaderOption {
	return func(r *Reader) error {
		if timeout <= 0 {
			return errors.Join(ErrInvalidTimeout, errors.New("inactivity timeout must be > 0"))
		}

		r.inactivityTimeout = timeout
		return nil
	}
}

// WithReaderErrorCallback sets the callback function for reader error notifications.
// The callback receives detailed error information with context strings describing
// where the error occurred (e.g., "failed to read the length prefix").
// If nil, errors are not reported to the application.
func WithReaderErrorCallback(callback ErrorCallback) ReaderOption {
	return func(r *Reader) error {
		r.onError = callback
		return nil
	}
}

// WithMaxAcceptErrors sets the maximum number of consecutive accept errors
// before the reader stops accepting new connections.
// This prevents infinite error loops when the listener is persistently failing.
// Must be <= 63 to prevent overflow in exponential backoff calculation.
// Default is 10.
func WithMaxAcceptErrors(maxErrors int) ReaderOption {
	return func(r *Reader) error {
		if maxErrors > 63 { // nolint: mnd // See doc comment.
			return ErrMaxAcceptErrorsTooLarge
		}

		r.maxAcceptErrors = maxErrors
		return nil
	}
}

// WithReadBufferSize sets the kernel read buffer size (SO_RCVBUF).
// Larger buffers can improve performance by reducing kernel memory allocation overhead.
// Set to 0 to disable buffer size optimization and use system defaults.
// Default is 256KB.
func WithReadBufferSize(size uint32) ReaderOption {
	return func(r *Reader) error {
		r.readBufferSize = size
		return nil
	}
}
