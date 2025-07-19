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

// Package udsipc provides performance Unix Domain Socket (UDS) inter-process communication.
//
// This package implements a client-server communication system over UDS
// with built-in (but optional) support for systemd socket activation,
// automatic reconnection with exponential backoff, write retry logic,
// and comprehensive error reporting.
//
// # Basic Usage
//
// Create a reader to receive messages using functional options:
//
//	reader, err := udsipc.NewReader(
//		func(data []byte) error {
//			// IMPORTANT: Do not retain references to data slice!
//			// Copy data if you need to store it beyond this function.
//			fmt.Printf("Received: %s\n", data)
//			return nil
//		},
//		"/tmp/ipc.sock",                             // fallback socket path
//		udsipc.WithMaxMessageSize(1024*1024),         // max message size (1MB)
//		udsipc.WithInactivityTimeout(30*time.Second), // close idle connections
//		udsipc.WithReaderErrorCallback(errorHandler), // error callback
//		udsipc.WithMaxAcceptErrors(10),               // max consecutive accept errors
//	)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	if err := reader.Start(); err != nil {
//		log.Fatal(err)
//	}
//	defer reader.Stop()
//
// Create a writer to send messages using functional options:
//
//	writer, err := udsipc.NewWriter(
//		"/tmp/ipc.sock",                                // socket path
//		udsipc.WithWriterErrorCallback(errorHandler),   // error callback
//		udsipc.WithWriteTimeout(5*time.Second),         // write timeout
//		udsipc.WithDialTimeout(2*time.Second),          // dial timeout
//		udsipc.WithMaxBackoff(30*time.Second),          // max backoff
//		udsipc.WithMaxBufferedWrites(1000),             // max buffered writes
//	)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	writer.Start()
//	defer writer.Stop()
//
//	// Send messages (non-blocking)
//	writer.WriteMessage([]byte("hello world"))
//
// # API Design
//
// Both Reader and Writer use a simple Start()/Stop() lifecycle pattern:
//
//   - Start() begins operation (non-blocking for Writer, may return error for Reader)
//   - Stop() gracefully shuts down and waits for cleanup
//   - Both methods are idempotent and safe to call multiple times
//   - No context management required - the library handles internal coordination
//
// # Functional Options
//
// Both constructors use functional options for configuration flexibility:
//
// Reader options:
//
//   - [WithMaxMessageSize](size uint64): Set maximum message size (default: 10MB)
//   - [WithInactivityTimeout](timeout time.Duration): Close idle connections (default: 10s)
//   - [WithReaderErrorCallback](callback ErrorCallback): Set error callback
//   - [WithMaxAcceptErrors](maxErrors int): Set max consecutive accept errors (default: 10)
//   - [WithReadBufferSize](size uint32): Set socket read buffer size (default: 256KB)
//
// Writer options:
//
//   - [WithMaxBufferedWrites](size uint32): Set message channel buffer size (default: 10,000)
//   - [WithWriteTimeout](timeout time.Duration): Set write timeout (default: 1s)
//   - [WithDialTimeout](timeout time.Duration): Set connection timeout (default: 1s)
//   - [WithMaxBackoff](maxBackoff time.Duration): Set max retry backoff (default: 10s)
//   - [WithWriterErrorCallback](callback ErrorCallback): Set error callback
//   - [WithWriteBufferSize](size uint32): Set socket write buffer size (default: 256KB)
//
// # Systemd Integration
//
// The package automatically detects systemd environments and uses socket
// activation when available. When running under systemd with socket
// activation, the reader will use the pre-configured listener instead
// of creating its own socket.
//
// Environment variables used for systemd detection:
//
//   - RUNTIME_DIRECTORY: systemd runtime directory
//   - STATE_DIRECTORY: systemd state directory
//   - LISTEN_FDS: number of file descriptors passed by systemd
//   - LISTEN_PID: process ID that should receive the file descriptors
//   - NOTIFY_SOCKET: socket for systemd notifications
//
// # Error Handling
//
// Both Reader and Writer accept optional ErrorCallback functions
// to handle various error conditions:
//
//	errorHandler := func(err error, context string) {
//		log.Printf("Error in %s: %v", context, err)
//		// Implement custom error handling logic.
//	}
//
// # Protocol
//
// Messages are sent using a length-prefixed protocol:
//  1. Variable-length integer (varint) indicating message length
//  2. Message bytes of the specified length
//
// This ensures reliable message framing and supports messages up to the
// configured maximum size. Protocol overhead is minimal (~0.1% for 1KB+ messages).
//
// # MessageHandler Safety
//
// MessageHandler implementations must NOT retain references to the data slice passed to them.
// The slice is backed by pooled buffers that are reused after the handler returns.
// If you need to retain the data, make a copy:
//
//	func handler(data []byte) error {
//		// GOOD: Copy if you need to retain.
//		msg := make([]byte, len(data))
//		copy(msg, data)
//
//		// GOOD: Process immediately.
//		return process(data)
//
//		// BAD: Don't store references.
//		// global = data  // This risks message corruption via buffer reuse
//	}
//
// # Thread Safety
//
// All types in this package are safe for concurrent use. Multiple goroutines
// can safely call WriteMessage() concurrently, and all methods are protected
// by appropriate synchronization mechanisms.
//
// # Metrics and Monitoring
//
// Both Reader and Writer provide comprehensive metrics:
//
//	// Reader metrics
//	received, connections, errors := reader.GetMetrics()
//
//	// Writer metrics
//	sent, dropped, failed, queueDepth := writer.GetMetrics()
//
// Use these metrics for health monitoring, alerting, and performance analysis.
package udsipc
