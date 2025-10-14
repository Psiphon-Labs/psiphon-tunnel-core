# UDS-IPC

[![Go Reference](https://pkg.go.dev/badge/github.com/Psiphon-Inc/uds-ipc.svg)](https://pkg.go.dev/github.com/Psiphon-Inc/uds-ipc)
[![Go Report Card](https://goreportcard.com/badge/github.com/Psiphon-Inc/uds-ipc)](https://goreportcard.com/report/github.com/Psiphon-Inc/uds-ipc)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

A Go library for inter-process communication using Unix Domain Sockets with length-prefixed message framing, backpressure handling, and automatic reconnection. Extensively optimized for minimal memory allocation and maximum throughput.

## Features

- **Length-prefixed messaging**: Reliable message boundaries using varint encoding
- **Backpressure handling**: Non-blocking writes with configurable buffering
- **Automatic reconnection**: Built-in connection recovery with exponential backoff and write retry
- **Performance optimized**: Vectored I/O, buffer pooling, and socket buffer tuning
- **Systemd integration**: Automatic socket activation support
- **Graceful shutdown**: Context-controlled shutdown with timeout support for clean draining
- **Internal metrics**: Message counts, error tracking, and queue depth monitoring
- **Zero external dependencies**: Uses only Go standard library
- **Tested**: Comprehensive test suite with race detection and benchmarks

## Installation

```bash
go get github.com/Psiphon-Inc/uds-ipc
```

## Quick Start

### Basic Usage

```go
package main

import (
    "context"
    "fmt"
    "log"
    "time"

    "github.com/Psiphon-Inc/uds-ipc"
)

func main() {
    socketPath := "/tmp/myapp.sock"
    
    // Create reader (server).
    reader, err := udsipc.NewReader(
        func(data []byte) error {
            fmt.Printf("Received: %s\n", data)
            return nil
        },
        socketPath,
    )
    if err != nil {
        log.Fatal(err)
    }
    defer reader.Stop(context.Background())

    // Create writer (client).
    writer, err := udsipc.NewWriter(socketPath)
    if err != nil {
        log.Fatal(err)
    }
    defer writer.Stop(context.Background())
    
    // Start components.
    if err := reader.Start(); err != nil {
        log.Fatal(err)
    }
    writer.Start()
    
    // Give reader time to start.
    time.Sleep(100 * time.Millisecond)
    
    // Send messages (returns error if queue is full).
    if err := writer.WriteMessage([]byte("Hello, UDS!")); err != nil {
        log.Printf("Failed to queue message: %v", err)
    }
    if err := writer.WriteMessage([]byte("Another message")); err != nil {
        log.Printf("Failed to queue message: %v", err)
    }
    
    // Allow time for processing.
    time.Sleep(100 * time.Millisecond)
}
```

### Advanced Configuration

```go
// Reader with custom options.
reader, err := udsipc.NewReader(
    messageHandler,
    socketPath,
    udsipc.WithMaxMessageSize(1024*1024),         // 1MB max message.
    udsipc.WithInactivityTimeout(30*time.Second), // Close idle connections.
    udsipc.WithReadBufferSize(512*1024),          // 512KB read buffer.
    udsipc.WithReaderErrorCallback(errorHandler),
)

// Writer with custom options.
writer, err := udsipc.NewWriter(
    socketPath,
    udsipc.WithMaxBufferedWrites(50000),          // 50k message queue.
    udsipc.WithWriteTimeout(5*time.Second),       // Per-write timeout.
    udsipc.WithWriteBufferSize(256*1024),         // 256KB write buffer.
    udsipc.WithWriterErrorCallback(errorHandler),
)
```

## Performance

### Optimization Features

- **Message buffer pooling**: Reuses 4KB buffers to eliminate allocations for small messages
- **BufIO reader pooling**: Reuses buffered readers across connections
- **Vectored I/O buffer pooling**: Reuses net.Buffers slices for write operations
- **Write retry logic**: Failed writes are buffered and retried on reconnect, blocking new writes until successful
- **Socket buffer tuning**: Configurable kernel buffers to optimize network performance

### Benchmark Results

```
BenchmarkReaderWriter/SmallMessages_1KB-48        684.82 MB/s    24 B/op    1 allocs/op
BenchmarkReaderWriter/MediumMessages_10KB-48      2477.98 MB/s   10279 B/op 2 allocs/op  
BenchmarkReaderWriter/LargeMessages_100KB-48      4636.78 MB/s   106983 B/op 2 allocs/op
BenchmarkReadOnly-48                               675.21 MB/s    23 B/op    0 allocs/op
BenchmarkWriteOnly-48                              84717.89 MB/s  0 B/op     0 allocs/op
```

### Memory Optimization Results

- **Small messages (≤4KB)**: Zero heap allocations using buffer pools
- **Medium messages**: Minimal allocation overhead (10KB messages = 10KB + 279 bytes overhead)
- **Large messages**: Linear scaling with message size, no additional overhead

## Systemd Integration

The library automatically detects and uses systemd socket activation:

```ini
# /etc/systemd/system/myapp.socket  
[Unit]
Description=MyApp Socket

[Socket]
ListenStream=/run/myapp/myapp.sock
SocketUser=myapp
SocketMode=0660

[Install]
WantedBy=sockets.target
```

```bash
systemctl enable myapp.socket
systemctl start myapp.socket
```

## Message Protocol

Messages use varint length prefixes for efficient parsing:

```
┌────────────────┬──────────────────┐
│ Length(varint) │   Message Data   │
└────────────────┴──────────────────┘
```

- Length is encoded as a varint (1-10 bytes)
- Maximum message size is configurable (default: 10MB)
- Zero-length messages are supported
- Protocol overhead is minimal: ~0.1% for 1KB+ messages

## Best Practices

### Resource Management

```go
// Always defer Stop() calls with appropriate context
defer reader.Stop(context.Background())
defer writer.Stop(context.Background())

// Start() and Stop() are idempotent and safe to call multiple times
reader.Start()  // Safe to call multiple times
reader.Stop(context.Background())   // Safe to call multiple times

// For controlled shutdown with timeout
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()
reader.Stop(ctx)  // Gracefully drain for up to 5 seconds, then force shutdown
writer.Stop(ctx)  // Drain buffered messages for up to 5 seconds, then discard remaining
```

### Error Handling

```go
// Handle WriteMessage errors when queue is full
if err := writer.WriteMessage(data); err != nil {
    if errors.Is(err, udsipc.ErrBufferFull) {
        log.Printf("Message dropped: queue is full")
        // Consider implementing retry logic or backoff
    }
}

// Monitor metrics for health checking
sent, dropped, failed, queueDepth := writer.GetMetrics()
if dropped > 0 {
    log.Printf("Warning: %d messages dropped due to backpressure", dropped)
}

// Use error callbacks for monitoring
writer, err := udsipc.NewWriter(socketPath,
    udsipc.WithWriterErrorCallback(func(err error, context string) {
        log.Printf("Writer error in %s: %v", context, err)
    }),
)
```

### Performance Tuning

```go
// For high-throughput scenarios
writer, err := udsipc.NewWriter(socketPath,
    udsipc.WithMaxBufferedWrites(100000),  // Larger queue
    udsipc.WithWriteBufferSize(1024*1024), // 1MB socket buffer
)

reader, err := udsipc.NewReader(handler, socketPath,
    udsipc.WithReadBufferSize(1024*1024),  // 1MB socket buffer  
)
```

### Message Handler Safety

```go
// IMPORTANT: MessageHandler must NOT retain references to the data slice
func messageHandler(data []byte) error {
    // GOOD: Copy data if you need to retain it
    message := make([]byte, len(data))
    copy(message, data)
    
    // GOOD: Process data immediately
    return processMessage(data)
    
    // BAD: Don't store references to data
    // storedData = data  // This will cause corruption!
}
```

## Testing

```bash
# Run all tests
go test ./...

# Run with race detection  
go test -race ./...

# Run benchmarks
go test -bench=. -benchmem -run=^$

# Run specific test categories
go test -run=TestReader
go test -run=TestWriter  
go test -run=TestIntegration

# Generate coverage report
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Ensure there are tests covering any new functionality
4. Run the full test suite (`go test -race ./...`)
5. Run benchmarks to ensure no performance regressions
6. Commit your changes (`git commit -am 'Add amazing feature'`)
7. Push to the branch (`git push origin feature/amazing-feature`)
8. Open a Pull Request

### Performance Contributions

If making performance-related changes, please include benchmark comparisons:

```bash
# Before your changes
go test -bench=BenchmarkReaderWriter -benchmem -count=5 > before.txt

# After your changes  
go test -bench=BenchmarkReaderWriter -benchmem -count=5 > after.txt

# Compare results
benchcmp before.txt after.txt
```

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.
