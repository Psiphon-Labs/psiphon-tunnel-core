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
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// Use a buffer pool for message allocation to reduce GC pressure.
const maxPooledMessageSize = 4096

// messageBuffer wraps a fixed-size array to enable pooling without heap allocation.
type messageBuffer struct {
	data [maxPooledMessageSize]byte
}

// messageBufferPool pools messageBuffer instances to reduce allocations.
// nolint: gochecknoglobals // Pools are package-global for efficiency.
var messageBufferPool = sync.Pool{
	New: func() any {
		return &messageBuffer{}
	},
}

// bufioReaderPool pools bufio.Reader instances to reduce allocations.
// nolint: gochecknoglobals // Pools are package-global for efficiency.
var bufioReaderPool = sync.Pool{
	New: func() any {
		return bufio.NewReader(nil)
	},
}

var (
	ErrInvalidLengthPrefix     = errors.New("invalid length prefix")
	ErrConnectionClosed        = errors.New("connection closed")
	ErrHandlerFailed           = errors.New("handler failed")
	ErrHandlerNil              = errors.New("handler cannot be nil")
	ErrMaxAcceptErrorsTooLarge = errors.New("maxAcceptErrors must be <= 63 to prevent overflow")
	ErrInvalidSocketPath       = errors.New("invalid socket path")
)

// MessageHandler implementations process received messages.
// MessageHandler's MUST NOT retain references to the passed slice.
// If a MessageHandler needs to retain the data from this slice, it MUST copy it.
// This restriction is because the passed slice is retrieved from a buffer pool prior to
// being passed to the handler and returned to the pool for reuse when the handler returns.
type MessageHandler func(data []byte) error

// Reader receives length-prefixed messages via Unix domain socket.
// nolint: govet
type Reader struct {
	handler           MessageHandler
	onError           ErrorCallback
	systemd           *SystemdManager
	listener          net.Listener
	socketPath        string
	shutdownStart     chan struct{} // Signals running→stopping transition.
	shutdownForced    chan struct{} // Signals stopping→stopped forcefully.
	maxMessageSize    uint64
	receivedCount     uint64 // Successfully processed messages.
	connectionCount   uint64 // Total connections accepted.
	errorCount        uint64 // Handler or protocol errors.
	inactivityTimeout time.Duration
	wg                sync.WaitGroup
	closeOnce         sync.Once
	readBufferSize    uint32 // Size of kernel read buffer (SO_RCVBUF).
	maxAcceptErrors   int
}

// NewReader creates a new reader with optional systemd integration.
// nolint: gocognit
func NewReader(handler MessageHandler, fallbackSocketPath string, opts ...ReaderOption) (*Reader, error) {
	if handler == nil {
		return nil, ErrHandlerNil
	}

	if fallbackSocketPath == "" {
		return nil, fmt.Errorf("%w: empty path", ErrInvalidSocketPath)
	}

	// nolint: mnd // Default values.
	r := &Reader{
		handler:           handler,
		maxMessageSize:    10 << 20, // 10MB.
		inactivityTimeout: 10 * time.Second,
		maxAcceptErrors:   10,
		readBufferSize:    256 << 10, // 256KB.
		shutdownStart:     make(chan struct{}),
		shutdownForced:    make(chan struct{}),
	}

	for _, opt := range opts {
		if err := opt(r); err != nil {
			return nil, fmt.Errorf("failed to apply option: %w", err)
		}
	}

	systemd, err := NewSystemdManager()
	if err != nil {
		return nil, fmt.Errorf("failed to set up systemd manager: %w", err)
	}

	r.systemd = systemd

	r.socketPath = ResolveSocketPath(systemd, fallbackSocketPath)
	if len(r.socketPath) > MaxSocketPathLength() {
		return nil, fmt.Errorf("%w: socket path too long: %s", ErrInvalidSocketPath, r.socketPath)
	}

	// Try to get systemd-provided listener first, falling back to creating one directly.
	r.listener = systemd.GetSystemdListener()

	if r.listener == nil {
		if err = EnsureSocketDir(r.socketPath); err != nil {
			return nil, fmt.Errorf("failed to create socket directory: %w", err)
		}

		if err = CleanupSocket(r.socketPath); err != nil {
			return nil, fmt.Errorf("failed to clean up previous socket: %w", err)
		}

		r.listener, err = net.Listen("unix", r.socketPath) // nolint: noctx
		if err != nil {
			return nil, fmt.Errorf("failed to listen on socket: %w", err)
		}
	}

	if r.readBufferSize > 0 {
		if unixListener, ok := r.listener.(*net.UnixListener); ok {
			// Set read buffer on the listening socket.
			if file, err := unixListener.File(); err == nil { //nolint: govet // Safely shadowed error.
				defer file.Close()
				fd := int(file.Fd())
				// Use syscall to set SO_RCVBUF on the listening socket.
				//
				// As per: https://www.man7.org/linux/man-pages/man7/unix.7.html,
				// setting SO_RCVBUF has no effect on streaming UDS sockets on Linux.
				//  > The SO_SNDBUF socket option does have an effect for UNIX domain
				//  > sockets, but the SO_RCVBUF option does not.  For datagram sockets,
				//  > the SO_SNDBUF value imposes an upper limit on the size of outgoing
				//  > datagrams.
				//
				// As per: https://man.freebsd.org/cgi/man.cgi?setsockopt(2),
				// setting SO_RCVBUF does set the buffer size for input on BSD.
				// An assumption is made that other BSDs (and derivatives like Darwin)
				// will have the same behavior as FreeBSD.
				//  > SO_SNDBUF and SO_RCVBUF are options to adjust the normal buffer sizes
				//  > allocated for output and input buffers,	respectively. The buffer size
				//  > may be increased for high-volume connections, or may be decreased to
				//  > limit the possible backlog of incoming data. The system places an ab-
				//  > solute maximum on these values, which is accessible through the
				//  > sysctl(3) MIB variable "kern.ipc.maxsockbuf".
				//
				// This syscall safely no-ops on Linux sockets, so no platform
				// detection logic or conditional calling is necessary.
				_ = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, int(r.readBufferSize))
			}
		}
	}

	return r, nil
}

// GetMetrics returns current counter values and connection info.
func (r *Reader) GetMetrics() (uint64, uint64, uint64) {
	return atomic.LoadUint64(&r.receivedCount),
		atomic.LoadUint64(&r.connectionCount),
		atomic.LoadUint64(&r.errorCount)
}

// Start begins listening for connections.
func (r *Reader) Start() error {
	if r.systemd.IsSystemd() {
		if err := r.systemd.NotifyReady(); err != nil {
			return fmt.Errorf("failed to notify systemd ready socket: %w", err)
		}
	}

	r.wg.Add(1)
	go r.run()

	return nil
}

// Stop shuts down the reader gracefully, allowing in-flight messages to complete
// until the provided context is cancelled or expires. Subsequent calls return nil.
func (r *Reader) Stop(ctx context.Context) error {
	var err error

	r.closeOnce.Do(func() {
		close(r.shutdownStart)

		// Unix domain socket Accept() doesn't seem to respect SetDeadline.
		// Force the blocked Accept() to return by connecting to ourselves.
		if r.listener != nil {
			go func() {
				//nolint: mnd // Brief delay to ensure r.shutdownStart channel is processed first.
				time.Sleep(10 * time.Millisecond)
				if conn, dialErr := net.Dial("unix", r.socketPath); dialErr == nil { // nolint: noctx
					_ = conn.Close()
				}
			}()
		}

		// Monitor context and abort drain if context is cancelled or expires.
		stopComplete := make(chan struct{})
		go func() {
			select {
			case <-ctx.Done():
				// Context cancelled or expired - force immediate shutdown.
				close(r.shutdownForced)
			case <-stopComplete:
				// Clean shutdown completed before context cancellation/expiration.
			}
		}()

		// Wait for all goroutines to finish before closing the listener.
		// This prevents a race condition where SetDeadline() is called
		// on an invalid file descriptor (as warned in os.File.Fd docs).
		r.wg.Wait()

		// Signal context monitor that we're done.
		close(stopComplete)

		if r.systemd.IsSystemd() {
			// r.systemd.Close will close the listener internally.
			// The file lifecycle of systemd managed sockets is handled by
			// systemd itself, so we don't have to remove the socket file.
			if systemdErr := r.systemd.Close(); systemdErr != nil {
				err = errors.Join(err, systemdErr)
			}
		} else {
			if r.listener != nil {
				err = r.listener.Close()
			}

			if cleanupErr := CleanupSocket(r.socketPath); cleanupErr != nil {
				err = errors.Join(err, cleanupErr)
			}
		}
	})

	return err
}

// run is the main accept loop.
func (r *Reader) run() {
	defer r.wg.Done()

	consecutiveErrors := 0
	for {
		conn, err := r.listener.Accept()
		if err != nil {
			select {
			case <-r.shutdownStart:
				return
			default:
				consecutiveErrors++

				if consecutiveErrors > r.maxAcceptErrors {
					if r.onError != nil {
						r.onError(err, "too many consecutive failures in accept loop")
					}
					return
				}

				// nolint: mnd // Fixed 100ms sleep to prevent busy looping on Accept errors
				time.Sleep(100 * time.Millisecond)
			}

			continue
		}

		// Reset error count on successful accept.
		consecutiveErrors = 0
		atomic.AddUint64(&r.connectionCount, 1)

		// Check for shutdown after successful accept as well.
		select {
		case <-r.shutdownStart:
			_ = conn.Close()
			return
		default:
		}

		r.wg.Add(1)
		go r.handleConnection(conn)
	}
}

// handleConnection processes length-prefixed messages from a connection.
// nolint: gocognit,funlen
func (r *Reader) handleConnection(conn net.Conn) {
	defer r.wg.Done()
	defer conn.Close() // nolint: errcheck // Nothing to do with this error.

	if r.readBufferSize > 0 {
		if unixConn, ok := conn.(*net.UnixConn); ok {
			// Optimize read buffer for this connection.
			_ = unixConn.SetReadBuffer(int(r.readBufferSize))
		}
	}

	// Get pooled bufio.Reader and reset it for this connection.
	reader, _ := bufioReaderPool.Get().(*bufio.Reader)
	reader.Reset(conn)
	defer bufioReaderPool.Put(reader)

	draining := false

	for {
		select {
		case <-r.shutdownStart:
			draining = true
		case <-r.shutdownForced:
			// Forced shutdown - exit immediately without processing further messages.
			// IMPORTANT: This cannot interrupt an already-executing handler. If the handler
			// is blocking (e.g., in time.Sleep or blocking I/O), this goroutine will wait
			// for it to complete before returning. An open connection that continues to
			// write messages while the handler is blocked will cause this goroutine to
			// remain blocked indefinitely until the handler completes or the connection
			// closes. To prevent this, ensure handlers are responsive and don't block
			// indefinitely, or ensure clients close connections promptly on shutdown.
			return
		default:
		}

		// Set read deadline based on shutdown state.
		// Potential errors are ignored because there is nothing to do with them.
		var deadline time.Time

		if !draining {
			// Normal operation - set inactivity timeout to close idle connections.
			deadline = time.Now().Add(r.inactivityTimeout)
		} else {
			// Draining - add a short inactivity timeout to allow continued reading of
			// data from the socket while draining (using time.Now() is too fast).
			// nolint: mnd
			deadline = time.Now().Add(time.Millisecond)
		}

		_ = conn.SetReadDeadline(deadline)

		length, err := binary.ReadUvarint(reader)
		if err != nil {
			if errors.Is(err, io.EOF) {
				// Client closed the connection.
				return
			}

			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				// Close idle connections after inactivity timeout.
				return
			}

			// Neither the client closing the connection nor closing idle
			// connections after they reach timeout should incremenet the
			// error count, so only do it once those checks have happened.
			atomic.AddUint64(&r.errorCount, 1)

			if r.onError != nil {
				r.onError(err, "failed to read the length prefix")
			}

			return
		}

		if length > r.maxMessageSize {
			atomic.AddUint64(&r.errorCount, 1)
			if r.onError != nil {
				r.onError(fmt.Errorf("invalid message size: %d: exceeds limit: %d", length, r.maxMessageSize), "message too large")
			}

			return
		}

		if length < 1 {
			// Empty messages aren't sent by this package's writer, but
			// if we receive one, there is no need to treat it as an error.
			// There is nothing else to be done with this message.
			continue
		}

		// Read message bytes with known length.
		var message []byte
		var msgBuf *messageBuffer

		if length <= maxPooledMessageSize {
			// Use pooled buffer for small messages.
			msgBuf, _ = messageBufferPool.Get().(*messageBuffer)
			message = msgBuf.data[:length]
		} else {
			// Fall back to heap allocation for large messages.
			message = make([]byte, length)
		}

		if _, err := io.ReadFull(reader, message); err != nil { //nolint: govet // Safely shadowed error.
			if msgBuf != nil {
				messageBufferPool.Put(msgBuf)
			}

			atomic.AddUint64(&r.errorCount, 1)
			if r.onError != nil {
				r.onError(err, "failed to read the complete message")
			}

			return
		}

		if err := r.handler(message); err != nil { //nolint: govet // Safely shadowed error.
			if msgBuf != nil {
				messageBufferPool.Put(msgBuf)
			}

			atomic.AddUint64(&r.errorCount, 1)
			if r.onError != nil {
				r.onError(err, "handler failed to process a message")
			}

			// Don't close connection for handler errors on individual messages.
			continue
		}

		// Return buffer to pool after successful processing.
		if msgBuf != nil {
			messageBufferPool.Put(msgBuf)
		}

		atomic.AddUint64(&r.receivedCount, 1)
	}
}
