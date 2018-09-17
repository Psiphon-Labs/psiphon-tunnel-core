package marionette

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"sync"
	"time"

	"go.uber.org/zap"
)

var (
	// ErrStreamClosed is returned enqueuing cells or writing data to a closed stream.
	// Dequeuing cells and reading data will be available until pending data is exhausted.
	ErrStreamClosed = errors.New("marionette: stream closed")

	// ErrWriteTooLarge is returned when a Write() is larger than the buffer.
	ErrWriteTooLarge = errors.New("marionette: write too large")
)

// Ensure type implements interface.
var _ net.Conn = &Stream{}

// Stream represents a readable and writable connection for plaintext data.
// Data is injected into the stream using cells which provide ordering and payload data.
// Implements the net.Conn interface.
type Stream struct {
	mu   sync.RWMutex
	id   int
	rseq int
	wseq int

	// Read-side close management.
	ronce       sync.Once
	readClosed  bool
	readClosing chan struct{}

	// Write-side close management.
	wonce        sync.Once
	writeClosed  bool
	writeClosing chan struct{}

	// Notification when write-side has been closed.
	writeCloseNotified       bool
	writeCloseNotifiedNotify chan struct{}

	// Local & remote addresses for net.Conn implementation.
	localAddr  net.Addr
	remoteAddr net.Addr

	// Read & write buffer queues & notification.
	rbuf, wbuf []byte        // buffer pending processing
	rqueue     []*Cell       // cells processed from read buffer
	rnotify    chan struct{} // notification when read buffer changed
	wnotify    chan struct{} // notification when write buffer changed

	modTime time.Time // last change to read or write

	onWrite func() // callback when a new write buffer changes

	// Stream verbosely logs to trace writer when set.
	TraceWriter io.Writer
}

// NewStream returns a new stream with a givenZ
func NewStream(id int) *Stream {
	return &Stream{
		id:           id,
		rbuf:         make([]byte, 0, MaxCellLength),
		wbuf:         make([]byte, 0, MaxCellLength),
		readClosing:  make(chan struct{}),
		writeClosing: make(chan struct{}),
		rnotify:      make(chan struct{}),
		wnotify:      make(chan struct{}),
		modTime:      time.Now(),

		writeCloseNotifiedNotify: make(chan struct{}),
	}
}

// ID returns the stream id.
func (s *Stream) ID() int { return s.id }

// ModTime returns the last time a cell was added or removed from the stream.
func (s *Stream) ModTime() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.modTime
}

// ReadNotify returns a channel that receives a notification when a new read is available.
func (s *Stream) ReadNotify() <-chan struct{} {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.rnotify
}

func (s *Stream) notifyRead() {
	if s.TraceWriter != nil {
		fmt.Fprintf(s.TraceWriter, "[notifyRead]")
	}
	close(s.rnotify)
	s.rnotify = make(chan struct{})
}

// Read reads n bytes from the stream.
func (s *Stream) Read(b []byte) (n int, err error) {
	if s.TraceWriter != nil {
		s.TraceWriter.Write([]byte("[Read]"))
	}

	for {
		// Attempt to read from the buffer. Exit if bytes read or error.
		s.mu.Lock()
		if n, err = s.read(b); n != 0 || err != nil {
			s.mu.Unlock()
			return n, err
		} else if n == 0 && len(s.rqueue) == 0 && s.readClosed {
			s.rbuf = nil
			s.mu.Unlock()
			return 0, io.EOF
		}
		notify := s.rnotify

		s.processReadQueue()
		s.mu.Unlock()

		// Wait for notification of new read buffer bytes.
		select {
		case <-s.readClosing:
		case <-notify:
		}
	}
}

// read reads available bytes from read buffer to b.
func (s *Stream) read(b []byte) (n int, err error) {
	if len(s.rbuf) == 0 {
		return 0, nil
	}

	// Copy bytes to caller.
	n = len(b)
	if n > len(s.rbuf) {
		n = len(s.rbuf)
	}
	copy(b, s.rbuf)

	// Remove bytes from buffer.
	copy(s.rbuf, s.rbuf[n:])
	s.rbuf = s.rbuf[:len(s.rbuf)-n]

	return n, nil
}

// ReadBufferLen returns the number of bytes in the read buffer.
func (s *Stream) ReadBufferLen() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.rbuf)
}

// Write appends b to the write buffer. This method will continue to try until
// the entire byte slice is written atomically to the buffer.
func (s *Stream) Write(b []byte) (n int, err error) {
	if s.TraceWriter != nil {
		fmt.Fprintf(s.TraceWriter, "[Write] len=%d", len(b))
	}

	for {
		// Attempt to write to write buffer.
		// If no room available then wait for write buffer to change and try again.
		s.mu.Lock()
		if s.writeClosed {
			s.mu.Unlock()
			return 0, ErrStreamClosed
		} else if n, err = s.write(b); n != 0 || err != nil {
			s.notifyWrite()
			s.mu.Unlock()
			return n, err
		}
		notify := s.wnotify
		s.mu.Unlock()

		// Wait for a change in the write buffer.
		select {
		case <-s.writeClosing:
		case <-notify:
		}
	}
}

// write atomically writes b to the write buffer.
// Returns ErrWriteTooLarge if b is larger than write buffer capacity.
// Returns n=0 and no error if there is not enough space to write all of b.
func (s *Stream) write(b []byte) (n int, err error) {
	if len(b) > cap(s.wbuf) {
		return 0, ErrWriteTooLarge
	} else if len(b) > cap(s.wbuf)-len(s.wbuf) {
		return 0, nil // not enough space
	}

	// Copy bytes to the end of the write buffer.
	s.wbuf = s.wbuf[:len(s.wbuf)+len(b)]
	copy(s.wbuf[len(s.wbuf)-len(b):], b)
	return len(b), nil
}

// WriteNotify returns a channel that receives a notification when a new write is available.
func (s *Stream) WriteNotify() <-chan struct{} {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.wnotify
}

// notifyWrite closes previous write notify channel and creates a new one.
// This provides a broadcast for all interested parties.
func (s *Stream) notifyWrite() {
	if s.TraceWriter != nil {
		fmt.Fprintf(s.TraceWriter, "[notifyWrite]")
	}
	close(s.wnotify)
	s.wnotify = make(chan struct{})
}

// WriteBufferLen returns the number of bytes in the write buffer.
func (s *Stream) WriteBufferLen() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.wbuf)
}

// Enqueue pushes a cell's payload on to the stream if it is the next sequence.
// Out of sequence cells are added to the queue and are read after earlier cells.
func (s *Stream) Enqueue(cell *Cell) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.TraceWriter != nil {
		fmt.Fprintf(s.TraceWriter, "[Enqueue] seq=%d rseq=%d", cell.SequenceID, s.rseq)
	}

	// If sequence is a duplicate then ignore it.
	if cell.SequenceID < s.rseq {
		s.logger().Info("duplicate cell sequence",
			zap.Int("local", s.rseq),
			zap.Int("remote", cell.SequenceID))
		return nil // duplicate cell
	}

	// Add to queue & sort.
	s.rqueue = append(s.rqueue, cell)
	sort.Slice(s.rqueue, func(i, j int) bool { return s.rqueue[i].Compare(s.rqueue[j]) == -1 })

	// Process read queue to convert cells in the queue to bytes on the read buffer.
	s.processReadQueue()
	s.modTime = time.Now()

	return nil
}

// processReadQueue deserializes cells in the read queue and writes the bytes to
// the read buffer. Queue processing stops when the next cell does not match the
// next expected sequence or if there is not enough room left in the read buffer.
func (s *Stream) processReadQueue() {
	// Read all consecutive cells onto the buffer.
	var notify bool
	for len(s.rqueue) > 0 {
		cell := s.rqueue[0]
		if cell.SequenceID != s.rseq {
			break // out-of-order
		} else if len(cell.Payload) > cap(s.rbuf)-len(s.rbuf) {
			break // not enough space on buffer
		}

		// Extend buffer and copy cell payload.
		s.rbuf = s.rbuf[:len(s.rbuf)+len(cell.Payload)]
		copy(s.rbuf[len(s.rbuf)-len(cell.Payload):], cell.Payload)
		notify = true

		// Shift cell off queue and increment sequence.
		s.rqueue[0] = nil
		s.rqueue = s.rqueue[1:]
		s.rseq++

		// If this is the end of the stream then close out reads.
		if cell.Type == CellTypeEOS {
			if s.TraceWriter != nil {
				fmt.Fprintf(s.TraceWriter, "[eos:recv] seq=%d rseq=%d qlen=%d rbuf=%d", cell.SequenceID, s.rseq, len(s.rqueue), len(s.rbuf))
			}

			s.rqueue = nil
			s.closeRead()
		}
	}

	// Notify of read buffer change.
	if notify {
		s.notifyRead()
	}
}

// Dequeue reads n bytes from the write buffer and encodes it as a cell.
func (s *Stream) Dequeue(n int) *Cell {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.TraceWriter != nil {
		fmt.Fprintf(s.TraceWriter, "[Dequeue] n=%d", n)
	}

	// Exit immediately if stream has already notified that its writes are closed.
	if s.writeCloseNotified {
		return nil
	}

	// Determine the amount of data to read.
	if n == 0 {
		n = len(s.wbuf) + CellHeaderSize
	} else if n > MaxCellLength {
		n = MaxCellLength
	}

	// Determine next sequence.
	sequenceID := s.wseq
	s.wseq++
	s.modTime = time.Now()

	// End stream if there's no more data and it's marked as closed.
	if len(s.wbuf) == 0 && s.writeClosed {
		if s.TraceWriter != nil {
			fmt.Fprintf(s.TraceWriter, "[eos:send] seq=%d", sequenceID)
		}
		s.writeCloseNotified = true
		close(s.writeCloseNotifiedNotify)
		return NewCell(s.id, sequenceID, n, CellTypeEOS)
	}

	// Build cell.
	cell := NewCell(s.id, sequenceID, n, CellTypeNormal)

	// Determine payload size.
	payloadN := n - CellHeaderSize
	if payloadN > len(s.wbuf) {
		payloadN = len(s.wbuf)
	}

	// Copy buffer to payload
	if payloadN > 0 {
		cell.Payload = make([]byte, payloadN)
		copy(cell.Payload, s.wbuf[:payloadN])

		// Remove payload bytes from buffer.
		remaining := len(s.wbuf) - payloadN
		copy(s.wbuf[:remaining], s.wbuf[payloadN:len(s.wbuf)])
		s.wbuf = s.wbuf[:remaining]

		// Send notification that write buffer has changed.
		s.notifyWrite()
	}

	return cell
}

// Close marks the stream as closed for writes. The server will close the read side.
func (s *Stream) Close() error {
	return s.CloseWrite()
}

// CloseWrite marks the stream as closed for writes.
func (s *Stream) CloseWrite() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closeWrite()
	return nil
}

func (s *Stream) closeWrite() {
	s.writeClosed = true
	s.wonce.Do(func() { close(s.writeClosing) })
	s.notifyWrite()
}

// CloseRead marks the stream as closed for reads.
func (s *Stream) CloseRead() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closeRead()
	return nil
}

func (s *Stream) closeRead() {
	s.readClosed = true
	s.ronce.Do(func() { close(s.readClosing) })
}

// Closed returns true if the stream has been closed.
func (s *Stream) Closed() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.readClosed && s.writeClosed
}

// ReadClosed returns true if the stream has been closed for reads.
func (s *Stream) ReadClosed() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.readClosed
}

// ReadCloseNotify returns a channel that sends when the stream has been closed for writing.
func (s *Stream) ReadCloseNotify() <-chan struct{} { return s.readClosing }

// WriteClosed returns true if the stream has been requested to be closed for writes.
func (s *Stream) WriteClosed() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.writeClosed
}

// WriteCloseNotify returns a channel that sends when the stream has been closed for writing.
func (s *Stream) WriteCloseNotify() <-chan struct{} { return s.writeClosing }

// WriteCloseNotified returns true if the stream has notified the peer connection of the end of stream.
func (s *Stream) WriteCloseNotified() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.writeCloseNotified
}

func (s *Stream) WriteCloseNotifiedNotify() <-chan struct{} { return s.writeCloseNotifiedNotify }

// ReadWriteCloseNotified returns true if the stream is closed for read and write and has been notified.
func (s *Stream) ReadWriteCloseNotified() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.readClosed && s.writeCloseNotified
}

// LocalAddr returns the local address. Implements net.Conn.
func (c *Stream) LocalAddr() net.Addr { return c.localAddr }

// RemoteAddr returns the remote address. Implements net.Conn.
func (c *Stream) RemoteAddr() net.Addr { return c.remoteAddr }

// SetDeadline is a no-op. Implements net.Conn.
func (c *Stream) SetDeadline(t time.Time) error { return nil }

// SetReadDeadline is a no-op. Implements net.Conn.
func (c *Stream) SetReadDeadline(t time.Time) error { return nil }

// SetWriteDeadline is a no-op. Implements net.Conn.
func (c *Stream) SetWriteDeadline(t time.Time) error { return nil }

func (s *Stream) logger() *zap.Logger {
	return Logger.With(zap.Int("stream_id", s.id))
}

// streamExpVar is a wrapper for stream to generate expvar data.
type streamExpVar Stream

// String returns JSON representation of the expvar data.
func (s *streamExpVar) String() string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	buf, _ := json.Marshal(streamExpVarJSON{
		Rseq:   s.rseq,
		Wseq:   s.wseq,
		Rbuf:   len(s.rbuf),
		Wbuf:   len(s.wbuf),
		Rqueue: len(s.rqueue),
	})
	return string(buf)
}

// streamExpVarJSON is the JSON representation of a stream in expvar.
type streamExpVarJSON struct {
	Rseq   int `json:"rseq"`
	Wseq   int `json:"wseq"`
	Rbuf   int `json:"rbuf"`
	Wbuf   int `json:"wbuf"`
	Rqueue int `json:"rqueue"`
}
