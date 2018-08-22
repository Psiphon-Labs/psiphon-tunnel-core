package marionette

import (
	"expvar"
	"fmt"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"go.uber.org/zap"
)

const (
	// StreamCloseTimeout is the amount of time before an idle read-closed or
	// write-closed stream is reaped by a monitoring goroutine.
	StreamCloseTimeout = 5 * time.Second
)

// evStreams is a global expvar variable for tracking open streams.
var evStreams = expvar.NewInt("streams")

// StreamSet represents a multiplexer for a set of streams for a connection.
type StreamSet struct {
	mu        sync.RWMutex
	streams   map[int]*Stream // streams by id
	streamIDs []int           // cached list of all stream ids
	wnotify   chan struct{}   // notification of write changes

	// Close management
	closing chan struct{}
	once    sync.Once
	wg      sync.WaitGroup

	// Callback executed when a new stream is created.
	OnNewStream func(*Stream)

	// Directory for storing stream traces.
	TracePath string
}

// NewStreamSet returns a new instance of StreamSet.
func NewStreamSet() *StreamSet {
	ss := &StreamSet{
		streams: make(map[int]*Stream),
		closing: make(chan struct{}),
		wnotify: make(chan struct{}),
	}
	return ss
}

// Close closes all streams in the set.
func (ss *StreamSet) Close() (err error) {
	ss.mu.Lock()
	for _, stream := range ss.streams {
		if e := stream.CloseWrite(); e != nil && err == nil {
			err = e
		} else if e := stream.CloseRead(); e != nil && err == nil {
			err = e
		}
	}
	ss.mu.Unlock()

	ss.once.Do(func() { close(ss.closing) })
	ss.wg.Wait()
	return err
}

// monitorStream checks a stream until its read & write channels are closed
// and then removes the stream from the set.
func (ss *StreamSet) monitorStream(stream *Stream) {
	readCloseNotify := stream.ReadCloseNotify()
	writeCloseNotifiedNotify := stream.WriteCloseNotifiedNotify()
	var timeout <-chan time.Time

LOOP:
	for {
		// Wait until stream closed state is changed or the set is closed.
		select {
		case <-ss.closing:
			break LOOP
		case <-timeout:
			break LOOP
		case <-readCloseNotify:
			readCloseNotify = nil
			timeout = time.After(StreamCloseTimeout)
		case <-writeCloseNotifiedNotify:
			writeCloseNotifiedNotify = nil
			timeout = time.After(StreamCloseTimeout)
		}

		// If stream is completely closed then remove from the set.
		if stream.ReadWriteCloseNotified() {
			break
		}
	}

	// Ensure both sides are closed.
	stream.CloseRead()
	stream.CloseWrite()

	ss.mu.Lock()
	ss.remove(stream)
	ss.mu.Unlock()
}

// Stream returns a stream by id.
func (ss *StreamSet) Stream(id int) *Stream {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	return ss.streams[id]
}

// Streams returns a list of streams.
func (ss *StreamSet) Streams() []*Stream {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	streams := make([]*Stream, 0, len(ss.streams))
	for _, stream := range ss.streams {
		streams = append(streams, stream)
	}
	return streams
}

// Create returns a new stream with a random stream id.
func (ss *StreamSet) Create() *Stream {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	return ss.create(0)
}

func (ss *StreamSet) create(id int) *Stream {
	if id == 0 {
		id = int(rand.Int31() + 1)
	}

	stream := NewStream(id)

	// Create a per-stream log if trace path is specified.
	if ss.TracePath != "" {
		path := filepath.Join(ss.TracePath, strconv.Itoa(id))
		if err := os.MkdirAll(ss.TracePath, 0777); err != nil {
			Logger.Warn("cannot create trace directory", zap.Error(err))
		} else if w, err := os.Create(path); err != nil {
			Logger.Warn("cannot create trace file", zap.Error(err))
		} else {
			fmt.Fprintf(w, "# STREAM %d\n\n", id)
			stream.TraceWriter = &timestampWriter{Writer: w}
		}
		stream.TraceWriter.Write([]byte("[create]"))
	}

	// Add stream to set.
	ss.streams[stream.id] = stream
	ss.streamIDs = append(ss.streamIDs, stream.id)

	// Add to global counter.
	evStreams.Add(1)

	// Monitor each stream closing in a separate goroutine.
	ss.wg.Add(1)
	go func() { defer ss.wg.Done(); ss.monitorStream(stream) }()

	// Monitor read/write changes in a separate goroutine per stream.
	ss.wg.Add(1)
	go func() { defer ss.wg.Done(); ss.handleStream(stream) }()

	// Execute callback, if exists.
	if ss.OnNewStream != nil {
		ss.OnNewStream(stream)
	}

	return stream
}

// remove removes stream from the set and decrements open stream count.
// This must be called under lock.
func (ss *StreamSet) remove(stream *Stream) {
	streamID := stream.ID()

	evStreams.Add(-1)

	if stream.TraceWriter != nil {
		stream.TraceWriter.Write([]byte("[remove]"))
		if traceWriter, ok := stream.TraceWriter.(io.Closer); ok {
			traceWriter.Close()
		}
	}
	delete(ss.streams, streamID)

	for i, id := range ss.streamIDs {
		if id == streamID {
			ss.streamIDs = append(ss.streamIDs[:i], ss.streamIDs[i+1:]...)
		}
	}
}

// Enqueue pushes a cell onto a stream's read queue.
// If the stream doesn't exist then it is created.
func (ss *StreamSet) Enqueue(cell *Cell) error {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	// Ignore empty cells.
	if cell.StreamID == 0 {
		return nil
	}

	// Create or find stream and enqueue cell.
	stream := ss.streams[cell.StreamID]
	if stream == nil {
		stream = ss.create(cell.StreamID)
	}
	return stream.Enqueue(cell)
}

// Dequeue returns a cell containing data for a random stream's write buffer.
func (ss *StreamSet) Dequeue(n int) *Cell {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	// Choose a random stream with data.
	var stream *Stream
	for _, i := range rand.Perm(len(ss.streamIDs)) {
		s := ss.streams[ss.streamIDs[i]]
		if s.WriteBufferLen() > 0 || s.WriteClosed() {
			stream = s
			break
		}
	}

	// If there is no stream with data then send an empty
	if stream == nil {
		return nil
	}

	// Generate cell from stream.
	return stream.Dequeue(n)
}

// WriteNotify returns a channel that receives a notification when a new write is available.
func (ss *StreamSet) WriteNotify() <-chan struct{} {
	ss.mu.RLock()
	defer ss.mu.RUnlock()
	return ss.wnotify
}

// notifyWrite closes previous write notification channel and creates a new one.
// This provides a broadcast to all interested parties.
func (ss *StreamSet) notifyWrite() {
	ss.mu.Lock()
	close(ss.wnotify)
	ss.wnotify = make(chan struct{})
	ss.mu.Unlock()
}

// handleStream continually monitors write changes for stream.
func (ss *StreamSet) handleStream(stream *Stream) {
	notify := stream.WriteNotify()
	ss.notifyWrite()

	for {
		select {
		case <-notify:
			notify = stream.WriteNotify()
			ss.notifyWrite()
		case <-stream.WriteCloseNotify():
			ss.notifyWrite()
			return
		}
	}
}

// timestampWriter wraps a writer and prepends a timestamp & appends a newline to every write.
type timestampWriter struct {
	Writer io.Writer
}

func (w *timestampWriter) Write(p []byte) (n int, err error) {
	return fmt.Fprintf(w.Writer, "%s %s\n", time.Now().UTC().Format("2006-01-02T15:04:05.000Z"), p)
}
