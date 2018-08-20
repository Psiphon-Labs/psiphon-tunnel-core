package marionette

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"

	"github.com/redjack/marionette/mar"
	"go.uber.org/zap"
)

var (
	// ErrListenerClosed is returned when trying to operate on a closed listener.
	ErrListenerClosed = errors.New("marionette: listener closed")
)

// Listener listens on a port and communicates over the marionette protocol.
type Listener struct {
	mu         sync.RWMutex
	iface      string                // bind hostname
	ln         net.Listener          // underlying listener
	conns      map[net.Conn]struct{} // open connections
	fsms       map[FSM]struct{}      // open FSMs
	doc        *mar.Document         // executing MAR document
	newStreams chan *Stream          // channel used to send all new streams
	err        error                 // last received error

	ctx    context.Context
	cancel func()

	// Close management
	once    sync.Once
	wg      sync.WaitGroup
	closing chan struct{}
	closed  bool

	// Specifies directory for dumping stream traces. Passed to StreamSet.TracePath.
	TracePath string
}

// Listen returns a new instance of Listener.
func Listen(doc *mar.Document, iface string) (*Listener, error) {
	// Parse port from MAR specification.
	port, err := strconv.Atoi(doc.Port)
	if err != nil {
		return nil, errors.New("invalid connection port")
	}
	addr := net.JoinHostPort(iface, strconv.Itoa(port))

	Logger.Debug("listen", zap.String("transport", doc.Transport), zap.String("bind", addr))

	// Open the underlying listener.
	ln, err := net.Listen(doc.Transport, addr)
	if err != nil {
		return nil, err
	}
	l := &Listener{
		ln:         ln,
		iface:      iface,
		doc:        doc,
		conns:      make(map[net.Conn]struct{}),
		fsms:       make(map[FSM]struct{}),
		newStreams: make(chan *Stream),
		closing:    make(chan struct{}),
	}
	l.ctx, l.cancel = context.WithCancel(context.Background())

	// Hand off connection handling to separate goroutine.
	l.wg.Add(1)
	go func() { defer l.wg.Done(); l.accept() }()

	return l, nil
}

// Err returns the last error that occurred on the listener.
func (l *Listener) Err() error {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.err
}

// Addr returns the underlying network address.
func (l *Listener) Addr() net.Addr { return l.ln.Addr() }

// Close stops the listener and waits for the connections to finish.
func (l *Listener) Close() error {
	err := l.ln.Close()

	l.mu.Lock()
	l.closed = true
	for conn := range l.conns {
		if e := conn.Close(); e != nil && err == nil {
			err = e
		}
		delete(l.conns, conn)
	}
	for fsm := range l.fsms {
		if e := fsm.Close(); e != nil && err == nil {
			err = e
		}
		delete(l.fsms, fsm)
	}
	l.mu.Unlock()

	l.once.Do(func() {
		l.cancel()
		close(l.closing)
	})
	l.wg.Wait()

	return err
}

// Closed returns true if the listener has been closed.
func (l *Listener) Closed() bool {
	l.mu.RLock()
	closed := l.closed
	l.mu.RUnlock()
	return closed
}

// Accept waits for a new connection.
func (l *Listener) Accept() (net.Conn, error) {
	select {
	case <-l.closing:
		return nil, ErrListenerClosed
	case stream := <-l.newStreams:
		return stream, l.Err()
	}
}

// accept continually accepts networks connections and multiplexes to streams.
func (l *Listener) accept() {
	defer close(l.newStreams)

	for {
		// Wait for next connection.
		conn, err := l.ln.Accept()
		if err != nil {
			l.mu.Lock()
			if l.closed {
				l.err = ErrListenerClosed
			} else {
				l.err = err
			}
			l.mu.Unlock()
			return
		}

		// Generate a new multiplexing set for connection.
		streamSet := NewStreamSet()
		streamSet.OnNewStream = l.onNewStream
		streamSet.TracePath = l.TracePath

		// Create FSM for processing communication.
		fsm := NewFSM(l.doc, l.iface, PartyServer, conn, streamSet)

		// Run execution in a separate goroutine.
		l.wg.Add(1)
		go func() { defer l.wg.Done(); l.execute(fsm, conn) }()
	}
}

// execute continually executes the FSM until connection is closed.
// This function is run in a separate goroutine for each connection.
func (l *Listener) execute(fsm FSM, conn net.Conn) {
	defer fsm.StreamSet().Close()

	l.addConn(conn, fsm)
	defer l.removeConn(conn, fsm)

	for !l.Closed() {
		if err := fsm.Execute(l.ctx); err == ErrStreamClosed {
			Logger.Debug("stream closed", zap.String("addr", conn.RemoteAddr().String()))
			return
		} else if err == io.EOF {
			Logger.Debug("client disconnected", zap.String("addr", conn.RemoteAddr().String()))
			return
		} else if err != nil {
			Logger.Debug("server fsm execution error", zap.Error(err))
			return
		}
		fsm.Reset()
	}
}

// onNewStream is called everytime the FSM's stream set creates a new stream.
func (l *Listener) onNewStream(stream *Stream) {
	l.newStreams <- stream
}

// addConn adds a connection & associated FSM to the open set.
func (l *Listener) addConn(conn net.Conn, fsm FSM) {
	l.mu.Lock()
	l.conns[conn] = struct{}{}
	l.fsms[fsm] = struct{}{}
	l.mu.Unlock()
}

// removeConn removes a connection & associated FSM from the open set.
func (l *Listener) removeConn(conn net.Conn, fsm FSM) {
	l.mu.Lock()
	delete(l.conns, conn)
	delete(l.fsms, fsm)
	l.mu.Unlock()
}
