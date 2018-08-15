package marionette

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"regexp"
	"strconv"
	"sync"

	"github.com/redjack/marionette/fte"
	"github.com/redjack/marionette/mar"
	"go.uber.org/zap"
)

var (
	// ErrNoTransitions is returned from FSM.Next() when no transitions can be found.
	ErrNoTransitions = errors.New("no transitions available")

	// ErrRetryTransition is returned from FSM.Next() when a transition should be reattempted.
	ErrRetryTransition = errors.New("retry transition")

	// ErrUUIDMismatch is returned when a cell is received from a different UUID.
	// This can occur when communicating with a peer using a different MAR document.
	ErrUUIDMismatch = errors.New("uuid mismatch")
)

// FSM represents an interface for the Marionette state machine.
type FSM interface {
	io.Closer

	// Document & FSM identifiers.
	UUID() int
	SetInstanceID(int)
	InstanceID() int

	// Party & networking.
	Party() string
	Host() string
	Port() int

	// The current state in the FSM.
	State() string

	// Returns true if State() == 'dead'
	Dead() bool

	// Moves to the next available state.
	// Returns ErrNoTransition if there is no state to move to.
	Next(ctx context.Context) error

	// Moves through the entire state machine until it reaches 'dead' state.
	Execute(ctx context.Context) error

	// Restarts the FSM so it can be reused.
	Reset()

	// Returns an FTE cipher or DFA from the cache or creates a new one.
	Cipher(regex string, n int) (Cipher, error)
	DFA(regex string, msgLen int) (DFA, error)

	// Returns the network connection attached to the FSM.
	Conn() *BufferedConn

	// Listen opens a new listener to accept data and drains into the buffer.
	Listen() (int, error)

	// Returns the stream set attached to the FSM.
	StreamSet() *StreamSet

	// Sets and retrieves key/values from the FSM.
	SetVar(key string, value interface{})
	Var(key string) interface{}

	// Returns a copy of the FSM with a different format.
	Clone(doc *mar.Document) FSM

	Logger() *zap.Logger
}

// Ensure implementation implements interface.
var _ FSM = &fsm{}

// fsm is the default implementation of the FSM.
type fsm struct {
	mu       sync.Mutex
	doc      *mar.Document // executing document
	host     string        // bind hostname
	party    string        // "client", "server"
	fteCache *fte.Cache

	conn       *BufferedConn        // connection to remote peer
	streamSet  *StreamSet           // multiplexing stream set
	listeners  map[int]net.Listener // spawn() listeners
	closeFuncs []func() error       // closers used by spawn()

	state string     // current state
	stepN int        // number of steps completed
	rand  *rand.Rand // PRNG, seed shared by peer

	// Close management
	closed bool
	ctx    context.Context
	cancel func()

	// Lookup of transitions by src state.
	transitions map[string][]*mar.Transition

	// Variable storage used by tg module.
	vars map[string]interface{}

	// Set by the first sender and used to seed PRNG.
	instanceID int
}

// NewFSM returns a new FSM. If party is the first sender then the instance id is set.
func NewFSM(doc *mar.Document, host, party string, conn net.Conn, streamSet *StreamSet) FSM {
	fsm := &fsm{
		state:     "start",
		vars:      make(map[string]interface{}),
		doc:       doc,
		host:      host,
		party:     party,
		fteCache:  fte.NewCache(),
		conn:      NewBufferedConn(conn, MaxCellLength),
		streamSet: streamSet,
		listeners: make(map[int]net.Listener),
	}
	fsm.ctx, fsm.cancel = context.WithCancel(context.TODO())
	fsm.buildTransitions()
	fsm.initFirstSender()
	return fsm
}

// buildTransitions caches a mapping of source to destination transition for the document.
func (fsm *fsm) buildTransitions() {
	fsm.transitions = make(map[string][]*mar.Transition)
	for _, t := range fsm.doc.Transitions {
		fsm.transitions[t.Source] = append(fsm.transitions[t.Source], t)
	}
}

// initFirstSender generates an instance ID & seeds the PRNG if this party initiates the connection.
func (fsm *fsm) initFirstSender() {
	if fsm.party != fsm.doc.FirstSender() {
		return
	}
	fsm.instanceID = int(rand.Int31())
	fsm.rand = rand.New(rand.NewSource(int64(fsm.instanceID)))
}

// Close closes the underlying connection & context.
func (fsm *fsm) Close() error {
	fsm.mu.Lock()
	defer fsm.mu.Unlock()
	fsm.closed = true
	fsm.cancel()
	return fsm.Conn().Close()
}

// Closed returns true if FSM has been closed.
func (fsm *fsm) Closed() bool {
	fsm.mu.Lock()
	defer fsm.mu.Unlock()
	return fsm.closed
}

// Reset resets the state and variable set.
func (fsm *fsm) Reset() {
	fsm.state = "start"
	fsm.vars = make(map[string]interface{})

	for _, fn := range fsm.closeFuncs {
		if err := fn(); err != nil {
			fsm.Logger().Error("close error", zap.Error(err))
		}
	}
	fsm.closeFuncs = nil
}

// UUID returns the computed MAR document UUID.
func (fsm *fsm) UUID() int { return fsm.doc.UUID }

// InstanceID returns the ID for this specific FSM.
func (fsm *fsm) InstanceID() int { return fsm.instanceID }

// SetInstanceID sets the ID for the FSM.
func (fsm *fsm) SetInstanceID(id int) { fsm.instanceID = id }

// State returns the current state of the FSM.
func (fsm *fsm) State() string { return fsm.state }

// Conn returns the connection the FSM was initialized with.
func (fsm *fsm) Conn() *BufferedConn { return fsm.conn }

// StreamSet returns the stream set the FSM was initialized with.
func (fsm *fsm) StreamSet() *StreamSet { return fsm.streamSet }

// Host returns the hostname the FSM was initialized with.
func (fsm *fsm) Host() string { return fsm.host }

// Party returns "client" or "server" depending on who is initializing the FSM.
func (fsm *fsm) Party() string { return fsm.party }

// Port returns the port from the underlying document.
// If port is a named port then it is looked up in the local variables.
func (fsm *fsm) Port() int {
	// Use specified port, if numeric.
	if port, err := strconv.Atoi(fsm.doc.Port); err == nil {
		return port
	}

	// Otherwise lookup port set as a variable.
	if v := fsm.Var(fsm.doc.Port); v != nil {
		port, _ := v.(int)
		return port
	}

	return 0
}

// Dead returns true when the FSM is complete.
func (fsm *fsm) Dead() bool { return fsm.state == "dead" }

// Execute runs the the FSM to completion.
func (fsm *fsm) Execute(ctx context.Context) error {
	// If no connection is passed in, create one.
	// This occurs when an FSM is spawned.
	if err := fsm.ensureConn(ctx); err != nil {
		return err
	}

	// Continually move to the next state until we reach the "dead" state.
	for !fsm.Dead() {
		// Transitions can request to retry if the instance ID is updated.
		// In this case, the PRNG is seeded and stepN steps are reprocessed w/ new PRNG.
		if err := fsm.Next(ctx); err == ErrRetryTransition {
			fsm.Logger().Debug("retry transition", zap.String("state", fsm.State()))
			continue
		} else if err != nil {
			return err
		}
	}
	return nil
}

// Next transitions to the next state in the executing MAR document..
func (fsm *fsm) Next(ctx context.Context) (err error) {
	// Notify caller stream is closed if FSM has been closed.
	if fsm.Closed() {
		return ErrStreamClosed
	}

	// Generate a new PRNG once we have an instance ID.
	if err := fsm.init(); err != nil {
		return err
	}

	// If we have a successful transition, update our state info.
	// Exit if no transitions were successful.
	nextState, err := fsm.next(true)
	if err != nil {
		return err
	}

	// Track number of steps so they can be replayed once the instance ID is received.
	// This only occurs if FSM's party is not the first sender.
	fsm.stepN += 1
	fsm.state = nextState

	return nil
}

func (fsm *fsm) next(eval bool) (nextState string, err error) {
	// Find all possible transitions from the current state.
	transitions := mar.FilterTransitionsBySource(fsm.doc.Transitions, fsm.state)
	errorTransitions := mar.FilterErrorTransitions(transitions)

	// Then filter by PRNG (if available) or return all (if unavailable).
	transitions = mar.FilterNonErrorTransitions(transitions)
	transitions = mar.ChooseTransitions(transitions, fsm.rand)
	assert(len(transitions) > 0)

	// Add error transitions back in after selection.
	transitions = append(transitions, errorTransitions...)

	// Attempt each possible transition.
	for _, transition := range transitions {
		// If there's no action block then move to the next state.
		if transition.ActionBlock == "NULL" {
			return transition.Destination, nil
		}

		// Find all actions for this destination and current party.
		blk := fsm.doc.ActionBlock(transition.ActionBlock)
		if blk == nil {
			return "", fmt.Errorf("fsm.Next(): action block not found: %q", transition.ActionBlock)
		}
		actions := mar.FilterActionsByParty(blk.Actions, fsm.party)

		// Attempt to execute each action.
		if eval {
			if err := fsm.evalActions(actions); err != nil {
				return "", err
			}
		}
		return transition.Destination, nil
	}
	return "", nil
}

// init initializes the PRNG if we now have a instance id.
func (fsm *fsm) init() (err error) {
	// Skip if already initialized or we don't have an instance ID yet.
	if fsm.rand != nil || fsm.instanceID == 0 {
		return nil
	}

	// Create new PRNG.
	fsm.rand = rand.New(rand.NewSource(int64(fsm.instanceID)))

	// Restart FSM from the beginning and iterate until the current step.
	fsm.state = "start"
	for i := 0; i < fsm.stepN; i++ {
		fsm.state, err = fsm.next(false)
		if err != nil {
			return err
		}
		assert(fsm.state != "")
	}
	return nil
}

// evalActions attempts to evaluate every action until one succeeds.
func (fsm *fsm) evalActions(actions []*mar.Action) error {
	if len(actions) == 0 {
		return nil
	}

	for _, action := range actions {
		// If there is no matching regex then simply evaluate action.
		if action.Regex != "" {
			// Compile regex.
			re, err := regexp.Compile(action.Regex)
			if err != nil {
				return err
			}

			// Only evaluate action if buffer matches.
			buf, err := fsm.conn.Peek(-1, false)
			if err != nil {
				return err
			} else if !re.Match(buf) {
				continue
			}
		}

		fn := FindPlugin(action.Module, action.Method)
		if fn == nil {
			return fmt.Errorf("plugin not found: %s", action.Name())
		} else if err := fn(fsm.ctx, fsm, action.ArgValues()...); err != nil {
			return err
		}
		return nil
	}

	return ErrNoTransitions
}

// Var returns the variable value for a given key.
func (fsm *fsm) Var(key string) interface{} {
	switch key {
	case "model_instance_id":
		return fsm.InstanceID
	case "model_uuid":
		return fsm.doc.UUID
	case "party":
		return fsm.party
	default:
		return fsm.vars[key]
	}
}

// SetVar sets the variable value for a given key.
func (fsm *fsm) SetVar(key string, value interface{}) {
	fsm.vars[key] = value
}

// Cipher returns a cipher with the given settings.
// If no cipher exists then a new one is created and returned.
func (fsm *fsm) Cipher(regex string, n int) (Cipher, error) {
	return fsm.fteCache.Cipher(regex, n)
}

// DFA returns a DFA with the given settings.
// If no DFA exists then a new one is created and returned.
func (fsm *fsm) DFA(regex string, n int) (DFA, error) {
	return fsm.fteCache.DFA(regex, n)
}

// Listen opens a listener used by channel.bind(). Listener closed by Close().
//
// Port is chosen randomly unless MARIONETTE_CHANNEL_BIND_PORT environment variable is set.
func (fsm *fsm) Listen() (port int, err error) {
	addr := fsm.host
	if s := os.Getenv("MARIONETTE_CHANNEL_BIND_PORT"); s != "" {
		addr = net.JoinHostPort(addr, s)
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return 0, err
	}
	port = ln.Addr().(*net.TCPAddr).Port
	fsm.listeners[port] = ln
	fsm.closeFuncs = append(fsm.closeFuncs, ln.Close)

	return port, nil
}

// ensureConn ensures that the conn variable is set. Root FSMs are populated with
// a connection during instantiation, however, spawned FSMs require new connections.
//
// For client parties, a new connection is dialed to the server.
// For server parties, a listener is opened and it waits for the next accepted connection.
func (fsm *fsm) ensureConn(ctx context.Context) error {
	if fsm.conn != nil {
		return nil
	}
	if fsm.party == PartyClient {
		return fsm.ensureClientConn(ctx)
	}
	return fsm.ensureServerConn(ctx)
}

// ensureClientConn dials a connection to the server. Connection closed on Close().
func (fsm *fsm) ensureClientConn(ctx context.Context) error {
	conn, err := net.Dial(fsm.doc.Transport, net.JoinHostPort(fsm.host, strconv.Itoa(fsm.Port())))
	if err != nil {
		return err
	}

	fsm.conn = NewBufferedConn(conn, MaxCellLength)
	fsm.closeFuncs = append(fsm.closeFuncs, conn.Close)

	return nil
}

// ensureServerConn opens a listener and waits for the next connection.
// Will reuse listener if previously spawned. Listener closed on Close().
func (fsm *fsm) ensureServerConn(ctx context.Context) (err error) {
	ln := fsm.listeners[fsm.Port()]
	if ln == nil {
		if ln, err = net.Listen("tcp", net.JoinHostPort(fsm.host, strconv.Itoa(fsm.Port()))); err != nil {
			return err
		}
		fsm.listeners[fsm.Port()] = ln
	}

	conn, err := ln.Accept()
	if err != nil {
		return err
	}

	fsm.conn = NewBufferedConn(conn, MaxCellLength)
	fsm.closeFuncs = append(fsm.closeFuncs, conn.Close)

	return nil
}

// Clone returns a copy of f. Used when spawning new FSMs.
func (f *fsm) Clone(doc *mar.Document) FSM {
	other := &fsm{
		state:     "start",
		vars:      make(map[string]interface{}),
		doc:       doc,
		host:      f.host,
		party:     f.party,
		fteCache:  f.fteCache,
		streamSet: f.streamSet,
		listeners: f.listeners,
	}

	other.buildTransitions()
	other.initFirstSender()

	other.vars = make(map[string]interface{})
	for k, v := range f.vars {
		other.vars[k] = v
	}

	return other
}

// Logger returns the logger for this FSM.
func (fsm *fsm) Logger() *zap.Logger {
	if fsm.Closed() {
		return zap.NewNop()
	}
	return Logger.With(zap.String("party", fsm.party))
}
