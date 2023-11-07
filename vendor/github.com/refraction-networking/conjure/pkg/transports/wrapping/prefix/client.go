package prefix

import (
	"bufio"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"math/big"
	"net"

	"github.com/refraction-networking/conjure/pkg/core"
	"github.com/refraction-networking/conjure/pkg/transports"
	pb "github.com/refraction-networking/conjure/proto"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

// ClientTransport implements the client side transport interface for the Min transport. The
// significant difference is that there is an instance of this structure per client session, where
// the station side Transport struct has one instance to be re-used for all sessions.
//
// External libraries must set parameters through SetParams using PrefixTransportParams.
type ClientTransport struct {
	parameters    *pb.PrefixTransportParams
	sessionParams *pb.PrefixTransportParams

	// // state tracks fields internal to the registrar that survive for the lifetime
	// // of the transport session without being shared - i.e. local derived keys.
	// state any

	Prefix        Prefix
	TagObfuscator transports.Obfuscator

	connectTag       []byte
	stationPublicKey [32]byte
}

const (
	// DefaultFlush uses the flush pattern defined by the chosen prefix
	DefaultFlush int32 = iota
	// NoAddedFlush no flushes when writing prefix and tag
	NoAddedFlush
	// FlushAfterPrefix flush after the prefix before the tag (if possible), but not after tag
	// before client data is sent over the connection
	FlushAfterPrefix
)

// ClientParams are parameters available to a calling library to configure the Prefix transport
// outside of the specific Prefix
type ClientParams struct {
	RandomizeDstPort bool
	FlushPolicy      int32
	PrefixID         int32
}

func (c *ClientParams) String() string {
	return fmt.Sprintf("RandomizeDstPort: %t, FlushPolicy: %d, Prefix: %d", c.RandomizeDstPort, c.FlushPolicy, c.PrefixID)
}

func (c *ClientParams) GetParams() any {
	return c
}

// Prefix struct used by, selected by, or given to the client. This interface allows for non-uniform
// behavior like a rand prefix for example.
type Prefix interface {
	Bytes() []byte
	FlushPolicy() int32
	ID() PrefixID
	DstPort([]byte) uint16
}

// DefaultPrefixes provides the prefixes supported by default for use when by the client.
var DefaultPrefixes = map[PrefixID]Prefix{}

// Name returns the human-friendly name of the transport, implementing the Transport interface.
func (t *ClientTransport) Name() string {
	if t.Prefix == nil {
		return "prefix"
	}
	return "prefix_" + t.Prefix.ID().Name()
}

// String returns a string identifier for the Transport for logging (including string formatters)
func (t *ClientTransport) String() string {
	return t.Name()
}

// ID provides an identifier that will be sent to the conjure station during the registration so
// that the station knows what transport to expect connecting to the chosen phantom.
func (*ClientTransport) ID() pb.TransportType {
	return pb.TransportType_Prefix
}

// Prepare lets the transport use the dialer to prepare. This is called before GetParams to let the
// transport prepare stuff such as nat traversal.
func (t *ClientTransport) Prepare(ctx context.Context, dialer func(ctx context.Context, network, laddr, raddr string) (net.Conn, error)) error {
	t.debug("prepare-b")
	defer t.debug("prepare-e")
	if t.parameters == nil {
		t.parameters = proto.Clone(defaultParams()).(*pb.PrefixTransportParams)
		if t.Prefix != nil {
			t.parameters.PrefixId = proto.Int32(int32(t.Prefix.ID()))
		} else {
			t.Prefix = DefaultPrefixes[PrefixID(t.parameters.GetPrefixId())]
		}
	}
	t.sessionParams = proto.Clone(t.parameters).(*pb.PrefixTransportParams)

	// If the user set random Prefix ID in the immutable params then we need to pick a random prefix
	// for the sessions.
	if t.sessionParams.GetPrefixId() == int32(Rand) {
		newPrefix, err := pickRandomPrefix(rand.Reader)
		if err != nil {
			return err
		}

		t.Prefix = newPrefix
		t.sessionParams.PrefixId = proto.Int32(int32(newPrefix.ID()))
	}

	return nil
}

// GetParams returns a generic protobuf with any parameters from both the registration and the
// transport.
func (t *ClientTransport) GetParams() (proto.Message, error) {
	if t == nil {
		return nil, ErrBadParams
	}

	if t.Prefix == nil {
		return nil, fmt.Errorf("%w: empty or invalid Prefix provided", ErrBadParams)
	}

	if t.sessionParams == nil {
		if t.parameters != nil {
			t.sessionParams = proto.Clone(t.parameters).(*pb.PrefixTransportParams)
		} else {
			t.sessionParams = defaultParams()
		}
	}
	return t.sessionParams, nil
}

// ParseParams gives the specific transport an option to parse a generic object into parameters
// provided by the station in the registration response during registration.
func (t ClientTransport) ParseParams(data *anypb.Any) (any, error) {
	if data == nil {
		return nil, nil
	}

	var m = &pb.PrefixTransportParams{}
	err := transports.UnmarshalAnypbTo(data, m)
	return m, err
}

// DefaultParams returns the default parameters for the transport
func DefaultParams() *ClientParams {
	return &ClientParams{
		RandomizeDstPort: false,
		FlushPolicy:      DefaultFlush,
		PrefixID:         int32(Min),
	}
}

// defaultParams returns the internal default parameters for the transport
func defaultParams() *pb.PrefixTransportParams {
	return &pb.PrefixTransportParams{
		PrefixId:          proto.Int32(int32(Min)),
		RandomizeDstPort:  proto.Bool(false),
		CustomFlushPolicy: proto.Int32(DefaultFlush),
	}
}

// SetSessionParams allows the session to apply updated params that are only used within an
// individual dial, returning an error if the provided generic message is not compatible. the
// variadic bool parameter is used to indicate whether the client should sanity check the params
// or just apply them. This is useful in cases where the registrar may provide options to the
// client that it is able to handle, but are outside of the clients sanity checks. (see prefix
// transport for an example)
func (t *ClientTransport) SetSessionParams(incoming *anypb.Any, unchecked ...bool) error {
	t.debug("setsessionparams-b")
	defer t.debug("setsessionparams-e")
	if incoming == nil {
		return nil
	}

	p, err := t.ParseParams(incoming)
	if err != nil {
		return err
	}

	var prefixParams *pb.PrefixTransportParams
	switch px := p.(type) {
	case *pb.GenericTransportParams:
		if t.sessionParams == nil {
			if t.parameters == nil {
				t.sessionParams = proto.Clone(defaultParams()).(*pb.PrefixTransportParams)
			} else {
				t.sessionParams = proto.Clone(t.parameters).(*pb.PrefixTransportParams)
			}
		}
		t.sessionParams.RandomizeDstPort = proto.Bool(p.(*pb.GenericTransportParams).GetRandomizeDstPort())
		return nil
	case *pb.PrefixTransportParams:
		// make a copy of params so that we don't modify the original during an active session.
		prefixParams = proto.Clone(px).(*pb.PrefixTransportParams)
	}

	if prefixParams == nil {
		return fmt.Errorf("%w, nil params", ErrBadParams)
	}

	// If the client set a custom flush policy, use it over whatever the bidirectional registrar
	// is trying to set.
	if t.parameters.CustomFlushPolicy != nil {
		if t.parameters.GetCustomFlushPolicy() != DefaultFlush {
			prefixParams.CustomFlushPolicy = t.parameters.CustomFlushPolicy
		}
	}

	if len(unchecked) != 0 && unchecked[0] {
		// Overwrite the prefix bytes and type without checking the default set. This is used for
		// RegResponse where the registrar may override the chosen prefix with a prefix outside of
		// the prefixes that the client known about.
		t.sessionParams = prefixParams
		t.Prefix = &clientPrefix{
			bytes:       prefixParams.GetPrefix(),
			id:          PrefixID(prefixParams.GetPrefixId()),
			flushPolicy: prefixParams.GetCustomFlushPolicy(),
		}

		return nil
	}

	if prefix, ok := DefaultPrefixes[PrefixID(prefixParams.GetPrefixId())]; ok {
		t.Prefix = prefix
		t.sessionParams = proto.Clone(prefixParams).(*pb.PrefixTransportParams)

		// clear the prefix if it was set. this is used only when we don't have a known prefix
		t.sessionParams.Prefix = []byte{}
		return nil
	}

	if prefixParams.GetPrefixId() == int32(Rand) {
		newPrefix, err := pickRandomPrefix(rand.Reader)
		if err != nil {
			return err
		}

		t.Prefix = newPrefix

		if t.sessionParams == nil {
			if t.parameters != nil {
				t.sessionParams = proto.Clone(t.parameters).(*pb.PrefixTransportParams)
			} else {
				t.parameters = proto.Clone(defaultParams()).(*pb.PrefixTransportParams)
			}
		}

		t.sessionParams.PrefixId = proto.Int32(int32(t.Prefix.ID()))
		t.sessionParams.RandomizeDstPort = proto.Bool(prefixParams.GetRandomizeDstPort())

		return nil
	}

	return ErrUnknownPrefix
}

// SetParams allows the caller to set parameters associated with the transport, returning an
// error if the provided generic message is not compatible or the parameters are otherwise invalid
func (t *ClientTransport) SetParams(p any) error {
	t.debug("setparams-b")
	defer t.debug("setparams-e")
	if genericParams, ok := p.(*pb.GenericTransportParams); ok {
		// If the parameters are nil, set them to the default otherwise leave them alone so that
		// this can be used to override the RandomizeDstPort parameter for phantoms that do not
		// support it. HOWEVER, THAT WILL PERSIST if the Params are re-used.
		if t.parameters == nil {
			t.parameters = defaultParams()
		}
		t.parameters.RandomizeDstPort = proto.Bool(genericParams.GetRandomizeDstPort())
		return nil
	}

	var prefixParams *pb.PrefixTransportParams
	if clientParams, ok := p.(*pb.PrefixTransportParams); ok {
		// make a copy of params so that we don't modify the original during an active session.
		prefixParams = proto.Clone(clientParams).(*pb.PrefixTransportParams)
	} else if clientParams, ok := p.(*ClientParams); ok {
		prefixParams = &pb.PrefixTransportParams{
			PrefixId:          proto.Int32(clientParams.PrefixID),
			CustomFlushPolicy: proto.Int32(clientParams.FlushPolicy),
			RandomizeDstPort:  proto.Bool(clientParams.RandomizeDstPort),
		}
	} else if clientParams, ok := p.(ClientParams); ok {
		prefixParams = &pb.PrefixTransportParams{
			PrefixId:          proto.Int32(clientParams.PrefixID),
			CustomFlushPolicy: proto.Int32(clientParams.FlushPolicy),
			RandomizeDstPort:  proto.Bool(clientParams.RandomizeDstPort),
		}
	} else if p == nil {
		prefixParams = defaultParams()
		if t.Prefix != nil {
			prefixParams.PrefixId = proto.Int32(int32(t.Prefix.ID()))
		} else {
			t.Prefix = DefaultPrefixes[PrefixID(t.parameters.GetPrefixId())]
		}
	} else {
		return fmt.Errorf("%w, incorrect param type", ErrBadParams)
	}

	if prefixParams == nil {
		return fmt.Errorf("%w, nil params", ErrBadParams)
	}

	// Parameters set by user SetParams must either be random or known Prefix ID.
	if prefix, ok := DefaultPrefixes[PrefixID(prefixParams.GetPrefixId())]; ok {
		t.Prefix = prefix
		t.parameters = prefixParams

		// clear the prefix if it was set. this is used for RegResponse only.
		t.parameters.Prefix = []byte{}
		return nil
	} else if prefixParams.GetPrefixId() == int32(Rand) {

		newPrefix, err := pickRandomPrefix(rand.Reader)
		if err != nil {
			return err
		}

		t.Prefix = newPrefix
		t.parameters = prefixParams
		// t.parameters.PrefixId = proto.Int32(int32(Rand))
		return nil
	}

	return ErrUnknownPrefix
}

// GetDstPort returns the destination port that the client should open the phantom connection to
func (t *ClientTransport) GetDstPort(seed []byte) (uint16, error) {
	t.debug("getdstport-b")
	defer t.debug("getdstport-e")

	if t == nil {
		return 0, ErrBadParams
	}

	if t.Prefix == nil {
		return 0, fmt.Errorf("%w: empty or invalid Prefix provided", ErrBadParams)
	}

	prefixID := t.Prefix.ID()

	if prefixID == Rand {
		return 0, fmt.Errorf("%w: use SetParams or FromID if using Rand prefix", ErrUnknownPrefix)
	}

	if t.sessionParams == nil {
		p := int32(prefixID)
		t.sessionParams = &pb.PrefixTransportParams{PrefixId: &p}
	}

	if t.sessionParams.GetRandomizeDstPort() {
		return transports.PortSelectorRange(portRangeMin, portRangeMax, seed)
	}

	return t.Prefix.DstPort(seed), nil
}

// PrepareKeys provides an opportunity for the transport to integrate the station public key
// as well as bytes from the deterministic random generator associated with the registration
// that this ClientTransport is attached to.
func (t *ClientTransport) PrepareKeys(pubkey [32]byte, sharedSecret []byte, hkdf io.Reader) error {
	t.connectTag = core.ConjureHMAC(sharedSecret, "PrefixTransportHMACString")
	t.stationPublicKey = pubkey
	return nil
}

// WrapConn gives the transport the opportunity to perform a handshake and wrap / transform the
// incoming and outgoing bytes send by the implementing client.
func (t *ClientTransport) WrapConn(conn net.Conn) (net.Conn, error) {
	if t.Prefix == nil {
		return nil, ErrBadParams
	}

	if t.TagObfuscator == nil {
		t.TagObfuscator = transports.CTRObfuscator{}
	}

	if t.sessionParams == nil {
		if t.parameters == nil {
			t.sessionParams = defaultParams()
		}
		t.sessionParams = proto.Clone(t.parameters).(*pb.PrefixTransportParams)
	}

	obfuscatedID, err := t.TagObfuscator.Obfuscate(t.connectTag, t.stationPublicKey[:])
	if err != nil {
		return nil, err
	}

	w := bufio.NewWriter(conn)

	var msg []byte = t.Prefix.Bytes()

	if _, err := w.Write(msg); err != nil {
		return nil, err
	}

	// Maybe flush based on prefix spec and client param override
	switch t.sessionParams.GetCustomFlushPolicy() {
	case NoAddedFlush:
		break
	case FlushAfterPrefix:
		w.Flush()
	case DefaultFlush:
		fallthrough
	default:
		switch t.Prefix.FlushPolicy() {
		case NoAddedFlush:
			break
		case FlushAfterPrefix:
			w.Flush()
		case DefaultFlush:
			fallthrough
		default:
		}
	}

	n, err := w.Write(obfuscatedID)
	if err != nil {
		return nil, err
	} else if n != len(obfuscatedID) {
		return nil, fmt.Errorf("failed to write all bytes of obfuscated ID")
	}

	// We are **REQUIRED** to flush here otherwise the prefix and tag will not be written into
	// the wrapped net.Conn So FlushAfterTag does not make much sense.
	w.Flush()
	return conn, nil
}

// ---

type clientPrefix struct {
	bytes       []byte
	id          PrefixID
	port        uint16
	flushPolicy int32

	// // Function allowing encoding / transformation of obfuscated ID bytes after they have been
	// // obfuscated. Examples - base64 encode, padding
	// [FUTURE WORK]
	// tagEncode() func([]byte) ([]byte, int, error)

	// // Function allowing encoding / transformation of stream bytes after they have been. Examples
	// // - base64 encode, padding
	// [FUTURE WORK]
	// streamEncode() func([]byte) ([]byte, int, error)
}

func (c *clientPrefix) Bytes() []byte {
	return c.bytes
}

func (c *clientPrefix) ID() PrefixID {
	return c.id
}

func (c *clientPrefix) DstPort([]byte) uint16 {
	return c.port
}

func (c *clientPrefix) FlushPolicy() int32 {
	return c.flushPolicy
}

// ---

// TryFromID returns a Prefix based on the Prefix ID. This is useful for non-static prefixes like the
// random prefix
func TryFromID(id PrefixID) (Prefix, error) {

	if len(DefaultPrefixes) == 0 || id < Rand || int(id) > len(DefaultPrefixes) {
		return nil, ErrUnknownPrefix
	}

	if id == Rand {
		return pickRandomPrefix(rand.Reader)
	}

	return DefaultPrefixes[id], nil
}

func pickRandomPrefix(r io.Reader) (Prefix, error) {
	var n = big.NewInt(int64(len(DefaultPrefixes)))
	i, err := rand.Int(r, n)
	if err != nil {
		return nil, err
	}

	return DefaultPrefixes[PrefixID(i.Int64())], nil
}

func (t *ClientTransport) debug(s string) {
	if false {
		fmt.Printf("%s - %+v\n\t%+v\n\t%+v\n", s, t.Prefix, t.parameters, t.sessionParams)
	}
}
