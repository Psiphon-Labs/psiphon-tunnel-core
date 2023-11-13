package interfaces

import (
	"context"
	"io"
	"net"

	pb "github.com/refraction-networking/conjure/proto"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

type dialFunc = func(ctx context.Context, network, laddr, raddr string) (net.Conn, error)

// Transport provides a generic interface for utilities that allow the client to dial and connect to
// a phantom address when creating a Conjure connection.
type Transport interface {
	// Name returns a string identifier for the Transport for logging
	Name() string
	// String returns a string identifier for the Transport for logging (including string formatters)
	String() string

	// ID provides an identifier that will be sent to the conjure station during the registration so
	// that the station knows what transport to expect connecting to the chosen phantom.
	ID() pb.TransportType

	// GetParams returns a generic protobuf with any parameters from both the registration and the
	// transport.
	GetParams() (proto.Message, error)

	// ParseParams gives the specific transport an option to parse a generic object into parameters
	// provided by the station in the registration response during registration.
	ParseParams(data *anypb.Any) (any, error)

	// SetParams allows the caller to set parameters associated with the transport, returning an
	// error if the provided generic message is not compatible.
	SetParams(any) error

	// SetSessionParams allows the session to apply updated params that are only used within an
	// individual dial, returning an error if the provided generic message is not compatible. the
	// variadic bool parameter is used to indicate whether the client should sanity check the params
	// or just apply them. This is useful in cases where the registrar may provide options to the
	// client that it is able to handle, but are outside of the clients sanity checks. (see prefix
	// transport for an example)
	SetSessionParams(incoming *anypb.Any, unchecked ...bool) error

	// Prepare lets the transport use the dialer to prepare. This is called before GetParams to let the
	// transport prepare stuff such as nat traversal.
	Prepare(ctx context.Context, dialer func(ctx context.Context, network, laddr, raddr string) (net.Conn, error)) error

	// GetDstPort returns the destination port that the client should open the phantom connection with.
	GetDstPort(seed []byte) (uint16, error)

	// PrepareKeys provides an opportunity for the transport to integrate the station public key
	// as well as bytes from the deterministic random generator associated with the registration
	// that this ClientTransport is attached to.
	PrepareKeys(pubkey [32]byte, sharedSecret []byte, dRand io.Reader) error
}

type WrappingTransport interface {
	Transport

	// Connect returns a net.Conn connection given a context and ConjureReg
	WrapConn(conn net.Conn) (net.Conn, error)
}

type ConnectingTransport interface {
	Transport

	WrapDial(dialer dialFunc) (dialFunc, error)

	DisableRegDelay() bool
}

// Overrides makes it possible to treat an array of overrides as a single override note that the
// subsequent overrides are not aware of those that come before so they may end up undoing their
// changes.
type Overrides []RegOverride

// Override implements the RegOverride interface.
func (o Overrides) Override(reg *pb.C2SWrapper, randReader io.Reader) error {
	var err error
	for _, override := range o {
		err = override.Override(reg, randReader)
		if err != nil {
			return err
		}
	}
	return nil
}

// RegOverride provides a generic way for the station to mutate an incoming registration before
// handing it off to the stations or returning it to the client as part of the RegResponse protobuf.
type RegOverride interface {
	Override(*pb.C2SWrapper, io.Reader) error
}

// DNAT used by the station side DTLS transport implementation to warm up the DNAT table such that
// we are able to handle incoming client connections.
type DNAT interface {
	AddEntry(clientAddr *net.IP, clientPort uint16, phantomIP *net.IP, phantomPort uint16) error
}

// DnatBuilder function type alias for building a DNAT object
type DnatBuilder func() (DNAT, error)
