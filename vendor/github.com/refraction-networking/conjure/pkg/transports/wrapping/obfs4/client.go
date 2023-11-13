package obfs4

import (
	"context"
	"fmt"
	"io"
	"net"

	"github.com/refraction-networking/conjure/pkg/transports"
	pb "github.com/refraction-networking/conjure/proto"
	"github.com/refraction-networking/obfs4/transports/obfs4"

	pt "gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/goptlib"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

// ClientTransport implements the client side transport interface for the Min transport. The
// significant difference is that there is an instance of this structure per client session, where
// the station side Transport struct has one instance to be re-used for all sessions.
type ClientTransport struct {
	// Parameters are fields that will be shared with the station in the registration. This object
	// should be considered immutable after initialization otherwise changes will persist across
	// subsequent dials.
	Parameters *pb.GenericTransportParams
	// SessionParams are fields that will be used for the current session only
	sessionParams *pb.GenericTransportParams

	keys Obfs4Keys
}

// Name returns a string identifier for the Transport for logging
func (*ClientTransport) Name() string {
	return "obfs4"
}

// String returns a string identifier for the Transport for logging (including string formatters)
func (*ClientTransport) String() string {
	return "obfs4"
}

// ID provides an identifier that will be sent to the conjure station during the registration so
// that the station knows what transport to expect connecting to the chosen phantom.
func (*ClientTransport) ID() pb.TransportType {
	return pb.TransportType_Obfs4
}

func (t *ClientTransport) Prepare(ctx context.Context, dialer func(ctx context.Context, network, laddr, raddr string) (net.Conn, error)) error {
	// make a fresh copy of the parameters so that we don't modify the original during an active session.
	t.sessionParams = proto.Clone(t.Parameters).(*pb.GenericTransportParams)
	return nil
}

// GetParams returns a generic protobuf with any parameters from both the registration and the
// transport.
func (t *ClientTransport) GetParams() (proto.Message, error) {
	return t.sessionParams, nil
}

// SetSessionParams allows the session to apply updated params that are only used within an
// individual dial, returning an error if the provided generic message is not compatible. the
// variadic bool parameter is used to indicate whether the client should sanity check the params
// or just apply them. This is useful in cases where the registrar may provide options to the
// client that it is able to handle, but are outside of the clients sanity checks. (see prefix
// transport for an example)
func (t *ClientTransport) SetSessionParams(incoming *anypb.Any, unchecked ...bool) error {
	if incoming == nil {
		return nil
	}

	if t.sessionParams == nil {
		if t.Parameters == nil {
			t.Parameters = &pb.GenericTransportParams{}
		}
		// make a fresh copy of the parameters so that we don't modify the original during an active session.
		t.sessionParams = proto.Clone(t.Parameters).(*pb.GenericTransportParams)
	}
	p, err := t.ParseParams(incoming)
	if err != nil {
		return err
	}

	if p == nil {
		return nil
	}

	t.sessionParams = proto.Clone(p.(*pb.GenericTransportParams)).(*pb.GenericTransportParams)
	return nil
}

// SetParams allows the caller to set parameters associated with the transport, returning an
// error if the provided generic message is not compatible.
func (t *ClientTransport) SetParams(p any) error {
	var parsedParams *pb.GenericTransportParams
	if params, ok := p.(*pb.GenericTransportParams); ok {
		// make a copy of params so that we don't modify the original during an active session.
		parsedParams = proto.Clone(params).(*pb.GenericTransportParams)
	} else if p == nil {
		parsedParams = &pb.GenericTransportParams{}
		parsedParams.RandomizeDstPort = proto.Bool(true)
	} else {
		return fmt.Errorf("unable to parse params")
	}
	t.Parameters = parsedParams
	return nil
}

// ParseParams gives the specific transport an option to parse a generic object into parameters
// provided by the station in the registration response during registration.
func (t ClientTransport) ParseParams(data *anypb.Any) (any, error) {
	if data == nil {
		return nil, nil
	}

	var m = &pb.GenericTransportParams{}
	err := transports.UnmarshalAnypbTo(data, m)
	return m, err
}

// GetDstPort returns the destination port that the client should open the phantom connection to
func (t *ClientTransport) GetDstPort(seed []byte) (uint16, error) {
	if t.sessionParams == nil || !t.sessionParams.GetRandomizeDstPort() {
		return 443, nil
	}

	return transports.PortSelectorRange(portRangeMin, portRangeMax, seed)
}

// WrapConn creates the connection to the phantom address negotiated in the registration phase of
// Conjure connection establishment.
func (t ClientTransport) WrapConn(conn net.Conn) (net.Conn, error) {
	obfsTransport := obfs4.Transport{}
	args := pt.Args{}

	args.Add("node-id", t.keys.NodeID.Hex())
	args.Add("public-key", t.keys.PublicKey.Hex())
	args.Add("iat-mode", "1")

	c, err := obfsTransport.ClientFactory("")
	if err != nil {
		return nil, fmt.Errorf("failed to create client factory")
	}

	parsedArgs, err := c.ParseArgs(&args)
	if err != nil {
		return nil, fmt.Errorf("failed to parse obfs4 args")
	}

	d := func(network, address string) (net.Conn, error) {
		return conn, nil
	}

	return c.Dial("tcp", "", d, parsedArgs)
}

func (t *ClientTransport) PrepareKeys(pubkey [32]byte, sharedSecret []byte, dRand io.Reader) error {
	// Generate shared keys
	var err error
	t.keys, err = generateObfs4Keys(dRand)
	if err != nil {
		return err
	}
	return nil
}
