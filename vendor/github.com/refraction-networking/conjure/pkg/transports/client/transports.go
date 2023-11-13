package transports

import (
	"errors"

	cj "github.com/refraction-networking/conjure/pkg/core/interfaces"
	"github.com/refraction-networking/conjure/pkg/transports/connecting/dtls"
	"github.com/refraction-networking/conjure/pkg/transports/wrapping/min"
	"github.com/refraction-networking/conjure/pkg/transports/wrapping/obfs4"
	"github.com/refraction-networking/conjure/pkg/transports/wrapping/prefix"
	pb "github.com/refraction-networking/conjure/proto"
)

// These track a builder function instead of an instance because ClientTransports with a pointer
// receiver will return a pointer over and over.
var transportsByName map[string]func() cj.Transport = make(map[string]func() cj.Transport)
var transportsByID map[pb.TransportType]func() cj.Transport = make(map[pb.TransportType]func() cj.Transport)

var (
	// ErrAlreadyRegistered error when registering a transport that matches
	// an already registered ID or name.
	ErrAlreadyRegistered = errors.New("transport already registered")

	// ErrUnknownTransport provided id or name does npt match any enabled
	// transport.
	ErrUnknownTransport = errors.New("unknown transport")
)

// New returns a new Transport
func New(name string) (cj.Transport, error) {
	builder, ok := transportsByName[name]
	if !ok {
		return nil, ErrUnknownTransport
	}

	return builder(), nil
}

// NewWithParamsByID returns a new Transport by Type ID, if one exists, and attempts to set the
// parameters provided.
func NewWithParamsByID(id pb.TransportType, params any) (cj.Transport, error) {
	builder, ok := transportsByID[id]
	if !ok {
		return nil, ErrUnknownTransport
	}

	transport := builder()
	err := transport.SetParams(params)
	return transport, err
}

// NewWithParams returns a new Transport and attempts to set the parameters provided
func NewWithParams(name string, params any) (cj.Transport, error) {
	builder, ok := transportsByName[name]
	if !ok {
		return nil, ErrUnknownTransport
	}

	transport := builder()
	err := transport.SetParams(params)
	return transport, err
}

// GetTransportByName returns transport by name
func GetTransportByName(name string) (cj.Transport, bool) {
	builder, ok := transportsByName[name]
	if !ok {
		return nil, ok
	}

	return builder(), true
}

// GetTransportByID returns transport by name
func GetTransportByID(id pb.TransportType) (cj.Transport, bool) {
	builder, ok := transportsByID[id]
	if !ok {
		return nil, ok
	}

	return builder(), true
}

var defaultTransportBuilders = []func() cj.Transport{
	func() cj.Transport { return &min.ClientTransport{} },
	func() cj.Transport { return &obfs4.ClientTransport{} },
	func() cj.Transport { return &prefix.ClientTransport{} },
	func() cj.Transport { return &dtls.ClientTransport{} },
}

// AddTransport adds new transport
func AddTransport(build func() cj.Transport) error {
	t := build()
	if t == nil {
		return ErrUnknownTransport
	}
	name := t.Name()
	id := t.ID()

	if _, ok := transportsByName[name]; ok {
		return ErrAlreadyRegistered
	} else if _, ok := transportsByID[id]; ok {
		return ErrAlreadyRegistered
	}

	transportsByName[name] = build
	transportsByID[id] = build
	return nil
}

// EnableDefaultTransports initializes the library with default transports
func EnableDefaultTransports() error {
	var err error
	for _, builder := range defaultTransportBuilders {

		err = AddTransport(builder)
		if err != nil {
			return err
		}
	}

	return nil
}

func init() {
	err := EnableDefaultTransports()
	if err != nil {
		panic(err)
	}
}

func ConfigFromTransportType(transportType pb.TransportType, randomizePortDefault bool) (cj.Transport, error) {
	switch transportType {
	case pb.TransportType_Min:
		return &min.ClientTransport{Parameters: &pb.GenericTransportParams{RandomizeDstPort: &randomizePortDefault}}, nil
	case pb.TransportType_Obfs4:
		return &obfs4.ClientTransport{Parameters: &pb.GenericTransportParams{RandomizeDstPort: &randomizePortDefault}}, nil
	default:
		return nil, errors.New("unknown transport by TransportType try using TransportConfig")
	}
}
