package min

import (
	"bytes"
	"fmt"
	"net"

	core "github.com/refraction-networking/conjure/pkg/core"
	"github.com/refraction-networking/conjure/pkg/transports"
	pb "github.com/refraction-networking/conjure/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

const (
	// Earliest client library version ID that supports destination port randomization
	randomizeDstPortMinVersion uint = 3

	// port range boundaries for min when randomizing
	portRangeMin = 1024
	portRangeMax = 65535
)

const (
	minTagLength = 32

	// This is a misspelling that cannot be changed without also adding checks for client Library
	// version otherwise the min transport will not be backwards compatible.
	hmacString = "MinTrasportHMACString"
)

// Transport provides a struct implementing the Transport, WrappingTransport,
// PortRandomizingTransport, and FixedPortTransport interfaces.
type Transport struct{}

// Name returns the human-friendly name of the transport, implementing the
// Transport interface..
func (Transport) Name() string { return "MinTransport" }

// LogPrefix returns the prefix used when including this transport in logs,
// implementing the Transport interface.
func (Transport) LogPrefix() string { return "MIN" }

// GetIdentifier takes in a registration and returns an identifier for it. This
// identifier should be unique for each registration on a given phantom;
// registrations on different phantoms can have the same identifier.
func (Transport) GetIdentifier(d transports.Registration) string {
	return string(core.ConjureHMAC(d.SharedSecret(), hmacString))
}

// GetProto returns the next layer protocol that the transport uses. Implements
// the Transport interface.
func (Transport) GetProto() pb.IPProto {
	return pb.IPProto_Tcp
}

// ParseParams gives the specific transport an option to parse a generic object
// into parameters provided by the client during registration.
func (Transport) ParseParams(libVersion uint, data *anypb.Any) (any, error) {
	if data == nil {
		return nil, nil
	}

	// For backwards compatibility we create a generic transport params object
	// for transports that existed before the transportParams fields existed.
	if libVersion < randomizeDstPortMinVersion {
		f := false
		return &pb.GenericTransportParams{
			RandomizeDstPort: &f,
		}, nil
	}

	var m = &pb.GenericTransportParams{}
	err := transports.UnmarshalAnypbTo(data, m)
	return m, err
}

// ParamStrings returns an array of tag string that will be added to tunStats when a proxy
// session is closed. For now, no params of interest.
func (t Transport) ParamStrings(p any) []string {
	return nil
}

// WrapConnection attempts to wrap the given connection in the transport. It
// takes the information gathered so far on the connection in data, attempts to
// identify itself, and if it positively identifies itself wraps the connection
// in the transport, returning a connection that's ready to be used by others.
//
// If the returned error is nil or non-nil and non-{ transports.ErrTryAgain,
// transports.ErrNotTransport }, the caller may no longer use data or conn.
func (Transport) WrapConnection(data *bytes.Buffer, c net.Conn, originalDst net.IP, regManager transports.RegManager) (transports.Registration, net.Conn, error) {
	if data.Len() < minTagLength {
		return nil, nil, transports.ErrTryAgain
	}

	hmacID := data.String()[:minTagLength]
	reg, ok := regManager.GetRegistrations(originalDst)[hmacID]
	if !ok {
		return nil, nil, transports.ErrNotTransport
	}

	// We don't want the first 32 bytes
	data.Next(minTagLength)

	return reg, transports.PrependToConn(c, data), nil
}

// GetDstPort Given the library version, a seed, and a generic object
// containing parameters the transport should be able to return the
// destination port that a clients phantom connection will attempt to reach
func (Transport) GetDstPort(libVersion uint, seed []byte, params any) (uint16, error) {

	if libVersion < randomizeDstPortMinVersion {
		return 443, nil
	}

	if params == nil {
		return 443, nil
	}

	parameters, ok := params.(*pb.GenericTransportParams)
	if !ok {
		return 0, fmt.Errorf("bad parameters provided")
	}

	if parameters.GetRandomizeDstPort() {
		return transports.PortSelectorRange(portRangeMin, portRangeMax, seed)
	}

	return 443, nil
}
