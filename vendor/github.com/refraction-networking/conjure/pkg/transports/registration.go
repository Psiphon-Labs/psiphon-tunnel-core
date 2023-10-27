package transports

import (
	"io"
	"net"

	pb "github.com/refraction-networking/conjure/proto"
)

// Registration provides an abstraction around station tracked registrations.
type Registration interface {
	SharedSecret() []byte
	GetRegistrationAddress() string
	GetDstPort() uint16
	PhantomIP() *net.IP

	// Transport management functions
	TransportType() pb.TransportType
	TransportParams() any
	SetTransportKeys(interface{}) error
	TransportKeys() interface{}
	TransportReader() io.Reader
}

// RegManager provides an abstraction for the RegistrationManager which tracks registrations.
type RegManager interface {
	GetRegistrations(phantomAddr net.IP) map[string]Registration
}
