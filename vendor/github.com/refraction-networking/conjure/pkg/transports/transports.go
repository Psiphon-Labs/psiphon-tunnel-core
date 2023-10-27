package transports

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"math/big"
	"net"

	"golang.org/x/crypto/hkdf"
)

var (
	// ErrUnknownTransport provided id or name does npt match any enabled transport.
	ErrUnknownTransport = errors.New("unknown transport")

	// ErrTryAgain is returned by transports when it is inconclusive with the current amount of data
	// whether the transport exists in the connection.
	ErrTryAgain = errors.New("not enough information to determine transport")

	// ErrNotTransport is returned by transports when they
	// can conclusively determine that the connection does not
	// contain this transport. The caller shouldn't retry
	// with this transport.
	ErrNotTransport = errors.New("connection does not contain transport")

	// ErrTransportNotSupported is returned when a transport is unable to service one or more of the
	// required functions because the clientLibVersion is to old and the transport is not backward
	// compatible to that version.
	ErrTransportNotSupported = errors.New("Transport not supported ")

	// ErrPublicKeyLen is returned when the length of the provided public key is incorrect for
	// ed25519.
	ErrPublicKeyLen = errors.New("Unexpected station pubkey length. Expected: 32B")
)

// PrefixConn allows arbitrary readers to serve as the data source of a net.Conn. This allows us to
// consume data from the socket while later making it available again (for things like handshakes).
type PrefixConn struct {
	net.Conn
	r io.Reader
}

func (pc PrefixConn) Read(p []byte) (int, error) {
	return pc.r.Read(p)
}

// PrependToConn creates a PrefixConn which allows arbitrary readers to serve as
// the data source of a net.Conn.
func PrependToConn(c net.Conn, r io.Reader) PrefixConn {
	return PrefixConn{Conn: c, r: io.MultiReader(r, c)}
}

// PortSelectorRange provides a generic and basic way to return a seeded port
// selection function that uses a custom range.
func PortSelectorRange(min, max int64, seed []byte) (uint16, error) {

	// Naive Method. Get random in port range.
	hkdfReader := hkdf.New(sha256.New, seed, nil, []byte("phantom-select-dst-port"))
	port, err := rand.Int(hkdfReader, big.NewInt(max-min))
	if err != nil {
		return 0, nil
	}

	port.Add(port, big.NewInt(min))
	return uint16(port.Uint64()), nil
}
