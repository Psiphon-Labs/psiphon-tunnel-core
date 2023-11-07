package tapdance

import (
	"context"

	"github.com/refraction-networking/conjure/pkg/core/interfaces"
)

// Transport provides a generic interface for utilities that allow the client to dial and connect to
// a phantom address when creating a Conjure connection.
type Transport interfaces.Transport

// Registrar defines the interface for a module completing the initial portion of the conjure
// protocol which registers the clients intent to connect, along with the specifics of the session
// they wish to establish.
type Registrar interface {
	Register(*ConjureSession, context.Context) (*ConjureReg, error)

	// PrepareRegKeys prepares key materials specific to the registrar
	PrepareRegKeys(stationPubkey [32]byte, sessionSecret []byte) error
}
