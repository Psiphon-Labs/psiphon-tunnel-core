package registration

import (
	dr "github.com/refraction-networking/conjure/pkg/registrars/decoy-registrar"
)

// NewDecoyRegistrar returns a decoy registrar..
func NewDecoyRegistrar() *dr.DecoyRegistrar {
	return dr.NewDecoyRegistrar()
}

// NewDecoyRegistrarWithDialer returns a decoy registrar with custom dialer.
//
// Deprecated: Set dialer in tapdace.Dialer.DialerWithLaddr instead.
func NewDecoyRegistrarWithDialer(dialer dr.DialFunc) *dr.DecoyRegistrar {
	return dr.NewDecoyRegistrarWithDialer(dialer)
}
