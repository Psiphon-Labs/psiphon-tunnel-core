package tls

// [Psiphon] MakeClientSessionState constructs a ClientSessionState from raw
// components. This is used by consumers that need to create session state
// directly, such as for obfuscated tickets or QUIC PSK injection.
func MakeClientSessionState(
	Ticket []byte,
	Vers uint16,
	CipherSuite uint16,
	MasterSecret []byte,
	CreatedAt uint64,
	AgeAdd uint32,
	UseBy uint64,
) *ClientSessionState {
	css := &ClientSessionState{
		session: &SessionState{
			version:     Vers,
			cipherSuite: CipherSuite,
			secret:      MasterSecret,
			createdAt:   CreatedAt,
			ageAdd:      AgeAdd,
			useBy:       UseBy,
			ticket:      Ticket,
		},
	}
	return css
}
