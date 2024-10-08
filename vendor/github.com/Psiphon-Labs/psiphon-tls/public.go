package tls

// [Psiphon]
// ClientSessionState contains the state needed by clients to resume TLS sessions.
func MakeClientSessionState(
	Ticket []uint8,
	Vers uint16,
	CipherSuite uint16,
	MasterSecret []byte,
	CreatedAt uint64,
	AgeAdd uint32,
	UseBy uint64,
) *ClientSessionState {
	css := &ClientSessionState{
		ticket: Ticket,
		session: &SessionState{
			version:     Vers,
			cipherSuite: CipherSuite,
			secret:      MasterSecret,
			createdAt:   CreatedAt,
			ageAdd:      AgeAdd,
			useBy:       UseBy,
		},
	}
	return css
}
