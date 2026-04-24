package randomize

import (
	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
	"github.com/Psiphon-Labs/covert-dtls/pkg/utils"
)

// [Psiphon] RandomizedMessageServerHello provides a ServerHello hook that
// shuffles extension order to avoid trivial ServerHello fingerprinting.
// The ServerHello has a single cipher suite and fewer extensions than the
// ClientHello, so only extension order is randomized.
type RandomizedMessageServerHello struct {
	// Seed enables deterministic replay of the extension ordering.
	// When non-nil, a seeded PRNG is used; otherwise a fresh random seed.
	Seed *prng.Seed
}

// Hook is the ServerHelloMessageHook callback for pion/dtls.
// It shuffles the extension order of the ServerHello message.
func (m *RandomizedMessageServerHello) Hook(sh handshake.MessageServerHello) handshake.Message {
	r := utils.NewPRNG(m.Seed)

	if len(sh.Extensions) > 1 {
		r.Shuffle(len(sh.Extensions), func(i, j int) {
			sh.Extensions[i], sh.Extensions[j] = sh.Extensions[j], sh.Extensions[i]
		})
	}

	return &sh
}
