package randomize

import (
	"encoding/binary"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
	"github.com/Psiphon-Labs/covert-dtls/pkg/utils"
)

// [Psiphon] eccCipherSuiteIDs lists all ECDHE-ECDSA cipher suites supported
// by pion/dtls. At least one of these must survive truncation so that pion's
// ECDSA P-256 certificates can complete the handshake.
var eccCipherSuiteIDs = []uint16{
	0xc02b, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
	0xc009, // TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA (note: pion uses 0xc00a for the 128-bit variant)
	0xc02c, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
	0xc0ac, // TLS_ECDHE_ECDSA_WITH_AES_128_CCM
	0xc0ae, // TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8
}

/*
RandomizedMessageClientHello
*/
type RandomizedMessageClientHello struct {
	Version    protocol.Version
	Random     handshake.Random
	Cookie     []byte
	RandomALPN bool // Add a random ALPN if there is none in the hooked message

	// [Psiphon] Seed enables deterministic replay of randomization choices.
	// When non-nil, a seeded PRNG is used instead of crypto/rand.
	Seed *prng.Seed

	SessionID []byte

	CipherSuiteIDs     []uint16
	CompressionMethods []*protocol.CompressionMethod
	Extensions         []extension.Extension
}

const handshakeMessageClientHelloVariableWidthStart = 34

// Type returns the Handshake Type
func (m RandomizedMessageClientHello) Type() handshake.Type {
	return handshake.TypeClientHello
}

// ClientHello Hook for randomization
func (m *RandomizedMessageClientHello) Hook(ch handshake.MessageClientHello) handshake.Message {
	// [Psiphon] Construct PRNG from seed (deterministic) or fresh random seed
	r := utils.NewPRNG(m.Seed)

	buf, err := ch.Marshal()
	if err != nil {
		return &ch
	}
	err = m.unmarshalWithRand(buf, r)
	if err != nil {
		return &ch
	}

	m.CipherSuiteIDs = utils.ShuffleRandomLength(m.CipherSuiteIDs, true, r)

	// [Psiphon] ECC cipher suite floor: ensure at least one ECDHE-ECDSA
	// cipher suite survives truncation, required for pion's ECDSA P-256
	// certificates to complete the handshake.
	ensureECCCipherSuite(&m.CipherSuiteIDs, r)

	hasALPN := false
	for _, e := range m.Extensions {
		if e.TypeValue() == extension.TypeValue(extension.ALPNTypeValue) {
			hasALPN = true
		}
	}
	if !hasALPN && m.RandomALPN {
		e := &extension.ALPN{
			ProtocolNameList: []string{utils.ALPNS[r.Intn(len(utils.ALPNS))]},
		}
		m.Extensions = append(m.Extensions, e)
	}

	m.Extensions = utils.ShuffleRandomLength(m.Extensions, false, r)
	return m
}

// [Psiphon] ensureECCCipherSuite checks that at least one ECDHE-ECDSA cipher
// suite is present. If none survived truncation, one is randomly selected from
// the known ECC suites, appended, and the list is re-shuffled.
func ensureECCCipherSuite(suites *[]uint16, r *prng.PRNG) {
	for _, id := range *suites {
		for _, eccID := range eccCipherSuiteIDs {
			if id == eccID {
				return
			}
		}
	}

	// No ECC suite found -- pick one and append
	picked := eccCipherSuiteIDs[r.Intn(len(eccCipherSuiteIDs))]
	*suites = append(*suites, picked)

	// Re-shuffle so the appended suite isn't always last
	r.Shuffle(len(*suites), func(i, j int) {
		(*suites)[i], (*suites)[j] = (*suites)[j], (*suites)[i]
	})
}

// Marshal encodes the Handshake
func (m *RandomizedMessageClientHello) Marshal() ([]byte, error) {
	if len(m.Cookie) > 255 {
		return nil, errCookieTooLong
	}

	out := make([]byte, handshakeMessageClientHelloVariableWidthStart)
	out[0] = m.Version.Major
	out[1] = m.Version.Minor

	rand := m.Random.MarshalFixed()
	copy(out[2:], rand[:])

	out = append(out, byte(len(m.SessionID)))
	out = append(out, m.SessionID...)

	out = append(out, byte(len(m.Cookie)))
	out = append(out, m.Cookie...)
	out = append(out, utils.EncodeCipherSuiteIDs(m.CipherSuiteIDs)...)
	out = append(out, protocol.EncodeCompressionMethods(m.CompressionMethods)...)
	extensions, err := utils.ExtensionMarshal(m.Extensions)
	if err != nil {
		return nil, err
	}

	return append(out, extensions...), nil
}

// unmarshalWithRand populates the message from encoded data, using the
// provided Rand for extension randomization.
func (m *RandomizedMessageClientHello) unmarshalWithRand(data []byte, r *prng.PRNG) error {
	if len(data) < 2+handshake.RandomLength {
		return errBufferTooSmall
	}

	m.Version.Major = data[0]
	m.Version.Minor = data[1]

	var random [handshake.RandomLength]byte
	copy(random[:], data[2:])
	m.Random.UnmarshalFixed(random)

	// rest of packet has variable width sections
	currOffset := handshakeMessageClientHelloVariableWidthStart

	currOffset++
	if len(data) <= currOffset {
		return errBufferTooSmall
	}
	n := int(data[currOffset-1])
	if len(data) <= currOffset+n {
		return errBufferTooSmall
	}
	m.SessionID = append([]byte{}, data[currOffset:currOffset+n]...)
	currOffset += len(m.SessionID)

	currOffset++
	if len(data) <= currOffset {
		return errBufferTooSmall
	}
	n = int(data[currOffset-1])
	if len(data) <= currOffset+n {
		return errBufferTooSmall
	}
	m.Cookie = append([]byte{}, data[currOffset:currOffset+n]...)
	currOffset += len(m.Cookie)

	// Cipher Suites
	if len(data) < currOffset {
		return errBufferTooSmall
	}
	cipherSuiteIDs, err := utils.DecodeCipherSuiteIDs(data[currOffset:])
	if err != nil {
		return err
	}
	m.CipherSuiteIDs = cipherSuiteIDs
	if len(data) < currOffset+2 {
		return errBufferTooSmall
	}
	currOffset += int(binary.BigEndian.Uint16(data[currOffset:])) + 2

	// Compression Methods
	if len(data) < currOffset {
		return errBufferTooSmall
	}
	compressionMethods, err := protocol.DecodeCompressionMethods(data[currOffset:])
	if err != nil {
		return err
	}
	m.CompressionMethods = compressionMethods
	if len(data) < currOffset {
		return errBufferTooSmall
	}
	currOffset += int(data[currOffset]) + 1

	// Extensions
	extensions, err := RandomizeExtensionUnmarshal(data[currOffset:], r)
	if err != nil {
		return err
	}
	m.Extensions = extensions
	return nil
}

// Unmarshal populates the message from encoded data.
// Uses crypto/rand (non-deterministic) for extension randomization.
func (m *RandomizedMessageClientHello) Unmarshal(data []byte) error {
	return m.unmarshalWithRand(data, utils.NewPRNG(nil))
}
