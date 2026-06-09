package mimicry

import (
	"encoding/binary"
	"encoding/hex"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
	"github.com/Psiphon-Labs/covert-dtls/pkg/fingerprints"
	"github.com/Psiphon-Labs/covert-dtls/pkg/utils"
)

const handshakeMessageClientHelloVariableWidthStart = 34

// MimickedClientHello is to be used as a way to replay DTLS client hello messages. To be used with the Pion dtls library.
type MimickedClientHello struct {
	clientHelloFingerprint fingerprints.ClientHelloFingerprint
	Version                protocol.Version
	Random                 handshake.Random
	Cookie                 []byte
	SessionID              []byte

	// [Psiphon] Seed enables deterministic fingerprint selection in
	// LoadRandomFingerprint. When non-nil, the same seed always selects
	// the same fingerprint, enabling replay.
	Seed *prng.Seed

	CipherSuiteIDs         []uint16
	CompressionMethods     []*protocol.CompressionMethod
	Extensions             []extension.Extension
	SRTPProtectionProfiles []extension.SRTPProtectionProfile
}

// Hook handler, initialize client hello
func (m *MimickedClientHello) Hook(ch handshake.MessageClientHello) handshake.Message {
	m.Random = ch.Random
	m.SessionID = ch.SessionID
	m.Cookie = ch.Cookie
	return m
}

// Type returns the Handshake Type
func (m MimickedClientHello) Type() handshake.Type {
	return handshake.TypeClientHello
}

// Parses hexstring fingerprint and sets Extensions and SRTPProtectionProfiles
func (m *MimickedClientHello) LoadFingerprint(fingerprint fingerprints.ClientHelloFingerprint) error {
	m.clientHelloFingerprint = fingerprint
	data, err := hex.DecodeString(string(m.clientHelloFingerprint))
	if err != nil {
		return errHexstringDecode
	}
	err = m.Unmarshal(data)
	return err
}

// Loads a random fingerprint to mimic.
// [Psiphon] When Seed is set, the fingerprint is selected deterministically.
func (m *MimickedClientHello) LoadRandomFingerprint() error {
	allFingerprints := fingerprints.GetClientHelloFingerprints()
	length := len(allFingerprints)
	if length == 0 {
		return errNoFingerprints
	}

	r := utils.NewPRNG(m.Seed)
	randomFingerprint := allFingerprints[r.Intn(length)]
	return m.LoadFingerprint(randomFingerprint)
}

// Marshal encodes the Handshake
func (m *MimickedClientHello) Marshal() ([]byte, error) {
	out := make([]byte, handshakeMessageClientHelloVariableWidthStart)

	if string(m.clientHelloFingerprint) == "" {
		random := m.Random
		sid := m.SessionID
		cookie := m.Cookie
		fingerprints := fingerprints.GetClientHelloFingerprints()
		if len(fingerprints) < 1 {
			return out, errNoFingerprints
		}
		fingerprint := fingerprints[len(fingerprints)-1]
		err := m.LoadFingerprint(fingerprint)
		if err != nil {
			return out, err
		}
		m.Random = random
		m.SessionID = sid
		m.Cookie = cookie
	}

	data, err := hex.DecodeString(string(m.clientHelloFingerprint))
	if err != nil {
		return out, errHexstringDecode
	}

	if len(data) <= 2 {
		return out, errBufferTooSmall
	}

	if len(m.Cookie) > 255 {
		return nil, errCookieTooLong
	}

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

// Unmarshal populates the message from encoded data
func (m *MimickedClientHello) Unmarshal(data []byte) error {
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
	extensions, err := MimicExtensionsUnmarshal(data[currOffset:])
	if err != nil {
		return err
	}
	m.Extensions = extensions
	return nil
}
