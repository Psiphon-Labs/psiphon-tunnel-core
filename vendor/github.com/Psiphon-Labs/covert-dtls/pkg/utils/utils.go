package utils

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"fmt"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/prng"
	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
)

// [Psiphon] NewPRNG returns a *prng.PRNG. If seed is non-nil, a deterministic
// PRNG is returned for replay; otherwise a fresh randomly-seeded PRNG is
// created. This avoids a custom Rand interface -- prng.PRNG already provides
// Intn, Shuffle, and FlipCoin.
func NewPRNG(seed *prng.Seed) *prng.PRNG {
	if seed != nil {
		return prng.NewPRNGWithSeed(seed)
	}
	newSeed, err := prng.NewSeed()
	if err != nil {
		// This should not happen in practice; prng.NewSeed reads from
		// crypto/rand. If it fails, fall back to a zero seed rather
		// than panic in a circumvention tool.
		return prng.NewPRNGWithSeed(&prng.Seed{})
	}
	return prng.NewPRNGWithSeed(newSeed)
}

func DefaultSRTPProtectionProfiles() []dtls.SRTPProtectionProfile {
	return []dtls.SRTPProtectionProfile{
		dtls.SRTP_AES128_CM_HMAC_SHA1_80,
		dtls.SRTP_AES128_CM_HMAC_SHA1_32,
		dtls.SRTP_AES256_CM_SHA1_80,
		dtls.SRTP_AES256_CM_SHA1_32,
		dtls.SRTP_NULL_HMAC_SHA1_80,
		dtls.SRTP_NULL_HMAC_SHA1_32,
		dtls.SRTP_AEAD_AES_128_GCM,
		dtls.SRTP_AEAD_AES_256_GCM,
	}
}

var ALPNS = []string{"http/1.0", "http/1.1", "h2c", "h2", "h3", "stun.turn", "webrtc", "c-webrtc", "ftp", "pop3", "imap", "mqtt", "smb", "irc", "sip/2"}

// [Psiphon] ShuffleRandomLength shuffles a slice and optionally truncates it.
// When randomLen is true, a geometric/coin-flip distribution is used for
// truncation length, biased toward keeping more elements (matching
// tunnel-core's existing DTLS randomization behavior).
func ShuffleRandomLength[T any](s []T, randomLen bool, p *prng.PRNG) []T {
	if len(s) == 0 {
		return s
	}

	result := make([]T, len(s))
	copy(result, s)

	p.Shuffle(len(result), func(i, j int) {
		result[i], result[j] = result[j], result[i]
	})

	if randomLen {
		// [Psiphon] Geometric/coin-flip truncation: keep at least 1 element.
		// Each coin flip decides whether to remove one more element from the end.
		// This is biased toward keeping more elements, which is safer
		// than uniform truncation for maintaining handshake compatibility.
		n := len(result)
		for ; n > 1; n-- {
			if !p.FlipCoin() {
				break
			}
		}
		result = result[:n]
	}

	return result
}

// GenerateRandomP256PublicKey generates a random valid secp256r1 public key
func GenerateRandomP256PublicKey() (*ecdh.PublicKey, error) {
	curve := ecdh.P256()

	privateKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %v", err)
	}

	return privateKey.PublicKey(), nil
}

// GenerateRandomPublicKey generates a random valid X25519 public key
func GenerateRandomX25519PublicKey() (*ecdh.PublicKey, error) {
	curve := ecdh.X25519()

	privateKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %v", err)
	}

	return privateKey.PublicKey(), nil
}

// Marshal many extensions at once
func ExtensionMarshal(e []extension.Extension) ([]byte, error) {
	extensions := []byte{}
	for _, e := range e {
		raw, err := e.Marshal()
		if err != nil {
			return nil, err
		}
		extensions = append(extensions, raw...)
	}
	out := []byte{0x00, 0x00}
	binary.BigEndian.PutUint16(out, uint16(len(extensions)))
	return append(out, extensions...), nil
}
