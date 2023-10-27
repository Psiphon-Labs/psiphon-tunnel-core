package core

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"strconv"

	pb "github.com/refraction-networking/conjure/proto"
	"github.com/refraction-networking/ed25519/extra25519"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// ConjureSharedKeys contains keys that the station is required to keep.
type ConjureSharedKeys struct {
	SharedSecret []byte
	ConjureSeed  []byte

	TransportReader io.Reader
	TransportKeys   interface{}
}

// ConjureHMAC implements the hmak that can then be used for further hkdf key generation
func ConjureHMAC(key []byte, str string) []byte {
	hash := hmac.New(sha256.New, key)
	hash.Write([]byte(str))
	return hash.Sum(nil)
}

// takes Station's Public Key
// returns Shared Secret, and Eligator Representative
func generateEligatorTransformedKey(stationPubkey []byte) ([]byte, []byte, error) {
	if len(stationPubkey) != 32 {
		return nil, nil, errors.New("Unexpected station pubkey length. Expected: 32." +
			" Received: " + strconv.Itoa(len(stationPubkey)) + ".")
	}
	var sharedSecret, clientPrivate, clientPublic, representative [32]byte
	for ok := false; !ok; {
		var sliceKeyPrivate []byte = clientPrivate[:]
		_, err := rand.Read(sliceKeyPrivate)
		if err != nil {
			return nil, nil, err
		}

		ok = extra25519.ScalarBaseMult(&clientPublic, &representative, &clientPrivate)
	}
	var stationPubkeyByte32 [32]byte
	copy(stationPubkeyByte32[:], stationPubkey)
	s, err := curve25519.X25519(clientPrivate[:], stationPubkeyByte32[:])
	if err != nil {
		return nil, nil, err
	}
	copy(sharedSecret[:], s[:])

	// extra25519.ScalarBaseMult does not randomize most significant bit(sign of y_coord?)
	// Other implementations of elligator may have up to 2 non-random bits.
	// Here we randomize the bit, expecting it to be flipped back to 0 on station
	randByte := make([]byte, 1)
	_, err = rand.Read(randByte)
	if err != nil {
		return nil, nil, err
	}
	representative[31] |= (0xC0 & randByte[0])
	return sharedSecret[:], representative[:], nil
}

// GenSharedKeys generates the keys requires to form a Conjure connection based on the SharedSecret
func GenSharedKeys(clientLibVer uint, sharedSecret []byte, tt pb.TransportType) (ConjureSharedKeys, error) {
	var err error
	cjHkdf := hkdf.New(sha256.New, sharedSecret, []byte("conjureconjureconjureconjure"), nil)
	keys := ConjureSharedKeys{
		SharedSecret: sharedSecret,
		ConjureSeed:  make([]byte, 16),
	}

	if clientLibVer < SharedKeysRefactorMinVersion {
		l := 16 + 12 + 16 + 12 + 48
		buf := make([]byte, l)
		// In older versions of the client these keys are not used by the station, but the bytes are
		// drawn from the HKDF so we must do the same to ensure backwards compatible key generation.
		// https://github.com/refraction-networking/conjure/pull/202
		if n, err := cjHkdf.Read(buf); err != nil || n != l {
			return keys, err
		}
	}
	if _, err := cjHkdf.Read(keys.ConjureSeed); err != nil {
		return keys, err
	}

	keys.TransportReader = cjHkdf

	return keys, err
}

type SharedKeys struct {
	SharedSecret, Representative []byte
	ConjureSeed                  []byte
	Reader                       io.Reader
}

var conjureGeneralHkdfSalt = []byte("conjureconjureconjureconjure")

func GenerateClientSharedKeys(pubkey [32]byte) (*SharedKeys, error) {
	sharedSecret, representative, err := generateEligatorTransformedKey(pubkey[:])
	if err != nil {
		return nil, err
	}

	cjHkdf := hkdf.New(sha256.New, sharedSecret, conjureGeneralHkdfSalt, nil)
	keys := &SharedKeys{
		SharedSecret:   sharedSecret,
		Representative: representative,
		ConjureSeed:    make([]byte, 16),
		Reader:         cjHkdf,
	}

	if _, err := cjHkdf.Read(keys.ConjureSeed); err != nil {
		return keys, err
	}
	return keys, err
}
