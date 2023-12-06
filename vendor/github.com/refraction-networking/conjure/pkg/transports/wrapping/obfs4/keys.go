package obfs4

import (
	"io"

	"github.com/refraction-networking/obfs4/common/ntor"
	"golang.org/x/crypto/curve25519"
)

type Obfs4Keys struct {
	PrivateKey *ntor.PrivateKey
	PublicKey  *ntor.PublicKey
	NodeID     *ntor.NodeID
}

func generateObfs4Keys(rand io.Reader) (Obfs4Keys, error) {
	keys := Obfs4Keys{
		PrivateKey: new(ntor.PrivateKey),
		PublicKey:  new(ntor.PublicKey),
		NodeID:     new(ntor.NodeID),
	}

	_, err := rand.Read(keys.PrivateKey[:])
	if err != nil {
		return keys, err
	}

	keys.PrivateKey[0] &= 248
	keys.PrivateKey[31] &= 127
	keys.PrivateKey[31] |= 64

	pub, err := curve25519.X25519(keys.PrivateKey[:], curve25519.Basepoint)
	if err != nil {
		return keys, err
	}
	copy(keys.PublicKey[:], pub)

	_, err = rand.Read(keys.NodeID[:])
	return keys, err
}
